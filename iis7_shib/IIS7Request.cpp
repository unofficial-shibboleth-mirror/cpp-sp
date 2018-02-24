/**
* Licensed to the University Corporation for Advanced Internet
* Development, Inc. (UCAID) under one or more contributor license
* agreements. See the NOTICE file distributed with this work for
* additional information regarding copyright ownership.
*
* UCAID licenses this file to you under the Apache License,
* Version 2.0 (the "License"); you may not use this file except
* in compliance with the License. You may obtain a copy of the
* License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
*/

#include "IIS7_shib.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/tokenizer.hpp>

#include <xercesc/util/Base64.hpp>
#include <xmltooling/util/NDC.h>

#include <shibsp/exceptions.h>

#include <codecvt> // 16 bit to 8 bit chars
#include "IIS7Request.hpp"
#include "ShibHttpModule.hpp"
#include "ShibUser.hpp"

using namespace Config;

IIS7Request::IIS7Request(IHttpContext *pHttpContext, IHttpEventProvider *pEventProvider, bool checkUser) : AbstractSPRequest(SHIBSP_LOGCAT ".NATIVE"),
    m_ctx(pHttpContext), m_request(pHttpContext->GetRequest()), m_response(pHttpContext->GetResponse()),
    m_firsttime(true), m_gotBody(false), m_event(pEventProvider)
{
    DWORD len;

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    setRequestURI(converter.to_bytes(m_ctx->GetScriptName()).c_str());

    PCSTR port;
    HRESULT hr = m_ctx->GetServerVariable("SERVER_PORT_SECURE", &port, &len);

    if (SUCCEEDED(hr)) {
        if (len) {
            int secure = lexical_cast<int>(port);
            m_SSL = (0 != secure)? true:false;
        }
        else {
            m_SSL = (nullptr == m_request->GetRawHttpRequest()->pSslInfo);
        }
    }
    else {
        throwError("Get Server Secure", hr);
    }

    map<string, site_t>::const_iterator map_i = g_Sites.find(lexical_cast<string>(m_request->GetSiteId()));
    bool setPort = false;
    string thePort("");
    if (!g_bNormalizeRequest) {
        // Only grab the port from IIS if the user said no to normalization
        hr = m_ctx->GetServerVariable("SERVER_PORT", &port, &len);
        if (SUCCEEDED(hr)) {
            thePort = port;
        }
    }

    if (map_i == g_Sites.end()) {

        log(SPRequest::SPDebug, "Site not found, using IIS provided information");

        // ServerVariable SERVER_NAME is what the client sent.  So use the IIS site name (which needs to have been set to something sensible)
        m_hostname = converter.to_bytes(m_ctx->GetSite()->GetSiteName());
        to_lower(m_hostname);
        log(SPRequest::SPDebug, "Host name: " + m_hostname);

        m_useHeaders = g_bUseHeaders;
        m_useVariables = g_bUseVariables;
    }
    else {
        log(SPRequest::SPDebug, "Site found, using site informatiom");

        site_t site = map_i->second;

        m_useHeaders = site.m_useHeaders;
        m_useVariables = site.m_useVariables;

        // Grab the host from the site
        m_hostname = site.m_name;

        // Grab the port from the site - if present
        if (m_SSL && !site.m_sslport.empty()) {
            m_port = lexical_cast<int>(site.m_sslport);
            setPort = true;
        }
        else if (!m_SSL && !site.m_port.empty()) {
            m_port = lexical_cast<int>(site.m_port);
            setPort = true;
        }
    }

    if (!setPort) {
        if (!thePort.empty()) {
            // We've not set the port so far (from the site) *AND* we are not normalising, grab from IIS
            setPort = true;
            m_port = lexical_cast<int>(port);
        }
        else {
            // hardwire.
            if (m_SSL) {
                m_port = 443;
            }
            else {
                m_port = 80;
            }
        }
    }

    PCSTR ru;
    hr = m_ctx->GetServerVariable("REMOTE_USER", &ru, &len);
    if (SUCCEEDED(hr)) {
        if (len) {
            m_remoteUser = ru;
        }
        else {
            m_remoteUser = "";
        }
    }
    else {
        throwError("Get remote user", hr);
    }

    if (checkUser && m_useHeaders && !g_spoofKey.empty()) {
        const string hdr = getHeader(SpoofHeaderName);
        if (hdr == g_spoofKey) {
            m_firsttime = false;
        }
        if (!m_firsttime) {
            log(SPDebug, "IIS filter running more than once");
        }
    }
}

void IIS7Request::setHeader(const char* name, const char* value)
{
    if (m_useHeaders) {
        const string hdr = g_bSafeHeaderNames ? makeSafeHeader(name) : (string(name) + ':');
        const HRESULT hr (m_request->SetHeader(hdr.c_str(), value, static_cast<USHORT>(strlen(value)), TRUE));
        if (FAILED(hr)) {
            throwError("setHeader (Header)", hr);
        }
    }
    if (m_useVariables) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        const wstring wValue(converter.from_bytes(value));
        const HRESULT hr(m_ctx->SetServerVariable(const_cast<char*>(name), wValue.c_str()));
        if (FAILED(hr)) {
            throwError("setHeader (Variable)", hr);
        }

        for (vector<string>::iterator roleAttribute = g_RoleAttributeNames.begin(); roleAttribute != g_RoleAttributeNames.end(); ++roleAttribute) {
            if (*roleAttribute == name) {
                const string str(value);
                tokenizer<escaped_list_separator<char>> tok(str, escaped_list_separator<char>('\\', ';', '"'));
                for (tokenizer<escaped_list_separator<char>>::iterator it = tok.begin(); it != tok.end(); ++it) {
                    m_roles.insert(converter.from_bytes(*it));
                }
            }
        }
    }
}

void IIS7Request::setRemoteUser(const char* user)
{
    m_remoteUser = user;
    // Setting the variable REMOTE_USER fails, so set the Principal if we are called appropriately.
    // Getting REMOTE_USER goes via the Principal.
    auto_ptr_XMLCh widen(user);
    IAuthenticationProvider *auth = dynamic_cast<IAuthenticationProvider*>(m_event);

    if (auth) {
        if (!g_authNRole.empty()) {
            m_roles.insert(g_authNRole);
        }
        auth->SetUser(new ShibUser(user, m_roles));
    }
    else {
        log(SPError, "Internal Error:  setting remote user in a non AuthN Context");
    }
}

const vector<string>& IIS7Request::getClientCertificates() const
// TODO test - all the calls are commented out.
{
    if (m_certs.empty()) {
        HTTP_SSL_CLIENT_CERT_INFO *certInfo = NULL;
        BOOL negotiated;
        HRESULT hr = m_request->GetClientCertificate(&certInfo, &negotiated);
        if (HRESULT_FROM_WIN32(ERROR_NOT_FOUND) == hr) {
            return m_certs;
        }
        else if (FAILED(hr)) {
            throwError("GetClientCertificate", hr);
        }
        if (nullptr == certInfo) {
            return m_certs;
        }
        XMLSize_t outlen;
        XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(certInfo->pCertEncoded), certInfo->CertEncodedSize, &outlen);
        m_certs.push_back(reinterpret_cast<char*>(serialized));
        XMLString::release((char**)&serialized);
    }
    return m_certs;
}

const char* IIS7Request::getMethod() const
{
    return m_request->GetHttpMethod();
}

void IIS7Request::clearHeader(const char* rawname, const char* cginame)
{
    if (m_useHeaders) {
        if (g_checkSpoofing && m_firsttime) {
            if (m_allhttp.empty()) {
                PCSTR all = m_request->GetHeader("ALL_HTTP");
                m_allhttp =  (nullptr == all) ? "" : all;
            }
            if (!m_allhttp.empty()) {
                string hdr = g_bSafeHeaderNames ? ("HTTP_" + makeSafeHeader(cginame + 5)) : (string(cginame) + ':');
                if (strstr(m_allhttp.c_str(), hdr.c_str())) {
                    throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, hdr.c_str()));
                }
            }
        }
        if (g_bSafeHeaderNames) {
            string hdr = makeSafeHeader(rawname);
            HRESULT hr = m_request->SetHeader(hdr.c_str(), g_unsetHeaderValue.c_str(), static_cast<USHORT>(g_unsetHeaderValue.length()), TRUE);
            if (FAILED(hr)) {
                throwError("clearHeader", hr);
            }
        }
    }
}

long IIS7Request::returnDecline()
{
    return RQ_NOTIFICATION_CONTINUE;
}

long IIS7Request::returnOK()
{
    return RQ_NOTIFICATION_CONTINUE;
}

void IIS7Request::log(SPLogLevel level, const string& msg) const
{
    AbstractSPRequest::log(level, msg);
    if (level >= SPCrit)
        LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_CRITICAL, nullptr, msg.c_str());
}

string IIS7Request::getRemoteAddr() const
{
    string ret = AbstractSPRequest::getRemoteAddr();
    if (ret.empty()) {
        PCSTR addr;
        DWORD len;
        HRESULT hr = m_ctx->GetServerVariable("REMOTE_ADDR", &addr, &len);
        if (SUCCEEDED(hr)) {
            ret = addr;
        }
    }
    return ret;
}

string IIS7Request::getSecureHeader(const char* name) const
{
    string hdr = g_bSafeHeaderNames ? makeSafeHeader(name) : (string(name) + ':');
    PCSTR p = m_request->GetHeader(hdr.c_str());
    return (nullptr == p) ? "" : p;
}
//
// XMLTooling::GenericRequest
//
const char* IIS7Request::getScheme() const
{
    return m_SSL ? "https" : "http";
}

const char* IIS7Request::getHostname() const
{
    return m_hostname.c_str();
}

int IIS7Request::getPort() const
{
    return m_port;
}

string IIS7Request::getContentType() const
{
    PCSTR type;
    DWORD len;
    HRESULT hr = m_ctx->GetServerVariable("CONTENT_TYPE", &type, &len);
    if (SUCCEEDED(hr)) {
        return string(type);
    }
    return "";
}

long IIS7Request::getContentLength() const
{
    PCSTR length;
    DWORD len;
    HRESULT hr = m_ctx->GetServerVariable("CONTENT_LENGTH", &length, &len);
    if (SUCCEEDED(hr)) {
        return lexical_cast<int>(length);
    }
    return 0;
}

string IIS7Request::getRemoteUser() const
{
    if (!m_remoteUser.empty()) {
        return m_remoteUser;
    }
    PCSTR p = m_request->GetHeader("REMOTE_USER");
    m_remoteUser = (nullptr == p) ? "" : p;
    return m_remoteUser;
}

const char* IIS7Request::getRequestBody() const
{
    if (m_gotBody) {
        return m_body.c_str();
    }
    // TODO Not Thread safe?
    DWORD totalBytesLeft = m_request->GetRemainingEntityBytes();
    if (totalBytesLeft > 1024 * 1024) {
        throw opensaml::SecurityPolicyException("Size of request body exceeded 1M size limit.");
    }
    while (totalBytesLeft) {
        char buf[8192];
        DWORD bytesRead;
        HRESULT hr = m_request->ReadEntityBody(buf, sizeof(buf), FALSE, &bytesRead);
        if (FAILED(hr)) {
            throwError("request->ReadEntityBody", hr);
        }
        m_body.append(buf, bytesRead);
        if (totalBytesLeft < bytesRead) {
            totalBytesLeft = 0;
        } 
        else {
            totalBytesLeft -= bytesRead;
        }
    }
    m_gotBody = true;

    return m_body.c_str();
}

//
// XMLTooing:: HTTPRequest
//
const char* IIS7Request::getQueryString() const
{
    PCSTR qs;
    DWORD len;
    HRESULT hr = m_ctx->GetServerVariable("QUERY_STRING", &qs, &len);
    if (SUCCEEDED(hr)) {
        return qs;
    }
    return "";
}

string IIS7Request::getHeader(const char* name) const
{
    PCSTR p = m_request->GetHeader(name);
    return  (nullptr == p) ? "" : p;
}

// XMLTooing:: HTTPResponse, GenericResponse
long IIS7Request::sendResponse(istream& in, long status)
{
    const char* codestr="200 OK";
    switch (status) {
    case XMLTOOLING_HTTP_STATUS_NOTMODIFIED:    codestr="304 Not Modified"; break;
    case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="401 Authorization Required"; break;
    case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="403 Forbidden"; break;
    case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="404 Not Found"; break;
    case XMLTOOLING_HTTP_STATUS_ERROR:          codestr="500 Server Error"; break;
    }

    HRESULT hr = m_response->SetStatus(static_cast<USHORT>(status), codestr);
    if (FAILED(hr)) {
        logFatal("Response->SetStatus", hr);
        m_ctx->SetRequestHandled();
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    while (in) {
        char buf[1024];
        in.read(buf, sizeof(buf));

        HTTP_DATA_CHUNK chunk;
        chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE::HttpDataChunkFromMemory;
        chunk.FromMemory.BufferLength = static_cast<ULONG>(in.gcount());
        chunk.FromMemory.pBuffer = buf;

        DWORD sent;
        hr = m_response->WriteEntityChunks(&chunk, 1, FALSE, in.eof()? FALSE: TRUE, &sent);
        if (FAILED(hr)) {
            logFatal("Response->WriteEntityChunks", hr);
            m_ctx->SetRequestHandled();
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
    }
    m_ctx->SetRequestHandled();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}

// XMLTooing:: HTTPResponse
void IIS7Request::setResponseHeader(const char* name, const char* value)
{
    HTTPResponse::setResponseHeader(name, value);

    size_t sz = strlen(value);

    if (sz > USHRT_MAX) {
        // TODO Do this elsewhere?
        log(SPWarn, "Header value overflow");
        sz = USHRT_MAX;
    }

    HRESULT hr = m_response->SetHeader(name, value,  static_cast<USHORT>(sz), FALSE);
    if (FAILED(hr)) {
        throwError("setResponseHeader", hr);
    }
}

long IIS7Request::sendRedirect(const char* url)
{
    HTTPResponse::sendRedirect(url);
    HRESULT hr = m_response->Redirect(url);
    if (FAILED(hr)) {
        logFatal("Redirect", hr);
    }
    m_ctx->SetRequestHandled();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}

string IIS7Request::makeSafeHeader(const char* rawname) const
{
    string hdr;
    for (; *rawname; ++rawname) {
        if (isalnum(*rawname))
            hdr += *rawname;
    }
    return (hdr + ':');
}

// TODO We need a strategy for what is logged, what is fatal and how.
void IIS7Request::logFatal(const string& operation, HRESULT hr) const
{
    string msg(operation + " failed: " + lexical_cast<string>(hr));
    LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_CRITICAL, nullptr, msg.c_str());
    if (m_response) {
        (void)m_response->SetStatus(static_cast<USHORT>(XMLTOOLING_HTTP_STATUS_ERROR), "Fatal Server Error", 0, hr);
    }
}

void IIS7Request::throwError(const string& operation, HRESULT hr) const
{
    string msg(operation + " failed: " + lexical_cast<string>(hr));
    throw IOException(msg.c_str());
}
