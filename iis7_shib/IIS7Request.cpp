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
using xmltooling::logging::Priority;

IIS7Request::IIS7Request(IHttpContext *pHttpContext, IHttpEventProvider *pEventProvider, bool checkUser, const site_t& site)
    : AbstractSPRequest(SHIBSP_LOGCAT ".IISNative"),
        m_ctx(pHttpContext), m_request(pHttpContext->GetRequest()), m_response(pHttpContext->GetResponse()),
        m_firsttime(true), m_port(0), m_gotBody(false), m_event(pEventProvider)
{
    DWORD len;
    PCSTR var;

    setRequestURI(m_request->GetRawHttpRequest()->pRawUrl);

    bool bSSL = false;
    HRESULT hr = m_ctx->GetServerVariable("SERVER_PORT_SECURE", &var, &len);
    if (SUCCEEDED(hr)) {
        if (len) {
            try {
                int secure = lexical_cast<int>(var);
                bSSL = (0 != secure) ? true : false;
            }
            catch (const bad_lexical_cast&) {
                log(SPRequest::SPError, "exception converting SERVER_PORT_SECURE value to int");
                bSSL = (nullptr != m_request->GetRawHttpRequest()->pSslInfo);
            }
        }
        else {
            bSSL = (nullptr != m_request->GetRawHttpRequest()->pSslInfo);
        }
    }
    else {
        throwError("Get Server Secure", hr);
    }

    m_useHeaders = site.m_useHeaders;
    m_useVariables = site.m_useVariables;

    // Port may come from IIS or from site def.
    if (!g_bNormalizeRequest || (bSSL && site.m_sslport.empty()) || (!bSSL && site.m_port.empty())) {
        hr = m_ctx->GetServerVariable("SERVER_PORT", &var, &len);
        if (SUCCEEDED(hr)) {
            try {
                m_port = lexical_cast<int>(var);
            }
            catch (const bad_lexical_cast&) {
                throwError("Get Port", hr);
            }
        }
        else {
            throwError("Get Port", hr);
        }
    }
    else if (bSSL) {
        m_port = atoi(site.m_sslport.c_str());
    }
    else {
        m_port = atoi(site.m_port.c_str());
    }

    // Scheme may come from site def or be derived from IIS.
    m_scheme=site.m_scheme;
    if (m_scheme.empty() || !g_bNormalizeRequest)
        m_scheme = bSSL ? "https" : "http";

    hr = m_ctx->GetServerVariable("SERVER_NAME", &var, &len);
    if (SUCCEEDED(hr)) {
        // Make sure SERVER_NAME is "authorized" for use on this site. If not, or empty, set to canonical name.
        if (!len) {
            m_hostname = site.m_name;
        }
        else {
            m_hostname = var;
            if (site.m_name != m_hostname && site.m_aliases.find(m_hostname) == site.m_aliases.end())
                m_hostname = site.m_name;
        }
    }
    else {
        m_hostname = site.m_name;
    }

    hr = m_ctx->GetServerVariable("REMOTE_USER", &var, &len);
    if (SUCCEEDED(hr)) {
        if (len) {
            m_remoteUser = var;
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
        const HRESULT hr (m_request->SetHeader(g_bSafeHeaderNames ? makeSafeHeader(name).c_str() : name, value, static_cast<USHORT>(strlen(value)), TRUE));
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
        log(SPError, "attempt to set REMOTE_USER in an inappropriate context");
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
                PCSTR val = nullptr;
                DWORD len = 0;
                HRESULT hr = m_ctx->GetServerVariable("ALL_HTTP", &val, &len);
                if (FAILED(hr)) {
                    throwError("clearHeader", hr);
                }
                m_allhttp =  (nullptr == val) ? "" : val;
            }
            if (!m_allhttp.empty()) {
                string hdr = (g_bSafeHeaderNames ? ("HTTP_" + makeSafeHeader(cginame + 5)) : string(cginame)) + ':';
                if (strstr(m_allhttp.c_str(), hdr.c_str())) {
                    throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, hdr.c_str()));
                }
            }
        }
        HRESULT hr = m_request->SetHeader(g_bSafeHeaderNames ? makeSafeHeader(rawname).c_str() : rawname,
            g_unsetHeaderValue.c_str(), static_cast<USHORT>(g_unsetHeaderValue.length()), TRUE);
        if (FAILED(hr)) {
            throwError("clearHeader", hr);
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
    if (m_useVariables) {
        PCSTR p;
        DWORD len;
        HRESULT hr = m_ctx->GetServerVariable(name, &p, &len);
        if (SUCCEEDED(hr)) {
            return (nullptr == p) ? "" : p;
        }
        return "";
    }
    PCSTR p = m_request->GetHeader(g_bSafeHeaderNames ? makeSafeHeader(name).c_str() : name);
    return (nullptr == p) ? "" : p;
}
//
// XMLTooling::GenericRequest
//
const char* IIS7Request::getScheme() const
{
    return m_scheme.c_str();
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
    return m_remoteUser;
}

const char* IIS7Request::getRequestBody() const
{
    if (m_gotBody) {
        return m_body.c_str();
    }
    // TODO Not Thread safe?
    DWORD totalBytesLeft = m_request->GetRemainingEntityBytes();

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

void IIS7Request::setResponseHeader(const char* name, const char* value, bool replace)
{
    HTTPResponse::setResponseHeader(name, value, replace);

    size_t sz = value ? strlen(value) : 0;
    if (sz > USHRT_MAX) {
        log(SPWarn, "Header value overflow");
        sz = USHRT_MAX;
    }

    HRESULT hr = m_response->SetHeader(name, value, static_cast<USHORT>(sz), replace || !value ? TRUE : FALSE);
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
    return hdr;
}

void IIS7Request::logFatal(const string& operation, HRESULT hr) const
{
    string msg(operation + " failed: " + lexical_cast<string>(hr));
    log(SPRequest::SPCrit, msg.c_str());
    if (m_response) {
        m_response->SetStatus(static_cast<USHORT>(XMLTOOLING_HTTP_STATUS_ERROR), "Fatal Server Error", 0, hr);
    }
}

void IIS7Request::throwError(const string& operation, HRESULT hr) const
{
    logFatal(operation, hr);
    string msg(operation + " failed: " + lexical_cast<string>(hr));
    throw IOException(msg.c_str());
}
