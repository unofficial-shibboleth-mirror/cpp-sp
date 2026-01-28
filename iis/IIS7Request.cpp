/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iis.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

#include <shibsp/exceptions.h>
#include <shibsp/util/Misc.h>

#include "IIS7Request.hpp"
#include "ShibHttpModule.hpp"
#include "ShibUser.hpp"

using namespace Config;

IIS7Request::IIS7Request(IHttpContext *pHttpContext, IHttpEventProvider *pEventProvider, bool checkUser, const PropertySet& site)
    : AbstractSPRequest(SHIBSP_LOGCAT ".IIS"),
        m_ctx(pHttpContext), m_request(pHttpContext->GetRequest()), m_response(pHttpContext->GetResponse()), m_site(site),
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
                int secure = boost::lexical_cast<int>(var);
                bSSL = (0 != secure) ? true : false;
            }
            catch (const boost::bad_lexical_cast&) {
                log(Priority::SHIB_ERROR, "exception converting SERVER_PORT_SECURE value to int");
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

    bool normalizeRequest = site.getBool(
        ModuleConfig::NORMALIZE_REQUEST_PROP_NAME, ModuleConfig::NORMALIZE_REQUEST_PROP_DEFAULT);
    unsigned int site_port = site.getUnsignedInt(ModuleConfig::SITE_PORT_PROP_NAME, 0);
    unsigned int site_sslport = site.getUnsignedInt(ModuleConfig::SITE_SSLPORT_PROP_NAME, 0);
    const char* site_name = site.getString(ModuleConfig::SITE_NAME_PROP_NAME, "");

    // Port may come from IIS or from site config.
    if (!normalizeRequest || (bSSL && !site_sslport) || (!bSSL && !site_port)) {
        hr = m_ctx->GetServerVariable("SERVER_PORT", &var, &len);
        if (SUCCEEDED(hr)) {
            try {
                m_port = boost::lexical_cast<int>(var);
            }
            catch (const boost::bad_lexical_cast&) {
                throwError("Get Port", hr);
            }
        }
        else {
            throwError("Get Port", hr);
        }
    }
    else {
        m_port = bSSL ? site_sslport : site_port;
    }

    // Scheme may come from site config or be derived from IIS.
    m_scheme = site.getString(ModuleConfig::SITE_SCHEME_PROP_NAME, "");
    if (m_scheme.empty() || !normalizeRequest) {
        m_scheme = bSSL ? "https" : "http";
    }

    hr = m_ctx->GetServerVariable("SERVER_NAME", &var, &len);
    if (SUCCEEDED(hr)) {
        // Make sure SERVER_NAME is "authorized" for use on this site. If not, or empty, set to canonical name.
        if (!len) {
            m_hostname = site_name;
        }
        else {
            m_hostname = var;
            if (site_name != m_hostname) {
                set<string> aliases;
                const char* s = site.getString(ModuleConfig::SITE_ALIASES_PROP_NAME, "");
                split_to_container(aliases, s);
                if (find(aliases.begin(), aliases.end(), m_hostname) == aliases.end()) {
                    m_hostname = site_name;
                }
            }
        }
    }
    else {
        m_hostname = site_name;
    }


    // Check for header/variable settings in RequestMap and only if absent fall back to Site info.
    const PropertySet* mappedProperties = getRequestSettings().first;
    if (mappedProperties->hasProperty(RequestMapper::USE_HEADERS_PROP_NAME)) {
        m_useHeaders = mappedProperties->getBool(
            RequestMapper::USE_HEADERS_PROP_NAME, RequestMapper::USE_HEADERS_PROP_DEFAULT);
    }
    else {
        m_useHeaders = site.getBool(RequestMapper::USE_HEADERS_PROP_NAME, RequestMapper::USE_HEADERS_PROP_DEFAULT);
    }

    if (mappedProperties->hasProperty(RequestMapper::USE_VARIABLES_PROP_NAME)) {
        m_useVariables = mappedProperties->getBool(
            RequestMapper::USE_VARIABLES_PROP_NAME, RequestMapper::USE_VARIABLES_PROP_DEFAULT);
    }
    else {
        m_useVariables = site.getBool(RequestMapper::USE_VARIABLES_PROP_NAME, RequestMapper::USE_VARIABLES_PROP_DEFAULT);
    }

    // This default matches the previous setting.
    m_safeHeaderNames = site.getBool(ModuleConfig::SAFE_HEADER_NAMES_PROP_NAME, m_useHeaders);

    string prop(site.getString(ModuleConfig::ROLE_ATTRIBUTES_PROP_NAME, ""));
    split_to_container(m_roleAttributeNames, prop.c_str());

    hr = m_ctx->GetServerVariable("REMOTE_USER", &var, &len);
    if (SUCCEEDED(hr)) {
        m_remoteUser = len ? var : "";
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
            log(Priority::SHIB_DEBUG, "IIS filter running more than once");
        }
    }
}

const char* IIS7Request::getRequestID() const
{
    // TODO: Use AgentConfig generateRandom if IIS has nothing to use, would store
    // off in string member and just return that here.
    return nullptr;
}

bool IIS7Request::isUseHeaders() const
{
    return m_useHeaders;
}

bool IIS7Request::isUseVariables() const
{
    return m_useVariables;
}

void IIS7Request::setHeader(const char* name, const char* value)
{
    if (isUseHeaders()) {
        const HRESULT hr (m_request->SetHeader(m_safeHeaderNames ? makeSafeHeader(name).c_str() : name, value, static_cast<USHORT>(strlen(value)), TRUE));
        if (FAILED(hr)) {
            throwError("setHeader (Header)", hr);
        }
    }

    if (isUseVariables()) {
        const wstring wValue(utf8ToUtf16(value));
        const HRESULT hr(m_ctx->SetServerVariable(const_cast<char*>(name), wValue.c_str()));
        if (FAILED(hr)) {
            throwError("setHeader (Variable)", hr);
        }

        if (m_roleAttributeNames.find(name) != m_roleAttributeNames.end()) {
            const string str(value);
            boost::tokenizer<boost::escaped_list_separator<char>> tok(str, boost::escaped_list_separator<char>('\\', ';', '"'));
            for (boost::tokenizer<boost::escaped_list_separator<char>>::iterator it = tok.begin(); it != tok.end(); ++it) {
                m_roles.insert(utf8ToUtf16(it->c_str()));
            }
        }
    }
}

void IIS7Request::setRemoteUser(const char* user)
{
    m_remoteUser = user;

    // Setting the variable REMOTE_USER fails, so set the Principal if we are called appropriately.
    // Getting REMOTE_USER goes via the Principal.
    IAuthenticationProvider *auth = dynamic_cast<IAuthenticationProvider*>(m_event);

    if (auth) {
        string authnRole(m_site.getString(ModuleConfig::AUTHENTICATED_ROLE_PROP_NAME,
            ModuleConfig::AUTHENTICATED_ROLE_PROP_DEFAULT));
        m_roles.insert(utf8ToUtf16(authnRole.c_str()));
        auth->SetUser(new ShibUser(utf8ToUtf16(user), m_roles));
    }
    else {
        log(Priority::SHIB_ERROR, "attempt to set REMOTE_USER in an inappropriate context");
    }
}

const char* IIS7Request::getMethod() const
{
    return m_request->GetHttpMethod();
}

void IIS7Request::clearHeader(const char* name)
{
    if (isUseHeaders()) {
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
                string hdr = (m_safeHeaderNames ? ("HTTP_" + makeSafeHeader(getCGINameForHeader(name).c_str() + 5)) : getCGINameForHeader(name)) + ':';
                if (strstr(m_allhttp.c_str(), hdr.c_str())) {
                    throw SessionException(string("Attempt to spoof header (") + hdr + ") was detected.");
                }
            }
        }
        string unsetHeaderValue(g_Config->getAgent().getString(Agent::UNSET_HEADER_VALUE_PROP_NAME, ""));
        HRESULT hr = m_request->SetHeader(m_safeHeaderNames ? makeSafeHeader(name).c_str() : name,
            unsetHeaderValue.c_str(), static_cast<USHORT>(unsetHeaderValue.length()), TRUE);
        if (FAILED(hr)) {
            throwError("clearHeader", hr);
        }
    }
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

string IIS7Request::getLocalAddr() const
{
    PCSTR addr;
    DWORD len;
    HRESULT hr = m_ctx->GetServerVariable("LOCAL_ADDR", &addr, &len);
    if (SUCCEEDED(hr)) {
        return addr;
    }
    return "";
}

string IIS7Request::getSecureHeader(const char* name) const
{
    if (isUseVariables()) {
        PCWSTR p;
        DWORD len;
        HRESULT hr = m_ctx->GetServerVariable(name, &p, &len);
        if (SUCCEEDED(hr) && p) {
            return utf16ToUtf8(p);
        }
        return "";
    }
    PCSTR p = m_request->GetHeader(m_safeHeaderNames ? makeSafeHeader(name).c_str() : name);
    return (nullptr == p) ? "" : p;
}

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
        return boost::lexical_cast<int>(length);
    }
    return 0;
}

string IIS7Request::getRemoteUser() const
{
    return m_remoteUser;
}

string IIS7Request::getAuthType() const
{
    PCSTR type;
    DWORD len;
    HRESULT hr = m_ctx->GetServerVariable("AUTH_TYPE", &type, &len);
    if (SUCCEEDED(hr)) {
        return string(type);
    }
    return "";
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
    case SHIBSP_HTTP_STATUS_NOTMODIFIED:    codestr="304 Not Modified"; break;
    case SHIBSP_HTTP_STATUS_UNAUTHORIZED:   codestr="401 Authorization Required"; break;
    case SHIBSP_HTTP_STATUS_FORBIDDEN:      codestr="403 Forbidden"; break;
    case SHIBSP_HTTP_STATUS_NOTFOUND:       codestr="404 Not Found"; break;
    case SHIBSP_HTTP_STATUS_ERROR:          codestr="500 Server Error"; break;
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
        log(Priority::SHIB_WARN, "Header value overflow");
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
    
    if (getRequestSettings().first->getBool(
            RequestMapper::EXPIRE_REDIRECTS_PROP_NAME, RequestMapper::EXPIRE_REDIRECTS_PROP_DEFAULT)) {
        setResponseHeader("Expires", "Wed, 01 Jan 1997 12:00:00 GMT", true);
        setResponseHeader("Cache-Control", "private,no-store,no-cache,max-age=0", true);
    }

    HRESULT hr = m_response->Redirect(url);
    if (FAILED(hr)) {
        logFatal("Redirect", hr);
    }
    m_ctx->SetRequestHandled();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}

wstring IIS7Request::utf8ToUtf16(const char* input) const {
    DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input, -1, nullptr, 0);

    LPWSTR output = new WCHAR[sizeNeeded + 1];
    if (output == nullptr) {
        log(Priority::SHIB_CRIT, "Out of memory allocating conversion buffer");
        throw runtime_error("Utf8toUtf16 conversion failed");
    }
    ZeroMemory(output, sizeof(WCHAR) * (sizeNeeded + 1));

    if (MultiByteToWideChar(CP_UTF8, 0, input, -1, output, sizeNeeded) == 0) {
        log(Priority::SHIB_CRIT, "MultiByteToWideChar failure");
        throw runtime_error("Utf8toUtf16 conversion failed");
    }

    wstring result(output);
    delete[] output;
    return result;
}

string IIS7Request::utf16ToUtf8(const wstring input) const {
    DWORD sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);

    LPCH output = new CHAR[sizeNeeded + 1];
    if (output == nullptr) {
        log(Priority::SHIB_CRIT, "Out of memory allocating conversion buffer");
        throw runtime_error("Utf16toUtf8 conversion failed");
    }
    ZeroMemory(output, sizeNeeded + 1);

    if (WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, output, sizeNeeded, nullptr, nullptr) == 0) {
        log(Priority::SHIB_CRIT, "WideCharToMultiByte failure");
        throw runtime_error("Utf16toUtf8 conversion failed");
    }

    string result(output);
    delete[] output;
    return result;
}

void IIS7Request::logFatal(const string& operation, HRESULT hr) const
{
    string msg(operation + " failed: " + boost::lexical_cast<string>(hr));
    log(Priority::SHIB_CRIT, msg.c_str());
    if (m_response) {
        m_response->SetStatus(static_cast<USHORT>(SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Error", 0, hr);
    }
}

void IIS7Request::throwError(const string& operation, HRESULT hr) const
{
    logFatal(operation, hr);
    string msg(operation + " failed: " + boost::lexical_cast<string>(hr));
    throw IOException(msg.c_str());
}
