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

 /**
  * remoting/impl/CurlHTTPRemotingService.cpp
  *
  * Base class for HTTP-based remoting.
  */

#include "internal.h"
#include "exceptions.h"
#include <Windows.h>
#include <winhttp.h>

#include "logging/Category.h"
#include "remoting/SecretSource.h"
#include "remoting/impl/AbstractHTTPRemotingService.h"
#include "util/BoostPropertySet.h"

#include <stdexcept>
#include <codecvt> // 16 bit to 8 bit chars
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#include <list>
#include <mutex>
#include <sstream>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

namespace {

    class SHIBSP_DLLLOCAL WinHTTPRemotingService : public virtual AbstractHTTPRemotingService {
    public:
        WinHTTPRemotingService(ptree& pt);
        virtual ~WinHTTPRemotingService();

        Category& logger() const {
            return m_log;
        }

        Category& winHTTP_logger() const {
            return m_winHTTPlog;
        }

        bool isChunked() const {
            return m_chunked;
        }

        wstring utf8ToUtf16(const char* input) const;

        void send(const char* path, istream& input, ostream& output) const;

        void handleCert(HINTERNET Handle) const;

    private:
        Category& m_log;
        Category& m_winHTTPlog;
        bool m_init;
        HINTERNET m_session;
        HINTERNET m_connection;
        string m_ciphers;
        bool m_chunked;
        bool m_secure;
        wstring m_baseURLPath;
        wstring m_username;
        DWORD m_authScheme;
    };

    class HINTERNETJanitor
    {
    public:
        HINTERNETJanitor(HINTERNET &handle) : m_handle(handle) {}
        ~HINTERNETJanitor() { WinHttpCloseHandle(m_handle); }
    private:
        HINTERNET &m_handle;
        HINTERNETJanitor(const HINTERNETJanitor&);
        HINTERNETJanitor& operator=(const HINTERNETJanitor&);
    };

}

namespace shibsp {
    RemotingService* WinHTTPRemotingServiceFactory(ptree& pt, bool deprecationSupport) {
        return new WinHTTPRemotingService(pt);
    }
};

wstring WinHTTPRemotingService::utf8ToUtf16(const char* input) const {
    // IDK why this cannot be exbedded.
    DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input, -1, nullptr, 0);

    LPWSTR output = new WCHAR[sizeNeeded + 1];
    if (output == nullptr) {
        m_log.crit("Out of memrory allocating %d butes for conversion buffer", sizeNeeded + 1);
        throw runtime_error("Utf8toUtf16 conversion failed");
    }
    ZeroMemory(output, sizeof(WCHAR) * (sizeNeeded + 1));

    if (MultiByteToWideChar(CP_UTF8, 0, input, -1, output, sizeNeeded) == 0) {
        m_log.crit("MultiByteToWideChar failure: %d", GetLastError());
        throw runtime_error("Utf8toUtf16 conversion failed");
    }

    wstring result(output);
    delete[] output;
    return result;
}

void WinHTTPRemotingService::handleCert(HINTERNET Handle) const 
{
    PCCERT_CONTEXT pCert = NULL;
    DWORD dwSize = sizeof(pCert);

    if (!m_secure) {
        m_log.debug("Skipping certificate check on insecure attach");
    }
    else if (!WinHttpQueryOption(Handle, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCert, &dwSize)) {
        m_log.crit("Could not get the certificate on conect");
        throw RemotingException("Could not get certificate");
    }
    else {
        //
        // We probably want to put some caching in here - this is called twice for each WinHttpSend...
        //
        CHAR buffer[1024] = {0};
        CertNameToStrA(X509_ASN_ENCODING, &pCert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, buffer, sizeof(buffer));
        m_log.debug("Checking certificate with subject %s", buffer);
        //
        // TODO check the certificate
        // 
        cout << "Subject name " << buffer << endl;
        CertFreeCertificateContext(pCert);
    }
}

static void StatusCallback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength) {

    WinHTTPRemotingService *service = reinterpret_cast<WinHTTPRemotingService*>(dwContext);

    if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SENDING_REQUEST) {
        service->handleCert(hInternet);
    }
};

WinHTTPRemotingService::WinHTTPRemotingService(ptree& pt)
    : AbstractHTTPRemotingService(pt), AbstractRemotingService(pt),
    m_log(Category::getInstance(SHIBSP_LOGCAT ".RemotingService.WinHTTP")),
    m_winHTTPlog(Category::getInstance(SHIBSP_LOGCAT ".winHTTP")),
    m_init(false), m_chunked(true)
{
    if (getUserAgent() == nullptr) {
        string useragent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION + '/' + "WINHTTP";
        setUserAgent(useragent.c_str());
    }

    static const char CIPHER_LIST_PROP_NAME[] = "tlsCipherList";
    static const char CHUNKED_PROP_NAME[] = "chunkedEncoding";
    
    BoostPropertySet props;
    props.load(pt);

    m_chunked = props.getBool(CHUNKED_PROP_NAME, true);
    m_ciphers = props.getString(CIPHER_LIST_PROP_NAME, "");
    m_username = utf8ToUtf16(getAgentID());
    switch (getAuthMethod()) {
        case agent_auth_basic:  m_authScheme = WINHTTP_AUTH_SCHEME_BASIC; break;
        case agent_auth_digest: m_authScheme = WINHTTP_AUTH_SCHEME_DIGEST; break;
        case agent_auth_gss:    m_authScheme = WINHTTP_AUTH_SCHEME_NEGOTIATE; break; // Selects between NTLM and Kerberos authentication.
        case agent_auth_none:
        default:                m_authScheme = 0; break;
    }

    m_session = WinHttpOpen(utf8ToUtf16(getUserAgent()).c_str(),
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME,
                            WINHTTP_NO_PROXY_BYPASS, 0);
    if (m_session == nullptr) {
        m_log.crit("WinHttpOpen failure: %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize service");
    }
    //
    // Arrange to be called back so we can check certificates
    //
    DWORD_PTR context = reinterpret_cast<DWORD_PTR>(this);

    // Set up this as the context
    if (!WinHttpSetOption(m_session, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) {
        m_log.crit("WinHttpSetOption failure: %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Could not set callback option");
    }

    // And register the callback
    if (WinHttpSetStatusCallback(m_session, StatusCallback, WINHTTP_CALLBACK_STATUS_SENDING_REQUEST, NULL) == WINHTTP_INVALID_STATUS_CALLBACK) {
        m_log.crit("WinHttpSetStatusCallback failure: %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Could not register callback");
    }

    //
    // Pop the URL into a wstring which we can parse and then point
    // other wstring constructors at
    //
    wstring wURL(utf8ToUtf16(getBaseURL()));
    //
    // Split it into little bits
    //
    URL_COMPONENTS components = {0};
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = -1;
    components.dwUrlPathLength = -1;
    if (!WinHttpCrackUrl(wURL.c_str(), 0, 0, &components)) {
        m_log.crit("WinHttpCrackUrl failure: %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: failed to parse baseURL");
    }

    if (components.dwHostNameLength == 0 || components.dwUrlPathLength == 0) {
        m_log.crit("Invalid baseUrl '%s' HostNameLength: %d, pathLength: %d",
                   getBaseURL(), components.dwHostNameLength == 0, components.dwUrlPathLength);
        throw runtime_error("WinHHHTP failed to initialize: Invalid baseUrl");
    }

    m_secure = (components.nScheme == INTERNET_SCHEME_HTTPS);
    m_baseURLPath = wstring(components.lpszUrlPath, components.dwUrlPathLength);
    wstring host(components.lpszHostName, components.dwHostNameLength);

    m_connection = WinHttpConnect(m_session, host.c_str(), components.nPort, 0);
    if (m_connection == nullptr) {
        // Note use of WINDOWS formatting
        m_log.crit("WinHttpConnect failure.  Could not connect to host %S : %d", host.c_str(), GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Could no");
    }

    m_log.info("WinHTTP RemotingService installed for agent (%s), baseURL (%s)", getAgentID(), getBaseURL());
}

WinHTTPRemotingService::~WinHTTPRemotingService()
{
    if (m_session) {
        WinHttpCloseHandle(m_session);
    }
    if (m_connection) {
        WinHttpCloseHandle(m_connection);
    }
}

void WinHTTPRemotingService::send(const char* path, istream& input, ostream& output) const
{
    wstring wPath(m_baseURLPath + utf8ToUtf16(path));

    HINTERNET request = WinHttpOpenRequest(
                    m_connection, 
                    L"POST",
                    wPath.c_str(),
                    nullptr, // HTTP/1.1
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    m_secure ? WINHTTP_FLAG_SECURE : 0);

    if (request == nullptr) {
        m_log.crit("Send.  Failed to open request to %s : %d", path, GetLastError());
        throw RemotingException("send failed");
    }
    HINTERNETJanitor req(request);

    //
    // TODO: somethimg magical with ciphers
    //
    if (m_authScheme) {
        bool sendPass = (m_authScheme == WINHTTP_AUTH_SCHEME_BASIC || m_authScheme == WINHTTP_AUTH_SCHEME_DIGEST);
        if (!WinHttpSetCredentials(request,
                    WINHTTP_AUTH_TARGET_SERVER,
                    m_authScheme, 
                    m_username.c_str(),
                    sendPass ? utf8ToUtf16(getSecretSource()->getSecret().c_str()).c_str(): nullptr,
                    nullptr)) {
            m_log.crit("Send. Failed to setup AuthN to %s : %d", path, GetLastError());
            throw RemotingException("send failed");
        }
    }

    wstring headers(L"Content-Type: text/plain\nExpect:");
    if (m_chunked) {
        //
        // TODO Add the chunking headers.  HttpRead (below) hides the chunking from us, HttpWrite, less so. See below
        //
        //headers += L"\nTransfer-Encoding: chunked";
        //
        // I think that in this case we send WinHttpSendRequest with length = WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH
        // and use WinHttpWriteData to write the buffer in the loop below.
        //
    }
    if (!WinHttpAddRequestHeaders(request, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD)) {
        m_log.crit("Send: Could not add request headers : %d", GetLastError());
        throw RemotingException("send failed");
    }

    if (m_chunked) {
        //
        // I think that in this case we send WinHttpSendRequest with length = WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH
        // and use WinHttpWriteData to write the buffer in the loop below.
        // We dont have to worry about the read since its all done for us regardless
        //
    }

    string msg;
    while(input) {
        char buf[1024];
        input.read(buf, sizeof(buf));
        msg.append(buf, input.gcount());
    }
    m_log.debug("Sending %d bytes to %s", msg.length(), path);
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, const_cast<char*>(msg.c_str()), static_cast<DWORD>(msg.length()), static_cast<DWORD>(msg.length()), 0)) {
        m_log.crit("Send. Failed to send request to %s : %d", path, GetLastError());
        throw RemotingException("send failed");
    }

    if (!WinHttpReceiveResponse(request, NULL)) {
        //
        // TODO handle ERROR_WINHTTP_RESEND_REQUEST "The WinHTTP function failed. The desired function can be retried on the same request handle."
        //
        m_log.crit("Send. Failed to recieve response to %s : %d", path, GetLastError());
        throw RemotingException("send failed");
    }
    DWORD statusCode;
    DWORD statusCodeSize = sizeof(statusCode);
    //
    // Not clear if this is needed..
    //
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statusCode, &statusCodeSize, nullptr)) {
        m_log.crit("Send. Failed to Query response from %s : %d", path, GetLastError());
        throw runtime_error("send failed");
    }
    if (statusCode != HTTP_STATUS_OK) {
        //
        // TODO - something meaningfull
        //
        m_log.crit("Send. Bad status from %s : %d", path, statusCode);
        throw RemotingException("send failed");
    }

    DWORD bufferSize = 0;
    char *buffer = nullptr;
    while (true)  {

        DWORD bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(request, &bytesAvailable)) {
            m_log.crit("ReceiveData. WinHttpQueryDataAvailable on %s failed: %d", path, GetLastError());
            throw RemotingException("send failed");
        }
        if (bytesAvailable == 0) {
            break;
        }
        if (bytesAvailable > bufferSize) {
            if (buffer) {
                delete[] buffer;
            }
            bufferSize = bytesAvailable;
            buffer = new char[bytesAvailable + 1];
            if (buffer == nullptr) {
                m_log.crit("ReceiveData. Out of Memory reading %d bytes from %s", bufferSize, path);
                throw RemotingException("send failed");
            }
            ZeroMemory(buffer, bufferSize+1);
        }

        DWORD bytesRead;
        if (!WinHttpReadData(request, buffer, bytesAvailable, &bytesRead)) {
            m_log.crit("ReceiveData. WinHttpReadData on %s failed: %d", path, GetLastError());
            throw RemotingException("send failed");
        }
        m_log.debug("%d bytes read from %s", bytesRead, path);
        output.write(buffer, bytesRead);
    }
    if (buffer) {
        delete[] buffer;
    }
}