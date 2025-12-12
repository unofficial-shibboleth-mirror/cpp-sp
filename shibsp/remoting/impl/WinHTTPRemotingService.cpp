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
  * remoting/impl/WinHTTPRemotingService.cpp
  *
  * Base class for HTTP-based remoting.
  */

#include "internal.h"
#include "exceptions.h"
#include <Windows.h>
#include <winhttp.h>

#include "Agent.h"
#include "AgentConfig.h"
#include "logging/Category.h"
#include "remoting/SecretSource.h"
#include "remoting/impl/AbstractHTTPRemotingService.h"
#include "util/BoostPropertySet.h"

#include <stdexcept>
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

constexpr bool defaultChunking(false);

namespace {

    class SHIBSP_DLLLOCAL WinHTTPRemotingService : public virtual AbstractHTTPRemotingService {
    public:
        WinHTTPRemotingService(ptree& pt);
        virtual ~WinHTTPRemotingService();

        Category& logger() const {
            return m_log;
        }

        bool isChunked() const {
            return m_chunked;
        }

        wstring utf8ToUtf16(const char* input) const;

        void send(const char* path, istream& input, ostream& output) const;

        void handleCert(HINTERNET handle) const;

        void logSecureFailure(DWORD status) const;

    private:
        Category& m_log;
        bool m_init;
        HINTERNET m_session;
        HINTERNET m_connection;
        string m_ciphers;
        bool m_chunked;
        bool m_secure;
        wstring m_baseURLPath;
        wstring m_username;
        DWORD m_authScheme;
        HCERTCHAINENGINE m_caChainEngine;
        HCERTSTORE m_caStore;
        void setupCaChecking();
        string getCertName(PCCERT_CONTEXT certContext) const;
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
    DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, input, -1, nullptr, 0);

    LPWSTR output = new WCHAR[sizeNeeded + 1];
    if (output == nullptr) {
        m_log.crit("Out of memory allocating %d bytes for conversion buffer", sizeNeeded + 1);
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

void WinHTTPRemotingService::setupCaChecking() {

    if (!getCAFile())
        return;

    //
    // In order to do CA checking we need to read the pem file into a volatile (in memory) certificate
    // store and then set up a cert engine.
    //
    // When we set up the request (in WinHTTPRemotingService::send) we tell winHttp not to check any root certificate validity
    // but to check the CN.  We get a callback (to be finalized but before BASICAUTH) and getgiven the 
    // certificate presented.  We pass this to WinHTTPRemotingService::handleCert which calls into the crypto
    // library to check the chain.
    //
    //This method sets up the CA store and the cert engine (as part of object construction)
    
    wstring caFile(utf8ToUtf16(getCAFile()));
    DWORD msgAndCertEncodingType, contentType, formatType;
    PCERT_CONTEXT certContext = NULL;

    m_caStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);

    if (m_caStore == NULL) {

        m_log.crit("Could not create caStore : 0x%x", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize tlsCa store");
    }

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                          caFile.c_str(),
                          CERT_QUERY_CONTENT_FLAG_CERT,
                          CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED,
                          0,
                          &msgAndCertEncodingType,
                          &contentType,
                          &formatType,
                          NULL,
                          NULL,
                          (void const**)&certContext)) {
        m_log.crit("CryptQueryObject failure on file '%s': %d", caFile.c_str(), GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: failed to open tlsCAFile");
    }

    if ((msgAndCertEncodingType != X509_ASN_ENCODING) ||
        (contentType != CERT_QUERY_CONTENT_CERT) ||
        (formatType != CERT_QUERY_FORMAT_BASE64_ENCODED)) {

        m_log.crit("Unexpected tlsCaFile format: Encoding 0x%x type 0x%x format 0x%x", msgAndCertEncodingType, contentType, formatType);
        CertFreeCertificateContext(certContext);
        throw runtime_error("WinHHHTP failed to initialize: failed bad TtsCaFile format");
    }

    if (m_log.isDebugEnabled()) {
        m_log.debug("Loaded certificate with name %s", getCertName(certContext).c_str());
    }

    if (!CertAddCertificateContextToStore(m_caStore, certContext, CERT_STORE_ADD_ALWAYS, NULL)) {
        m_log.crit("Could not add cert to store: 0x%x", GetLastError());
        CertFreeCertificateContext(certContext);
        throw runtime_error("WinHHHTP failed to initialize: could not add cert");
    }
    CertFreeCertificateContext(certContext);

    CERT_CHAIN_ENGINE_CONFIG cfg = { 0 };
    cfg.cbSize = sizeof(cfg);
    cfg.hExclusiveRoot = m_caStore;
    // This is the flag which allows partial chains
    cfg.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;

    if (!CertCreateCertificateChainEngine(&cfg, &m_caChainEngine)) {
        m_log.crit("Could not create chain engine: 0x%x", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: could not create chain engine");
    }

}

static
void 
_stdcall
StatusCallback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength) {

    WinHTTPRemotingService *service = reinterpret_cast<WinHTTPRemotingService*>(dwContext);

    if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SENDING_REQUEST) {
        service->handleCert(hInternet);
    } else if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE) {
        service->logSecureFailure(*((DWORD*)lpvStatusInformation));
    }
};

WinHTTPRemotingService::WinHTTPRemotingService(ptree& pt)
    : AbstractHTTPRemotingService(pt), AbstractRemotingService(pt),
    m_log(Category::getInstance(SHIBSP_LOGCAT ".RemotingService")),
    m_secure(false), m_caChainEngine(nullptr), m_caStore(nullptr),
    m_init(false), m_chunked(defaultChunking)
{
    if (getUserAgent() == nullptr) {
        string useragent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION + '/' + "WINHTTP";
        setUserAgent(useragent.c_str());
    }

    //static const char CIPHER_LIST_PROP_NAME[] = "tlsCipherList";
    static const char CHUNKED_PROP_NAME[] = "chunkedEncoding";
    
    BoostPropertySet props;
    props.load(pt);

    m_chunked = props.getBool(CHUNKED_PROP_NAME, defaultChunking);
    //m_ciphers = props.getString(CIPHER_LIST_PROP_NAME, "");
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
        throw runtime_error("WinHHHTP failed to initialize service (WinHttpOpen)");
    }

    //
    // Set up our CaPath environment
    //
    setupCaChecking();


    //
    // Pop the URL into a wstring which we can parse and then point
    // other wstring constructors at
    //
    wstring wURL(utf8ToUtf16(getBaseURL()));

    //
    // Split it into little bits
    //
    URL_COMPONENTS components = { 0 };
    components.dwStructSize = sizeof(components);
    components.dwHostNameLength = -1;
    components.dwUrlPathLength = -1;

    if (!WinHttpCrackUrl(wURL.c_str(), 0, 0, &components)) {
        m_log.crit("WinHttpCrackUrl failure: %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Invalid baseURL");
    }

    if (components.dwHostNameLength == 0 || components.dwUrlPathLength == 0) {
        m_log.crit("Invalid baseUrl '%s' HostNameLength: %d, pathLength: %d",
            getBaseURL(), components.dwHostNameLength == 0, components.dwUrlPathLength);
        throw runtime_error("WinHHHTP failed to initialize: Invalid baseURL");
    }
    m_baseURLPath = wstring(components.lpszUrlPath, components.dwUrlPathLength);

    if ((components.nScheme != INTERNET_SCHEME_HTTP) && (components.nScheme != INTERNET_SCHEME_HTTPS)) {
        //
        // FTP/ Socks?  Just say no
        //
        m_log.crit("Protocol Scheme not supported : %d", GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Unsupported protocol");
    }
    m_secure = (components.nScheme == INTERNET_SCHEME_HTTPS);

    if (m_secure && (m_caChainEngine != NULL)) {
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
        if (WinHttpSetStatusCallback(m_session, StatusCallback, WINHTTP_CALLBACK_STATUS_SENDING_REQUEST | WINHTTP_CALLBACK_STATUS_SECURE_FAILURE, NULL) == WINHTTP_INVALID_STATUS_CALLBACK) {
            m_log.crit("WinHttpSetStatusCallback failure: %d", GetLastError());
            throw runtime_error("WinHHHTP failed to initialize: Could not register callback");
        }
    }

    wstring host(components.lpszHostName, components.dwHostNameLength);
    m_connection = WinHttpConnect(m_session, host.c_str(), components.nPort, 0);
    if (m_connection == nullptr) {
        // Note use of WINDOWS formatting
        m_log.crit("WinHttpConnect failure.  Could not connect to host %S : %d", host.c_str(), GetLastError());
        throw runtime_error("WinHHHTP failed to initialize: Could not connect");
    }

    m_log.info("WinHTTP RemotingService installed for agent ID (%s), baseURL (%s)", getAgentID(), getBaseURL());
}

WinHTTPRemotingService::~WinHTTPRemotingService()
{
    if (m_session)
        WinHttpCloseHandle(m_session);

    if (m_connection)
        WinHttpCloseHandle(m_connection);

    if (m_caChainEngine)
        CertFreeCertificateChainEngine(m_caChainEngine);

    if (m_caStore)
        CertCloseStore(m_caStore, 0);
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
        throw RemotingException("Send failed");
    }
    HINTERNETJanitor req(request);

    //
    //  The flags we set https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-httpspolicycallbackdata
    //      SECURITY_FLAG_IGNORE_UNKNOWN_CA   Ignore errors associated with an unknown certification authority.
    //                                        We check this in WinHTTPRemotingService::handleCert
    //
    // Critically we do NOT set
    //      SECURITY_FLAG_IGNORE_WRONG_USAGE
    //                   Ignore errors associated with the use of a certificate.
    //      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    //                   Ignore errors associated with an expired certificate.
    //      SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    //                   Ignore errors associated with a certificate that contains a common name that is not valid.
    //
    DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;

    if (!WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags))) {
        m_log.crit("Send.  Failed to set security flags : %d", GetLastError());
        throw RemotingException("Send failed");
    }

    if (isRevocationCheck()) {
        DWORD enableFeature = WINHTTP_ENABLE_SSL_REVOCATION;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_ENABLE_FEATURE, &enableFeature, sizeof(enableFeature))) {
            m_log.crit("Send.  Failed to set feature : %d", GetLastError());
            throw RemotingException("Send failed");
        }
    }

    if (m_authScheme) {
        bool sendPass = (m_authScheme == WINHTTP_AUTH_SCHEME_BASIC || m_authScheme == WINHTTP_AUTH_SCHEME_DIGEST);
        if (!WinHttpSetCredentials(request,
                    WINHTTP_AUTH_TARGET_SERVER,
                    m_authScheme, 
                    m_username.c_str(),
                    sendPass ? utf8ToUtf16(getSecretSource()->getSecret().c_str()).c_str(): nullptr,
                    nullptr)) {
            m_log.crit("Send. Failed to setup AuthN to %s : %d", path, GetLastError());
            throw RemotingException("Send failed");
        }
    }
    else {
        if (!WinHttpSetCredentials(request,
                    WINHTTP_AUTH_TARGET_SERVER,
                    WINHTTP_AUTH_SCHEME_BASIC,
                    m_username.c_str(),
                    utf8ToUtf16("none").c_str(),
                    nullptr)) {
            m_log.crit("Send. Failed to setup dummy AuthN to %s : %d", path, GetLastError());
            throw RemotingException("Send failed");
        }
    }

    wchar_t headers[]= L"Content-Type: text/plain\r\nExpect:";
    //
    // Add the headers.
    //
    if (!WinHttpAddRequestHeaders(request, headers, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
        m_log.crit("Send: Could not add request headers : %d", GetLastError());
        throw RemotingException("Send failed");
    }

    if (m_chunked) {
        //
        // Send the request, then the chunked data
        //
        m_log.debug("Sending chunked data to %s", path);
        if (!WinHttpSendRequest(request, L"Transfer-Encoding: chunked", -1, WINHTTP_NO_REQUEST_DATA, 0, WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH, 0)) {
            m_log.crit("Send. Failed to send request to %s : %d", path, GetLastError());
            throw RemotingException("Send failed");
        }

        DWORD written;
        while (input) {
            //
            // This is a pain - we have to do the chunking by hand so we send the chunky bit, then the data, end the end of chucky bit
            //
            char buf[1024];
            char chunkString[128];
            input.read(buf, sizeof(buf));
            int transferSize = static_cast<int>(input.gcount());
            sprintf_s(chunkString, sizeof(chunkString), "%X\r\n", transferSize);
            DWORD chunkStringLen = static_cast<DWORD>(strnlen_s(chunkString, sizeof(chunkString)));

            m_log.debug("Sending chunk with %d bytes to %s", transferSize, path);
            if (!WinHttpWriteData(request, chunkString, chunkStringLen, &written)) {
                m_log.crit("Send. Failed to send chunk header to %s : %d", path, GetLastError());
                throw RemotingException("Send failed");
            }
            if (!WinHttpWriteData(request, buf, transferSize, &written)) {
                m_log.crit("Send. Failed to send chunk data to %s : %d", path, GetLastError());
                throw RemotingException("Send failed");
            }
            if (!WinHttpWriteData(request, "\r\n", 2, &written)) {
                m_log.crit("Send. Failed to send chunk trailer to %s : %d", path, GetLastError());
                throw RemotingException("Send failed");
            }
        }
        //
        // And when all gthe data is gone we say that the last chunk is zero long
        //
        if (!WinHttpWriteData(request, "0\r\n", 3, &written)) {
            m_log.crit("Send. Failed to send chunk header to %s : %d", path, GetLastError());
            throw RemotingException("Send failed");
        }
    }
    else {
        //
        // Just buffer up all the data and send it in a wunner
        //
        string msg;
        while(input) {
            char buf[1024];
            input.read(buf, sizeof(buf));
            msg.append(buf, input.gcount());
        }
        m_log.debug("Sending %d bytes to %s", msg.length(), path);
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, const_cast<char*>(msg.c_str()), static_cast<DWORD>(msg.length()), static_cast<DWORD>(msg.length()), 0)) {
            m_log.crit("Send. Failed to send request to %s : %d", path, GetLastError());
            throw RemotingException("Send failed");
        }
    }

    if (!WinHttpReceiveResponse(request, NULL)) {
        //
        // TODO handle ERROR_WINHTTP_RESEND_REQUEST "The WinHTTP function failed. The desired function can be retried on the same request handle."
        //
        m_log.crit("Send. Failed to recieve response to %s : %d", path, GetLastError());
        throw RemotingException("Send failed");
    }
    DWORD statusCode;
    DWORD statusCodeSize = sizeof(statusCode);
    //
    // Not clear if this is needed..
    //
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &statusCode, &statusCodeSize, nullptr)) {
        m_log.crit("Send. Failed to Query response from %s : %d", path, GetLastError());
        throw runtime_error("Send failed");
    }
    if (statusCode != HTTP_STATUS_OK) {
        //
        // TODO - something meaningfull
        //
        m_log.crit("Send. Bad status from %s : %d", path, statusCode);
        throw RemotingException("Send failed");
    }

    DWORD bufferSize = 0;
    char *buffer = nullptr;
    while (true)  {

        DWORD bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(request, &bytesAvailable)) {
            m_log.crit("ReceiveData. WinHttpQueryDataAvailable on %s failed: %d", path, GetLastError());
            throw RemotingException("Send failed");
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
                throw RemotingException("Send failed");
            }
            ZeroMemory(buffer, bufferSize+1);
        }

        DWORD bytesRead;
        if (!WinHttpReadData(request, buffer, bytesAvailable, &bytesRead)) {
            m_log.crit("ReceiveData. WinHttpReadData on %s failed: %d", path, GetLastError());
            throw RemotingException("Send failed");
        }
        m_log.debug("%d bytes read from %s", bytesRead, path);
        output.write(buffer, bytesRead);
    }
    if (buffer) {
        delete[] buffer;
    }
}

//
// Called if the TLS handshake (called when we call WinHttpSendRequest as part of ::send) failed
//
void WinHTTPRemotingService::logSecureFailure(DWORD Status) const
{
    string details("");
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_CERT_WRONG_USAGE)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_CERT_WRONG_USAGE ";
    if (Status & WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR)
        details += "WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR ";
    m_log.crit("WinHttp Security Error 0x%x (%s)", Status, details.c_str());
}

//
// Called during WinHttpSendRequest to allow us to police the certificate.
//
void WinHTTPRemotingService::handleCert(HINTERNET handle) const
{
    PCCERT_CONTEXT certCtx = NULL;
    DWORD size = sizeof(certCtx);

    if (!WinHttpQueryOption(handle, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &certCtx, &size)) {
        m_log.crit("Could not get the certificate on connect");
        throw RemotingException("Could not get certificate");

    }

    if (m_log.isDebugEnabled()) {
        m_log.debug("Connection: got cert with name '%s'", getCertName(certCtx).c_str());
    }

    CERT_CHAIN_PARA chainPara = { 0 };
    PCCERT_CHAIN_CONTEXT chainContext;

    chainPara.cbSize = sizeof(chainPara);

    DWORD flags = CERT_CHAIN_CACHE_END_CERT;

    if (isRevocationCheck()) {
        flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    }

    BOOL gotCertChain = CertGetCertificateChain(m_caChainEngine,
                                                certCtx,
                                                NULL,
                                                certCtx->hCertStore,
                                                &chainPara,
                                                flags,
                                                NULL,
                                                &chainContext);
    CertFreeCertificateContext(certCtx);
    if (!gotCertChain) {
        m_log.error("Could not get the certificate chain on connect");
        throw RemotingException("Could not get certificate chain");
    }
    //
    // Why do we only look at chain zero?
    //
    CERT_TRUST_STATUS status = chainContext->rgpChain[0]->TrustStatus;
    CertFreeCertificateChain(chainContext);

    m_log.debug("Connection Error %x Info %x", status.dwErrorStatus, status.dwInfoStatus);
    //
    // per CURL strip out (undocumented) CERT_TRUST_IS_NOT_TIME_NESTED
    //
    DWORD error = status.dwErrorStatus & (~CERT_TRUST_IS_NOT_TIME_NESTED);
    if (error != CERT_TRUST_NO_ERROR) {
        // We might want to expand the errors, wbut which ones?
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status
        m_log.error("Certificate presented is not trusted.  Error : 0x%x", status.dwErrorStatus);
        throw RemotingException("Certificate presented is not trusted");
    }
}

string WinHTTPRemotingService::getCertName(PCCERT_CONTEXT certContext) const {

    char buffer[1024] = {0};
    CertNameToStrA(X509_ASN_ENCODING, &certContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, buffer, sizeof(buffer));
    return string(buffer);

}
