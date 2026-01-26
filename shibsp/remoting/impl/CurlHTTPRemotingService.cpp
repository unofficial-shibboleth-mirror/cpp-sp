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

#include "Agent.h"
#include "AgentConfig.h"
#include "logging/Category.h"
#include "remoting/SecretSource.h"
#include "remoting/impl/AbstractHTTPRemotingService.h"
#include "util/BoostPropertySet.h"
#include "util/PathResolver.h"

#include <stdexcept>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#include <list>
#include <mutex>
#include <fstream>
#include <sstream>

#include <curl/curl.h>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

namespace {

    /* This is the actual service, and manages the pool of handles for reuse. */
    class SHIBSP_DLLLOCAL CurlHTTPRemotingService : public virtual AbstractHTTPRemotingService {
    public:
        CurlHTTPRemotingService(ptree& pt);
        virtual ~CurlHTTPRemotingService();

        Category& logger() const {
            return m_log;
        }

        const string& getTraceFileBase() const {
            return m_traceFileBase;
        }

        bool isChunked() const {
            return m_chunked;
        }

        void send(const char* path, istream& input, ostream& output) const;

        CURL* checkout() const;
        void checkin(CURL* handle) const;
        void attachCachedAuthentication(CURL* handle) const;

    private:
        Category& m_log;
        string m_traceFileBase;
        bool m_curlInit;
        mutable list<CURL*> m_pool;
        mutable int m_poolsize;
        mutable mutex m_lock;
        string m_ciphers;
        bool m_chunked;
    };

    class SHIBSP_DLLLOCAL CurlOperation
    {
    public:
        CurlOperation(const CurlHTTPRemotingService& service) : m_service(service), m_handle(nullptr), m_keepHandle(false), m_headers(nullptr) {
            m_handle = service.checkout();
            m_headers = curl_slist_append(m_headers, "Content-Type: text/plain");
            m_headers = curl_slist_append(m_headers, "Expect:");
        }

        virtual ~CurlOperation() {
            curl_slist_free_all(m_headers);
            if (m_keepHandle) {
                if (curl_easy_setopt(m_handle, CURLOPT_URL, 0) == CURLE_OK &&
                    curl_easy_setopt(m_handle, CURLOPT_ERRORBUFFER, 0) == CURLE_OK &&
                    curl_easy_setopt(m_handle, CURLOPT_PASSWORD, 0) == CURLE_OK &&
                    curl_easy_setopt(m_handle, CURLOPT_DEBUGDATA, nullptr) == CURLE_OK) {
                    m_service.checkin(m_handle);
                    return;
                }
            }
            curl_easy_cleanup(m_handle);
        }

        string getContentType() const {
            char* content_type = nullptr;
            curl_easy_getinfo(m_handle, CURLINFO_CONTENT_TYPE, &content_type);
            return content_type ? content_type : "";
        }
        
        bool setRequestHeader(const char* name, const char* val) {
            string temp(name);
            temp = temp + ": " + val;
            m_headers = curl_slist_append(m_headers,temp.c_str());
            return true;
        }

        void send(const char* path, istream& in, ostream& out);

    private:
        // per-call state
        const CurlHTTPRemotingService& m_service;
        CURL* m_handle;
        bool m_keepHandle;
        struct curl_slist* m_headers;
		string m_useragent;
    };

    // callback to send data to server
    size_t curl_read_hook(void* ptr, size_t size, size_t nmemb, void* stream) {
        // stream is actually an istream pointer
        istream* buf=reinterpret_cast<istream*>(stream);
        buf->read(reinterpret_cast<char*>(ptr), size * nmemb);
        return buf->gcount();
    }

    // callback to buffer data from server
    size_t curl_write_hook(void* ptr, size_t size, size_t nmemb, void* stream) {
        size_t len = size * nmemb;
        reinterpret_cast<ostream*>(stream)->write(reinterpret_cast<const char*>(ptr), len);
        return len;
    }

    // callback for curl debug data
    int curl_debug_hook(CURL* handle, curl_infotype type, char* data, size_t len, void* ptr) {
        if (ptr) {
            // Strip non-printables...
            string buf;
            for (unsigned char* ch = (unsigned char*)data; len && (isprint(*ch) || isspace(*ch)); len--) {
                buf += *ch++;
            }
            // *ptr is actually an ofstream that should be open
            *(reinterpret_cast<ofstream*>(ptr)) << buf;
        }
        return 0;
    }
    
};

namespace shibsp {
    RemotingService* CurlHTTPRemotingServiceFactory(ptree& pt, bool deprecationSupport) {
        return new CurlHTTPRemotingService(pt);
    }
};

CurlHTTPRemotingService::CurlHTTPRemotingService(ptree& pt) :
    AbstractRemotingService(pt),
    AbstractHTTPRemotingService(pt),
    m_log(Category::getInstance(SHIBSP_LOGCAT ".RemotingService")),
        m_curlInit(false), m_poolsize(20), m_chunked(true)
{

    CURLcode status = curl_global_init(CURL_GLOBAL_ALL);
    if (status != CURLE_OK) {
        m_log.crit("libcurl initialization failure: %d", status);
        throw runtime_error("libcurl failed to initialize");
    }
    m_curlInit = true;

    static const char CIPHER_LIST_PROP_NAME[] = "tlsCipherList";
    static const char CHUNKED_PROP_NAME[] = "chunkedEncoding";
    static const char TRACE_FILE_PROP_NAME[] = "traceFileBase";

    static const char CIPHER_LIST_PROP_DEFAULT[] = "";
    static bool CHUNKED_PROP_DEFAULT = true;
    static const char TRACE_FILE_PROP_DEFAULT[] = "";

    BoostPropertySet props;
    props.load(pt);

    m_chunked = props.getBool(CHUNKED_PROP_NAME, CHUNKED_PROP_DEFAULT);
    m_ciphers = props.getString(CIPHER_LIST_PROP_NAME, CIPHER_LIST_PROP_DEFAULT);

    if (getUserAgent() == nullptr) {
        string useragent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION;
        curl_version_info_data* curlver = curl_version_info(CURLVERSION_NOW);
        if (curlver) {
            useragent = useragent + " libcurl/" + curlver->version + ' ' + curlver->ssl_version;
        }
        setUserAgent(useragent.c_str());
    }

    m_log.info("CurlHTTP RemotingService installed for agent ID (%s), baseURL (%s)", getAgentID(), getBaseURL());

    m_traceFileBase = props.getString(TRACE_FILE_PROP_NAME, TRACE_FILE_PROP_DEFAULT);
    if (!m_traceFileBase.empty()) {
        AgentConfig::getConfig().getPathResolver().resolve(m_traceFileBase, PathResolver::SHIBSP_LOG_FILE);
        m_log.warn("tracing enabled (%s), sensitive information *will* be logged; do not share and protect appropriately",
            m_traceFileBase.c_str());
    }
}

CurlHTTPRemotingService::~CurlHTTPRemotingService()
{
    for (CURL* handle : m_pool) {
        curl_easy_cleanup(handle);
    }
    m_pool.clear();

    if (m_curlInit) {
        curl_global_cleanup();
    }
}

#define SHIB_CURL_SET(opt, val) \
    if (curl_easy_setopt(m_handle, opt, val) != CURLE_OK) { \
        curl_easy_cleanup(m_handle); \
        throw RemotingException("Failed to set "#opt) ; \
    }

CURL* CurlHTTPRemotingService::checkout() const
{
    m_log.debug("getting connection handle");

    unique_lock<mutex> locker(m_lock);

    // If a free connection exists, return it.
    if (!m_pool.empty()) {
        CURL* m_handle = m_pool.back();
        m_pool.pop_back();
        m_poolsize--;
        locker.unlock();
        attachCachedAuthentication(m_handle);
        m_log.debug("returning existing connection handle from pool");
        return m_handle;
    }

    locker.unlock();
    m_log.debug("nothing free in pool, returning new connection handle");

    // Create a new connection and set non-varying options.
    CURL* m_handle = curl_easy_init();
    if (!m_handle) {
        return nullptr;
    }

    SHIB_CURL_SET(CURLOPT_NOPROGRESS, 1);
    SHIB_CURL_SET(CURLOPT_NOSIGNAL, 1);
    SHIB_CURL_SET(CURLOPT_FAILONERROR, 1);
#ifdef CURLOPT_PROTOCOLS_STR
    SHIB_CURL_SET(CURLOPT_PROTOCOLS_STR, "http,https");
#endif
    SHIB_CURL_SET(CURLOPT_FOLLOWLOCATION, 0);
#if HAVE_DECL_CURLOPT_ACCEPT_ENCODING
    SHIB_CURL_SET(CURLOPT_ACCEPT_ENCODING, "");
#else
    SHIB_CURL_SET(CURLOPT_ENCODING, "");
#endif
    SHIB_CURL_SET(CURLOPT_USERAGENT, getUserAgent());

    // This may (but probably won't) help with < 7.20 bug in DNS caching.
    SHIB_CURL_SET(CURLOPT_DNS_CACHE_TIMEOUT, 120);

    SHIB_CURL_SET(CURLOPT_SSL_VERIFYPEER, 1);
    SHIB_CURL_SET(CURLOPT_SSL_VERIFYHOST, 2);
    if (!m_ciphers.empty()) {
        SHIB_CURL_SET(CURLOPT_SSL_CIPHER_LIST, m_ciphers.c_str());
    }
    if (getCAFile()) {
        SHIB_CURL_SET(CURLOPT_CAINFO, getCAFile());
    }

    SHIB_CURL_SET(CURLOPT_CONNECTTIMEOUT, getConnectTimeout());
    SHIB_CURL_SET(CURLOPT_TIMEOUT, getTimeout());

    // One of these has to be enabled. Default is for both.
    if (!isEnableIP6()) {
        SHIB_CURL_SET(CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    }
    else if (!isEnableIP4()) {
        SHIB_CURL_SET(CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
    }

    long flag=0;
    switch (getAuthMethod()) {
        case agent_auth_none:
        case agent_auth_basic:  flag = CURLAUTH_BASIC; break;
        case agent_auth_digest: flag = CURLAUTH_DIGEST; break;
    #ifdef CURLAUTH_NEGOTIATE
        case agent_auth_gss:    flag = CURLAUTH_NEGOTIATE; break;
    #else
        case agent_auth_gss:
            curl_easy_cleanup(m_handle);
            throw RemotingException("GSS unsupporyed by this version of curl.");
            break;
    #endif
        default:                flag = 0; break;
    }
    SHIB_CURL_SET(CURLOPT_HTTPAUTH, flag);
    // Password will be acquired during call.
    SHIB_CURL_SET(CURLOPT_USERNAME, getAgentID());

    attachCachedAuthentication(m_handle);

    SHIB_CURL_SET(CURLOPT_WRITEFUNCTION, &curl_write_hook);

    return m_handle;
}

void CurlHTTPRemotingService::checkin(CURL* handle) const
{
    unique_lock<mutex> locker(m_lock);
    m_pool.push_back(handle);

    CURL* killit=nullptr;
    if (++m_poolsize > 256) {
        // Grab and dispose of the "front" element.
        killit = m_pool.front();
        m_pool.pop_front();
        m_poolsize--;
    }
    locker.unlock();

    if (killit) {
        curl_easy_cleanup(killit);
        m_log.info("conn_pool_max limit reached, dropping an old connection");
    }
}

void CurlHTTPRemotingService::attachCachedAuthentication(CURL* m_handle) const
{
    const char* name = getAuthCachingCookie();
    if (name) {
        string val(getAuthCachingCookieValue());
        if (!val.empty()) {
            string cookie(name);
            cookie += '=' + val;
            SHIB_CURL_SET(CURLOPT_COOKIE, cookie.c_str());
        }
    }

}

void CurlHTTPRemotingService::send(const char* path, istream& input, ostream& output) const
{
    CurlOperation op(*this);
    op.send(path, input, output);
    string content_type(op.getContentType());
    if (content_type != "text/plain" && !boost::starts_with(content_type, "text/plain;")) {
        throw RemotingException("Response had unsupported content type.");
    }
}

void CurlOperation::send(const char* path, istream& in, ostream& out)
{
    // Append call path to base URL.
    string url(m_service.getBaseURL());
    if (path) {
        url += path;
    }
    SHIB_CURL_SET(CURLOPT_URL, url.c_str());

    if (m_service.getAuthMethod() == CurlHTTPRemotingService::agent_auth_none) {
        SHIB_CURL_SET(CURLOPT_PASSWORD, "none");
    }
    else if (m_service.getAuthMethod() == CurlHTTPRemotingService::agent_auth_basic ||
        m_service.getAuthMethod() == CurlHTTPRemotingService::agent_auth_digest) {
        SHIB_CURL_SET(CURLOPT_PASSWORD, m_service.getSecretSource()->getSecret().c_str());
    }

    string msg;

    // Setup standard per-call curl properties.

    bool tracing = false;

    ofstream debugStream;
    if (!m_service.getTraceFileBase().empty()) {
        curl_easy_setopt(m_handle, CURLOPT_VERBOSE, 1);
        try {
            string tracename = m_service.getTraceFileBase() + boost::lexical_cast<string>(m_handle) + ".log";
            debugStream.open(tracename, ios_base::out | ios_base::app);
            if (debugStream) {
                SHIB_CURL_SET(CURLOPT_DEBUGFUNCTION, &curl_debug_hook);
                SHIB_CURL_SET(CURLOPT_DEBUGDATA, &debugStream);
                tracing = true;
            }
            else {
                m_service.logger().error("error opening trace file (%s) for remoting service handle, errno=%d",
                    tracename.c_str(), errno);
            }
        }
        catch (const boost::bad_lexical_cast& ex) {
            m_service.logger().error("unable to generate trace file name: %s", ex.what());
        }
    }

    SHIB_CURL_SET(CURLOPT_WRITEDATA, &out);
    if (m_service.isChunked()) {
        SHIB_CURL_SET(CURLOPT_POST, 1);
        m_headers = curl_slist_append(m_headers, "Transfer-Encoding: chunked");
        SHIB_CURL_SET(CURLOPT_READFUNCTION, &curl_read_hook);
        SHIB_CURL_SET(CURLOPT_READDATA, &in);
    }
    else {
        char buf[1024];
        while (in) {
            in.read(buf, 1024);
            msg.append(buf, in.gcount());
        }
        SHIB_CURL_SET(CURLOPT_POST, 1);
        SHIB_CURL_SET(CURLOPT_READFUNCTION, 0);
        SHIB_CURL_SET(CURLOPT_POSTFIELDS, msg.c_str());
        SHIB_CURL_SET(CURLOPT_POSTFIELDSIZE, msg.length());
    }

    char curl_errorbuf[CURL_ERROR_SIZE];
    curl_errorbuf[0] = 0;
    SHIB_CURL_SET(CURLOPT_ERRORBUFFER, curl_errorbuf);

    // Set request headers.
    SHIB_CURL_SET(CURLOPT_HTTPHEADER, m_headers);

    // Make the call.
    m_service.logger().debug("sending request to %s", url.c_str());
    if (tracing) {
        debugStream << "----- AGENT CALL START -----" << endl;
    }
    CURLcode code = curl_easy_perform(m_handle);
    if (tracing) {
        debugStream << "----- AGENT CALL END -----" << endl;
    }

    if (code != CURLE_OK) {
        throw RemotingException("Remote request failed at " + url + ": " +
            (curl_errorbuf[0] ? curl_errorbuf : "no further information available"));
    }

    // This won't prevent every possible failed connection from being kept, but it's something.
    m_keepHandle = true;
}

