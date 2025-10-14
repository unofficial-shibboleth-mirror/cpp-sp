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
 * remoting/impl/AbstractHTTPRemotingService.h
 *
 * Base class for HTTP-based remoting.
 */

#ifndef __shibsp_httpremotingservice_h__
#define __shibsp_httpremotingservice_h__

#include "remoting/impl/AbstractRemotingService.h"

#include <memory>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

namespace shibsp {

    class SHIBSP_API SecretSource;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for HTTP remoting services.
     */
    class SHIBSP_API AbstractHTTPRemotingService : public virtual AbstractRemotingService
    {
    public:
        virtual ~AbstractHTTPRemotingService();

#ifdef HAVE_CXX14
        DDF send(const DDF& in) const;
#endif

        /**
         * Common types of authentication that may be supported.
         */
        enum auth_t {
            agent_auth_none,
            agent_auth_basic,
            agent_auth_digest,
            agent_auth_gss,
            agent_auth_tls
        };

        const SecretSource* getSecretSource(bool required=true) const;

        /**
         * Get the base URL for connection to the hub.
         * 
         * <p>This URL will end in a path separator (/).</p>
         * 
         * @return the base URL, with a terminating slash
         */
        const char* getBaseURL() const;

        const char* getUserAgent() const;
        void setUserAgent(const char* ua);
        auth_t getAuthMethod() const;
        const char* getAuthCachingCookie() const;
        std::string getAuthCachingCookieValue() const;
        unsigned int getConnectTimeout() const;
        unsigned int getTimeout() const;
        bool isRevocationCheck() const;
        const char* getCAFile() const;

        // Property names and defaults.
        static const char SECRET_SOURCE_TYPE_PROP_NAME[];
        static const char BASE_URL_PROP_NAME[];
        static const char USER_AGENT_PROP_NAME[];
        static const char AUTH_METHOD_PROP_NAME[];
        static const char AUTH_CACHING_COOKIE_PROP_NAME[];
        static const char CONNECT_TIMEOUT_PROP_NAME[];
        static const char TIMEOUT_PROP_NAME[];
        static const char CA_FILE_PROP_NAME[];
        static const char REVOCATION_CHECK_PROP_NAME[];

        static const char SECRET_SOURCE_TYPE_PROP_DEFAULT[];
        static const char BASE_URL_PROP_DEFAULT[];
        static const char AUTH_METHOD_PROP_DEFAULT[];
        static const char AUTH_CACHING_COOKIE_PROP_DEFAULT[];
        static unsigned int CONNECT_TIMEOUT_PROP_DEFAULT;
        static unsigned int TIMEOUT_PROP_DEFAULT;
        static const char CA_FILE_PROP_DEFAULT[];
        static const bool REVOCATION_CHECK_DEFAULT;

    protected:
        AbstractHTTPRemotingService(boost::property_tree::ptree& pt);

    private:
        auth_t getAuthMethod(const char* method);

        std::unique_ptr<SecretSource> m_secretSource;
        std::string m_baseURL;
        std::string m_userAgent;
        std::string m_authCachingCookie;
        mutable std::string m_authCachingValue;
        std::string m_caFile;
        auth_t m_authMethod;
        unsigned int m_connectTimeout;
        unsigned int m_timeout;
        bool m_revocationCheck;
        /** Shared lock for guarding auth cache value. */
#if defined(HAVE_CXX17)
        std::unique_ptr<std::shared_mutex> m_authcachelock;
#elif defined(HAVE_CXX14)
        std::unique_ptr<std::shared_timed_mutex> m_authcachelock;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_httpremotingservice_h__ */
