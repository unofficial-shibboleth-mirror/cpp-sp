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

namespace shibsp {

    class SHIBSP_API SecretSource;

    /**
     * Base class for HTTP remoting services.
     */
    class SHIBSP_API AbstractHTTPRemotingService : public virtual AbstractRemotingService
    {
    public:
        virtual ~AbstractHTTPRemotingService();

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
        const char* getBaseURL() const;
        const char* getAgentID() const;
        const char* getUserAgent() const;
        void setUserAgent(const char* ua);
        auth_t getAuthMethod() const;
        const char* getAuthCachingCookie() const;
        unsigned int getConnectTimeout() const;
        unsigned int getTimeout() const;
        const char* getCAFile() const;

        // Property names and defaults.
        static const char SECRET_SOURCE_TYPE_PROP_NAME[];
        static const char BASE_URL_PROP_NAME[];
        static const char AGENT_ID_PROP_NAME[];
        static const char USER_AGENT_PROP_NAME[];
        static const char AUTH_METHOD_PROP_NAME[];
        static const char AUTH_CACHING_COOKIE_PROP_NAME[];
        static const char CONNECT_TIMEOUT_PROP_NAME[];
        static const char TIMEOUT_PROP_NAME[];
        static const char CA_FILE_PROP_NAME[];

        static const char SECRET_SOURCE_TYPE_PROP_DEFAULT[];
        static const char BASE_URL_PROP_DEFAULT[];
        static const char AUTH_METHOD_PROP_DEFAULT[];
        static const char AUTH_CACHING_COOKIE_PROP_DEFAULT[];
        static unsigned int CONNECT_TIMEOUT_PROP_DEFAULT;
        static unsigned int TIMEOUT_PROP_DEFAULT;
        static const char CA_FILE_PROP_DEFAULT[];

    protected:
        AbstractHTTPRemotingService(boost::property_tree::ptree& pt);

    private:
        auth_t getAuthMethod(const char* method);

        std::unique_ptr<SecretSource> m_secretSource;
        std::string m_baseURL;
        std::string m_agentID;
        std::string m_userAgent;
        std::string m_authCachingCookie;
        std::string m_caFile;
        auth_t m_authMethod;
        unsigned int m_connectTimeout;
        unsigned int m_timeout;
    };

};

#endif /* __shibsp_httpremotingservice_h__ */
