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
 * remoting/impl/AbstractHTTPRemotingService.cpp
 *
 * Base class for HTTP-based remoting.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "logging/Category.h"
#include "remoting/SecretSource.h"
#include "remoting/impl/AbstractHTTPRemotingService.h"
#include "util/BoostPropertySet.h"
#include "util/PathResolver.h"

#include <sys/stat.h>

#include <stdexcept>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

AbstractHTTPRemotingService::AbstractHTTPRemotingService(ptree& pt)
    : AbstractRemotingService(pt), m_authMethod(agent_auth_none)
{
    BoostPropertySet props;
    props.load(pt);

    static const char AGENT_ID_PROP_NAME[] = "agentID";
    static const char SECRET_SOURCE_TYPE_PROP_NAME[] = "secretSourceType";
    static const char BASE_URL_PROP_NAME[] = "baseURL";
    static const char USER_AGENT_PROP_NAME[] = "userAgent";
    static const char AUTH_METHOD_PROP_NAME[] = "authMethod";
    static const char AUTH_CACHING_COOKIE_PROP_NAME[] = "authCachingCookie";
    static const char CONNECT_TIMEOUT_PROP_NAME[] = "connectTimeout";
    static const char TIMEOUT_PROP_NAME[] = "timeout";
    static const char CA_FILE_PROP_NAME[] = "tlsCAFile";
    static const char REVOCATION_CHECK_PROP_NAME[] = "revocationCheck";
    static const char ENABLE_IP4_PROP_NAME[] = "enableIP4";
    static const char ENABLE_IP6_PROP_NAME[] = "enableIP6";

    static const char AGENT_ID_PROP_DEFAULT[] = "localhost";
    static const char SECRET_SOURCE_TYPE_PROP_DEFAULT[] = FILE_SECRET_SOURCE;
    static const char BASE_URL_PROP_DEFAULT[] = "http://localhost:8080/idp/profile/sp/";
    static const char USER_AGENT_PROP_DEFAULT[] = "";
    static const char AUTH_METHOD_PROP_DEFAULT[] = "none";
    static const char AUTH_CACHING_COOKIE_PROP_DEFAULT[] = "__Host-JSESSIONID";
    static unsigned int CONNECT_TIMEOUT_PROP_DEFAULT = 3;
    static unsigned int TIMEOUT_PROP_DEFAULT = 10;
    static const char CA_FILE_PROP_DEFAULT[] = "";
    static const bool REVOCATION_CHECK_DEFAULT = false;
    static const bool ENABLE_IP4_PROP_DEFAULT = true;
    static const bool ENABLE_IP6_PROP_DEFAULT = true;

    m_agentID = props.getString(AGENT_ID_PROP_NAME, AGENT_ID_PROP_DEFAULT);    
    m_userAgent = props.getString(USER_AGENT_PROP_NAME, USER_AGENT_PROP_DEFAULT);
    m_baseURL = props.getString(BASE_URL_PROP_NAME, BASE_URL_PROP_DEFAULT);
    if (m_baseURL.back() != '/') {
        m_baseURL += '/';
    }

    m_authMethod = getAuthMethod(props.getString(AUTH_METHOD_PROP_NAME, AUTH_METHOD_PROP_DEFAULT));
    m_connectTimeout = props.getUnsignedInt(CONNECT_TIMEOUT_PROP_NAME, CONNECT_TIMEOUT_PROP_DEFAULT);
    m_timeout = props.getUnsignedInt(TIMEOUT_PROP_NAME, TIMEOUT_PROP_DEFAULT);
    m_revocationCheck = props.getBool(REVOCATION_CHECK_PROP_NAME, REVOCATION_CHECK_DEFAULT);
    m_enableIP4 = props.getBool(ENABLE_IP4_PROP_NAME, ENABLE_IP4_PROP_DEFAULT);
    m_enableIP6 = props.getBool(ENABLE_IP6_PROP_NAME, ENABLE_IP6_PROP_DEFAULT);

    if (!m_enableIP4 && !m_enableIP6) {
        throw ConfigurationException("One of IP4 or IP6 must be enabled.");
    }

    if (m_authMethod != agent_auth_none) {
        m_secretSource.reset(AgentConfig::getConfig().SecretSourceManager.newPlugin(
            props.getString(SECRET_SOURCE_TYPE_PROP_NAME, SECRET_SOURCE_TYPE_PROP_DEFAULT), pt, false)
            );
    }

    m_caFile = props.getString(CA_FILE_PROP_NAME, CA_FILE_PROP_DEFAULT);
    if (!m_caFile.empty()) {
        AgentConfig::getConfig().getPathResolver().resolve(m_caFile, PathResolver::SHIBSP_CFG_FILE);
#ifdef WIN32
        struct _stat stat_buf;
        if (_stat(m_caFile.c_str(), &stat_buf) != 0) {
#else
        struct stat stat_buf;
        if (stat(m_caFile.c_str(), &stat_buf) != 0) {
#endif
            throw ConfigurationException(string("Unable to access CA file: ") + m_caFile);
        } else if (stat_buf.st_size == 0) {
            throw ConfigurationException(string("CA file is empty: ") + m_caFile);
        }
    }
    else if (boost::starts_with(m_baseURL, "https://")) {
        throw ConfigurationException("No tlsCAFile provided for https:// baseURL.");
    }

    m_authCachingCookie = props.getString(AUTH_CACHING_COOKIE_PROP_NAME, AUTH_CACHING_COOKIE_PROP_DEFAULT);
    if (!m_authCachingCookie.empty()) {
#if defined(HAVE_CXX17)
        m_authcachelock.reset(new shared_mutex());
#elif defined(HAVE_CXX14)
        m_lock.reset(new shared_timed_mutex());
#else
        Category::getInstance(SHIBSP_LOGCAT ".RemotingService").warn(
            "disabling agent authentication caching due to age of C++ compiler used");
        m_authCachingCookie.clear();
#endif
    }
}

#ifdef HAVE_CXX14
DDF AbstractHTTPRemotingService::send(const DDF& in) const
{
    DDF output = AbstractRemotingService::send(in);
    if (!m_authCachingCookie.empty()) {
        const char* latestValue = output.getmember("cached_auth").string();
        if (latestValue) {
            m_authcachelock->lock_shared();
            if (m_authCachingValue != latestValue) {
                m_authcachelock->unlock_shared();
#if defined(HAVE_CXX17)
                lock_guard<shared_mutex> locker(*m_authcachelock);
#elif defined(HAVE_CXX14)
                lock_guard<shared_timed_mutex> locker(*m_authcachelock);
#endif
                m_authCachingValue = latestValue;
            }
            else {
                m_authcachelock->unlock_shared();
            }
        }
    }

    return output;
}
#endif

const SecretSource* AbstractHTTPRemotingService::getSecretSource(bool required) const
{
    if (required && !m_secretSource) {
        throw ConfigurationException("SecretSource is not available.");
    }

    return m_secretSource.get();
}

const char* AbstractHTTPRemotingService::getBaseURL() const
{
    return m_baseURL.c_str();
}

const char* AbstractHTTPRemotingService::getUserAgent() const
{
    return m_userAgent.c_str();
}

const char* AbstractHTTPRemotingService::getAgentID() const
{
    return m_agentID.c_str();
}


void AbstractHTTPRemotingService::setUserAgent(const char* ua)
{
    m_userAgent = ua ? ua : "";
}

const char* AbstractHTTPRemotingService::getAuthCachingCookie() const
{
    return m_authCachingCookie.c_str();
}

string AbstractHTTPRemotingService::getAuthCachingCookieValue() const
{
#if defined(HAVE_CXX14)
    if (!m_authCachingCookie.empty()) {
        shared_lock<shared_mutex> locker(*m_authcachelock);
        return m_authCachingValue;
    }
#endif        
    return "";
}

AbstractHTTPRemotingService::auth_t AbstractHTTPRemotingService::getAuthMethod() const
{
    return m_authMethod;
}

unsigned int AbstractHTTPRemotingService::getConnectTimeout() const
{
    return m_connectTimeout;
}

unsigned int AbstractHTTPRemotingService::getTimeout() const
{
    return m_timeout;
}

bool AbstractHTTPRemotingService::isEnableIP4() const
{
    return m_enableIP4;
}

bool AbstractHTTPRemotingService::isEnableIP6() const
{
    return m_enableIP6;
}

bool AbstractHTTPRemotingService::isRevocationCheck() const
{
    return m_revocationCheck;
}

const char* AbstractHTTPRemotingService::getCAFile() const
{
    if (m_caFile.empty()) {
        return nullptr;
    }
    return m_caFile.c_str();
}

AbstractHTTPRemotingService::auth_t AbstractHTTPRemotingService::getAuthMethod(const char* method)
{
    if (method) {
        if (!strcmp(method, "none")) {
            return agent_auth_none;
        }
        else if (!strcmp(method, "basic")) {
            return agent_auth_basic;
        }
        else if (!strcmp(method, "digest")) {
            return agent_auth_digest;
        }
        else if (!strcmp(method, "gss")) {
            return agent_auth_gss;
        }
        else if (!strcmp(method, "tls")) {
            return agent_auth_tls;
        }
        else {
            throw range_error("Unrecognized remoting authentication method.");
        }
    }

    return agent_auth_none;
}

AbstractHTTPRemotingService::~AbstractHTTPRemotingService() {}
