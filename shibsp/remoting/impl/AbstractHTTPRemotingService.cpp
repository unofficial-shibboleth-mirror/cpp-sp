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
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

const char AbstractHTTPRemotingService::SECRET_SOURCE_TYPE_PROP_NAME[] = "secretSourceType";
const char AbstractHTTPRemotingService::BASE_URL_PROP_NAME[] = "baseURL";
const char AbstractHTTPRemotingService::USER_AGENT_PROP_NAME[] = "userAgent";
const char AbstractHTTPRemotingService::AUTH_METHOD_PROP_NAME[] = "authMethod";
const char AbstractHTTPRemotingService::AUTH_CACHING_COOKIE_PROP_NAME[] = "authCachingCookie";
const char AbstractHTTPRemotingService::CONNECT_TIMEOUT_PROP_NAME[] = "connectTimeout";
const char AbstractHTTPRemotingService::TIMEOUT_PROP_NAME[] = "timeout";
const char AbstractHTTPRemotingService::CA_FILE_PROP_NAME[] = "tlsCAFile";
const char AbstractHTTPRemotingService::REVOCATION_CHECK_PROP_NAME[] = "revocationCheck";

const char AbstractHTTPRemotingService::SECRET_SOURCE_TYPE_PROP_DEFAULT[] = "File";
const char AbstractHTTPRemotingService::BASE_URL_PROP_DEFAULT[] = "http://localhost/idp/profile/sp";
const char AbstractHTTPRemotingService::AUTH_METHOD_PROP_DEFAULT[] = "basic";
const char AbstractHTTPRemotingService::AUTH_CACHING_COOKIE_PROP_DEFAULT[] = "__Host-JSESSIONID";
unsigned int AbstractHTTPRemotingService::CONNECT_TIMEOUT_PROP_DEFAULT = 3;
unsigned int AbstractHTTPRemotingService::TIMEOUT_PROP_DEFAULT = 10;
const bool AbstractHTTPRemotingService::REVOCATION_CHECK_DEFAULT = false;
const char AbstractHTTPRemotingService::CA_FILE_PROP_DEFAULT[] = "trustlist.pem";

AbstractHTTPRemotingService::AbstractHTTPRemotingService(ptree& pt)
    : AbstractRemotingService(pt), m_authMethod(agent_auth_none)
{
    BoostPropertySet props;
    props.load(pt);

    m_secretSource.reset(AgentConfig::getConfig().SecretSourceManager.newPlugin(
        props.getString(SECRET_SOURCE_TYPE_PROP_NAME, SECRET_SOURCE_TYPE_PROP_DEFAULT), pt, false)
        );

    m_userAgent = props.getString(USER_AGENT_PROP_NAME, "");
    m_baseURL = props.getString(BASE_URL_PROP_NAME, BASE_URL_PROP_DEFAULT);    
    m_authMethod = getAuthMethod(props.getString(AUTH_METHOD_PROP_NAME, AUTH_METHOD_PROP_DEFAULT));
    m_connectTimeout = props.getUnsignedInt(CONNECT_TIMEOUT_PROP_NAME, CONNECT_TIMEOUT_PROP_DEFAULT);
    m_timeout = props.getUnsignedInt(TIMEOUT_PROP_NAME, TIMEOUT_PROP_DEFAULT);
    m_revocationCheck = props.getBool(REVOCATION_CHECK_PROP_NAME, REVOCATION_CHECK_DEFAULT);

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

bool AbstractHTTPRemotingService::isRevocationCheck() const
{
    return m_revocationCheck;
}

const char* AbstractHTTPRemotingService::getCAFile() const
{
    return m_caFile.c_str();
}

AbstractHTTPRemotingService::auth_t AbstractHTTPRemotingService::getAuthMethod(const char* method)
{
    if (method) {
        if (!strcmp(method, "basic")) {
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
