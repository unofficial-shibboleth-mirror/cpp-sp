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
#include "remoting/SecretSource.h"
#include "remoting/impl/AbstractHTTPRemotingService.h"
#include "util/BoostPropertySet.h"

#include <stdexcept>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

const char AbstractHTTPRemotingService::SECRET_SOURCE_TYPE_PROP_NAME[] = "secretSourceType";
const char AbstractHTTPRemotingService::BASE_URL_PROP_NAME[] = "baseURL";
const char AbstractHTTPRemotingService::AGENT_ID_PROP_NAME[] = "agentID";
const char AbstractHTTPRemotingService::AUTH_METHOD_PROP_NAME[] = "authMethod";
const char AbstractHTTPRemotingService::CONNECT_TIMEOUT_PROP_NAME[] = "connectTimeout";
const char AbstractHTTPRemotingService::TIMEOUT_PROP_NAME[] = "timeout";

const char AbstractHTTPRemotingService::SECRET_SOURCE_TYPE_PROP_DEFAULT[] = "File";
const char AbstractHTTPRemotingService::BASE_URL_PROP_DEFAULT[] = "http://localhost/idp/profile";
const char AbstractHTTPRemotingService::AUTH_METHOD_PROP_DEFAULT[] = "basic";
unsigned int AbstractHTTPRemotingService::CONNECT_TIMEOUT_PROP_DEFAULT = 3;
unsigned int AbstractHTTPRemotingService::TIMEOUT_PROP_DEFAULT = 10;

AbstractHTTPRemotingService::AbstractHTTPRemotingService(ptree& pt)
    : AbstractRemotingService(pt), m_authMethod(agent_auth_none)
{
    BoostPropertySet props;
    props.load(pt);

    m_agentID = props.getString(AGENT_ID_PROP_NAME, "");
    if (m_agentID.empty()) {
        throw ConfigurationException("Configuration is missing required agent ID.");
    }

    m_secretSource.reset(AgentConfig::getConfig().SecretSourceManager.newPlugin(
        props.getString(SECRET_SOURCE_TYPE_PROP_NAME, SECRET_SOURCE_TYPE_PROP_DEFAULT), pt, false)
        );

    m_baseURL = props.getString(BASE_URL_PROP_NAME, BASE_URL_PROP_DEFAULT);
    m_authMethod = getAuthMethod(props.getString(AUTH_METHOD_PROP_NAME, AUTH_METHOD_PROP_DEFAULT));
    m_connectTimeout = props.getUnsignedInt(CONNECT_TIMEOUT_PROP_NAME, CONNECT_TIMEOUT_PROP_DEFAULT);
    m_timeout = props.getUnsignedInt(TIMEOUT_PROP_NAME, TIMEOUT_PROP_DEFAULT);
}

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

const char* AbstractHTTPRemotingService::getAgentID() const
{
    return m_agentID.c_str();
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
