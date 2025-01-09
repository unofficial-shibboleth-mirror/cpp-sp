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
 * impl/DefaultAgent.cpp
 *
 * PropertyTree-based Agent configuration.
 */

#include "internal.h"

#include "exceptions.h"
#include "version.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "io/HTTPResponse.h"
#include "logging/Category.h"
#include "remoting/RemotingService.h"
#include "session/SessionCache.h"
#include "util/BoostPropertySet.h"
#include "util/SPConstants.h"
#include "util/Misc.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    // Top-level configuration implementation
    class SHIBSP_DLLLOCAL DefaultAgent : public Agent, public BoostPropertySet
    {
    public:
        DefaultAgent(ptree& pt) : m_pt(pt), m_log(Category::getInstance(SHIBSP_LOGCAT ".Agent")) {}
        ~DefaultAgent() {}

        void init();

        // Agent services.

        RemotingService* getRemotingService(bool required = true) const {
            if (required && !m_remotingService)
                throw ConfigurationException("No ListenerService available.");
            return m_remotingService.get();
        }

        SessionCache* getSessionCache(bool required = true) const {
            if (required && !m_sessionCache)
                throw ConfigurationException("No SessionCache available.");
            return m_sessionCache.get();
        }

        RequestMapper* getRequestMapper(bool required = true) const {
            if (required && !m_requestMapper)
                throw ConfigurationException("No RequestMapper available.");
            return m_requestMapper.get();
        }

    private:
        void doRemotingService();
        void doSessionCache();
        void doRequestMapper();

        ptree& m_pt;
        Category& m_log;

        // The order of these members actually matters. If we want to rely on auto-destruction, then
        // anything dependent on anything else has to come later in the object so it will pop first.
        // Remoting is the lowest, then the cache, and finally the rest.
        unique_ptr<RemotingService> m_remotingService;
        unique_ptr<SessionCache> m_sessionCache;
        unique_ptr<RequestMapper> m_requestMapper;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Agent* DefaultAgentFactory(ptree& pt, bool deprecationSupport)
    {
        return new DefaultAgent(pt);
    }
};

namespace shibsp {
    void SHIBSP_API shibsp::registerAgents() {
        AgentConfig::getConfig().AgentManager.registerFactory(DEFAULT_AGENT, DefaultAgentFactory);
    }
};

void DefaultAgent::init()
{
    // First load "global" property tree as this PropertySet.
    const boost::optional<ptree&> global = m_pt.get_child_optional("global");
    if (global) {
        load(global.get());
    }

    const char* prop = getString("allowedSchemes", "https http");
    if (prop) {
        HTTPResponse::getAllowedSchemes().clear();
        split_to_container(HTTPResponse::getAllowedSchemes(), prop);
    }

    prop = getString("extraAuthTypes");
    if (prop) {
        split_to_container(m_authTypes, prop);
        m_authTypes.insert("shibboleth");
    }

    const AgentConfig& conf = AgentConfig::getConfig();

    doRemotingService();
    doSessionCache();
    doRequestMapper();

    // TODO: the Application related material needs to be replaced with new approaches.
}

void DefaultAgent::doRemotingService()
{
    boost::optional<ptree&> child = m_pt.get_child_optional("remoting");
    if (child) {
        string t(child->get("type", HTTP_REMOTING_SERVICE));
        m_log.info("building RemotingService of type %s...", t.c_str());
        m_remotingService.reset(AgentConfig::getConfig().RemotingServiceManager.newPlugin(t.c_str(), *child, true));
    } else {
        m_log.debug("[remoting] section absent, skipping RemotingService creation");
    }
}

void DefaultAgent::doSessionCache()
{
    boost::optional<ptree&> child = m_pt.get_child_optional("session-cache");
    if (child) {
        // TODO: change the expected default type
        string t(child->get("type", STORAGESERVICE_SESSION_CACHE));
        m_log.info("building SessionCache of type %s...", t.c_str());
        m_sessionCache.reset(AgentConfig::getConfig().SessionCacheManager.newPlugin(t.c_str(), *child, true));
    } else {
        m_log.debug("[session-cache] section absent, skipping SessionCache creation");
    }
}

void DefaultAgent::doRequestMapper()
{
    boost::optional<ptree&> child = m_pt.get_child_optional("request-mapper");
    if (child) {
        string t(child->get("type", NATIVE_REQUEST_MAPPER));
        m_log.info("building RequestMapper of type %s...", t.c_str());
        m_requestMapper.reset(AgentConfig::getConfig().RequestMapperManager.newPlugin(t.c_str(), *child, true));
    } else {
        m_log.debug("[request-mapper] section absent, skipping RequestMapper creation");
    }
}
