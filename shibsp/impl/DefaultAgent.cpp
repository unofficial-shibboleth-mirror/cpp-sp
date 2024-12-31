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
#include "SessionCache.h"
#include "io/HTTPResponse.h"
#include "logging/Category.h"
#include "util/BoostPropertySet.h"
#include "util/PathResolver.h"
#include "util/SPConstants.h"

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#ifndef min
# define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

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

        ListenerService* getListenerService(bool required = true) const {
            //if (required && !m_listener)
                throw ConfigurationException("No ListenerService available.");
            //return m_listener.get();
        }

        SessionCache* getSessionCache(bool required = true) const {
            //if (required && !m_sessionCache)
                throw ConfigurationException("No SessionCache available.");
            //return m_sessionCache.get();
        }

        RequestMapper* getRequestMapper(bool required = true) const {
            if (required && !m_requestMapper)
                throw ConfigurationException("No RequestMapper available.");
            return m_requestMapper.get();
        }

    private:
        void doRemoting();
        void doSessionCache();
        void doRequestMapper();

        ptree& m_pt;
        Category& m_log;

        // The order of these members actually matters. If we want to rely on auto-destruction, then
        // anything dependent on anything else has to come later in the object so it will pop first.
        // Remoting is the lowest, then the cache, and finally the rest.
        //unique_ptr<ListenerService> m_listener;
        unique_ptr<SessionCache> m_sessionCache;
        unique_ptr<RequestMapper> m_requestMapper;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh applicationId[] =        UNICODE_LITERAL_13(a,p,p,l,i,c,a,t,i,o,n,I,d);
    static const XMLCh _default[] =             UNICODE_LITERAL_7(d,e,f,a,u,l,t);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh InProcess[] =            UNICODE_LITERAL_9(I,n,P,r,o,c,e,s,s);
    static const XMLCh Listener[] =             UNICODE_LITERAL_8(L,i,s,t,e,n,e,r);
    static const XMLCh logger[] =               UNICODE_LITERAL_6(l,o,g,g,e,r);
    static const XMLCh _option[] =              UNICODE_LITERAL_6(o,p,t,i,o,n);
    static const XMLCh OutOfProcess[] =         UNICODE_LITERAL_12(O,u,t,O,f,P,r,o,c,e,s,s);
    static const XMLCh _path[] =                UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh _provider[] =            UNICODE_LITERAL_8(p,r,o,v,i,d,e,r);
    static const XMLCh _RequestMapper[] =       UNICODE_LITERAL_13(R,e,q,u,e,s,t,M,a,p,p,e,r);
    static const XMLCh RequestMap[] =           UNICODE_LITERAL_10(R,e,q,u,e,s,t,M,a,p);
    static const XMLCh _SessionCache[] =        UNICODE_LITERAL_12(S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh Site[] =                 UNICODE_LITERAL_4(S,i,t,e);
    static const XMLCh TCPListener[] =          UNICODE_LITERAL_11(T,C,P,L,i,s,t,e,n,e,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh UnixListener[] =         UNICODE_LITERAL_12(U,n,i,x,L,i,s,t,e,n,e,r);

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
        string schemes(prop);
        boost::trim(schemes);
        boost::split(HTTPResponse::getAllowedSchemes(), schemes, boost::is_space(), boost::algorithm::token_compress_on);
    }

    prop = getString("extraAuthTypes");
    if (prop) {
        string types(prop);
        boost::trim(types);
        boost::split(m_authTypes, types, boost::is_space(), boost::algorithm::token_compress_on);
        m_authTypes.insert("shibboleth");
    }

    const AgentConfig& conf = AgentConfig::getConfig();

    doRemoting();
    doSessionCache();
    doRequestMapper();

    // TODO: the Application related material needs to be replaced with new approaches.
}

void DefaultAgent::doRemoting()
{
    /*
#ifdef WIN32
    string plugtype(TCP_LISTENER_SERVICE);
#else
    string plugtype(UNIX_LISTENER_SERVICE);
#endif
    DOMElement* child = XMLHelper::getFirstChildElement(e, UnixListener);
    if (child)
        plugtype = UNIX_LISTENER_SERVICE;
    else {
        child = XMLHelper::getFirstChildElement(e, TCPListener);
        if (child)
            plugtype = TCP_LISTENER_SERVICE;
        else {
            child = XMLHelper::getFirstChildElement(e, Listener);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(nullptr, _type));
                if (type.get() && *type.get())
                    plugtype = type.get();
            }
        }
    }

    log.info("building ListenerService of type %s...", plugtype.c_str());
    conf->m_listener.reset(SPConfig::getConfig().ListenerServiceManager.newPlugin(plugtype.c_str(), child, m_deprecationSupport));
    */
}

void DefaultAgent::doSessionCache()
{
    /*
    const SPConfig& spConf = SPConfig::getConfig();

    DOMElement* child = XMLHelper::getFirstChildElement(e, _SessionCache);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (!t.empty()) {
            log.info("building SessionCache of type %s...", t.c_str());
            conf->m_sessionCache.reset(spConf.SessionCacheManager.newPlugin(t.c_str(), child, m_deprecationSupport));
        }
    }
    if (!conf->m_sessionCache) {
        log.info("no SessionCache specified, using StorageService-backed instance");
        conf->m_sessionCache.reset(spConf.SessionCacheManager.newPlugin(STORAGESERVICE_SESSION_CACHE, nullptr, m_deprecationSupport));
    }
    */
}

void DefaultAgent::doRequestMapper()
{
    const boost::optional<ptree&> child = m_pt.get_child_optional("request-mapper");

    /*
    // Back to the fully dynamic stuff...next up is the RequestMapper.
    if (child = XMLHelper::getFirstChildElement(e, _RequestMapper)) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (!t.empty()) {
            log.info("building RequestMapper of type %s...", t.c_str());
            m_requestMapper.reset(conf.RequestMapperManager.newPlugin(t.c_str(), child, m_deprecationSupport));
        }
    }
    if (!m_requestMapper) {
        log.info("no RequestMapper specified, using 'Native' plugin with empty/default map");
        child = e->getOwnerDocument()->createElementNS(nullptr, _RequestMapper);
        DOMElement* mapperDummy = e->getOwnerDocument()->createElementNS(e->getNamespaceURI(), RequestMap);
        mapperDummy->setAttributeNS(nullptr, applicationId, _default);
        child->appendChild(mapperDummy);
        m_requestMapper.reset(conf.RequestMapperManager.newPlugin(NATIVE_REQUEST_MAPPER, child, m_deprecationSupport));
    }
    */
}
