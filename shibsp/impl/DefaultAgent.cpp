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
        DefaultAgent(const ptree& pt) : m_pt(pt), m_log(Category::getInstance(SHIBSP_LOGCAT ".Agent")) {}
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
        void doExtensions(const ptree&);
        //void doListener(const xercesc::DOMElement*);
        //void doCaching(const xercesc::DOMElement*);

        const ptree& m_pt;
        Category& m_log;

        // The order of these members actually matters. If we want to rely on auto-destruction, then
        // anything dependent on anything else has to come later in the object so it will pop first.
        // Remoting is the lowest, then the cache, and finally the rest.
        //unique_ptr<ListenerService> m_listener;
        //unique_ptr<SessionCache> m_sessionCache;
        unique_ptr<RequestMapper> m_requestMapper;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh applicationId[] =        UNICODE_LITERAL_13(a,p,p,l,i,c,a,t,i,o,n,I,d);
    static const XMLCh _ArtifactMap[] =         UNICODE_LITERAL_11(A,r,t,i,f,a,c,t,M,a,p);
    static const XMLCh _DataSealer[] =          UNICODE_LITERAL_10(D,a,t,a,S,e,a,l,e,r);
    static const XMLCh _default[] =             UNICODE_LITERAL_7(d,e,f,a,u,l,t);
    static const XMLCh _Extensions[] =          UNICODE_LITERAL_10(E,x,t,e,n,s,i,o,n,s);
    static const XMLCh _fatal[] =               UNICODE_LITERAL_5(f,a,t,a,l);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh InProcess[] =            UNICODE_LITERAL_9(I,n,P,r,o,c,e,s,s);
    static const XMLCh Library[] =              UNICODE_LITERAL_7(L,i,b,r,a,r,y);
    static const XMLCh Listener[] =             UNICODE_LITERAL_8(L,i,s,t,e,n,e,r);
    static const XMLCh logger[] =               UNICODE_LITERAL_6(l,o,g,g,e,r);
    static const XMLCh _option[] =              UNICODE_LITERAL_6(o,p,t,i,o,n);
    static const XMLCh OutOfProcess[] =         UNICODE_LITERAL_12(O,u,t,O,f,P,r,o,c,e,s,s);
    static const XMLCh _path[] =                UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh _ProtocolProvider[] =    UNICODE_LITERAL_16(P,r,o,t,o,c,o,l,P,r,o,v,i,d,e,r);
    static const XMLCh _provider[] =            UNICODE_LITERAL_8(p,r,o,v,i,d,e,r);
    static const XMLCh _ReplayCache[] =         UNICODE_LITERAL_11(R,e,p,l,a,y,C,a,c,h,e);
    static const XMLCh _RequestMapper[] =       UNICODE_LITERAL_13(R,e,q,u,e,s,t,M,a,p,p,e,r);
    static const XMLCh RequestMap[] =           UNICODE_LITERAL_10(R,e,q,u,e,s,t,M,a,p);
    static const XMLCh SecurityPolicies[] =     UNICODE_LITERAL_16(S,e,c,u,r,i,t,y,P,o,l,i,c,i,e,s);
    static const XMLCh _SecurityPolicyProvider[] = UNICODE_LITERAL_22(S,e,c,u,r,i,t,y,P,o,l,i,c,y,P,r,o,v,i,d,e,r);
    static const XMLCh _SessionCache[] =        UNICODE_LITERAL_12(S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh Site[] =                 UNICODE_LITERAL_4(S,i,t,e);
    static const XMLCh _StorageService[] =      UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh TCPListener[] =          UNICODE_LITERAL_11(T,C,P,L,i,s,t,e,n,e,r);
    static const XMLCh tranLogFiller[] =        UNICODE_LITERAL_13(t,r,a,n,L,o,g,F,i,l,l,e,r);
    static const XMLCh tranLogFormat[] =        UNICODE_LITERAL_13(t,r,a,n,L,o,g,F,o,r,m,a,t);
    static const XMLCh TransportOption[] =      UNICODE_LITERAL_15(T,r,a,n,s,p,o,r,t,O,p,t,i,o,n);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh UnixListener[] =         UNICODE_LITERAL_12(U,n,i,x,L,i,s,t,e,n,e,r);

    Agent* DefaultAgentFactory(const ptree& pt, bool deprecationSupport)
    {
        return new DefaultAgent(pt);
    }
};

namespace shibsp {
    void SHIBSP_API shibsp::registerAgents()
    {
        AgentConfig::getConfig().AgentManager.registerFactory(DEFAULT_AGENT, DefaultAgentFactory);
    }
};

void DefaultAgent::init()
{
    /*
    const SPConfig& conf=SPConfig::getConfig();
    const DOMElement* SHAR=XMLHelper::getFirstChildElement(e, OutOfProcess);
    const DOMElement* SHIRE=XMLHelper::getFirstChildElement(e, InProcess);

    // Initialize logging manually in order to redirect log messages as soon as possible.
    // If no explicit config is supplied, we now assume the caller has done this, so that
    // setuid processes can potentially do this as root.

    // We also no longer do this on reloads, as this results in race conditions that could
    // crash the process.

    if (first && conf.isEnabled(SPConfig::Logging)) {
        string logconf;
        if (conf.isEnabled(SPConfig::OutOfProcess))
            logconf = XMLHelper::getAttrString(SHAR, nullptr, logger);
        else if (conf.isEnabled(SPConfig::InProcess))
            logconf = XMLHelper::getAttrString(SHIRE, nullptr, logger);
        if (logconf.empty())
            logconf = XMLHelper::getAttrString(e, nullptr, logger);
        if (!logconf.empty()) {
            log.debug("loading new logging configuration from (%s), check log destination for status of configuration", logconf.c_str());
            if (!XMLToolingConfig::getConfig().log_config(logconf.c_str()))
                log.crit("failed to load new logging configuration from (%s)", logconf.c_str());
        }
    }

    // Re-log library versions now that logging is set up.
    log.info("Shibboleth SP Version %s", PACKAGE_VERSION);
    log.info(
        "Library versions: %s %s, Xerces-C %s, XMLTooling-C %s, Shibboleth %s",
# if defined(LOG4SHIB_VERSION)
    "log4shib", LOG4SHIB_VERSION,
# elif defined(LOG4CPP_VERSION)
    "log4cpp", LOG4CPP_VERSION,
# else
    "", "",
# endif
        XERCES_FULLVERSIONDOT, gXMLToolingDotVersionStr, gShibSPDotVersionStr
        );

    if (XMLString::equals(e->getNamespaceURI(), shibspconstants::SHIB2SPCONFIG_NS)) {
        SPConfig::getConfig().deprecation().warn("legacy V2 configuration");
        m_deprecationSupport = true;
    }

    // First load any property sets.
    load(e, nullptr, this);

    DOMElement* child;

    // Much of the processing can only occur on the first instantiation.
    if (first) {
        // Set clock skew.
        pair<bool,unsigned int> skew=getUnsignedInt("clockSkew");
        if (skew.first)
            xmlConf.clock_skew_secs=min(skew.second,(60*60*24*7*28));

        pair<bool,const char*> unsafe = getString("unsafeChars");
        if (unsafe.first)
            TemplateEngine::unsafe_chars = unsafe.second;

        unsafe = getString("allowedSchemes");
        if (unsafe.first) {
            HTTPResponse::getAllowedSchemes().clear();
            string schemes(unsafe.second);
            trim(schemes);
            split(HTTPResponse::getAllowedSchemes(), schemes, is_space(), algorithm::token_compress_on);
        }

        // Extensions
        doExtensions(e, "global", log);
        if (conf.isEnabled(SPConfig::OutOfProcess))
            doExtensions(SHAR, "out of process", log);

        if (conf.isEnabled(SPConfig::InProcess))
            doExtensions(SHIRE, "in process", log);

        // Instantiate the ListenerService and SessionCache objects.
        if (conf.isEnabled(SPConfig::Listener))
            doListener(e, outer, log);

        if (conf.isEnabled(SPConfig::Caching))
            doCaching(e, outer, log);
    } // end of first-time-only stuff

    // Back to the fully dynamic stuff...next up is the RequestMapper.
    if (conf.isEnabled(SPConfig::RequestMapping)) {
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
    }

    // Load the default application.
    child = XMLHelper::getLastChildElement(e, ApplicationDefaults);
    if (!child) {
        log.crit("can't build default Application object, missing conf:ApplicationDefaults element?");
        throw ConfigurationException("can't build default Application object, missing conf:ApplicationDefaults element?");
    }
    boost::shared_ptr<XMLApplication> defapp(new XMLApplication(outer, child, m_deprecationSupport));
    m_appmap[defapp->getId()] = defapp;
    m_defaultApplication = defapp.get();

    // Load any overrides.
    DOMElement* override = XMLHelper::getFirstChildElement(child, ApplicationOverride);
    while (override) {
        boost::shared_ptr<XMLApplication> iapp(new XMLApplication(outer, override, m_deprecationSupport, m_defaultApplication));
        if (m_appmap.count(iapp->getId()))
            log.crit("found conf:ApplicationOverride element with duplicate id attribute (%s), skipping it", iapp->getId());
        else
            m_appmap[iapp->getId()] = iapp;

        override = XMLHelper::getNextSiblingElement(override, ApplicationOverride);
    }

    // Save off any external override paths.
    override = XMLHelper::getFirstChildElement(child, ExternalApplicationOverrides);
    while (override) {
        string extoverridepath(XMLHelper::getAttrString(override, nullptr, _path));
        AgentConfig::getConfig().getPathResolver().resolve(extoverridepath, PathResolver::SHIBSP_CFG_FILE);
        if (!extoverridepath.empty()) {
            log.info("adding external ApplicationOverride search path: %s", extoverridepath.c_str());
            m_externalAppPaths.push_back(extoverridepath);
        }

        override = XMLHelper::getNextSiblingElement(override, ExternalApplicationOverrides);
    }

    if (!m_externalAppPaths.empty())
        m_appMapLock.reset(Mutex::create());

    // Check for extra AuthTypes to recognize.
    if (conf.isEnabled(SPConfig::InProcess)) {
        const PropertySet* inprocs = getPropertySet("InProcess");
        if (inprocs) {
            pair<bool,const char*> extraAuthTypes = inprocs->getString("extraAuthTypes");
            if (extraAuthTypes.first) {
                string types(extraAuthTypes.second);
                trim(types);
                split(outer->m_authTypes, types, is_space(), algorithm::token_compress_on);
                outer->m_authTypes.insert("shibboleth");
            }
        }
    }
    */
}

void DefaultAgent::doExtensions(const ptree& pt)
{
    /*
    const DOMElement* exts = XMLHelper::getFirstChildElement(e, _Extensions);
    if (exts) {
        exts = XMLHelper::getFirstChildElement(exts, Library);
        while (exts) {
            string path(XMLHelper::getAttrString(exts, nullptr, _path));
            try {
                if (!path.empty()) {
                    if (!XMLToolingConfig::getConfig().load_library(path.c_str(), (void*)exts))
                        throw ConfigurationException("XMLToolingConfig::load_library failed.");
                    log.debug("loaded %s extension library (%s)", label, path.c_str());
                }
            }
            catch (const std::exception& e) {
                if (XMLHelper::getAttrBool(exts, false, _fatal)) {
                    log.crit("unable to load mandatory %s extension library %s: %s", label, path.c_str(), e.what());
                    throw;
                }
                else {
                    log.crit("unable to load optional %s extension library %s: %s", label, path.c_str(), e.what());
                }
            }
            exts = XMLHelper::getNextSiblingElement(exts, Library);
        }
    }
    */
}

/*
void XMLConfigImpl::doListener(const DOMElement* e, XMLConfig* conf, Category& log)
{
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
}

void XMLConfigImpl::doCaching(const DOMElement* e, XMLConfig* conf, Category& log)
{
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
}
*/
