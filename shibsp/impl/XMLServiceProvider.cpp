/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * XMLServiceProvider.cpp
 *
 * XML-based SP configuration and mgmt.
 */

#include "internal.h"
#include "version.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "SPRequest.h"
#include "impl/XMLApplication.h"
#include "impl/XMLServiceProvider.h"
#include "util/PathResolver.h"
#include "util/SPConstants.h"

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/tuple/tuple.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/version.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

#ifndef min
# define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

namespace {

    static const XMLCh applicationId[] =        UNICODE_LITERAL_13(a,p,p,l,i,c,a,t,i,o,n,I,d);
    static const XMLCh ApplicationDefaults[] =  UNICODE_LITERAL_19(A,p,p,l,i,c,a,t,i,o,n,D,e,f,a,u,l,t,s);
    static const XMLCh ApplicationOverride[] =  UNICODE_LITERAL_19(A,p,p,l,i,c,a,t,i,o,n,O,v,e,r,r,i,d,e);
    static const XMLCh _ArtifactMap[] =         UNICODE_LITERAL_11(A,r,t,i,f,a,c,t,M,a,p);
    static const XMLCh _DataSealer[] =          UNICODE_LITERAL_10(D,a,t,a,S,e,a,l,e,r);
    static const XMLCh _default[] =             UNICODE_LITERAL_7(d,e,f,a,u,l,t);
    static const XMLCh _Extensions[] =          UNICODE_LITERAL_10(E,x,t,e,n,s,i,o,n,s);
    static const XMLCh ExternalApplicationOverrides[] = UNICODE_LITERAL_28(E,x,t,e,r,n,a,l,A,p,p,l,i,c,a,t,i,o,n,O,v,e,r,r,i,d,e,s);
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
};

namespace shibsp {
    ServiceProvider* XMLServiceProviderFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new XMLConfig(e, deprecationSupport);
    }
};

DOMNodeFilter::FilterAction XMLConfigImpl::acceptNode(const DOMNode* node) const
{
    if (!XMLString::equals(node->getNamespaceURI(),shibspconstants::SHIB2SPCONFIG_NS)
            && !XMLString::equals(node->getNamespaceURI(), shibspconstants::SHIB3SPCONFIG_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,ApplicationDefaults) ||
        XMLString::equals(name,_ArtifactMap) ||
        XMLString::equals(name, _DataSealer) ||
        XMLString::equals(name,_Extensions) ||
        XMLString::equals(name,Listener) ||
        XMLString::equals(name,_ProtocolProvider) ||
        XMLString::equals(name,_RequestMapper) ||
        XMLString::equals(name,_ReplayCache) ||
        XMLString::equals(name,SecurityPolicies) ||
        XMLString::equals(name,_SecurityPolicyProvider) ||
        XMLString::equals(name,_SessionCache) ||
        XMLString::equals(name,Site) ||
        XMLString::equals(name,_StorageService) ||
        XMLString::equals(name,TCPListener) ||
        XMLString::equals(name,TransportOption) ||
        XMLString::equals(name,UnixListener))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void XMLConfigImpl::doExtensions(const DOMElement* e, const char* label, Category& log)
{
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
}

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

XMLConfigImpl::XMLConfigImpl(const DOMElement* e, bool first, XMLConfig* outer, Category& log)
    : m_document(nullptr), m_defaultApplication(nullptr), m_deprecationSupport(false)
{
    const SPConfig& conf=SPConfig::getConfig();
    XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
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
}

boost::shared_ptr<Application> XMLConfigImpl::findExternalOverride(const char* id, const XMLConfig* config)
{
    for (vector<string>::const_iterator i = m_externalAppPaths.begin(); i != m_externalAppPaths.end(); ++i) {
        string path(*i);
        if (!ends_with(path, "/"))
            path += '/';
        path = path + id + "-override.xml";
        try {
            ifstream in(path.c_str());
            if (in) {
                DOMDocument* doc = XMLToolingConfig::getConfig().getValidatingParser().parse(in);
                if (!XMLHelper::isNodeNamed(doc->getDocumentElement(), shibspconstants::SHIB3SPCONFIG_NS, ApplicationOverride)) {
                    throw ConfigurationException("External override not rooted in conf:ApplicationOverride element.");
                }

                string id2(XMLHelper::getAttrString(doc->getDocumentElement(), nullptr, _id));
                if (id2 != id)
                    throw ConfigurationException("External override's id ($1) did not match the expected value", params(1, id2.c_str()));

                boost::shared_ptr<XMLApplication> iapp(
                    new XMLApplication(config, doc->getDocumentElement(), m_deprecationSupport, m_defaultApplication, doc)
                    );
                return iapp;
            }
        }
        catch (const std::exception& ex) {
            config->m_log.error("Exception creating ApplicationOverride: %s", ex.what());
        }
    }

    return boost::shared_ptr<XMLApplication>();
}

const Application* XMLConfig::getApplication(const char* applicationId) const
{
    Lock locker(m_impl->m_appMapLock);

    map< string, boost::shared_ptr<Application> >::const_iterator i = m_impl->m_appmap.find(applicationId ? applicationId : "default");
    Application* ret = (i != m_impl->m_appmap.end()) ? i->second.get() : nullptr;

    if (!ret && m_impl->m_appMapLock && applicationId) {
        m_log.info("application override (%s) not found, searching external sources", applicationId);
        boost::shared_ptr<Application> newapp = m_impl->findExternalOverride(applicationId, this);
        if (newapp) {
            m_log.info("storing externally defined application override (%s)", applicationId);
            ret = newapp.get();
            m_impl->m_appmap[applicationId] = newapp;
        }
        else {
            m_log.warn("application override (%s) not found in external sources", applicationId);
        }
    }

    return ret;
}

#ifndef SHIBSP_LITE

void XMLConfig::receive(DDF& in, ostream& out)
{
    if (!strcmp(in.name(), "get::RelayState")) {
        const char* id = in["id"].string();
        const char* key = in["key"].string();
        if (!id || !key)
            throw ListenerException("Required parameters missing for RelayState recovery.");

        string relayState;
        StorageService* storage = getStorageService(id);
        if (storage) {
            if (storage->readString("RelayState",key,&relayState)>0) {
                if (in["clear"].integer())
                    storage->deleteString("RelayState",key);
            }
            else if (storage->readText("RelayState",key,&relayState)>0) {
                if (in["clear"].integer())
                    storage->deleteText("RelayState",key);
            }
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").error(
                "Storage-backed RelayState with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).unsafe_string(relayState.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
    else if (!strcmp(in.name(), "set::RelayState")) {
        const char* id = in["id"].string();
        const char* value = in["value"].string();
        if (!id || !value)
            throw ListenerException("Required parameters missing for RelayState creation.");

        string rsKey;
        StorageService* storage = getStorageService(id);
        if (storage) {
            SAMLConfig::getConfig().generateRandomBytes(rsKey,32);
            rsKey = SAMLArtifact::toHex(rsKey);
            if (strlen(value) <= storage->getCapabilities().getStringSize())
                storage->createString("RelayState", rsKey.c_str(), value, time(nullptr) + 600);
            else
                storage->createText("RelayState", rsKey.c_str(), value, time(nullptr) + 600);
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").error(
                "Storage-backed RelayState with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).string(rsKey.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
    else if (!strcmp(in.name(), "get::PostData")) {
        const char* id = in["id"].string();
        const char* key = in["key"].string();
        if (!id || !key)
            throw ListenerException("Required parameters missing for PostData recovery.");

        string postData;
        StorageService* storage = getStorageService(id);
        if (storage) {
            if (storage->readText("PostData",key,&postData) > 0) {
                storage->deleteText("PostData",key);
            }
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").error(
                "Storage-backed PostData with invalid StorageService ID (%s)", id
                );
        }
        // If the data's empty, we'll send nothing back.
        // If not, we don't need to round trip it, just send back the serialized DDF list.
        if (postData.empty()) {
            DDF ret(nullptr);
            DDFJanitor jret(ret);
            out << ret;
        }
        else {
            out << postData;
        }
    }
    else if (!strcmp(in.name(), "set::PostData")) {
        const char* id = in["id"].string();
        if (!id || !in["parameters"].islist())
            throw ListenerException("Required parameters missing for PostData creation.");

        string rsKey;
        StorageService* storage = getStorageService(id);
        if (storage) {
            SAMLConfig::getConfig().generateRandomBytes(rsKey,32);
            rsKey = SAMLArtifact::toHex(rsKey);
            ostringstream params;
            params << in["parameters"];
            storage->createText("PostData", rsKey.c_str(), params.str().c_str(), time(nullptr) + 600);
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").error(
                "Storage-backed PostData with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).string(rsKey.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
}

#endif

void XMLConfig::regListener(const char* address, Remoted* listener)
{
    m_listenerLock->wrlock();
    SharedLock locker(m_listenerLock, false);

    map< string,pair<Remoted*,Remoted*> >::iterator i = m_listenerMap.find(address);
    if (i != m_listenerMap.end()) {
        if (!i->second.first) {
            // First slot is null. Look for second slot and move up if needed.
            if (i->second.second) {
                i->second.first = i->second.second;
                i->second.second = listener;
                Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").debug("registered second remoted message endpoint (%s)",address);
            }
            else {
                // Both slots null, so put into first slot.
                i->second.first = listener;
                Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").debug("registered remoted message endpoint (%s)",address);
            }
        }
        else if (!i->second.second) {
            // First slot occupied, so put into empty second slot.
            i->second.second = listener;
            Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").debug("registered second remoted message endpoint (%s)",address);
        }
        else {
            // This should never happen...?
            throw ConfigurationException("Attempted to register more than two endpoints for a single listener address.");
        }
    }
    else {
        // Stick it in the first slot.
        m_listenerMap[address] = pair<Remoted*, Remoted*>(listener, nullptr);
        Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").debug("registered remoted message endpoint (%s)",address);
    }
}

bool XMLConfig::unregListener(const char* address, Remoted* current)
{
    m_listenerLock->wrlock();
    SharedLock locker(m_listenerLock, false);

    map< string,pair<Remoted*,Remoted*> >::iterator i = m_listenerMap.find(address);
    if (i != m_listenerMap.end()) {
        if (i->second.first == current) {
            if (i->second.second) {
                // Promote second slot to first.
                i->second.first = i->second.second;
                i->second.second = nullptr;
            }
            else {
                // Remove entirely.
                m_listenerMap.erase(address);
            }
        }
        else if (i->second.second == current) {
            if (!i->second.first)
                m_listenerMap.erase(address);
            else
                i->second.second = nullptr;
        }
        else {
            return false;
        }
        Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider").debug("unregistered remoted message endpoint (%s)", address);
        return true;
    }
    return false;
}

Remoted* XMLConfig::lookupListener(const char* address) const
{
    SharedLock locker(m_listenerLock, true);
    map< string,pair<Remoted*,Remoted*> >::const_iterator i = m_listenerMap.find(address);
    if (i != m_listenerMap.end())
        return i->second.first ? i->second.first : i->second.second;

    locker.release()->unlock();   // free up the listener map

    // Start iterating at slash boundaries.
    const char* slash = strstr(address, "/");
    while (slash) {
        string appId(address, slash - address);
        if (getApplication(appId.c_str())) {
            SharedLock sublocker(m_listenerLock, true); // relock and check again
            i = m_listenerMap.find(address);
            if (i != m_listenerMap.end())
                return i->second.first ? i->second.first : i->second.second;
        }
        slash = strstr(slash + 1, "/");
    }

    // Try a search based on the colons, which handles no embedded slashes in the address.
    const char* colons = strstr(address, "::");
    if (colons) {
        string appId(address, colons - address);
        if (getApplication(appId.c_str())) {
            SharedLock sublocker(m_listenerLock, true); // relock and check again
            i = m_listenerMap.find(address);
            if (i != m_listenerMap.end())
                return i->second.first ? i->second.first : i->second.second;
        }
    }
    return nullptr;
}

XMLConfig::XMLConfig(const DOMElement* e, bool deprecationSupport)
    : ReloadableXMLFile(e, xmltooling::logging::Category::getInstance(SHIBSP_LOGCAT ".Config"), true, deprecationSupport),
        m_listenerLock(RWLock::create())
{
}

XMLConfig::~XMLConfig()
{
    shutdown();
}

pair<bool,DOMElement*> XMLConfig::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    //scoped_ptr<XMLConfigImpl> impl(new XMLConfigImpl(raw.second, (m_impl==nullptr), this, m_log));
    scoped_ptr<XMLConfigImpl> impl(nullptr);

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}
