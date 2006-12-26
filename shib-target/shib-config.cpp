/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * shib-config.cpp -- ShibTarget initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"
#include <saml/util/SAMLConstants.h>
#include <shibsp/SPConfig.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>

#include <log4cpp/OstreamAppender.hh>

using namespace shibsp;
using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

using xmltooling::XMLToolingConfig;

namespace {
    STConfig g_Config;
}

// Factories for built-in plugins we can manufacture. Actual definitions
// will be with the actual object implementation.
#ifndef WIN32
PlugManager::Factory UnixListenerFactory;
#endif
PlugManager::Factory TCPListenerFactory;
//PlugManager::Factory MemoryListenerFactory;
PlugManager::Factory MemoryCacheFactory;
PlugManager::Factory XMLRequestMapFactory;
PlugManager::Factory ShibSessionInitiatorFactory;
PlugManager::Factory SAML1POSTFactory;
PlugManager::Factory SAML1ArtifactFactory;
PlugManager::Factory ShibLogoutFactory;
//PlugManager::Factory htaccessFactory;

SAML_EXCEPTION_FACTORY(ListenerException);
SAML_EXCEPTION_FACTORY(ConfigurationException);

ShibTargetConfig& ShibTargetConfig::getConfig()
{
    return g_Config;
}

bool STConfig::init(const char* schemadir)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log = Category::getInstance("shibtarget.Config");

    if (!schemadir) {
        log.fatal("XML schema directory not supplied");
        return false;
    }

    // This will cause some extra console logging, but for now,
    // initialize the underlying libraries.
    SAMLConfig& samlConf=SAMLConfig::getConfig();
    if (schemadir)
        samlConf.schema_dir = schemadir;
    if (!samlConf.init() || !SPConfig::getConfig().init(NULL)) {
        log.fatal("failed to initialize SP library");
        return false;
    }

    ShibConfig& shibConf=ShibConfig::getConfig();
    if (!shibConf.init()) {
        log.fatal("Failed to initialize Shib library");
        samlConf.term();
        return false;
    }

    // Register built-in plugin types.
    REGISTER_EXCEPTION_FACTORY(ListenerException);
    REGISTER_EXCEPTION_FACTORY(ConfigurationException);

    samlConf.getPlugMgr().regFactory(shibtarget::XML::MemorySessionCacheType,&MemoryCacheFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::LegacyRequestMapType,&XMLRequestMapFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::XMLRequestMapType,&XMLRequestMapFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::NativeRequestMapType,&XMLRequestMapFactory);
    
    auto_ptr_char temp1(Constants::SHIB_SESSIONINIT_PROFILE_URI);
    samlConf.getPlugMgr().regFactory(temp1.get(),&ShibSessionInitiatorFactory);
    samlConf.getPlugMgr().regFactory(samlconstants::SAML1_PROFILE_BROWSER_POST,&SAML1POSTFactory);
    samlConf.getPlugMgr().regFactory(samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT,&SAML1ArtifactFactory);
    auto_ptr_char temp4(Constants::SHIB_LOGOUT_PROFILE_URI);
    samlConf.getPlugMgr().regFactory(temp4.get(),&ShibLogoutFactory);
    
    saml::XML::registerSchema(shibtarget::XML::SHIBTARGET_NS,shibtarget::XML::SHIBTARGET_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(samlconstants::SAML20MD_NS,shibtarget::XML::SAML2META_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(samlconstants::SAML20_NS,shibtarget::XML::SAML2ASSERT_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(xmlconstants::XMLENC_NS,shibtarget::XML::XMLENC_SCHEMA_ID,NULL,false);
    
    log.info("finished initializing");
    return true;
}

bool STConfig::load(const char* config)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("load");
#endif
    Category& log = Category::getInstance("shibtarget.Config");

    if (!config) {
        log.fatal("path to configuration file not supplied");
        shutdown();
        return false;
    }

    try {
        log.info("loading configuration file: %s", config);
        static const XMLCh uri[] = { chLatin_u, chLatin_r, chLatin_i, chNull };
        DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(NULL);
        DOMDocument* dummydoc=impl->createDocument();
        DOMElement* dummy = dummydoc->createElementNS(NULL,XML::Literals::ShibbolethTargetConfig);
        auto_ptr_XMLCh src(config);
        dummy->setAttributeNS(NULL,uri,src.get());
        m_ini=ShibTargetConfigFactory(dummy);
        dummydoc->release();
        m_ini->init();
        
        pair<bool,unsigned int> skew=m_ini->getUnsignedInt("clockSkew");
        SAMLConfig::getConfig().clock_skew_secs=skew.first ? skew.second : 180;
        if (skew.first)
            XMLToolingConfig::getConfig().clock_skew_secs=skew.second;
        
        m_tranLog=new FixedContextCategory(SHIBTRAN_LOGCAT);
        m_tranLog->info("opened transaction log");
        m_tranLogLock = xmltooling::Mutex::create();
    }
    catch (SAMLException& ex) {
        log.fatal("caught exception while loading/initializing configuration: %s",ex.what());
        shutdown();
        return false;
    }
#ifndef _DEBUG
    catch (...) {
        log.fatal("caught exception while loading/initializing configuration");
        shutdown();
        return false;
    }
#endif

    log.info("finished loading configuration");
    return true;
}

void STConfig::shutdown()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("shutdown");
#endif
    Category& log = Category::getInstance("shibtarget.Config");
    log.info("shutting down the library");
    delete m_tranLogLock;
    m_tranLogLock = NULL;
    //delete m_tranLog; // This is crashing for some reason, but we're shutting down anyway.
    delete m_ini;
    m_ini = NULL;
    ShibConfig::getConfig().term();
    SAMLConfig::getConfig().term();
    SPConfig::getConfig().term();
    log.info("library shutdown complete");
}
