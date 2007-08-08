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

#if defined(HAVE_LOG4SHIB)
# include <log4shib/OstreamAppender.hh>
#elif defined(HAVE_LOG4CPP)
# include <log4cpp/OstreamAppender.hh>
#else
# error "Supported logging library not available."
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace shibtarget::logging;

namespace {
    STConfig g_Config;
}

// Factories for built-in plugins we can manufacture. Actual definitions
// will be with the actual object implementation.
#ifndef WIN32
PlugManager::Factory UnixListenerFactory;
#endif
PlugManager::Factory TCPListenerFactory;
PlugManager::Factory MemoryListenerFactory;
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
    // With new build of log4cpp, we need to establish a "default"
    // logging appender to stderr up front.
    const char* loglevel=getenv("SHIB_LOGGING");
    if (!loglevel)
        loglevel = SHIB_LOGGING;    
    Category& root = Category::getRoot();
    if (!strcmp(loglevel,"DEBUG"))
        root.setPriority(Priority::DEBUG);
    else if (!strcmp(loglevel,"INFO"))
        root.setPriority(Priority::INFO);
    else if (!strcmp(loglevel,"NOTICE"))
        root.setPriority(Priority::NOTICE);
    else if (!strcmp(loglevel,"WARN"))
        root.setPriority(Priority::WARN);
    else if (!strcmp(loglevel,"ERROR"))
        root.setPriority(Priority::ERROR);
    else if (!strcmp(loglevel,"CRIT"))
        root.setPriority(Priority::CRIT);
    else if (!strcmp(loglevel,"ALERT"))
        root.setPriority(Priority::ALERT);
    else if (!strcmp(loglevel,"EMERG"))
        root.setPriority(Priority::EMERG);
    else if (!strcmp(loglevel,"FATAL"))
        root.setPriority(Priority::FATAL);
    root.setAppender(new OstreamAppender("default",&cerr));
 
#ifdef _DEBUG
    saml::NDC ndc("init");
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
    try {
        if (!samlConf.init()) {
            log.fatal("Failed to initialize SAML Library");
            return false;
        }
    }
    catch (...) {
        log.fatal("Died initializing SAML Library");
        return false;
    }
    
    ShibConfig& shibConf=ShibConfig::getConfig();
    try { 
        if (!shibConf.init()) {
            log.fatal("Failed to initialize Shib library");
            samlConf.term();
            return false;
        }
    }
    catch (...) {
        log.fatal("Died initializing Shib library.");
        samlConf.term();
        return false;
    }

    // Register built-in plugin types.
    REGISTER_EXCEPTION_FACTORY(ListenerException);
    REGISTER_EXCEPTION_FACTORY(ConfigurationException);
#ifndef WIN32
    samlConf.getPlugMgr().regFactory(shibtarget::XML::UnixListenerType,&UnixListenerFactory);
#endif
    samlConf.getPlugMgr().regFactory(shibtarget::XML::TCPListenerType,&TCPListenerFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::MemoryListenerType,&MemoryListenerFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::MemorySessionCacheType,&MemoryCacheFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::LegacyRequestMapType,&XMLRequestMapFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::XMLRequestMapType,&XMLRequestMapFactory);
    samlConf.getPlugMgr().regFactory(shibtarget::XML::NativeRequestMapType,&XMLRequestMapFactory);
    
    auto_ptr_char temp1(Constants::SHIB_SESSIONINIT_PROFILE_URI);
    samlConf.getPlugMgr().regFactory(temp1.get(),&ShibSessionInitiatorFactory);
    auto_ptr_char temp2(SAMLBrowserProfile::BROWSER_POST);
    samlConf.getPlugMgr().regFactory(temp2.get(),&SAML1POSTFactory);
    auto_ptr_char temp3(SAMLBrowserProfile::BROWSER_ARTIFACT);
    samlConf.getPlugMgr().regFactory(temp3.get(),&SAML1ArtifactFactory);
    auto_ptr_char temp4(Constants::SHIB_LOGOUT_PROFILE_URI);
    samlConf.getPlugMgr().regFactory(temp4.get(),&ShibLogoutFactory);
    
    saml::XML::registerSchema(shibtarget::XML::SHIBTARGET_NS,shibtarget::XML::SHIBTARGET_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(shibtarget::XML::SAML2META_NS,shibtarget::XML::SAML2META_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(shibtarget::XML::SAML2ASSERT_NS,shibtarget::XML::SAML2ASSERT_SCHEMA_ID,NULL,false);
    saml::XML::registerSchema(shibtarget::XML::XMLENC_NS,shibtarget::XML::XMLENC_SCHEMA_ID,NULL,false);
    
    log.info("finished initializing");
    return true;
}

bool STConfig::load(const char* config)
{
#ifdef _DEBUG
    saml::NDC ndc("load");
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
        
        pair<bool,unsigned int> skew=m_ini->getUnsignedInt("clockSkew");
        SAMLConfig::getConfig().clock_skew_secs=skew.first ? skew.second : 180;
        
        m_tranLog=new FixedContextCategory(SHIBTRAN_LOGCAT);
        m_tranLog->info("opened transaction log");
        m_tranLogLock = Mutex::create();
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
    saml::NDC ndc("shutdown");
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
    log.info("library shutdown complete");
}
