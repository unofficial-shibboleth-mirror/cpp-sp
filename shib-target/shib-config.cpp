/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-config.cpp -- ShibTarget initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#include <log4cpp/OstreamAppender.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace {
    STConfig g_Config;
}

const XMLCh ShibTargetConfig::SHIBTARGET_NS[] = // urn:mace:shibboleth:target:config:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_t, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t, chColon,
  chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

// Factories for built-in plugins we can manufacture. Actual definitions
// will be with the actual object implementation.
#ifndef WIN32
PlugManager::Factory UnixListenerFactory;
#endif
PlugManager::Factory TCPListenerFactory;
PlugManager::Factory MemoryCacheFactory;
PlugManager::Factory XMLRequestMapFactory;
//PlugManager::Factory htaccessFactory;

ShibTargetConfig& ShibTargetConfig::getConfig()
{
    return g_Config;
}

bool STConfig::init(const char* schemadir, const char* config)
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
 
    saml::NDC ndc("init");
    Category& log = Category::getInstance("shibtarget.STConfig");

    if (!schemadir || !config) {
        log.fatal("schema directory or config file not supplied");
        return false;
    }

    // This will cause some extra console logging, but for now,
    // initialize the underlying libraries.
    SAMLConfig& samlConf=SAMLConfig::getConfig();
    if (schemadir)
        samlConf.schema_dir = schemadir;
    SAMLSOAPBinding::version=string("Shibboleth: ") + PACKAGE_VERSION;
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

#ifndef _DEBUG
    try {
#endif
        // Register plugin types.
#ifndef WIN32
        samlConf.m_plugMgr.regFactory(shibtarget::XML::UnixListenerType,&UnixListenerFactory);
#endif
        samlConf.m_plugMgr.regFactory(shibtarget::XML::TCPListenerType,&TCPListenerFactory);
        samlConf.m_plugMgr.regFactory(shibtarget::XML::MemorySessionCacheType,&MemoryCacheFactory);
        samlConf.m_plugMgr.regFactory(shibtarget::XML::RequestMapType,&XMLRequestMapFactory);
        //shibConf.m_plugMgr.regFactory(shibtarget::XML::htaccessType,&htaccessFactory);
        saml::XML::registerSchema(ShibTargetConfig::SHIBTARGET_NS,shibtarget::XML::SHIBTARGET_SCHEMA_ID);
        
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
        samlConf.clock_skew_secs=skew.first ? skew.second : 180;
        
        m_tranLog=new FixedContextCategory(SHIBTRAN_LOGCAT);
        m_tranLog->info("opened transaction log");
        m_tranLogLock = Mutex::create();

        m_rpcpool = new RPCHandlePool;
#ifndef _DEBUG
    }
    catch (...) {
        log.fatal("caught exception while loading/initializing configuration");
        delete m_ini;
        delete m_rpcpool;
        shibConf.term();
        samlConf.term();
        return false;
    }
#endif
  
    log.info("finished initializing");

    return true;
}

void STConfig::shutdown()
{
    saml::NDC ndc("shutdown");
    Category& log = Category::getInstance("shibtarget.STConfig");
    log.info("shutting down the library");
    delete m_rpcpool;
    m_rpcpool = NULL;
    delete m_tranLogLock;
    m_tranLogLock = NULL;
    //delete m_tranLog; // This is crashing for some reason, but we're shutting down anyway.
    delete m_ini;
    m_ini = NULL;
    ShibConfig::getConfig().term();
    SAMLConfig::getConfig().term();
    log.info("library shutdown complete");
}
