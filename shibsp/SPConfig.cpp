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
 * SPConfig.cpp
 *
 * Library configuration.
 */

#include "internal.h"

#if defined(XMLTOOLING_LOG4SHIB)
# ifndef SHIBSP_LOG4SHIB
#  error "Logging library mismatch (XMLTooling is using log4shib)."
# endif
#elif defined(XMLTOOLING_LOG4CPP)
# ifndef SHIBSP_LOG4CPP
#  error "Logging library mismatch (XMLTooling is using log4cpp)."
# endif
#else
# error "No supported logging library."
#endif

#include "exceptions.h"
#include "version.h"
#include "AccessControl.h"
#include "RequestMapper.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "attribute/Attribute.h"
#include "handler/LogoutInitiator.h"
#include "handler/SessionInitiator.h"
#include "remoting/ListenerService.h"

#include <ctime>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/version.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeExtractionException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeFilteringException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);

#ifdef SHIBSP_LITE
DECL_XMLTOOLING_EXCEPTION_FACTORY(BindingException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
#endif

namespace shibsp {
    class SHIBSP_DLLLOCAL SPInternalConfig : public SPConfig
    {
    public:
        SPInternalConfig() : m_initCount(0), m_lock(Mutex::create()) {}
        ~SPInternalConfig() {}

        bool init(const char* catalog_path=nullptr, const char* inst_prefix=nullptr);
        void term();

    private:
        int m_initCount;
        scoped_ptr<Mutex> m_lock;
    };
    
    SPInternalConfig g_config;
}

SPConfig& SPConfig::getConfig()
{
    return g_config;
}

SPConfig::SPConfig() : attribute_value_delimeter(';'), m_serviceProvider(nullptr), m_features(0), m_configDoc(nullptr)
{
}

SPConfig::~SPConfig()
{
}

void SPConfig::setFeatures(unsigned long enabled)
{
    m_features = enabled;
}

unsigned long SPConfig::getFeatures() const {
    return m_features;
}

bool SPConfig::isEnabled(components_t feature) const
{
    return (m_features & feature)>0;
}

ServiceProvider* SPConfig::getServiceProvider() const
{
    return m_serviceProvider;
}

void SPConfig::setServiceProvider(ServiceProvider* serviceProvider)
{
    delete m_serviceProvider;
    m_serviceProvider = serviceProvider;
}

bool SPConfig::init(const char* catalog_path, const char* inst_prefix)
{
    if (!inst_prefix)
        inst_prefix = getenv("SHIBSP_PREFIX");
    if (!inst_prefix)
        inst_prefix = SHIBSP_PREFIX;
    std::string inst_prefix2;
    while (*inst_prefix) {
        inst_prefix2.push_back((*inst_prefix=='\\') ? ('/') : (*inst_prefix));
        ++inst_prefix;
    }

    const char* logconf = getenv("SHIBSP_LOGGING");
    if (!logconf || !*logconf) {
        if (isEnabled(SPConfig::Logging) && isEnabled(SPConfig::OutOfProcess) && !isEnabled(SPConfig::InProcess))
            logconf = SHIBSP_OUTOFPROC_LOGGING;
        else if (isEnabled(SPConfig::Logging) && isEnabled(SPConfig::InProcess) && !isEnabled(SPConfig::OutOfProcess))
            logconf = SHIBSP_INPROC_LOGGING;
        else
            logconf = SHIBSP_LOGGING;
    }
    PathResolver localpr;
    localpr.setDefaultPrefix(inst_prefix2.c_str());
    inst_prefix = getenv("SHIBSP_CFGDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_CFGDIR;
    localpr.setCfgDir(inst_prefix);
    std::string lc(logconf);
    XMLToolingConfig::getConfig().log_config(localpr.resolve(lc, PathResolver::XMLTOOLING_CFG_FILE, PACKAGE_NAME).c_str());

    Category& log=Category::getInstance(SHIBSP_LOGCAT ".Config");
    log.debug("%s library initialization started", PACKAGE_STRING);

    XMLToolingConfig::getConfig().user_agent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION;

    PathResolver* pr = XMLToolingConfig::getConfig().getPathResolver();
    pr->setDefaultPackageName(PACKAGE_NAME);
    pr->setDefaultPrefix(inst_prefix2.c_str());
    pr->setCfgDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_LIBDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_LIBDIR;
    pr->setLibDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_LOGDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_LOGDIR;
    pr->setLogDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_RUNDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_RUNDIR;
    pr->setRunDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_CACHEDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_CACHEDIR;
    pr->setCacheDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_XMLDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_XMLDIR;
    pr->setXMLDir(inst_prefix);

    if (!catalog_path)
        catalog_path = getenv("SHIBSP_SCHEMAS");
    if (!catalog_path || !*catalog_path)
        catalog_path = SHIBSP_SCHEMAS;
    if (!XMLToolingConfig::getConfig().getValidatingParser().loadCatalogs(catalog_path)) {
        log.warn("failed to load schema catalogs into validating parser");
    }

    XMLToolingConfig::getConfig().setTemplateEngine(new TemplateEngine());
    XMLToolingConfig::getConfig().getTemplateEngine()->setTagPrefix("shibmlp");

    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeExtractionException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeFilteringException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);

#ifdef SHIBSP_LITE
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(BindingException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
#endif

    registerAttributeFactories();

    if (isEnabled(Handlers)) {
        registerHandlers();
        registerLogoutInitiators();
        registerSessionInitiators();
    }

    registerServiceProviders();

    if (isEnabled(Listener))
        registerListenerServices();

    if (isEnabled(RequestMapping)) {
        registerAccessControls();
        registerRequestMappers();
    }

    if (isEnabled(Caching))
        registerSessionCaches();

    // Yes, this isn't insecure, will review where we do any random generation
    // after full code cleanup is done.
    srand(static_cast<unsigned int>(std::time(nullptr)));

    log.info("%s library initialization complete", PACKAGE_STRING);
    return true;
}

void SPConfig::term()
{
    Category& log=Category::getInstance(SHIBSP_LOGCAT ".Config");
    log.info("%s library shutting down", PACKAGE_STRING);

    setServiceProvider(nullptr);
    if (m_configDoc)
        m_configDoc->release();
    m_configDoc = nullptr;

    if (isEnabled(Handlers)) {
        AssertionConsumerServiceManager.deregisterFactories();
        LogoutInitiatorManager.deregisterFactories();
        SessionInitiatorManager.deregisterFactories();
        SingleLogoutServiceManager.deregisterFactories();
        HandlerManager.deregisterFactories();
    }

    ServiceProviderManager.deregisterFactories();
    Attribute::deregisterFactories();

    if (isEnabled(Listener))
        ListenerServiceManager.deregisterFactories();

    if (isEnabled(RequestMapping)) {
        AccessControlManager.deregisterFactories();
        RequestMapperManager.deregisterFactories();
    }

    if (isEnabled(Caching))
        SessionCacheManager.deregisterFactories();

    log.info("%s library shutdown complete", PACKAGE_STRING);
}

bool SPConfig::instantiate(const char* config, bool rethrow)
{
    if (!config)
        config = getenv("SHIBSP_CONFIG");
    if (!config) {
        config = SHIBSP_CONFIG;
    }
    try {
        xercesc::DOMDocument* dummydoc;
        if (*config == '"' || *config == '\'') {
            throw ConfigurationException("The value of SHIBSP_CONFIG started with a quote.");
        }
        else if (*config != '<') {
            // Mock up some XML.
            string resolved(config);
            stringstream snippet;
            snippet
                << "<Dummy path='"
                << XMLToolingConfig::getConfig().getPathResolver()->resolve(resolved, PathResolver::XMLTOOLING_CFG_FILE)
                << "' validate='1'/>";
            dummydoc = XMLToolingConfig::getConfig().getParser().parse(snippet);
            XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
            setServiceProvider(ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER, dummydoc->getDocumentElement(), true));
            if (m_configDoc)
                m_configDoc->release();
            m_configDoc = docjanitor.release();
        }
        else {
            stringstream snippet(config);
            dummydoc = XMLToolingConfig::getConfig().getParser().parse(snippet);
            XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
            static const XMLCh _type[] = UNICODE_LITERAL_4(t,y,p,e);
            auto_ptr_char type(dummydoc->getDocumentElement()->getAttributeNS(nullptr,_type));
            if (type.get() && *type.get())
                setServiceProvider(ServiceProviderManager.newPlugin(type.get(), dummydoc->getDocumentElement(), true));
            else
                throw ConfigurationException("The supplied XML bootstrapping configuration did not include a type attribute.");
            if (m_configDoc)
                m_configDoc->release();
            m_configDoc = docjanitor.release();
        }

        getServiceProvider()->init();
        return true;
    }
    catch (const std::exception& ex) {
        if (rethrow) {
            throw;
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT ".Config").fatal("caught exception while loading configuration: %s", ex.what());
        }
    }
    return false;
}

bool SPInternalConfig::init(const char* catalog_path, const char* inst_prefix)
{
    Lock initLock(m_lock);

    if (m_initCount == INT_MAX) {
        Category::getInstance(SHIBSP_LOGCAT ".Config").crit("library initialized too many times");
        return false;
    }

    if (m_initCount >= 1) {
        ++m_initCount;
        return true;
    }

    if (!SPConfig::init(catalog_path, inst_prefix)) {
        return false;
    }

    ++m_initCount;
    return true;
}

void SPInternalConfig::term()
{
    Lock initLock(m_lock);
    if (m_initCount == 0) {
        Category::getInstance(SHIBSP_LOGCAT ".Config").crit("term without corresponding init");
        return;
    }
    else if (--m_initCount > 0) {
        return;
    }

    SPConfig::term();
}

Category& SPConfig::deprecation() const
{
    return Category::getInstance(SHIBSP_LOGCAT".DEPRECATION");
}
