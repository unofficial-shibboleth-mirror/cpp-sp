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

#include <ctime>
#include <sstream>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/version.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

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

    Category& log=Category::getInstance(SHIBSP_LOGCAT ".Config");
    log.debug("%s library initialization started", PACKAGE_STRING);

    XMLToolingConfig::getConfig().user_agent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION;

    if (!catalog_path)
        catalog_path = getenv("SHIBSP_SCHEMAS");
    if (!catalog_path || !*catalog_path)
        catalog_path = SHIBSP_SCHEMAS;
    if (!XMLToolingConfig::getConfig().getValidatingParser().loadCatalogs(catalog_path)) {
        log.warn("failed to load schema catalogs into validating parser");
    }

    registerAttributeFactories();

    if (isEnabled(Handlers)) {
        registerHandlers();
    }

    registerServiceProviders();

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
                << resolved
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
            Category::getInstance(SHIBSP_LOGCAT ".Config").crit("caught exception while loading configuration: %s", ex.what());
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
