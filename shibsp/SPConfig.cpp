
/*
 *  Copyright 2001-2007 Internet2
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

/**
 * SPConfig.cpp
 * 
 * Library configuration 
 */

#include "internal.h"
#include "AccessControl.h"
#include "exceptions.h"
#include "RequestMapper.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/resolver/AttributeResolver.h"
#include "handler/Handler.h"
#include "metadata/MetadataExt.h"
#include "remoting/ListenerService.h"
#include "security/PKIXTrustEngine.h"

#include <log4cpp/Category.hh>
#include <saml/SAMLConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;

DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);

namespace shibsp {
   SPInternalConfig g_config;
}

SPConfig& SPConfig::getConfig()
{
    return g_config;
}

SPInternalConfig& SPInternalConfig::getInternalConfig()
{
    return g_config;
}

void SPConfig::setServiceProvider(ServiceProvider* serviceProvider)
{
    delete m_serviceProvider;
    m_serviceProvider = serviceProvider;
}

bool SPInternalConfig::init(const char* catalog_path)
{
#ifdef _DEBUG
    NDC ndc("init");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".Config");
    log.debug("library initialization started");

    const char* loglevel=getenv("SHIBSP_LOGGING");
    if (!loglevel)
        loglevel = SHIBSP_LOGGING;
    XMLToolingConfig::getConfig().log_config(loglevel);

    if (!catalog_path)
        catalog_path = getenv("SHIBSP_SCHEMAS");
    if (!catalog_path)
        catalog_path = SHIBSP_SCHEMAS;
    XMLToolingConfig::getConfig().catalog_path = catalog_path;

    if (!SAMLConfig::getConfig().init()) {
        log.fatal("failed to initialize OpenSAML library");
        return false;
    }

    XMLToolingConfig::getConfig().setTemplateEngine(new TemplateEngine());
    XMLToolingConfig::getConfig().getTemplateEngine()->setTagPrefix("shibmlp");
    
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);
    
    registerMetadataExtClasses();
    registerPKIXTrustEngine();

    registerAccessControls();
    registerAttributeDecoders();
    registerAttributeFactories();
    registerAttributeResolvers();
    registerListenerServices();
    registerRequestMappers();
    registerSessionCaches();
    registerServiceProviders();
    
    log.info("library initialization complete");
    return true;
}

void SPInternalConfig::term()
{
#ifdef _DEBUG
    NDC ndc("term");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".Config");
    log.info("shutting down the library");

    delete m_serviceProvider;
    m_serviceProvider = NULL;

    AssertionConsumerServiceManager.deregisterFactories();
    ManageNameIDServiceManager.deregisterFactories();
    SessionInitiatorManager.deregisterFactories();
    SingleLogoutServiceManager.deregisterFactories();
    
    ServiceProviderManager.deregisterFactories();
    SessionCacheManager.deregisterFactories();
    RequestMapperManager.deregisterFactories();
    ListenerServiceManager.deregisterFactories();
    HandlerManager.deregisterFactories();
    AttributeResolverManager.deregisterFactories();
    AttributeDecoderManager.deregisterFactories();
    Attribute::deregisterFactories();
    AccessControlManager.deregisterFactories();

    SAMLConfig::getConfig().term();
    log.info("library shutdown complete");
}
