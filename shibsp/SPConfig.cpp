
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

#include "AccessControl.h"
#include "exceptions.h"
#include "RequestMapper.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "attribute/Attribute.h"
#include "handler/SessionInitiator.h"
#include "remoting/ListenerService.h"

#ifndef SHIBSP_LITE
# include "attribute/AttributeDecoder.h"
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/filtering/MatchFunctor.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "binding/ArtifactResolver.h"
# include "metadata/MetadataExt.h"
# include "security/PKIXTrustEngine.h"
# include <saml/SAMLConfig.h>
#else
# include <xmltooling/XMLToolingConfig.h>
#endif

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;

DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeExtractionException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeFilteringException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);

#ifdef SHIBSP_LITE
DECL_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
DECL_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
DECL_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);
#endif

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

#ifndef SHIBSP_LITE
    if (!SAMLConfig::getConfig().init()) {
        log.fatal("failed to initialize OpenSAML library");
        return false;
    }
#else
    if (!XMLToolingConfig::getConfig().init()) {
        log.fatal("failed to initialize XMLTooling library");
        return false;
    }
#endif

    XMLToolingConfig::getConfig().setTemplateEngine(new TemplateEngine());
    XMLToolingConfig::getConfig().getTemplateEngine()->setTagPrefix("shibmlp");
    
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeExtractionException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeFilteringException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(AttributeResolutionException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ConfigurationException,shibsp);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ListenerException,shibsp);

#ifdef SHIBSP_LITE
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(SecurityPolicyException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(ProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(FatalProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(RetryableProfileException,opensaml);
    REGISTER_XMLTOOLING_EXCEPTION_FACTORY(MetadataException,opensaml::saml2md);
#endif

#ifndef SHIBSP_LITE
    if (isEnabled(Metadata))
        registerMetadataExtClasses();
    if (isEnabled(Trust))
        registerPKIXTrustEngine();
#endif

    registerAttributeFactories();
    registerHandlers();
    registerSessionInitiators();
    registerServiceProviders();

#ifndef SHIBSP_LITE
    if (isEnabled(AttributeResolution)) {
        registerAttributeExtractors();
        registerAttributeDecoders();
        registerAttributeResolvers();
        registerAttributeFilters();
        registerMatchFunctors();
    }
#endif

    if (isEnabled(Listener))
        registerListenerServices();

    if (isEnabled(RequestMapping)) {
        registerAccessControls();
        registerRequestMappers();
    }

    if (isEnabled(Caching))
        registerSessionCaches();

#ifndef SHIBSP_LITE
    if (isEnabled(OutOfProcess))
        m_artifactResolver = new ArtifactResolver();
#endif

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

    setServiceProvider(NULL);
#ifndef SHIBSP_LITE
    setArtifactResolver(NULL);
#endif

    ArtifactResolutionServiceManager.deregisterFactories();
    AssertionConsumerServiceManager.deregisterFactories();
    LogoutInitiatorManager.deregisterFactories();
    ManageNameIDServiceManager.deregisterFactories();
    SessionInitiatorManager.deregisterFactories();
    SingleLogoutServiceManager.deregisterFactories();
    HandlerManager.deregisterFactories();
    ServiceProviderManager.deregisterFactories();
    Attribute::deregisterFactories();

#ifndef SHIBSP_LITE
    if (isEnabled(AttributeResolution)) {
        MatchFunctorManager.deregisterFactories();
        AttributeFilterManager.deregisterFactories();
        AttributeDecoderManager.deregisterFactories();
        AttributeExtractorManager.deregisterFactories();
        AttributeResolverManager.deregisterFactories();
    }
#endif

    if (isEnabled(Listener))
        ListenerServiceManager.deregisterFactories();

    if (isEnabled(RequestMapping)) {
        AccessControlManager.deregisterFactories();
        RequestMapperManager.deregisterFactories();
    }

    if (isEnabled(Caching))
        SessionCacheManager.deregisterFactories();

#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().term();
#else
    XMLToolingConfig::getConfig().term();
#endif
    log.info("library shutdown complete");
}
