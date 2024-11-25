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
 * AgentConfig.cpp
 *
 * Library/agent configuration.
 */

#include "internal.h"

#include "exceptions.h"
#include "version.h"
#include "AgentConfig.h"
#include "logging/LoggingService.h"
#include "util/PathResolver.h"

#include <ctime>
#include <thread>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost::property_tree;
using namespace boost;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL AgentInternalConfig : public AgentConfig
    {
    public:
        AgentInternalConfig() : m_initCount(0) {}
        ~AgentInternalConfig() {}

        bool init(const char* inst_prefix=nullptr, const char* config_file=nullptr, bool rethrow=false);
        void term();

        const PathResolver& getPathResolver() const {
            return m_pathResolver;
        }
        Agent& getAgent() const;
        LoggingService& getLoggingService() const;

    private:
        bool _init(const char* inst_prefix=nullptr, const char* config_file=nullptr, bool rethrow=false);
        void _term();

        unsigned int m_initCount;
        mutex m_lock;
        PathResolver m_pathResolver;
        unique_ptr<Agent> m_agent;
        unique_ptr<LoggingService> m_logging;
        unique_ptr<ptree> m_config;
    };
    
    AgentInternalConfig g_config;
}

AgentConfig& AgentConfig::getConfig()
{
    return g_config;
}

AgentConfig::AgentConfig()
{
}

AgentConfig::~AgentConfig()
{
}

shibsp::Category& AgentConfig::deprecation() const
{
    return Category::getInstance(SHIBSP_LOGCAT".DEPRECATION");
}

LoggingService& AgentInternalConfig::getLoggingService() const
{
    if (m_logging) {
        return *m_logging;
    }
    throw logic_error("LoggingService not initialized.");
}

Agent& AgentInternalConfig::getAgent() const
{
    if (m_agent) {
        return *m_agent;
    }
    throw logic_error("Agent not initialized.");
}

bool AgentInternalConfig::init(const char* inst_prefix, const char* config_file, bool rethrow)
{
    lock_guard<mutex> locker(m_lock);

    if (m_initCount == INT_MAX) {
        if (rethrow) {
            throw runtime_error("Library initialized too many times.");
        }
        return false;
    }

    if (m_initCount > 0) {
        ++m_initCount;
        return true;
    }

    if (!_init(inst_prefix, config_file, rethrow)) {
        return false;
    }

    ++m_initCount;
    return true;
}

bool AgentInternalConfig::_init(const char* inst_prefix, const char* config_file, bool rethrow)
{
    // Establish prefix and replace backward slashes in path.
    if (!inst_prefix)
        inst_prefix = getenv("SHIBSP_PREFIX");
    if (!inst_prefix)
        inst_prefix = SHIBSP_PREFIX;
    std::string inst_prefix2;
    while (*inst_prefix) {
        inst_prefix2.push_back((*inst_prefix=='\\') ? ('/') : (*inst_prefix));
        ++inst_prefix;
    }

    m_pathResolver.setDefaultPackageName(PACKAGE_NAME);
    m_pathResolver.setDefaultPrefix(inst_prefix2.c_str());
    m_pathResolver.setCfgDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_LIBDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_LIBDIR;
    m_pathResolver.setLibDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_LOGDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_LOGDIR;
    m_pathResolver.setLogDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_RUNDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_RUNDIR;
    m_pathResolver.setRunDir(inst_prefix);
    inst_prefix = getenv("SHIBSP_CACHEDIR");
    if (!inst_prefix || !*inst_prefix)
        inst_prefix = SHIBSP_CACHEDIR;
    m_pathResolver.setCacheDir(inst_prefix);

    registerLoggingServices();

/*

    Category& log=Category::getInstance(SHIBSP_LOGCAT ".Config");
    log.debug("%s library initialization started", PACKAGE_STRING);

    XMLToolingConfig::getConfig().user_agent = string(PACKAGE_NAME) + '/' + PACKAGE_VERSION;

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

    // Yes, this isn't secure, will review where we do any random generation
    // after full code cleanup is done.
    srand(static_cast<unsigned int>(std::time(nullptr)));

    log.info("%s library initialization complete", PACKAGE_STRING);
    */
    return true;
}

    /*
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
*/

void AgentInternalConfig::term()
{
    lock_guard<mutex> locker(m_lock);

    if (m_initCount == 0) {
        throw runtime_error("Library terminated without initialization.");
        return;
    }
    else if (--m_initCount > 0) {
        return;
    }

    _term();
}

void AgentInternalConfig::_term()
{
    /*
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
    */
}
