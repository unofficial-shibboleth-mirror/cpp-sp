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
#include "AccessControl.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "logging/LoggingService.h"
#include "util/PathResolver.h"
#include "util/URLEncoder.h"

#include <ctime>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <vector>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#ifdef WIN32
#include <Windows.h>
#endif

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif

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
        bool load_library(const char* path, void* context=nullptr);

        const PathResolver& getPathResolver() const {
            return m_pathResolver;
        }

        const URLEncoder& getURLEncoder() const {
            return m_urlEncoder;
        }

        Agent& getAgent() const;
        LoggingService& getLoggingService() const;

    private:
        bool _init(const char* inst_prefix=nullptr, const char* config_file=nullptr, bool rethrow=false);
        void _term();

        bool initLogging();

        unsigned int m_initCount;
        mutex m_lock;
        ptree m_config;
        PathResolver m_pathResolver;
        URLEncoder m_urlEncoder;
        vector<void*> m_libhandles;
        unique_ptr<LoggingService> m_logging;
        unique_ptr<Agent> m_agent;
    };
    
    static AgentInternalConfig g_agentConfig;
}

AgentConfig& AgentConfig::getConfig()
{
    return g_agentConfig;
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
    string inst_prefix2;
    while (*inst_prefix) {
        inst_prefix2.push_back((*inst_prefix=='\\') ? ('/') : (*inst_prefix));
        ++inst_prefix;
    }

    // Set up PathResolver component.
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

    // Resolve primary config path and parse as INI file.
    if (!config_file)
        config_file = getenv("SHIBSP_CONFIG");
    if (!config_file) {
        config_file = SHIBSP_CONFIG;
    }
    string config_file_resolved(config_file);
    m_pathResolver.resolve(config_file_resolved, PathResolver::SHIBSP_CFG_FILE);

    try {
        ini_parser::read_ini(config_file_resolved, m_config);
    } catch (const ini_parser_error& e) {
        if (rethrow) {
            throw;
        }
        return false;
    }

    registerLoggingServices();

    try {
        if (!initLogging()) {
            return false;
        }
    } catch (const std::exception& e) {
        if (rethrow) {
            throw;
        }
        return false;
    }

    // At this point, logging is active/usable.

    Category& log=Category::getInstance(SHIBSP_LOGCAT ".AgentConfig");
    log.info("%s agent initialization underway", PACKAGE_STRING);

    registerAccessControls();
    registerRequestMappers();

    /*
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

    if (isEnabled(Caching))
        registerSessionCaches();

    // Yes, this isn't secure, will review where we do any random generation
    // after full code cleanup is done.
    srand(static_cast<unsigned int>(std::time(nullptr)));

    log.info("%s library initialization complete", PACKAGE_STRING);
    */
    return true;
}

bool AgentInternalConfig::initLogging()
{
    // Config is loaded, look for logging section and type to instantiate.
    string type = m_config.get(LoggingService::LOGGING_TYPE_PROP_PATH,
#ifdef WIN32
        WINDOWS_LOGGING_SERVICE
#else
        SYSLOG_LOGGING_SERVICE
#endif
        );
    m_logging = unique_ptr<LoggingService>(LoggingServiceManager.newPlugin(type, m_config, false));
    if (!m_logging->init()) {
        return false;
    }
    return true;
}

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
    Category& log=Category::getInstance(SHIBSP_LOGCAT ".AgentConfig");
    log.info("%s agent shutting down", PACKAGE_STRING);

    AccessControlManager.deregisterFactories();
    RequestMapperManager.deregisterFactories();
    LoggingServiceManager.deregisterFactories();

    for (vector<void*>::reverse_iterator i=m_libhandles.rbegin(); i!=m_libhandles.rend(); i++) {
#if defined(WIN32)
        FARPROC fn=GetProcAddress(static_cast<HMODULE>(*i),"xmltooling_extension_term");
        if (fn)
            fn();
        FreeLibrary(static_cast<HMODULE>(*i));
#elif defined(HAVE_DLFCN_H)
        void (*fn)()=(void (*)())dlsym(*i,"shibsp_extension_term");
        if (fn)
            fn();
        dlclose(*i);
#else
# error "Don't know about dynamic loading on this platform!"
#endif
    }
    m_libhandles.clear();

    log.info("%s agent shutdown complete", PACKAGE_STRING);

    m_logging->term();

    /*
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

    if (isEnabled(Caching))
        SessionCacheManager.deregisterFactories();
    */
}

bool AgentInternalConfig::load_library(const char* path, void* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("LoadLibrary");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT ".Config");
    log.info("loading extension: %s", path);

    lock_guard<mutex> locker(m_lock);

    string resolved(path);
    m_pathResolver.resolve(resolved, PathResolver::SHIBSP_LIB_FILE);

#if defined(WIN32)
    HMODULE handle=nullptr;
    for (string::iterator i = resolved.begin(); i != resolved.end(); ++i)
        if (*i == '/')
            *i = '\\';

    UINT em=SetErrorMode(SEM_FAILCRITICALERRORS);
    try {
        handle=LoadLibraryExA(resolved.c_str(),nullptr,LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!handle)
             handle=LoadLibraryExA(resolved.c_str(),nullptr,0);
        if (!handle)
            throw runtime_error(string("unable to load extension library: ") + resolved);
        FARPROC fn=GetProcAddress(handle,"shibsp_extension_init");
        if (!fn)
            throw runtime_error(string("unable to locate shibsp_extension_init entry point: ") + resolved);
        if (reinterpret_cast<int(*)(void*)>(fn)(context)!=0)
            throw runtime_error(string("detected error in shibsp_extension_init: ") + resolved);
        SetErrorMode(em);
    }
    catch(std::exception&) {
        if (handle)
            FreeLibrary(handle);
        SetErrorMode(em);
        throw;
    }
#elif defined(HAVE_DLFCN_H)
    void* handle=dlopen(resolved.c_str(),RTLD_LAZY);
    if (!handle)
        throw runtime_error(string("unable to load extension library '") + resolved + "': " + dlerror());
    int (*fn)(void*)=(int (*)(void*))(dlsym(handle,"shibsp_extension_init"));
    if (!fn) {
        dlclose(handle);
        throw runtime_error(
            string("unable to locate shibsp_extension_init entry point in '") + resolved + "': " +
                (dlerror() ? dlerror() : "unknown error")
            );
    }
    try {
        if (fn(context)!=0)
            throw runtime_error(string("detected error in shibsp_extension_init in ") + resolved);
    }
    catch(std::exception&) {
        if (handle)
            dlclose(handle);
        throw;
    }
#else
# error "Don't know about dynamic loading on this platform!"
#endif
    m_libhandles.push_back(handle);
    log.info("loaded extension: %s", resolved.c_str());
    return true;
}
