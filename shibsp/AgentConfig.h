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
 * @file shibsp/AgentConfig.h
 *
 * Library/agent "global" configuration.
 */

#ifndef __shibsp_agentconfig_h__
#define __shibsp_agentconfig_h__

#include <shibsp/util/PluginManager.h>

#include <string>
#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

    class SHIBSP_API AccessControl;
    class SHIBSP_API Agent;
    class SHIBSP_API Category;
    class SHIBSP_API LoggingService;
    class SHIBSP_API PathResolver;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API URLEncoder;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * Singleton interface that manages agent startup/shutdown.
     */
    class SHIBSP_API AgentConfig
    {
        MAKE_NONCOPYABLE(AgentConfig);
    public:
        AgentConfig();
        virtual ~AgentConfig();

        /**
         * Returns the global configuration object for the agent.
         *
         * @return reference to the global agent configuration object
         */
        static AgentConfig& getConfig();

        /**
         * Initializes agent/library.
         *
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         *
         * @param catalog_path  delimited set of schema catalog files to load
         * @param inst_prefix   installation prefix for software
         * @return true iff initialization was successful
         */
        virtual bool init(const char* inst_prefix=nullptr, const char* config_file=nullptr, bool rethrow=false)=0;

        /**
         * Shuts down agent/library
         *
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself.
         */
        virtual void term()=0;

        /**
         * Manages factories for AccessControl plugins.
         */
        PluginManager<AccessControl,std::string,boost::property_tree::ptree&> AccessControlManager;

        /**
         * Manages factories for Agent plugins.
         */
        PluginManager<Agent,std::string,boost::property_tree::ptree&> AgentManager;

        /**
         * Manages factories for LoggingService plugins.
         */
        PluginManager<LoggingService,std::string,boost::property_tree::ptree&> LoggingServiceManager;

        /**
         * Manages factories for RequestMapper plugins.
         */
        PluginManager<RequestMapper,std::string,boost::property_tree::ptree&> RequestMapperManager;

        /**
         * Returns a PathResolver instance.
         * 
         * @return path resolver
         */
        virtual const PathResolver& getPathResolver() const=0;

        /**
         * Returns a URLEncoder instance.
         * 
         * @return URL encoder
         */
        virtual const URLEncoder& getURLEncoder() const=0;

        /**
         * Returns the configured logging service.
         * 
         * <p>This method will throw in the event the library is not yet initialized.</p>
         * 
         * @return logging service
         */
        virtual LoggingService& getLoggingService() const=0;

        /**
         * Returns the global Agent instance.
         * 
         * <p>This method will throw in the event the library is not yet initialized.</p>
         *
         * @return  global Agent
         */
        virtual Agent& getAgent() const=0;

        /**
         * Helper for deprecation warnings about an at-risk feature or setting.
         */
        shibsp::Category& deprecation() const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_agentconfig_h__ */
