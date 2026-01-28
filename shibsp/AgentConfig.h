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
    class SHIBSP_API Handler;
    class SHIBSP_API LoggingService;
    class SHIBSP_API PathResolver;
    class SHIBSP_API RemotingService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API SecretSource;
    class SHIBSP_API SessionCache;
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

    protected:
        AgentConfig();

    public:
        virtual ~AgentConfig();

        /**
         * Callback interface for post-initialization work prior to Agent creation.
         */
        class SHIBSP_API AgentConfigCallback
        {
            MAKE_NONCOPYABLE(AgentConfigCallback);
            
        protected:
            AgentConfigCallback();

        public:
            virtual ~AgentConfigCallback();

            /**
             * Method invoked by initialization routine prior to instantiating
             * the Agent implementation.
             * 
             * @param arg callback argument if needed
             * 
             * @return true iff initialization should proceed
             */
            virtual bool callback(void* arg) const=0;
        };

        /**
         * Returns the global configuration object for the agent.
         *
         * @return reference to the global agent configuration object
         */
        static AgentConfig& getConfig();

        /**
         * Sets a flag indicating a command line program is initializing the agent.
         * 
         * <p>This can be used to adjust/affect default settings and plugin types used.</p>
         */
        virtual void setCommandLine(bool flag)=0;

        /**
         * Installs a callback to invoke prior to Agent instantiation.
         * 
         * @param callback callback to invoke
         * @param arg argument to callback if any
         */
        virtual void setCallback(const AgentConfigCallback* callback, void* arg=nullptr)=0;

        /**
         * Initializes agent/library.
         *
         * <p>Each process using the library MUST call this function exactly once
         * before using any library classes.</p>
         *
         * @param catalog_path  delimited set of schema catalog files to load
         * @param inst_prefix   installation prefix for software
         * @return true iff initialization was successful
         */
        virtual bool init(const char* inst_prefix=nullptr, const char* config_file=nullptr, bool rethrow=false)=0;

        /**
         * Tells the agent it may start background threads or tasks.
         * 
         * <p>Should only be called once per child process but the implememntation will
         * ensure that subsequent calls are ignored. Must be called only after init()
         * is successful, failure to do so resulting in unspecified behavior.</p>
         */
        virtual bool start()=0;

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
         * Manages factories for Handler plugins.
         */
        PluginManager<Handler,std::string,std::pair<boost::property_tree::ptree&,const char*>> HandlerManager;

        /**
         * Manages factories for LoggingService plugins.
         */
        PluginManager<LoggingService,std::string,boost::property_tree::ptree&> LoggingServiceManager;

        /**
         * Manages factories for RemotingService plugins.
         */
        PluginManager<RemotingService,std::string,boost::property_tree::ptree&> RemotingServiceManager;

        /**
         * Manages factories for RequestMapper plugins.
         */
        PluginManager<RequestMapper,std::string,boost::property_tree::ptree&> RequestMapperManager;

        /**
         * Manages factories for SecretSource plugins.
         */
        PluginManager<SecretSource,std::string,boost::property_tree::ptree&> SecretSourceManager;

        /**
         * Manages factories for SessionCache plugins.
         */
        PluginManager<SessionCache,std::string,boost::property_tree::ptree&> SessionCacheManager;

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
         * Generates a random string of designated length encoded into hex.
         * 
         * <p>The implementation should be reasonably secure, i.e., suitable for generating
         * session IDs.</p>
         * 
         * @param len length of data in bytes to generate before encoding
         * 
         * @return hex encoded random data
         */
        virtual std::string generateRandom(unsigned int len) const=0;

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
