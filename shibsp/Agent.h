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
 * @file shibsp/Agent.h
 * 
 * Interface to a Shibboleth SP agent.
 */

#ifndef __shibsp_agent_h__
#define __shibsp_agent_h__

#include <shibsp/util/PropertySet.h>

#include <set>
#include <string>

namespace shibsp {

    class SHIBSP_API AttributeConfiguration;
    class SHIBSP_API Category;
    class SHIBSP_API Handler;
    class SHIBSP_API HandlerConfiguration;
    class SHIBSP_API RemotingService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API Session;
    class SHIBSP_API SessionCache;
    class SHIBSP_API SPRequest;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to a Shibboleth Agent instance.
     * 
     * <p>An agent exposes configuration and infrastructure services required
     * by the agent implementation.</p>
     */
	class SHIBSP_API Agent : public virtual PropertySet
    {
        MAKE_NONCOPYABLE(Agent);
    protected:
        Agent();
    public:
        virtual ~Agent();
        
        /**
         * Loads a configuration and prepares the instance for use.
         * 
         * <p>Implemented as a separate method so that services can rely on
         * other services while they initialize by accessing the Agent
         * from the AgentConfig singleton.</p>
         */
        virtual void init()=0;

        /**
         * Returns a SessionCache instance.
         * 
         * @param required  true iff an exception should be thrown if no SessionCache is available
         * 
         * @return  a SessionCache
         */
        virtual SessionCache* getSessionCache(bool required=true) const=0;

        /**
         * Returns a RemotingService instance.
         * 
         * @param required  true iff an exception should be thrown if no RemotingService is available
         * 
         * @return  a RemotingService
         */
        virtual const RemotingService* getRemotingService(bool required=true) const=0;
        
        /**
         * Returns a RequestMapper instance.
         * 
         * @param required  true iff an exception should be thrown if no RequestMapper is available
         * 
         * @return  a RequestMapper
         */
        virtual RequestMapper* getRequestMapper(bool required=true) const=0;
        
        /**
         * Gets the identified HandlerConfiguration.
         * 
         * <p>If no matching configurationn is found, an exception is raised.</p>
         * 
         * @param id identifier for configuration (null is assumed to be the default)
         * 
         * @return the matching configuration
         */
        virtual const HandlerConfiguration& getHandlerConfiguration(const char* id=nullptr) const=0;

        /**
         * Gets the identified AttributeConfiguration.
         * 
         * <p>If no matching configurationn is found, an exception is raised.</p>
         * 
         * @param id identifier for configuration (null is assumed to be the default)
         * 
         * @return the matching configuration
         */
        virtual const AttributeConfiguration& getAttributeConfiguration(const char* id=nullptr) const=0;

        /**
         * Enforces requirements for an authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue.</p>
         * 
         * @param request   SP request interface
         * @param handler   true iff a request to a registered Handler location can be directly executed
         * 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthentication(SPRequest& request, bool handler=false) const;
        
        /**
         * Enforces authorization requirements based on the authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue.</p>
         * 
         * @param request   SP request interface
         * 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthorization(SPRequest& request) const;
        
        /**
         * Publishes session contents to the request in the form of headers or environment variables.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue.</p>
         * 
         * @param request   SP request interface
         * @param requireSession    set to true iff an error should result if no session exists
         * 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doExport(SPRequest& request, bool requireSession=true) const;

        /**
         * Services requests for registered Handler locations. 
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue.</p>
         * 
         * @param request   SP request interface
         * 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doHandler(SPRequest& request) const;

        /** Property constants. */

        static const char UNSET_HEADER_VALUE_PROP_NAME[];
        static const char CHECK_SPOOFING_PROP_NAME[];
        static const char SPOOF_KEY_PROP_NAME[];
        static const char CATCH_ALL_PROP_NAME[];
        static const char PARTIAL_REGEX_MATCHING_PROP_NAME[];

        static bool CHECK_SPOOFING_PROP_DEFAULT;
        static bool CATCH_ALL_PROP_DEFAULT;
        static bool PARTIAL_REGEX_MATCHING_PROP_DEFAULT;

    protected:
        /** The AuthTypes to "recognize" (defaults to "shibboleth"). */
        std::set<std::string> m_authTypes;

    private:
        long handleError(
            SPRequest& request,
            std::exception* ex=nullptr,
            bool mayRedirect=true
        ) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    /**
     * Registers Agent plugins into the runtime.
     */
    void SHIBSP_API registerAgents();

    /** Default agent implementation. */
    #define DEFAULT_AGENT "Default"
};

#endif /* __shibsp_agent_h__ */
