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

#include <shibsp/util/Lockable.h>
#include <shibsp/util/PropertySet.h>

#include <set>

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Handler;
    class SHIBSP_API ListenerService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API SessionCache;
    class SHIBSP_API AgentRequest;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to a Shibboleth ServiceProvider instance.
     * 
     * <p>A ServiceProvider exposes configuration and infrastructure services required
     * by the SP implementation, allowing a flexible configuration format.
     */
	class SHIBSP_API Agent : public virtual SharedLockable, public virtual PropertySet
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
         * other services while they initialize by accessing the ServiceProvider
         * from the SPConfig singleton.
         */
        virtual void init()=0;

        /**
         * Returns a SessionCache instance.
         * 
         * @param required  true iff an exception should be thrown if no SessionCache is available
         * @return  a SessionCache
         */
        virtual SessionCache* getSessionCache(bool required=true) const=0;

        /**
         * Returns a ListenerService instance.
         * 
         * @param required  true iff an exception should be thrown if no ListenerService is available
         * @return  a ListenerService
         */
        virtual ListenerService* getListenerService(bool required=true) const=0;
        
        /**
         * Returns a RequestMapper instance.
         * 
         * @param required  true iff an exception should be thrown if no RequestMapper is available
         * @return  a RequestMapper
         */
        virtual RequestMapper* getRequestMapper(bool required=true) const=0;
        
        /**
         * Enforces requirements for an authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @param handler   true iff a request to a registered Handler location can be directly executed
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthentication(AgentRequest& request, bool handler=false) const;
        
        /**
         * Enforces authorization requirements based on the authenticated session.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doAuthorization(AgentRequest& request) const;
        
        /**
         * Publishes session contents to the request in the form of headers or environment variables.
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @param requireSession    set to true iff an error should result if no session exists 
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doExport(AgentRequest& request, bool requireSession=true) const;

        /**
         * Services requests for registered Handler locations. 
         * 
         * <p>If the return value's first member is true, then request processing should terminate
         * with the second member as a status value. If false, processing can continue. 
         * 
         * @param request   SP request interface
         * @return a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> doHandler(AgentRequest& request) const;

    protected:
        /** The AuthTypes to "recognize" (defaults to "shibboleth"). */
        std::set<std::string> m_authTypes;
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