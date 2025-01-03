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
 * @file shibsp/handler/SessionInitiator.h
 * 
 * Pluggable runtime functionality that handles initiating sessions.
 */

#ifndef __shibsp_sesinitiator_h__
#define __shibsp_sesinitiator_h__

#include <shibsp/handler/Handler.h>
#include <shibsp/util/DOMPropertySet.h>

#include <set>
#include <string>

#if defined (_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4251 )
#endif

namespace shibsp {

    /**
     * Pluggable runtime functionality that handles initiating sessions.
     *
     * <p>By default, SessionInitiators look for an entityID on the incoming request
     * and pass control to the specialized run method.
     */
    class SHIBSP_API SessionInitiator : public virtual Handler, public DOMPropertySet::Remapper
    {
        friend void SHIBSP_API registerSessionInitiators();
    protected:

        /** Set of optional settings supported by handler. */
        std::set<std::string> m_supportedOptions;

        SessionInitiator();

        /**
         * Examines the request and applicable settings to determine whether
         * the handler is able to support the request.
         * <p>If the handler is within a chain, the method will return false,
         * otherwise an exception will be raised.
         *
         * @param request   SP request context
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  true iff the request appears to be compatible
         */
        bool checkCompatibility(SPRequest& request, bool isHandler) const;

    public:
        virtual ~SessionInitiator();

        /**
         * Indicates the set of optional settings supported by the handler.
         *
         * @return  a set of the optional settings supported
         */
        virtual const std::set<std::string>& getSupportedOptions() const;

        /**
         * Executes an incoming request.
         * 
         * <p>SessionInitiators can be run either directly by incoming web requests
         * or indirectly/implicitly during other SP processing.
         * 
         * @param request   SP request context
         * @param entityID  the name of an IdP to request a session from, if known
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> run(SPRequest& request, std::string& entityID, bool isHandler=true) const=0;

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

        const char* remap(const char* src, Category& log) const;
    };
    
};

#if defined (_MSC_VER)
#pragma warning( pop )
#endif


#endif /* __shibsp_sesinitiator_h__ */
