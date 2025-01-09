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
 * @file shibsp/handler/AssertionConsumerService.h
 * 
 * Base class for handlers that create sessions by consuming SSO protocol responses. 
 */

#ifndef __shibsp_acshandler_h__
#define __shibsp_acshandler_h__

#include <shibsp/handler/AbstractHandler.h>
#include <shibsp/handler/RemotedHandler.h>

namespace shibsp {

    class SHIBSP_API Attribute;
    class SHIBSP_API LoginEvent;
    class SHIBSP_API ResolutionContext;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Base class for handlers that create sessions by consuming SSO protocol responses.
     */
    class SHIBSP_API AssertionConsumerService : public AbstractHandler
    {
    public:
        virtual ~AssertionConsumerService();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    protected:
        /**
         * Constructor
         * 
         * @param e         root of DOM configuration
         * @param log       a logging object to use
         */
        AssertionConsumerService(const boost::property_tree::ptree& pt, Category& log);

        /**
         * Enforce address checking requirements.
         * 
         * @param request       client request that initiated session
         * @param issuedTo      address for which security assertion was issued
         */
        void checkAddress(const SPRequest& request, const char* issuedTo) const;


        /**
         * Complete the client's transition back to the expected resource.
         * 
         * @param request       client request that included message
         * @param relayState    relay state token
         */
        virtual std::pair<bool,long> finalizeResponse(SPRequest& httpRequest, std::string& relayState) const;

    private:        
        std::pair<bool,long> sendRedirect(
            SPRequest& request,
            const char* entityID,
            const char* relayState
            ) const;                
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __shibsp_acshandler_h__ */
