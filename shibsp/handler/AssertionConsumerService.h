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
 * @file shibsp/handler/AssertionConsumerService.h
 * 
 * Base class for handlers that create sessions by consuming SSO protocol responses. 
 */

#ifndef __shibsp_acshandler_h__
#define __shibsp_acshandler_h__

#include <shibsp/handler/AbstractHandler.h>
#include <shibsp/handler/RemotedHandler.h>
#include <saml/binding/MessageDecoder.h>
#include <saml/saml2/metadata/Metadata.h>

namespace shibsp {

    class SHIBSP_API ResolutionContext;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Base class for handlers that create sessions by consuming SSO protocol responses.
     */
    class SHIBSP_API AssertionConsumerService : public AbstractHandler, public RemotedHandler 
    {
    public:
        virtual ~AssertionConsumerService();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, std::ostream& out);

    protected:
        AssertionConsumerService(const DOMElement* e, log4cpp::Category& log);
        
        /**
         * Implement protocol-specific handling of the incoming decoded message.
         * 
         * <p>The result of implementing the protocol should be an exception or
         * the key to a newly created session.
         * 
         * @param application   reference to application receiving message
         * @param httpRequest   client request that included message
         * @param policy        the SecurityPolicy in effect, after having evaluated the message
         * @param settings      policy configuration settings in effect
         * @param xmlObject     a protocol-specific message object
         * @return  the key to the newly created session
         */
        virtual std::string implementProtocol(
            const Application& application,
            const opensaml::HTTPRequest& httpRequest,
            opensaml::SecurityPolicy& policy,
            const PropertySet* settings,
            const xmltooling::XMLObject& xmlObject
            ) const=0;
            
        /**
         * Enforce address checking requirements.
         * 
         * @param application   reference to application receiving message
         * @param httpRequest   client request that initiated session
         * @param issuedTo      address for which security assertion was issued
         */
        void checkAddress(
            const Application& application, const opensaml::HTTPRequest& httpRequest, const char* issuedTo
            ) const;
        
        /**
         * Attempt SSO-initiated attribute resolution using the supplied information.
         * 
         * <p>The caller must free the returned context handle.
         * 
         * @param application   reference to application receiving message
         * @param httpRequest   client request that initiated session
         * @param issuer        source of SSO tokens
         * @param nameid        identifier of principal
         * @param tokens        tokens to resolve, if any
         */
        ResolutionContext* resolveAttributes(
            const Application& application,
            const opensaml::HTTPRequest& httpRequest,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::vector<const opensaml::Assertion*>* tokens=NULL
            ) const;
        
    private:
        std::string processMessage(
            const Application& application,
            opensaml::HTTPRequest& httpRequest,
            std::string& providerId,
            std::string& relayState
            ) const;
            
        std::pair<bool,long> sendRedirect(
            SPRequest& request, const char* key, const char* providerId, const char* relayState
            ) const;
        
        void maintainHistory(SPRequest& request, const char* providerId, const char* cookieProps) const;
                
        opensaml::MessageDecoder* m_decoder;
        xmltooling::auto_ptr_char m_configNS;
        xmltooling::QName m_role;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_acshandler_h__ */
