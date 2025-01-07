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
    class SHIBSP_API AssertionConsumerService : public AbstractHandler, public RemotedHandler 
    {
    public:
        virtual ~AssertionConsumerService();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, std::ostream& out);

    protected:
        /**
         * Constructor
         * 
         * @param e         root of DOM configuration
         * @param appId     ID of application that "owns" the handler
         * @param log       a logging object to use
         * @param filter    optional filter controls what child elements to include as nested PropertySets
         * @param remapper  optional property rename mapper for legacy property support
         * @param deprecationSupport true iff deprecated settings and features should be supported
         */
        AssertionConsumerService(
            const xercesc::DOMElement* e,
            const char* appId,
            Category& log,
            xercesc::DOMNodeFilter* filter=nullptr,
            const Remapper* remapper=nullptr,
            bool deprecationSupport=true
            );

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

#ifndef SHIBSP_LITE
        /**
         * Returns a profile identifier to inject into the SecurityPolicy created
         * by the base class.
         *
         * @return profile identifier if any
         */
        virtual const char* getProfile() const;

        /**
         * Implement protocol-specific handling of the incoming decoded message.
         * 
         * <p>The result of implementing the protocol should be an exception or
         * modifications to the request/response objects to reflect processing
         * of the message.</p>
         * 
         * @param request       client request that included message
         * @param policy        the SecurityPolicy in effect, after having evaluated the message
         * @param reserved      ignore this parameter
         * @param xmlObject     a protocol-specific message object
         */
        virtual void implementProtocol(
            SPRequest& httpRequest,
            opensaml::SecurityPolicy& policy,
            const PropertySet* reserved,
            const xmltooling::XMLObject& xmlObject
            ) const=0;

        /**
         * Extracts policy-relevant assertion details.
         * 
         * @param assertion the incoming assertion
         * @param protocol  the protocol family in use
         * @param policy    SecurityPolicy to provide various components and track message data
         */
        virtual void extractMessageDetails(
            const opensaml::Assertion& assertion, const XMLCh* protocol, opensaml::SecurityPolicy& policy
            ) const;

        /**
         * Attempt SSO-initiated attribute resolution using the supplied information,
         * including NameID and token extraction and filtering followed by
         * secondary resolution.
         * 
         * <p>The caller must free the returned context handle.</p>
         * 
         * @param request               request delivering message, if any
         * @param issuer                source of SSO tokens
         * @param protocol              SSO protocol used
         * @param protmsg               SSO protocol message, if any
         * @param v1nameid              identifier of principal in SAML 1.x form, if any
         * @param v1statement           SAML 1.x authentication statement, if any
         * @param nameid                identifier of principal in SAML 2.0 form
         * @param statement             SAML 2.0 authentication statement, if any
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl     specifics of authentication event, if known
         * @param tokens                available assertions, if any
         */
        ResolutionContext* resolveAttributes(
            const SPRequest* request=nullptr,
            const opensaml::saml2md::RoleDescriptor* issuer=nullptr,
            const XMLCh* protocol=nullptr,
            const xmltooling::XMLObject* protmsg=nullptr,
            const opensaml::saml1::NameIdentifier* v1nameid=nullptr,
            const opensaml::saml1::AuthenticationStatement* v1statement=nullptr,
            const opensaml::saml2::NameID* nameid=nullptr,
            const opensaml::saml2::AuthnStatement* statement=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const std::vector<const opensaml::Assertion*>* tokens=nullptr
            ) const;
#endif
    private:
        std::pair<bool,long> processMessage(const SPRequest& request) const;
        
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
