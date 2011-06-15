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
 * @file shibsp/binding/SOAPClient.h
 * 
 * Specialized SOAPClient for SP environment.
 */

#ifndef __shibsp_soap11client_h__
#define __shibsp_soap11client_h__

#include <shibsp/base.h>

#include <saml/binding/SOAPClient.h>

namespace shibsp {

    class SHIBSP_API PropertySet;
    class SHIBSP_API SecurityPolicy;

    /**
     * Specialized SOAPClient for SP environment.
     */
    class SHIBSP_API SOAPClient : public opensaml::SOAPClient
    {
    public:
        /**
         * Creates a SOAP client instance for an Application to use.
         * 
         * @param policy        reference to SP-SecurityPolicy to apply
         */
        SOAPClient(SecurityPolicy& policy);
        
        virtual ~SOAPClient();

        /**
         * Override handles message signing for SAML payloads.
         * 
         * @param env       SOAP envelope to send
         * @param from      identity of sending application
         * @param to        peer to send message to, expressed in metadata terms
         * @param endpoint  URL of endpoint to recieve message
         */
        void send(const soap11::Envelope& env, const char* from, opensaml::saml2md::MetadataCredentialCriteria& to, const char* endpoint);

        void reset();

    protected:
        /**
         * Override prepares transport by applying policy settings from Application.
         * 
         * @param transport reference to transport layer
         */
        void prepareTransport(xmltooling::SOAPTransport& transport);

        /** Application supplied to client. */
        const Application& m_app;

        /** RelyingParty properties, set after transport prep. */
        const PropertySet* m_relyingParty;

        /** Locked CredentialResolver for transport, set after transport prep. */
        xmltooling::CredentialResolver* m_credResolver;
    };

};

#endif /* __shibsp_soap11client_h__ */
