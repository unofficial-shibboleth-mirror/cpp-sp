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
 * @file shibsp/handler/Handler.h
 * 
 * Pluggable runtime functionality that implement protocols and services.
 */

#ifndef __shibsp_handler_h__
#define __shibsp_handler_h__

#include <shibsp/SPRequest.h>
#include <shibsp/util/PropertySet.h>

#ifndef SHIBSP_LITE
namespace opensaml {
    namespace saml2md {
        class SAML_API SPSSODescriptor;
    };
};
#endif

namespace xmltooling {
    class XMLTOOL_API HTTPRequest;
    class XMLTOOL_API HTTPResponse;
};

namespace shibsp {

    /**
     * Pluggable runtime functionality that implement protocols and services
     */
    class SHIBSP_API Handler : public virtual PropertySet
    {
        MAKE_NONCOPYABLE(Handler);
    protected:
        Handler();

        /**
         * Log using handler's specific logging object.
         *
         * @param level logging level
         * @param msg   message to log
         */
        virtual void log(SPRequest::SPLogLevel level, const std::string& msg) const;

        /**
         * Prevents unused relay state from building up by cleaning old state from the client.
         *
         * <p>Handlers that generate relay state should call this method as a house cleaning
         * step.
         *
         * @param application   the associated Application
         * @param request       incoming HTTP request
         * @param response      outgoing HTTP response
         */
        virtual void cleanRelayState(
            const Application& application, const xmltooling::HTTPRequest& request, xmltooling::HTTPResponse& response
            ) const;

        /**
         * Implements various mechanisms to preserve RelayState,
         * such as cookies or StorageService-backed keys.
         *
         * <p>If a supported mechanism can be identified, the input parameter will be
         * replaced with a suitable state key.
         *
         * @param application   the associated Application
         * @param response      outgoing HTTP response
         * @param relayState    RelayState token to supply with message
         */
        virtual void preserveRelayState(
            const Application& application, xmltooling::HTTPResponse& response, std::string& relayState
            ) const;

        /**
         * Implements various mechanisms to recover RelayState,
         * such as cookies or StorageService-backed keys.
         *
         * <p>If a supported mechanism can be identified, the input parameter will be
         * replaced with the recovered state information.
         *
         * @param application   the associated Application
         * @param request       incoming HTTP request
         * @param response      outgoing HTTP response
         * @param relayState    RelayState token supplied with message
         * @param clear         true iff the token state should be cleared
         */
        virtual void recoverRelayState(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            std::string& relayState,
            bool clear=true
            ) const;

    public:
        virtual ~Handler();

        /**
         * Returns an identifier for the protocol family associated with the handler, if any.
         *
         * @return  a protocol identifier, or nullptr
         */
        virtual const XMLCh* getProtocolFamily() const;

        /**
         * Executes handler functionality as an incoming request.
         * 
         * <p>Handlers can be run either directly by incoming web requests
         * or indirectly/implicitly during other SP processing.
         * 
         * @param request   SP request context
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const=0;

#ifndef SHIBSP_LITE
        /**
         * Generates and/or modifies metadata reflecting the Handler.
         *
         * <p>The default implementation does nothing.
         *
         * @param role          metadata role to decorate
         * @param handlerURL    base location of handler's endpoint
         */
        virtual void generateMetadata(opensaml::saml2md::SPSSODescriptor& role, const char* handlerURL) const;

        /**
         * Returns the "type" of the Handler plugin.
         *
         * @return  a Handler type
         */
        virtual const char* getType() const;
#endif
    };
    
    /** Registers Handler implementations. */
    void SHIBSP_API registerHandlers();

    /** Handler for SAML 1.x SSO. */
    #define SAML1_ASSERTION_CONSUMER_SERVICE "SAML1"

    /** Handler for SAML 2.0 SSO. */
    #define SAML20_ASSERTION_CONSUMER_SERVICE "SAML2"

    /** Handler for SAML 2.0 SLO. */
    #define SAML20_LOGOUT_HANDLER "SAML2"

    /** Handler for SAML 2.0 NIM. */
    #define SAML20_NAMEID_MGMT_SERVICE "SAML2"

    /** Handler for SAML 2.0 Artifact Resolution. */
    #define SAML20_ARTIFACT_RESOLUTION_SERVICE "SAML2"

    /** Handler for hooking new sessions with attribute checking. */
    #define ATTR_CHECKER_HANDLER "AttributeChecker"

    /** Handler for metadata generation. */
    #define DISCOVERY_FEED_HANDLER "DiscoveryFeed"

    /** Handler for external authentication integration. */
    #define EXTERNAL_AUTH_HANDLER "ExternalAuth"

    /** Handler for metadata generation. */
    #define METADATA_GENERATOR_HANDLER "MetadataGenerator"

    /** Handler for status information. */
    #define STATUS_HANDLER "Status"

    /** Handler for session diagnostic information. */
    #define SESSION_HANDLER "Session"
};

#endif /* __shibsp_handler_h__ */
