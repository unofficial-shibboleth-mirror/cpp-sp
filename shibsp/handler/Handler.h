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
 * @file shibsp/handler/Handler.h
 * 
 * Pluggable runtime functionality that implement protocols and services.
 */

#ifndef __shibsp_handler_h__
#define __shibsp_handler_h__

#include <shibsp/SPRequest.h>
#include <shibsp/logging/Priority.h>
#include <shibsp/util/PropertySet.h>

namespace shibsp {

    class SHIBSP_API HTTPRequest;
    class SHIBSP_API HTTPResponse;

    /**
     * Pluggable runtime functionality that implement protocols and services
     */
    class SHIBSP_API Handler
    {
        MAKE_NONCOPYABLE(Handler);
    protected:
        Handler();

    public:
        virtual ~Handler();

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

        /**
         * Get the type of event, as input to error handling in response to errors raised by this handler.
         *
         * @return an event type for error handling
         */
        virtual const char* getEventType() const;
    };
    
    /** Registers Handler implementations. */
    void SHIBSP_API registerHandlers();

    /** SessionInitiator that supports SAML 2.0 AuthnRequests. */
    #define SESSION_INITIATOR_HANDLER "SessionInitiator"

    /** Handler for SSO token handling (the inbound side of SSO). */
    #define TOKEN_CONSUMER_HANDLER "TokenConsumer"

    /** Handler for logout. */
    #define LOGOUT_INITIATOR_HANDLER "LogoutInitiator"

    /** Handler for logout. */
    #define LOGOUT_CONSUMER_HANDLER "LogoutConsumer"

    /** LogoutInitiator that supports administrative logout. */
    #define ADMIN_LOGOUT_HANDLER "AdminLogout"

    /** Handler for hooking new sessions with attribute checking. */
    #define ATTR_CHECKER_HANDLER "AttributeChecker"

    /** Handler for metadata generation. */
    #define METADATA_GENERATOR_HANDLER "MetadataGenerator"

    /** Handler for passthrough of requests into Hub flows. */
    #define PASSTHROUGH_HANDLER "Passthrough"

    /** Handler for status information. */
    #define STATUS_HANDLER "Status"

    /** Handler for session diagnostic information. */
    #define SESSION_HANDLER "Session"
};

#endif /* __shibsp_handler_h__ */
