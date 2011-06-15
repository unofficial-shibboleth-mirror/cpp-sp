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
 * @file shibsp/handler/AbstractHandler.h
 * 
 * Base class for handlers based on a DOMPropertySet. 
 */

#ifndef __shibsp_abshandler_h__
#define __shibsp_abshandler_h__

#include <shibsp/handler/Handler.h>
#include <shibsp/remoting/ddf.h>
#include <shibsp/util/DOMPropertySet.h>

#include <map>
#include <string>
#include <xmltooling/logging.h>

#ifndef SHIBSP_LITE
namespace opensaml {
    class SAML_API MessageEncoder;
    namespace saml2md {
        class SAML_API RoleDescriptor;
    };
    namespace saml2p {
        class SAML_API StatusResponseType;
    };
};
#endif

namespace xmltooling {
    class XMLTOOL_API XMLObject;
};

namespace shibsp {

    class SHIBSP_API Application;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Base class for handlers based on a DOMPropertySet.
     */
    class SHIBSP_API AbstractHandler : public virtual Handler, public DOMPropertySet
    {
    protected:
        /**
         * Constructor
         * 
         * @param e         DOM element to load as property set.
         * @param log       logging category to use
         * @param filter    optional filter controls what child elements to include as nested PropertySets
         * @param remapper  optional map of property rename rules for legacy property support
         */
        AbstractHandler(
            const xercesc::DOMElement* e,
            xmltooling::logging::Category& log,
            xercesc::DOMNodeFilter* filter=nullptr,
            const std::map<std::string,std::string>* remapper=nullptr
            );

        void log(SPRequest::SPLogLevel level, const std::string& msg) const;

#ifndef SHIBSP_LITE
        /**
         * Examines a protocol response message for errors and raises an annotated exception
         * if an error is found.
         * 
         * <p>The base class version understands SAML 1.x and SAML 2.0 responses.
         * 
         * @param response  a response message of some known protocol
         * @param role      issuer of message
         */
        virtual void checkError(
            const xmltooling::XMLObject* response,
            const opensaml::saml2md::RoleDescriptor* role=nullptr
            ) const;

        /**
         * Prepares Status information in a SAML 2.0 response.
         * 
         * @param response  SAML 2.0 response message
         * @param code      SAML status code
         * @param subcode   optional SAML substatus code
         * @param msg       optional message to pass back
         */
        void fillStatus(
            opensaml::saml2p::StatusResponseType& response, const XMLCh* code, const XMLCh* subcode=nullptr, const char* msg=nullptr
            ) const;

        /**
         * Encodes and sends SAML 2.0 message, optionally signing it in the process.
         * If the method returns, the message MUST NOT be freed by the caller.
         *
         * @param encoder           the MessageEncoder to use
         * @param msg               the message to send
         * @param relayState        any RelayState to include with the message
         * @param destination       location to send message, if not a backchannel response
         * @param role              recipient of message, if known
         * @param application       the Application sending the message
         * @param httpResponse      channel for sending message
         * @param signIfPossible    true iff signing should be attempted regardless of "signing" property
         * @return  the result of sending the message using the encoder
         */
        long sendMessage(
            const opensaml::MessageEncoder& encoder,
            xmltooling::XMLObject* msg,
            const char* relayState,
            const char* destination,
            const opensaml::saml2md::RoleDescriptor* role,
            const Application& application,
            xmltooling::HTTPResponse& httpResponse,
            bool signIfPossible=false
            ) const;
#endif

        /**
         * Implements a mechanism to preserve form post data.
         *
         * @param application   the associated Application
         * @param request       incoming HTTP request
         * @param response      outgoing HTTP response
         * @param relayState    relay state information attached to current sequence, if any
         */
        virtual void preservePostData(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            const char* relayState
            ) const;

        /**
         * Implements storage service and cookie mechanism to recover PostData.
         *
         * <p>If a supported mechanism can be identified, the return value will be
         * the recovered state information.
         *
         * @param application   the associated Application
         * @param request       incoming HTTP request
         * @param response      outgoing HTTP response
         * @param relayState    relay state information attached to current sequence, if any
         * @return  recovered form post data associated with request as a DDF list of string members
         */
        virtual DDF recoverPostData(
            const Application& application,
            const xmltooling::HTTPRequest& request,
            xmltooling::HTTPResponse& response,
            const char* relayState
            ) const;

        /**
         * Post a redirect response with post data.
         *
         * @param application   the associated Application
         * @param response      outgoing HTTP response
         * @param url           action url for the form
         * @param postData      list of parameters to load into the form, as DDF string members
         */
        virtual long sendPostResponse(
            const Application& application,
            xmltooling::HTTPResponse& response,
            const char* url,
            DDF& postData
            ) const;

        /**
         * Bitmask of property sources to read from
         * (request query parameter, request mapper, fixed handler property).
         */
        enum PropertySourceTypes {
            HANDLER_PROPERTY_REQUEST = 1,
            HANDLER_PROPERTY_MAP = 2,
            HANDLER_PROPERTY_FIXED = 4,
            HANDLER_PROPERTY_ALL = 255
        };

        using DOMPropertySet::getBool;
        using DOMPropertySet::getString;
        using DOMPropertySet::getUnsignedInt;
        using DOMPropertySet::getInt;

        /**
         * Returns a boolean-valued property.
         * 
         * @param name      property name
         * @param request   reference to incoming request
         * @param type      bitmask of property sources to use
         * @return a pair consisting of a nullptr indicator and the property value iff the indicator is true
         */
        std::pair<bool,bool> getBool(const char* name, const SPRequest& request, unsigned int type=HANDLER_PROPERTY_ALL) const;

        /**
         * Returns a string-valued property.
         * 
         * @param name      property name
         * @param request   reference to incoming request
         * @param type      bitmask of property sources to use
         * @return a pair consisting of a nullptr indicator and the property value iff the indicator is true
         */
        std::pair<bool,const char*> getString(const char* name, const SPRequest& request, unsigned int type=HANDLER_PROPERTY_ALL) const;

        /**
         * Returns an unsigned integer-valued property.
         * 
         * @param name      property name
         * @param request   reference to incoming request
         * @param type      bitmask of property sources to use
         * @return a pair consisting of a nullptr indicator and the property value iff the indicator is true
         */
        std::pair<bool,unsigned int> getUnsignedInt(const char* name, const SPRequest& request, unsigned int type=HANDLER_PROPERTY_ALL) const;

        /**
         * Returns an integer-valued property.
         * 
         * @param name      property name
         * @param request   reference to incoming request
         * @param type      bitmask of property sources to use
         * @return a pair consisting of a nullptr indicator and the property value iff the indicator is true
         */
        std::pair<bool,int> getInt(const char* name, const SPRequest& request, unsigned int type=HANDLER_PROPERTY_ALL) const;

        /** Logging object. */
        xmltooling::logging::Category& m_log;
        
        /** Configuration namespace for custom properties. */
        xmltooling::auto_ptr_char m_configNS;

    public:
        virtual ~AbstractHandler();

    private:
        std::pair<std::string,const char*> getPostCookieNameProps(const Application& app, const char* relayState) const;
        DDF getPostData(const Application& application, const xmltooling::HTTPRequest& request) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_abshandler_h__ */
