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
 * @file shibsp/handler/RemotedHandler.h
 * 
 * Base class for handlers that need SP request/response layer to be remoted. 
 */

#ifndef __shibsp_remhandler_h__
#define __shibsp_remhandler_h__

#include <shibsp/handler/Handler.h>
#include <shibsp/remoting/ListenerService.h>

#include <set>

namespace xmltooling {
    class XMLTOOL_API HTTPRequest;
    class XMLTOOL_API HTTPResponse;
};

namespace shibsp {

    /**
     * Base class for handlers that need HTTP request/response layer to be remoted.
     */
    class SHIBSP_API RemotedHandler : public virtual Handler, public Remoted 
    {
        static std::set<std::string> m_remotedHeaders;

    public:
        virtual ~RemotedHandler();

        /**
         * Ensures that a request header will be remoted.
         *
         * @param header    name of request header to remote
         */
        static void addRemotedHeader(const char* header);

    protected:
        RemotedHandler();

        /**
         * Establishes message remoting using the supplied address.
         * 
         * @param address   a unique "address" for remote message handling
         */
        void setAddress(const char* address);

        /**
         * Wraps a request by creating an outgoing data flow with the data needed
         * to remote the request information.
         *
         * @param request   an SPRequest to remote
         * @param headers   array of additional request headers to copy to remote request
         * @param certs     true iff client certificates should be available for the remote request
         * @return  the input dataflow object
         */
        DDF wrap(const SPRequest& request, const std::vector<std::string>* headers=nullptr, bool certs=false) const;
        
        /**
         * Unwraps a response by examining an incoming data flow to determine
         * whether a response was produced by the remoted handler. 
         * 
         * @param request   SP request context
         * @param out       the dataflow object to unpack
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        virtual std::pair<bool,long> unwrap(SPRequest& request, DDF& out) const;

        /**
         * Builds a new request instance around a remoted data object.
         * 
         * @param in    the dataflow object containing the remoted request
         * @return  a call-specific request object based on the input, to be freed by the caller 
         */
        xmltooling::HTTPRequest* getRequest(DDF& in) const;
        
        /**
         * Builds a new response instance around an outgoing data object.
         * 
         * @param out   the dataflow object to be returned by the caller
         * @return  a call-specific response object, to be freed by the caller 
         */
        xmltooling::HTTPResponse* getResponse(DDF& out) const;

        /** Message address for remote half. */
        std::string m_address;
    };
};

#endif /* __shibsp_remhandler_h__ */
