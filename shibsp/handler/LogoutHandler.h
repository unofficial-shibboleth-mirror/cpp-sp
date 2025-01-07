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
 * @file shibsp/handler/LogoutHandler.h
 * 
 * Base class for logout-related handlers.
 */

#ifndef __shibsp_logout_h__
#define __shibsp_logout_h__

#include <shibsp/handler/RemotedHandler.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for logout-related handlers.
     */
    class SHIBSP_API LogoutHandler : public RemotedHandler
    {
    public:
        virtual ~LogoutHandler();

        /**
         * The base method will iteratively attempt front-channel notification
         * of logout of the current session, and after the final round trip will
         * perform back-channel notification. Nothing will be done unless the 
         * handler detects that it is the "top" level logout handler.
         * If the method returns false, then the specialized class should perform
         * its work assuming that the notifications are completed.
         *
         * Note that the current session is NOT removed from the cache.
         * 
         * @param request   SP request context
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

        /**
         * A remoted procedure that will perform any necessary back-channel
         * notifications. The input structure must contain an "application_id" member,
         * and a "sessions" list containing the session keys, along with an integer
         * member called "notify" with a value of 1.
         * 
         * @param in    incoming DDF message
         * @param out   stream to write outgoing DDF message to
         */
        void receive(DDF& in, std::ostream& out);

    protected:
        LogoutHandler();
        
        /** Flag indicating whether the subclass is acting as a LogoutInitiator. */
        bool m_initiator;

        /** Array of query string parameters to preserve across front-channel notifications, if present. */
        std::vector<std::string> m_preserve;

        /**
         * Perform front-channel logout notifications for an Application.
         *
         * @param request       last request from browser
         * @param params        map of query string parameters to preserve across this notification
         * @return  indicator of a completed response along with the status code to return from the handler
         */
        std::pair<bool,long> notifyFrontChannel(
            SPRequest& request, const std::map<std::string,std::string>* params=nullptr
            ) const;

        /**
         * Perform back-channel logout notifications for an Application.
         *
         * @param request       request resulting in method call
         * @param sessions      array of session keys being logged out
         * @param local         true iff the logout operation is local to the SP, false iff global
         * @return  true iff all notifications succeeded
         */
        bool notifyBackChannel(
            const SPRequest& request, const std::vector<std::string>& sessions, bool local
            ) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __shibsp_logout_h__ */
