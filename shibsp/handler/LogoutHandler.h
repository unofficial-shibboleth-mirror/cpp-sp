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
 * @file shibsp/handler/LogoutHandler.h
 * 
 * Base class for logout-related handlers.
 */

#ifndef __shibsp_logout_h__
#define __shibsp_logout_h__

#include <shibsp/handler/Handler.h>

#include <map>
#include <string>
#include <vector>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for logout-related handlers, both when initiating from the
     * Agent or processing incoming requests or responses from other systems.
     */
    class SHIBSP_API LogoutHandler : public virtual Handler
    {
    public:
        virtual ~LogoutHandler();

        /**
         * The base method will iteratively attempt front-channel notification
         * of logout of the current session.
         * 
         * <p>Nothing will be done unless the handler detects that it is the "top" level
         * logout handler. If the method returns false, then the specialized class should
         * perform its work assuming that the notifications are completed.</p>
         *
         * <p>Note that the current session is NOT removed from the cache.</p>
         * 
         * @param request   SP request
         * @param isHandler true iff executing in the context of a direct handler invocation
         * @return  a pair containing a "request completed" indicator and a server-specific response code
         */
        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

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

    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __shibsp_logout_h__ */
