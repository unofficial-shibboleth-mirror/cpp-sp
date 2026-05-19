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

#include <shibsp/handler/AbstractHandler.h>

#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Base class for logout-related handlers, both when initiating from the
     * Agent or processing incoming requests or responses from other systems.
     */
    class SHIBSP_API LogoutHandler : public virtual AbstractHandler
    {
    public:
        virtual ~LogoutHandler();

    protected:
        LogoutHandler(const boost::property_tree::ptree& pt);
        
        /** Flag indicating whether the subclass is acting as a LogoutInitiator. */
        bool m_initiator;

        /**
         * Perform front-channel logout notifications for an Application.
         *
         * @param request       last request from browser
         * @param continueOnly  flag indicating whether to initiate notification or only continue/complete it
         * @param token         optional token string/parameter from Hub when initiating the loop
         * 
         * @return indicator of a completed response along with the status code to return from the handler
         */
        std::pair<bool,long> notifyFrontChannel(SPRequest& request, bool continueOnly=true, const char* token=nullptr) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __shibsp_logout_h__ */
