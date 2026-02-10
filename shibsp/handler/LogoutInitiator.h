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
 * @file shibsp/handler/LogoutInitiator.h
 * 
 * Handler that initiates logout.
 */

#ifndef __shibsp_logoutinitiator_h__
#define __shibsp_logoutinitiator_h__

#include <shibsp/handler/LogoutHandler.h>

#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

    /**
     * Marker interface for handlers that can initiate logout.
     */
    class SHIBSP_API LogoutInitiator : public virtual LogoutHandler
    {
    public:
        LogoutInitiator(const boost::property_tree::ptree& pt);
        virtual ~LogoutInitiator();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
    };

};

#endif /* __shibsp_logoutinitiator_h__ */
