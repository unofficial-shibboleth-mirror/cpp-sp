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
 * remoting/impl/AbstractRemotingService.h
 *
 * Base class for remoting services.
 */

#ifndef __shibsp_absremotingservice_h__
#define __shibsp_absremotingservice_h__

#include "remoting/RemotingService.h"
#include "logging/Category.h"

#include <iostream>
#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

    /**
     * Base class for remoting services that handles data marshalling/unmarshalling.
     */
    class SHIBSP_API AbstractRemotingService : public virtual RemotingService
    {
    public:
        virtual ~AbstractRemotingService();

        /**
         * Send a remoted message and return the response.
         *
         * @param in    input message to send
         * @return      response from remote service
         */
        DDF send(const DDF& in, bool checkEvent=true) const;

        virtual Category& logger() const = 0;

    protected:
        AbstractRemotingService(const boost::property_tree::ptree& pt);

        /**
         * Work method for implementations to stream data to hub and
         * return response stream to read from.
         * 
         * @param path  URL path to append to base URL to construct request
         * @param input input data to stream to hub
         * @param output output stream to capture response
         */
        virtual void send(const char* path, std::istream& input, std::ostream& output) const=0;
    };

};

#endif /* __shibsp_absremotingservice_h__ */
