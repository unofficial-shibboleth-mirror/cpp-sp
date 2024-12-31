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
 * @file shibsp/remoting/RemotingService.h
 *
 * Interface to a remoting service for agent/hub communication.
 */

#ifndef __shibsp_remotingservice_h__
#define __shibsp_remotingservice_h__

#include <shibsp/remoting/ddf.h>

namespace shibsp {

    /**
     * Interface to a remoting service.
     *
     * A RemotingService supports the remoting of DDF objects. It is responsible
     * for marshalling and transmitting messages, as well as managing connections
     * and communication errors.
     */
    class SHIBSP_API RemotingService
    {
    protected:
        RemotingService();
    public:
        virtual ~RemotingService();

        /**
         * Send a remoted message and return the response.
         *
         * @param in    input message to send
         * @return      response from remote service
         */
        virtual DDF send(const DDF& in)=0;
    };

    /**
     * Registers RemotingService classes into the runtime.
     */
    void SHIBSP_API registerRemotingServices();

    /** RemotingService based on an HTTP transport layer */
    #define HTTP_REMOTING_SERVICE "HTTP"
};

#endif /* __shibsp_remotingservice_h__ */
