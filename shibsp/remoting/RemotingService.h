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

    class SHIBSP_API SPRequest;

    /**
     * Interface to a remoting service.
     *
     * A RemotingService supports the remoting of DDF objects. It is responsible
     * for marshalling and transmitting messages, as well as managing connections
     * and communication errors.
     */
    class SHIBSP_API RemotingService
    {
        MAKE_NONCOPYABLE(RemotingService);
    protected:
        RemotingService();
    public:
        virtual ~RemotingService();

        /**
         * Builds a DDF to invoke a remote operation suitable to pass to
         * the send method.
         * 
         * <p>The caller owns the resulting object and it is guaranteed to be a structure.</p>
         * 
         * @param opname name of operation
         * @param application optional application ID to include
         * @param txid optional transaction identifier to include for debugging
         */
        virtual DDF build(const char* opname, const char* application=nullptr, const char* txid=nullptr) const=0;

        /**
         * Builds a DDF to invoke a remote operation suitable to pass to
         * the send method.
         * 
         * <p>The caller owns the resulting object and it is guaranteed to be a structure.</p>
         * 
         * @param opname name of operation
         * @param request active request from which to obtain information to include in call
         */
        virtual DDF build(const char* opname, const SPRequest& request) const;

        /**
         * Send a remoted message and return the response.
         * 
         * <p>The second parameter controls error detection. Operations typically
         * return an event field that will contain either "success" or signal some
         * error condition. If the flag is true/defaulted, the remoting layer will
         * examine the field and raise an OperationException containing the detected
         * event. If the flag is false, no detection occurs and the output is returned
         * without an exception.</p>
         * 
         * <p>Callers that invooke operations that are "expected" to produce
         * unusual events may use the flag to avoid triggering exceptions on what are
         * essentially "expected" control paths.</p>
         *
         * @param in    input message to send
         * @param checkEvent controls whether the event in the output is checked
         * 
         * @return      response from remote service
         */
        virtual DDF send(const DDF& in, bool checkEvent=true) const=0;
    };

    /**
     * Registers RemotingService classes into the runtime.
     */
    void SHIBSP_API registerRemotingServices();

    /** RemotingService based on HTTP using Curl library. */
    #define CURL_HTTP_REMOTING_SERVICE "CurlHTTP"

    /** RemotingService based on HTTP using WinHTTP library. */
    #define WIN_HTTP_REMOTING_SERVICE "WinHTTP"
};

#endif /* __shibsp_remotingservice_h__ */
