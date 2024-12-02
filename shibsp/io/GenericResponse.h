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
 * @file shibsp/io/GenericResponse.h
 * 
 * Interface to generic protocol responses issued by agents.
 */

#ifndef __shibsp_genres_h__
#define __shibsp_genres_h__

#include <shibsp/base.h>

#include <iostream>

namespace shibsp {
    
    /**
     * Interface to generic protocol responses issued by agents.
     * 
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API GenericResponse {
        MAKE_NONCOPYABLE(GenericResponse);
    protected:
        GenericResponse();
    public:
        virtual ~GenericResponse();

        /**
         * Sets or clears the MIME type of the response.
         * 
         * @param type the MIME type, or nullptr to clear
         */
        virtual void setContentType(const char* type=nullptr)=0;

        /**
         * Sends a completed response to the client along with a
         * transport-specific "OK" indication. Used for "normal" responses.
         * 
         * @param inputStream   reference to source of response data
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendResponse(std::istream& inputStream)=0;

        /**
         * Sends an "error" response to the client along with a
         * transport-specific error indication.
         * 
         * @param inputStream   reference to source of response data
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendError(std::istream& inputStream)=0;

        /**
         * Sends a completed response to the client.
         * 
         * @param inputStream   reference to source of response data
         * @param status        transport-specific status to return
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendResponse(std::istream& inputStream, long status)=0;
    };
};

#endif /* __shibsp_genres_h__ */
