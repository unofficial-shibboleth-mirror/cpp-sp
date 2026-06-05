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
 * @file shibsp/io/HTTPResponse.h
 * 
 * Interface to HTTP responses issued by agents.
 */

#ifndef __shibsp_httpres_h__
#define __shibsp_httpres_h__

#include <shibsp/base.h>

#include <string>
#include <vector>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to HTTP response issued by agents.
     * 
     * <p>To supply information to the surrounding web server environment,
     * a shim must be supplied in the form of this interface to adapt the
     * library to different proprietary server APIs. Typically this
     * is done via implementation of SPRequest.</p>
     * 
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API HTTPResponse {
        MAKE_NONCOPYABLE(HTTPResponse);
    protected:
        HTTPResponse();
    public:
        virtual ~HTTPResponse();
        
        /**
         * Sets, adds, or clears a response header.
         * 
         * <p>The default implementation polices name and value for control characters.</p>
         * 
         * @param name  header name
         * @param value value to set, or nullptr to clear
         * @param replace true iff this should replace existing header(s)
         */
        virtual void setResponseHeader(const char* name, const char* value, bool replace = false);

        /**
         * Sets or clears the MIME type of the response.
         * 
         * @param type the MIME type, or nullptr to clear
         */
        virtual void setContentType(const char* type=nullptr);

        /**
         * Sends a completed response to the client.
         * 
         * @param inputStream   reference to source of response data
         * @param status        transport-specific status to return
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendResponse(std::istream& inputStream, long status=SHIBSP_HTTP_STATUS_OK)=0;

        /**
         * Sends an "error" response to the client along with a
         * transport-specific error indication.
         * 
         * @param inputStream   reference to source of response data
         * @return a result code to return from the calling MessageEncoder
         */
        virtual long sendError(std::istream& inputStream);
        
        /**
         * Redirect the client to the specified URL and complete the response.
         * 
         * <p>Any headers previously set will be sent ahead of the redirect.</p>
         * 
         * <p>The flag, which defaults to false, controls whether the redirect should
         * be permitted blindly or if true, policed by local redirect-limiting policy.</p>
         *
         * @param url   location to redirect client
         * @param limit true iff the redirect should be limited and reviewed against policy
         * 
         * @return a result code to return
         */
        virtual long sendRedirect(const char* url, bool limit=false)=0;
        
        /** Some common HTTP status codes. */
        enum status_t {
            SHIBSP_HTTP_STATUS_OK = 200,
            SHIBSP_HTTP_STATUS_MOVED = 302,
            SHIBSP_HTTP_STATUS_NOTMODIFIED = 304,
            SHIBSP_HTTP_STATUS_BADREQUEST = 400,
            SHIBSP_HTTP_STATUS_UNAUTHORIZED = 401,
            SHIBSP_HTTP_STATUS_FORBIDDEN = 403,
            SHIBSP_HTTP_STATUS_NOTFOUND = 404,
            SHIBSP_HTTP_STATUS_ERROR = 500
        };
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
};

#endif /* __shibsp_httpres_h__ */
