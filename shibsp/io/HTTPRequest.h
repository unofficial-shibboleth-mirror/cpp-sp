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
 * @file shibsp/io/HTTPRequest.h
 * 
 * Interface to HTTP requests handled by agents.
 */

#ifndef __shibsp_httpreq_h__
#define __shibsp_httpreq_h__

#include <shibsp/io/GenericRequest.h>

#include <map>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to HTTP requests handled by agents.
     * 
     * <p>To supply information from the surrounding web server environment,
     * a shim must be supplied in the form of this interface to adapt the
     * library to different proprietary server APIs.</p>
     * 
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API HTTPRequest : public GenericRequest {
    protected:
        HTTPRequest();
    public:
        virtual ~HTTPRequest();

        bool isSecure() const;
        bool isDefaultPort() const;
          
        /**
         * Returns the HTTP method of the request (GET, POST, etc.)
         * 
         * @return the HTTP method
         */
        virtual const char* getMethod() const=0;
        
        /**
         * Returns the request URI.
         * 
         * @return the request URI
         */
        virtual const char* getRequestURI() const=0;
        
        /**
         * Returns the complete request URL, including scheme, host, port, and URI.
         * 
         * @return the request URL
         */
        virtual const char* getRequestURL() const=0;

        /**
         * Returns the HTTP query string appened to the request. The query
         * string is returned without any decoding applied, everything found
         * after the ? delimiter. 
         * 
         * @return the query string
         */
        virtual const char* getQueryString() const=0;

        /**
         * Returns a request header value.
         * 
         * @param name  the name of the header to return
         * @return the header's value, or an empty string
         */
        virtual std::string getHeader(const char* name) const=0;

        /**
        * Get a cookie value supplied by the client.
        * 
        * @param name  name of cookie
        * @return  cookie value or nullptr
        */
        virtual const char* getCookie(const char* name) const;

        /**
         * Get a cookie value supplied by the client.
         *
         * The boolean flag enables the workaround for older clients with
         * broken SameSite support by looking for a second cookie with
         * a decorated name that would not carry the SameSite flag.
         * 
         * @param name  name of cookie
         * @param sameSiteFallback enables lookaside to fallback cookie name
         * @return  cookie value or nullptr
         */
        virtual const char* getCookie(const char* name, bool sameSiteFallback) const;

        /**
         * Gets all the cookies supplied by the client.
         *
         * @return  a map of cookie name/value pairs
         */
        virtual const std::map<std::string,std::string>& getCookies() const;

    private:
        mutable std::map<std::string,std::string> m_cookieMap;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_httpreq_h__ */
