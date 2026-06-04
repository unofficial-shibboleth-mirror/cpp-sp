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

#include <shibsp/base.h>

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
     * library to different proprietary server APIs. Typically this
     * is done via implementation of SPRequest.</p>
     * 
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API HTTPRequest {
        MAKE_NONCOPYABLE(HTTPRequest);
    protected:
        HTTPRequest();
    public:
        virtual ~HTTPRequest();

            /**
         * Returns the URL scheme of the request (http, https, ftp, ldap, etc.)
         *
         * @return the URL scheme
         */
        virtual const char* getScheme() const=0;

        /**
         * Returns true iff the request is over a confidential channel.
         *
         * @return confidential channel indicator
         */
        virtual bool isSecure() const;

        /**
         * Returns hostname of service that received request.
         *
         * @return hostname of service
         */
        virtual const char* getHostname() const=0;

        /**
         * Returns incoming port.
         *
         * @return  incoming port
         */
        virtual int getPort() const=0;

        /**
         * Returns true iff the request port is the default port for the request protocol.
         *
         * @return  default port indicator
         */
        virtual bool isDefaultPort() const;

        /**
         * Returns the MIME type of the request, if known.
         *
         * @return the MIME type, or an empty string
         */
        virtual std::string getContentType() const=0;

        /**
         * Returns the length of the request body, if known.
         *
         * @return the content length, or -1 if unknown
         */
        virtual long getContentLength() const=0;

        /**
         * Returns the raw request body.
         *
         * @return the request body, or nullptr
         */
        virtual const char* getRequestBody() const=0;

        /**
         * Returns a decoded named parameter value from the request.
         * If a parameter has multiple values, only one will be returned.
         *
         * @param name  the name of the parameter to return
         * @return a single parameter value or nullptr
         */
        virtual const char* getParameter(const char* name) const=0;

        /**
         * Returns all of the decoded values of a named parameter from the request.
         * All values found will be returned.
         *
         * @param name      the name of the parameter to return
         * @param values    a vector in which to return pointers to the decoded values
         * @return  the number of values returned
         */
        virtual std::vector<const char*>::size_type getParameters(
            const char* name, std::vector<const char*>& values
            ) const=0;

        /**
         * Returns the transport-authenticated identity associated with the request,
         * if authentication is solely handled by the transport.
         *
         * @return the authenticated username or an empty string
         */
        virtual std::string getRemoteUser() const=0;

        /**
         * Gets the authentication type associated with the request.
         *
         * @return  the authentication type or nullptr
         */
        virtual std::string getAuthType() const=0;

        /**
         * Returns the IP address of the client.
         *
         * @return the client's IP address
         */
        virtual std::string getRemoteAddr() const=0;

        /**
         * Returns the IP address of the server.
         *
         * @return the server's IP address
         */
        virtual std::string getLocalAddr() const=0;

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
         * Gets all the cookies supplied by the client.
         *
         * @return  a map of cookie name/value pairs
         */
        virtual const std::map<std::string,std::string>& getCookies() const=0;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_httpreq_h__ */
