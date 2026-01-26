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
 * @file shibsp/SPRequest.h
 *
 * Interface to server request being processed.
 */

#ifndef __shibsp_req_h__
#define __shibsp_req_h__

#include <shibsp/RequestMapper.h>
#include <shibsp/io/HTTPRequest.h>
#include <shibsp/io/HTTPResponse.h>
#include <shibsp/logging/Priority.h>

#include <cstdarg>
#include <exception>
#include <mutex>

namespace shibsp {

    class SHIBSP_API Agent;
    class SHIBSP_API Session;

    /**
     * Interface to server request being processed
     *
     * <p>To supply information from the surrounding web server environment,
     * a shim must be supplied in the form of this interface to adapt the
     * library to different proprietary server APIs.
     *
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API SPRequest : public virtual HTTPRequest, public virtual HTTPResponse
    {
    protected:
        SPRequest();
    public:
        virtual ~SPRequest();

        /**
         * Returns the Agent processing the request.
         *
         * @return reference to Agent
         */
        virtual const Agent& getAgent() const=0;

        /**
         * Returns RequestMapper Settings associated with the request, guaranteed
         * to be valid for the request's duration.
         *
         * @return copy of settings
         */
        virtual RequestMapper::Settings getRequestSettings() const=0;

        /**
         * Gets a server/vhost/site level determination as to the use of HTTP request headers
         * for publication of attribute data.
         * 
         * <p>Headers should never be used now but remain supported for compatibbility and
         * influence the behavior other system components. If any ambiguiity ever exists as
         * to the answer, true should be returned.</p>
         * 
         * @return true iff headers are being used
         */
        virtual bool isUseHeaders() const=0;

        /**
         * Gets a server/vhost/site level determination as to the use of server variables
         * for publication of attribute data.
         * 
         * @return true iff varables are being used
         */
        virtual bool isUseVariables() const=0;

        /**
         * Returns a locked Session associated with the request.
         * 
         * @param checkTimeout  true iff the last-used timestamp should be updated and any timeout policy enforced
         * @param ignoreAddress true iff all address checking should be ignored, regardless of policy
         * @return a locked mutex wrapper around the Session (or an empty wrapper if no Session exists)
         */
        virtual std::unique_lock<Session> getSession(bool checkTimeout=true, bool ignoreAddress=false)=0;

        /**
         * Returns the effective base Handler URL for a resource,
         * or the current request URL.
         *
         * @param resource  resource URL to compute handler for
         * @return  base location of handler
         */
        virtual const char* getHandlerURL(const char* resource=nullptr) const=0;

        /**
         * Returns the designated notification URL, or an empty string if no more locations are specified.
         *
         * @param front     true iff front channel notification is desired, false iff back channel is desired
         * @param index     zero-based index of URL to return
         * @return  the designated URL, or an empty string
         */
        virtual std::string getNotificationURL(bool front, unsigned int index) const=0;

        /**
         * Checks a proposed redirect URL against policy settings for legal redirects,
         * such as same-host restrictions or allowed domains, and raises an exception
         * in the event of a violation.
         *
         * @param url       an absolute URL to validate
         */
        virtual void limitRedirect(const char* url) const=0;

        /**
         * Returns a non-spoofable request header value, if possible.
         * Platforms that support environment export can redirect header
         * lookups by overriding this method.
         *
         * @param name  the name of the secure header to return
         * @return the header's value, or an empty string
         */
        virtual std::string getSecureHeader(const char* name) const=0;

        /**
         * Ensures no value exists for a request header by installing an empty or hardcoded
         * value.
         * 
         * <p>The input parameter must be the undecorated/transformed version of the header rather
         * than the one actually populated by a web server's CGI interface, i.e., this lacks the
         * HTTP_ prefix and punctuation conversion.</p>
         *
         * @param name  raw name of header to clear
         */
        virtual void clearHeader(const char* name)=0;

        /**
         * Sets a value for a request header.
         *
         * @param name  name of header to set
         * @param value value to set
         */
        virtual void setHeader(const char* name, const char* value)=0;

        /**
         * Establish REMOTE_USER identity in request.
         *
         * @param user  REMOTE_USER value to set or nullptr to clear
         */
        virtual void setRemoteUser(const char* user)=0;

        /**
         * Establish AUTH_TYPE for request.
         *
         * @param authtype  AUTH_TYPE value to set or nullptr to clear
         */
        virtual void setAuthType(const char* authtype)=0;

        /**
         * Log exception to native server environment.
         * 
         * @param level logging level
         * @param e exception
         */
        virtual void log(Priority::Value level, const std::exception& e) const=0;

        /**
         * Log to native server environment.
         *
         * @param level logging level
         * @param msg   message to log
         */
        virtual void log(Priority::Value level, const std::string& msg) const=0;

        /**
         * Log to native server environment using a formatting string and variable arguments.
         *
         * @param level logging level
         * @param formatString formatting string
         * @param args message arguments
         */
        virtual void log(Priority::Value level, const char* formatString, va_list args) const=0;

        void debug(const std::string& msg) const;
        void info(const std::string& msg) const;
        void warn(const std::string& msg) const;
        void error(const std::string& msg) const;
        void crit(const std::string& msg) const;

        void debug(const char* formatString, ...) const;
        void info(const char* formatString, ...) const;
        void warn(const char* formatString, ...) const;
        void error(const char* formatString, ...) const;
        void crit(const char* formatString, ...) const;

        /**
         * Test logging level.
         *
         * @param level logging level
         * @return true iff logging level is enabled
         */
        virtual bool isPriorityEnabled(Priority::Value level) const=0;

        /**
         * Indicates that processing was declined, meaning no action is required during this phase of processing.
         *
         * @return  a status code to pass back to the server-specific layer
         */
        virtual long returnDecline()=0;

        /**
         * Indicates that processing was completed.
         *
         * @return  a status code to pass back to the server-specific layer
         */
        virtual long returnOK()=0;
    };
};

#endif /* __shibsp_req_h__ */
