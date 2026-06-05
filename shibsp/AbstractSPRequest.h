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
 * @file shibsp/AbstractSPRequest.h
 * 
 * Abstract base for SPRequest implementations.
 */

#ifndef __shibsp_abstreq_h__
#define __shibsp_abstreq_h__

#include <shibsp/SPRequest.h>

#include <memory>

namespace shibsp {
    
    class SHIBSP_API CGIParser;
    class SHIBSP_API Category;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Abstract base for SPRequest implementations
     */
    class SHIBSP_API AbstractSPRequest : public virtual SPRequest
    {
    protected:
        /**
         * Constructor.
         *
         * @param category  logging category to use
         */
        AbstractSPRequest(const char* category);
        
        /**
         * Stores a normalized request URI to ensure it contains no %-encoded characters
         * or other undesirable artifacts.
         *
         * @param uri   the request URI as obtained from the client
         */
        void setRequestURI(const char* uri);

    public:
        virtual ~AbstractSPRequest();

        /**
         * Returns a modifiable array of schemes to permit in sanitized URLs.
         *
         * <p>Updates to this array must be externally synchronized with any use
         * of this class or its subclasses.
         *
         * @return  a mutable array of strings containing the schemes to permit
         */
        static std::vector<std::string>& getAllowedSchemes();

        // Virtual function overrides.
        const Agent& getAgent() const;
        RequestMapper::Settings getRequestSettings() const;
        bool isUseHeaders() const;
        bool isUseVariables() const;
        std::unique_lock<Session> getSession(bool checkTimeout=true, bool ignoreAddress=false);
        Session* getCachedSession(bool checkTimeout=true, bool ignoreAddress=false);
        const char* getRequestURI() const;
        const char* getRequestURL() const;
        std::string getRemoteAddr() const;
        const char* getParameter(const char* name) const;
        std::vector<const char*>::size_type getParameters(const char* name, std::vector<const char*>& values) const;
        const std::map<std::string,std::string>& getCookies() const;
        const char* getHandlerURL(const char* resource=nullptr) const;
        std::string getNotificationURL(unsigned int index) const;

        std::string getSecureHeader(const char* name) const;
        void setAuthType(const char* authtype);

        // Calls doRedirect to perform the actual operation after
        // sanitzing the URL as required.
        long sendRedirect(const char* url, bool limit=false);

        void log(Priority::Value level, const std::exception& ex) const;
        void log(Priority::Value level, const std::string& msg) const;
        void log(Priority::Value level, const char* formatString, va_list args) const;
        bool isPriorityEnabled(Priority::Value level) const;

    protected:
        /**
         * Check for unsafe URLs vulnerable to injection attacks and promote
         * relative URLs to absolute based on current request.
         *
         * @param url   location to check/promote
         * 
         * @return sanitized and possibly altered URL
         */
        virtual long doRedirect(const char* url)=0;

        /**
         * Gets the transformed header name constructed from a raw input name by transforming
         * punctuation into underscores and prefixing with "HTTP_".
         * 
         * @return CGI name for input header name
         */ 
        std::string getCGINameForHeader(const char* name) const;

        /**
         * Optionally overrideable method to return logging context information to prefix
         * to request-specific logging.
         */
        virtual const char* getLogContext() const;

    private:
        static std::vector<std::string> m_allowedSchemes;
        void limitRedirect(const char* url) const;

        Category& m_log;
        Agent& m_agent;
        mutable RequestMapper* m_mapper;
        mutable RequestMapper::Settings m_settings;
        std::string m_uri;
        mutable std::string m_url;        
        mutable std::string m_handlerURL;
        mutable std::unique_ptr<CGIParser> m_parser;
        mutable std::map<std::string,std::string> m_cookieMap;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_abstreq_h__ */
