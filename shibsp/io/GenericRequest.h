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
 * @file shibsp/io/GenericRequest.h
 *
 * Interface to generic protocol requests handled by agents.
 */

#ifndef __shibsp_genreq_h__
#define __shibsp_genreq_h__

#include <xmltooling/unicode.h>

#include <map>
#include <string>
#include <vector>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Interface to generic protocol requests handled by agents.
     *
     * <p>This interface need not be threadsafe.</p>
     */
    class SHIBSP_API GenericRequest {
        MAKE_NONCOPYABLE(GenericRequest);
    protected:
        GenericRequest();
    public:
        virtual ~GenericRequest();

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
        virtual bool isSecure() const=0;

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
        virtual std::string getAuthType() const {
            return "";
        }

        /**
         * Returns the IP address of the client.
         *
         * @return the client's IP address
         */
        virtual std::string getRemoteAddr() const=0;

        /**
         * Converts a relative URL into an absolute one based on the properties of the request.
         *
         * @param url   input URL to convert, will be modified in place
         */
        virtual void absolutize(std::string& url) const;

        /**
         * Returns a language range to use in selecting language-specific
         * content for this request.
         * <p>The syntax is that of the HTTP 1.1 Accept-Language header, even
         * if the underlying request is not HTTP.
         *
         * @return an HTTP 1.1 syntax language range specifier
         */
        virtual std::string getLanguageRange() const {
            return "";
        }

        /**
         * Initializes the language matching process; call this method to begin the
         * matching process by calling the matchLang method.
         * <p>The language matching process is not thread-safe and must be externally
         * syncronized.
         *
         * @return  true iff language matching is possible
         */
        bool startLangMatching() const;

        /**
         * Continues the language matching process; additional calls to matchLang can
         * be done as long as this method returns true.
         * <p>The language matching process is not thread-safe and must be externally
         * syncronized.
         *
         * @return  true iff more ranges are available to match against
         */
        bool continueLangMatching() const;

        /**
         * Matches a language tag against the currently active range.
         * <p>The language matching process is not thread-safe and must be externally
         * syncronized.
         * 
         * @param tag   a language tag (e.g., an xml:lang value)
         * @return  true iff the tag matches the active range
         */
        bool matchLang(const XMLCh* tag) const;

        /**
         * Establish default handling of language ranges.
         * 
         * @param langFromClient    honor client's language preferences if any
         * @param defaultRange      priority list of space-delimited language tags to use by default
         */
        static void setLangDefaults(bool langFromClient, const XMLCh* defaultRange);

    private:
        typedef std::multimap< float,std::vector<xmltooling::xstring> > langrange_t;
        mutable langrange_t m_langRange;
        mutable langrange_t::const_reverse_iterator m_langRangeIter;
        static langrange_t m_defaultRange;
        static bool m_langFromClient;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_genreq_h__ */
