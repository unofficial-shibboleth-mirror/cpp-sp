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
 * @file shibsp/util/CookieManager.h
 * 
 * Manages reading and writing HTTP cookies.
 */

#ifndef __shibsp_cookiemgr_h__
#define __shibsp_cookiemgr_h__

#include <shibsp/base.h>

#include <map>
#include <string>

namespace shibsp {

    class SHIBSP_API SPRequest;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * HTTP cookie reading and writing helper object.
     * 
     * <p>This is a thread-safe object that encapsulates some of the older SP's messy handling
     * of cookie names and properties in various use cases. The name of the cookie managed is
     * determined by combining various parameters together with the RequestMapper settings
     * associated with the request provided to the mutating methods.</p>
     * 
     * <p>The only required input for use of the object is the default cookie name, input
     * to the constructor. The other settings default to absent, and the default max-age to
     * -1, indicating a per-session cookie (which in practice are semi-permanent now).</p>
     */
    class SHIBSP_API CookieManager
    {
        MAKE_NONCOPYABLE(CookieManager);
    public:
        /**
         * Constructor.
         * 
         * @param default basis for cookie name
         */
        CookieManager(const char* defaultName);

        /**
         * Destructor.
         */
        ~CookieManager();

        /** Cookie SameSite values. */
        enum samesite_t {
            SAMESITE_ABSENT = 0,
            SAMESITE_NONE = 1,
            SAMESITE_LAX = 2,
            SAMESITE_STRICT = 3
        };

        /**
         * Installs controls governing the generation of the name of the cookie managed by this
         * object.
         * 
         * <p>If the override property is specified and is present in the request's content
         * settings, then it will stipulate the exact cookie name to use.</p>
         * 
         * <p>If no override property is specified, or if the named property is not present in
         * the request's content settings, then the default name will be used unless modified by
         * the applicationSpecific flag. If set, the default name will be decorated by adding
         * a suffix generated from the agent and applicable "applicationId" setting for the request.</p>
         * 
         * @param overrideProperty name of request/content setting that if present will override
         *      the default cookoe name
         * @param applicationSpecific whether the default cookie name, if not overridden, should be
         *      decorated so as to be unique to the agent and request's applicationId setting
         */
        void setCookieNamePolicy(const char* overrideProperty=nullptr, bool applicationSpecific=false);

        /**
         * Sets the path attribute for cookies created by this object.
         * 
         * <p>Defaults to "/".</p>
         * 
         * @param path path to set
         */
        void setPath(const char* path);

        /**
         * Sets the domain attribute for cookies created by this object.
         * 
         * <p>Defaults to absent.</p>
         * 
         * @param domain domain to set
         */
        void setDomain(const char* domain);

        /**
         * Sets the default max-age for cookies created by this object.
         * 
         * <p>Defaults to -1.</p>
         * 
         * @param maxAge max-age value
         */
        void setMaxAge(int maxAge);

        /**
         * Sets default Secure attribute for cookies created by this object.
         * 
         * <p>Defaults to true.</p>
         * 
         * @param secure value of attribute
         */
        void setSecure(bool secure);

        /**
         * Sets default HttpOnly attribute for cookies created by this object.
         * 
         * <p>Defaults to true.</p>
         * 
         * @param httpOnly value of attribute
         */
        void setHttpOnly(bool httpOnly);

        /**
         * Sets default SameSite attribute for cookies created by this object.
         * 
         * <p>Defaults to absent.</p>
         * 
         * @param sameSiteValue attribute value
         */
        void setSameSite(samesite_t sameSiteValue);

        /**
         * Sets default SameSite attribute for cookies created by this object.
         * 
         * <p>Defaults to absent.</p>
         * 
         * @param sameSiteValue attribute value
         */
        void setSameSite(const char* sameSiteValue);
        
        /**
         * Adds a cookie with the specified value to the outgoing response for the supplied request.
         * 
         * <p>The name is determined per the settings configured on this object and the settings
         * associated with the request.</p>
         * 
         * <p>The value will NOT be encoded by this method and must be encoded by the caller
         * if necessary.</p>
         * 
         * @param request the request to operate on
         * @param value cookie value
         */
        void setCookie(SPRequest& request, const char* value) const;

        /**
         * Unsets a cookie via the outgoing response for the supplied request.
         * 
         * <p>The name is determined per the settings configured on this object and the settings
         * associated with the request.</p>
         * 
         * @param request the request to operate on
         */
        void unsetCookie(SPRequest& request) const;

        /**
         * Gets the value (if any) for the specified cookie.
         * 
         * <p>If multiple cookies of the same name are present, it is unspecified
         * which value will be returned.</p>
         * 
         * @param request the request to operate on
         * 
         * @return a value for the named cookie, or nullptr if none exists
         */
        const char* getCookieValue(const SPRequest& request) const;
        
    private:
        std::string computeCookieName(const SPRequest& request) const;
        void outputHeader(SPRequest& request, const char* value, int maxAge) const;

        std::string m_defaultName;
        std::string m_overrideProperty;
        bool m_appSpecific;
        std::string m_path;
        std::string m_domain;
        int m_maxAge;
        bool m_secure;
        bool m_httpOnly;
        samesite_t m_sameSiteValue;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_cookiemgr_h__ */
