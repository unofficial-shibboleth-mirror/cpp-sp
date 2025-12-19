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
 * @file shibsp/RequestMapper.h
 * 
 * Interface to a request mapping plugin
 */

#ifndef __shibsp_reqmap_h__
#define __shibsp_reqmap_h__

#include <shibsp/util/Lockable.h>

#include <tuple>

namespace shibsp {

    class SHIBSP_API AccessControl;
    class SHIBSP_API HTTPRequest;
    class SHIBSP_API PropertySet;

    /**
     * Interface to a request mapping plugin
     * 
     * Request mapping plugins return configuration settings that apply to resource requests.
     * They can be implemented through cross-platform or platform-specific mechanisms.
     */
    class SHIBSP_API RequestMapper : public virtual SharedLockable
    {
        MAKE_NONCOPYABLE(RequestMapper);
    protected:
        RequestMapper();
    public:
        virtual ~RequestMapper();

        /** Combination of configuration settings and effective access control. */
        typedef std::pair<const PropertySet*,AccessControl*> Settings;

        static const char APPLICATION_ID_PROP_NAME[];
        static const char ATTRIBUTE_CONFIG_ID_PROP_NAME[];
        static const char ATTRIBUTE_VALUE_DELIMITER_PROP_NAME[];
        static const char AUTH_TYPE_PROP_NAME[];
        static const char CONSISTENT_ADDRESS_PROP_NAME[];
        static const char COOKIE_MAXAGE_PROP_NAME[];
        static const char EXPIRE_REDIRECTS_PROP_NAME[];
        static const char HANDLER_CONFIG_ID_PROP_NAME[];
        static const char HANDLER_SSL_PROP_NAME[];
        static const char HANDLER_URL_PROP_NAME[];
        static const char HOME_URL_PROP_NAME[];
        static const char LIFETIME_PROP_NAME[];
        static const char PRESERVE_POST_DATA_PROP_NAME[];
        static const char POST_LIMIT_PROP_NAME[];
        static const char REDIRECT_ALLOW_PROP_NAME[];
        static const char REDIRECT_ERRORS_PROP_NAME[];
        static const char REDIRECT_LIMIT_PROP_NAME[];
        static const char REDIRECT_TO_SSL_PROP_NAME[];
        static const char REMOTE_USER_PROP_NAME[];
        static const char REQUIRE_SESSION_PROP_NAME[];
        static const char REQUIRE_LOGOUT_WITH_PROP_NAME[];
        static const char SESSION_COOKIE_NAME_PROP_NAME[];
        static const char SESSION_HOOK_PROP_NAME[];
        static const char TARGET_PROP_NAME[];
        static const char TIMEOUT_PROP_NAME[];
        static const char USE_HEADERS_PROP_NAME[];
        static const char USE_VARIABLES_PROP_NAME[];

        static const char APPLICATION_ID_PROP_DEFAULT[];
        static const char ATTRIBUTE_VALUE_DELIMITER_PROP_DEFAULT[];
        static bool CONSISTENT_ADDRESS_PROP_DEFAULT;
        static bool EXPIRE_REDIRECTS_PROP_DEFAULT;
        static bool HANDLER_SSL_PROP_DEFAULT;
        static const char HANDLER_URL_PROP_DEFAULT[];
        static const char HOME_URL_PROP_DEFAULT[];
        static unsigned int LIFETIME_PROP_DEFAULT;
        static bool PRESERVE_POST_DATA_PROP_DEFAULT;
        static unsigned int POST_LIMIT_PROP_DEFAULT;
        static const char REDIRECT_LIMIT_PROP_DEFAULT[];
        static bool REQUIRE_SESSION_PROP_DEFAULT;
        static unsigned int TIMEOUT_PROP_DEFAULT;
        static bool USE_HEADERS_PROP_DEFAULT;
        static bool USE_VARIABLES_PROP_DEFAULT;

        /**
         * Map request to settings.
         * 
         * @param request   SP request
         * @return configuration settings and effective AccessControl plugin, if any
         */        
        virtual Settings getSettings(const HTTPRequest& request) const=0;
    };

    /**
     * Registers RequestMapper classes into the runtime.
     */
    void SHIBSP_API registerRequestMappers();

    /** XML-based RequestMapper implementation. */
    #define XML_REQUEST_MAPPER      "XML"

    /** Hybrid of XML and platform-specific configuration. */
    #define NATIVE_REQUEST_MAPPER   "Native"
};

#endif /* __shibsp_reqmap_h__ */
