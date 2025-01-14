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

#ifndef __shibsp_iisconfig_h__
#define __shibsp_iisconfig_h__

#include <shibsp/util/BoostPropertySet.h>

#include <memory>

namespace shibsp {
    namespace iis {

        class ModuleConfig : public virtual PropertySet {
            MAKE_NONCOPYABLE(ModuleConfig);
        public:
            ModuleConfig();
            virtual ~ModuleConfig();

            /**
             * Get the configuration for a specific IIS site.
             * 
             * @param id site ID
             * @return site configuration expressed as a PropertySet
             */
            virtual const PropertySet* getSiteConfig(const char* id) const=0;

            /**
             * Create and return an instance of this class for use.
             * 
             * <p>The underlying agent library must be initialized before calling this method.</p>
             * <p>The path will be derived from the IISConfigPath global agent property if not supplied.</p>
             * <p>Paths must end in ".ini" or ".xml" and will be parsed accordingly.</p>
             * 
             * @param path optional path to config file to load
             */
            static std::unique_ptr<ModuleConfig> newModuleConfig(const char* path=nullptr);

            // Global
            static const char USE_VARIABLES_PROP_NAME[];
            static const char USE_HEADERS_PROP_NAME[];
            static const char AUTHENTICATED_ROLE_PROP_NAME[];
            static const char ROLE_ATTRIBUTES_PROP_NAME[];
            static const char NORMALIZE_REQUEST_PROP_NAME[];
            static const char SAFE_HEADER_NAMES_PROP_NAME[];
            static const char HANDLER_PREFIX_PROP_NAME[];

            static bool USE_VARIABLES_PROP_DEFAULT;
            static bool USE_HEADERS_PROP_DEFAULT;
            static const char AUTHENTICATED_ROLE_PROP_DEFAULT[];
            static bool NORMALIZE_REQUEST_PROP_DEFAULT;
            static const char HANDLER_PREFIX_PROP_DEFAULT[];

            // Site
            static const char SITE_NAME_PROP_NAME[];
            static const char SITE_SCHEME_PROP_NAME[];
            static const char SITE_PORT_PROP_NAME[];
            static const char SITE_SSLPORT_PROP_NAME[];
            static const char SITE_ALIASES_PROP_NAME[];
        };
    };
};

#endif // __shibsp_iisconfig_h__
