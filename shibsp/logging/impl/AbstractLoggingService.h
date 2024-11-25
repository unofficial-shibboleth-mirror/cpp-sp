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
 * shibsp/logging/AbstractLoggingService.h
 *
 * Base class for LoggingService/SPI implementations.
 */

#ifndef __shibsp_abstractlogging_h__
#define __shibsp_abstractlogging_h__

#include "internal.h"
#include "logging/impl/LoggingServiceSPI.h"

#include <map>
#include <memory>
#include <string>
#include <thread>
#include <shibsp/logging/LoggingService.h>
#include <shibsp/logging/Priority.h>

#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

     /**
     * Base class for logging services that handles category management.
     * 
     * The root property tree passed to the constructor must contain subkeys named "logging" and
     * "logging-levels" to configure both the default and per-category logging levels:
     * 
     * [logging]
     * default-level = INFO
     * 
     * [logging-categories]
     * categoryname = WARN
     * categoryname.subcategoryname = DEBUG
     * 
     * Inheritance of logging levels is not an implementation requirement at this time.
     */
    class SHIBSP_API AbstractLoggingService : public virtual LoggingService, public virtual LoggingServiceSPI
    {
        MAKE_NONCOPYABLE(AbstractLoggingService);
    protected:
        AbstractLoggingService(const boost::property_tree::ptree& pt);
    public:
        virtual ~AbstractLoggingService();

        Category& getCategory(const std::string& name);

        static const char LOGGING_SECTION_NAME[];
        static const char CATEGORIES_SECTION_NAME[];
        static const char DEFAULT_LEVEL_PROP_PATH[];

    private:
        // Default logging level.
        Priority::Value m_defaultPriority;

        // Result of parsing configuration.
        std::map<std::string,Priority::Value> m_priorityMap;

        // Manages shared Category objects.
        std::map<std::string,std::unique_ptr<Category>> m_categoryMap;

        // Guards category map.
        std::mutex m_lock;
    };

};

#endif /* __shibsp_abstractlogging_h__ */
