/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * logging/impl/AbstractLoggingService.cpp
 *
 * Base class for logging service implementations.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "logging/impl/AbstractLoggingService.h"

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
    class CategoryImpl : public virtual Category {
    public:
        CategoryImpl(LoggingServiceSPI& spi, const std::string& name, Priority::Value priority)
            : Category(spi, name, priority) {
        }
    };

    //extern LoggingService* SHIBSP_DLLLOCAL ConsoleLoggingServiceFactory(const ptree& pt, bool);
#ifdef WIN32
    extern LoggingService* SHIBSP_DLLLOCAL WindowsLoggingServiceFactory(const ptree& pt, bool);
#else
    //extern LoggingService* SHIBSP_DLLLOCAL SyslogLoggingServiceFactory(const ptree& pt, bool);
#endif
}

void SHIBSP_API shibsp::registerLoggingServices()
{
    AgentConfig& conf=AgentConfig::getConfig();
    //conf.LoggingServiceManager.registerFactory(CONSOLE_LOGGING_SERVICE, ConsoleLoggingServiceFactory);
#ifdef WIN32
    conf.LoggingServiceManager.registerFactory(WINDOWS_LOGGING_SERVICE, WindowsLoggingServiceFactory);
#else
    //conf.LoggingServiceManager.registerFactory(SYSLOG_LOGGING_SERVICE, SyslogLoggingServiceFactory);
#endif
}

LoggingService::LoggingService() {}

LoggingService::~LoggingService() {}

LoggingServiceSPI::LoggingServiceSPI() {}

LoggingServiceSPI::~LoggingServiceSPI() {}

AbstractLoggingService::~AbstractLoggingService() {}

AbstractLoggingService::AbstractLoggingService(const ptree& pt)
{
    // Processes property tree to create mappings from category name to logging level.
    // If an invalid property token is seen, the default level is SHIB_INFO.
}

Category& AbstractLoggingService::getCategory(const std::string& name)
{
    lock_guard<mutex> locker(m_lock);

    auto cat = m_categoryMap.find(name);
    if (cat != end(m_categoryMap)) {
        return *(cat->second);
    }

    // Whoever designed STL's map interface is some kind of sadistic psychppath.

    auto iter = m_priorityMap.find(name);
    Priority::PriorityLevel prio = iter != end(m_priorityMap) ? iter->second : m_defaultPriority;
    
    auto map_insert_result = m_categoryMap.insert({name, unique_ptr<Category>(new CategoryImpl(*this, name, prio))});
    // The insert result is a pair<iterator,bool> and the map's value is a pair<key.value>, thus....
    return *(map_insert_result.first->second.get());
}
