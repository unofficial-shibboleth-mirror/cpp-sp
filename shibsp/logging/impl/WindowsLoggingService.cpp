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
  * logging/impl/WindowsLoggingService.cpp
  *
  * Logging service implementation using the Windows Event log.
  */

#include "internal.h"
#include "logging/impl/AbstractLoggingService.h"
#include "exceptions.h"
#include "logging/priority.h"
#include "NativeEventLog.h"

#include <boost/property_tree/ptree.hpp>

#include <Windows.h>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

    class WindowsLoggingService : public virtual AbstractLoggingService {
    public:
        WindowsLoggingService(const ptree& pt);
        ~WindowsLoggingService();

        void outputMessage(const Category& category, Priority::Value prio, const string& message) {
            outputMessage(category, prio, message.c_str());
        }
        void outputMessage(const Category& category, Priority::Value prio, const char* message);

    protected:

        HANDLE m_EventSource;
    };

    LoggingService* SHIBSP_DLLLOCAL WindowsLoggingServiceFactory(ptree& pt, bool) {
        return new WindowsLoggingService(pt);
    }
}

WindowsLoggingService::WindowsLoggingService(const ptree& pt) : AbstractLoggingService(pt)
{
    // No dedicated settings at the moment, might be worth supporting some kind of
    // message formatting.
    m_EventSource = ::RegisterEventSourceA(NULL, SHIB_EVENT_SOURCE_NAME);

    if (m_EventSource == NULL) {
        string error("Could not load event source check HKLM\\SYSTEM\\CurrentControlSet\\EventLog\\Application\\" SHIB_EVENT_SOURCE_NAME ".  GLE = ");
        error += to_string(GetLastError());
        throw ConfigurationException(error.c_str());
    }
}

WindowsLoggingService::~WindowsLoggingService() {

    if (m_EventSource) {
        ::DeregisterEventSource(m_EventSource);
    }
}

static DWORD EventIdFor(const DWORD priority) {

    if (priority < Priority::PriorityLevel::SHIB_ERROR) {
        return SHIBSP_LOG_CRIT;
    }
    if (priority < Priority::PriorityLevel::SHIB_WARN) {
        return SHIBSP_LOG_ERROR;
    }
    if (priority < Priority::PriorityLevel::SHIB_INFO) {
        return SHIBSP_LOG_WARN;
    }
    if (priority < Priority::PriorityLevel::SHIB_DEBUG) {
        return SHIBSP_LOG_INFO;
    }
    return SHIBSP_LOG_DEBUG;
}

static WORD EventTypeFor(const DWORD priority) {
    if (priority < Priority::PriorityLevel::SHIB_WARN) {
        return EVENTLOG_ERROR_TYPE;
    }
    if (priority < Priority::PriorityLevel::SHIB_INFO) {
        return EVENTLOG_WARNING_TYPE;
    }
    if (priority < Priority::PriorityLevel::SHIB_DEBUG) {
        return EVENTLOG_INFORMATION_TYPE;
    }
    return EVENTLOG_SUCCESS;
}

static WORD EventCategoryFor(const DWORD priority) {

    if (priority < Priority::PriorityLevel::SHIB_ERROR) {
        return (WORD) SHIBSP_CATEGORY_CRIT;
    }
    if (priority < Priority::PriorityLevel::SHIB_WARN) {
        return (WORD) SHIBSP_CATEGORY_ERROR;
    }
    if (priority < Priority::PriorityLevel::SHIB_INFO) {
        return (WORD) SHIBSP_CATEGORY_WARN;
    }
    if (priority < Priority::PriorityLevel::SHIB_DEBUG) {
        return (WORD) SHIBSP_CATEGORY_INFO;
    }
    return (WORD) SHIBSP_CATEGORY_DEBUG;
}


void WindowsLoggingService::outputMessage(const Category& category, Priority::Value priority, const char* message)
{
    const char* msgs[2] {category.getName().c_str(),message};
    ::ReportEventA(m_EventSource, EventTypeFor(priority), EventCategoryFor(priority), EventIdFor(priority), NULL, 2, 0, msgs, NULL);
}
