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
 * logging/impl/SyslogLoggingService.cpp
 *
 * Logging service implementation using syslog.
 */

#include "internal.h"
#include "logging/impl/AbstractLoggingService.h"
#include "util/Misc.h"

#include <syslog.h>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace boost;
using namespace std;

namespace shibsp {

    class SyslogLoggingService : public virtual AbstractLoggingService {
    public:
        SyslogLoggingService(const ptree& pt);

        bool init();
        void term();

        void outputMessage(const Category& category, Priority::Value prio, const string& message) {
            outputMessage(category, prio, message.c_str());
        }
        void outputMessage(const Category& category, Priority::Value prio, const char* message);

    private:
        static int getSyslogPriority(Priority::Value prio);

        bool m_open;
        int m_facility;
    };

    LoggingService* SHIBSP_DLLLOCAL SyslogLoggingServiceFactory(ptree& pt, bool) {
        return new SyslogLoggingService(pt);
    }

}

SyslogLoggingService::SyslogLoggingService(const ptree& pt)
    : AbstractLoggingService(pt), m_open(false), m_facility(LOG_USER)
{
    static const char OPENSYSLOG_PROP_PATH[] = "logging.openSyslog";
    static const char FACILITY_PROP_PATH[] = "logging.facility";

    string_to_bool_translator tr;
    m_open = pt.get(OPENSYSLOG_PROP_PATH, true, tr);

    string opt = pt.get(FACILITY_PROP_PATH, "0");
    try {
        m_facility = lexical_cast<int>(opt);
        if (m_facility == 0) {
            m_facility = LOG_USER;
        }
    } catch (const bad_lexical_cast& e) {
        m_facility = LOG_USER;
    }
}

bool SyslogLoggingService::init()
{
    if (!AbstractLoggingService::init()) {
        return false;
    }

    if (m_open) {
        openlog(PACKAGE, 0, m_facility);
    }

    return true;
}

void SyslogLoggingService::term()
{
    if (m_open) {
        closelog();
    }
    AbstractLoggingService::term();
}

int SyslogLoggingService::getSyslogPriority(Priority::Value prio)
{
    switch (prio) {
        case Priority::SHIB_DEBUG:
            return LOG_DEBUG;
        case Priority::SHIB_INFO:
            return LOG_INFO;
        case Priority::SHIB_WARN:
            return LOG_WARNING;
        case Priority::SHIB_ERROR:
            return LOG_ERR;
        case Priority::SHIB_CRIT:
            return LOG_CRIT;
        default:
            return LOG_INFO;
    }
}

void SyslogLoggingService::outputMessage(const Category& category, Priority::Value prio, const char* message)
{
    string s("[");
    s += category.getName();
    s += "] - ";
    if (message) {
        s += message;
    }

    syslog(getSyslogPriority(prio) | m_facility, "%s", s.c_str());
}
