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
 * logging/impl/FileLoggingService.cpp
 *
 * Logging service implementation using the console.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "logging/impl/AbstractLoggingService.h"
#include "util/Date.h"
#include "util/PathResolver.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

    class FileLoggingService : public virtual AbstractLoggingService {
    public:
        FileLoggingService(const ptree& pt);
        virtual ~FileLoggingService();

        void outputMessage(const Category& category, Priority::Value prio, const string& message) {
            outputMessage(category, prio, message.c_str());
        }
        void outputMessage(const Category& category, Priority::Value prio, const char* message);

    private:
        ofstream m_out;
    };

    LoggingService* SHIBSP_DLLLOCAL FileLoggingServiceFactory(ptree& pt, bool) {
        return new FileLoggingService(pt);
    }

}

FileLoggingService::FileLoggingService(const ptree& pt) : AbstractLoggingService(pt)
{
    static const char PATH_PROP_PATH[] = "logging.path";

    string path = pt.get(PATH_PROP_PATH, "");
    if (path.empty()) {
        throw ConfigurationException(string("No ") + PATH_PROP_PATH + " in [logging] section of configuration.");
    }
    AgentConfig::getConfig().getPathResolver().resolve(path, PathResolver::SHIBSP_LOG_FILE);

    m_out.open(path, ios_base::out | ios_base::app);
    if (!m_out) {
        throw ConfigurationException(string("Unable to open log file (") + path + ") for writing.");
    }
}

FileLoggingService::~FileLoggingService()
{
    m_out.close();
}

void FileLoggingService::outputMessage(const Category& category, Priority::Value prio, const char* message)
{
    auto now = chrono::system_clock::now();

    stringstream sink;
    sink << date::format("%FT%TZ", date::floor<chrono::milliseconds>(now)) << " - "
        << Priority::getPriorityName(prio)
        << " [" << category.getName() << "] - "
        << message
        << endl;
    
    m_out << sink.str();
    m_out.flush();
}
