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
 * logging/impl/ConsoleLoggingService.cpp
 *
 * Logging service implementation using the console.
 */

#include "internal.h"
#include "logging/impl/AbstractLoggingService.h"
#include "util/Date.h"

#include <chrono>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

    class ConsoleLoggingService : public virtual AbstractLoggingService {
    public:
        ConsoleLoggingService(const ptree& pt);

        bool init() {}
        bool term() {}
        void outputMessage(const Category& category, const string& message) {
            outputMessage(category, message.c_str());
        }
        void outputMessage(const Category& category, const char* message);

    };

    LoggingService* SHIBSP_DLLLOCAL ConsoleLoggingServiceFactory(const ptree& pt, bool) {
        return new ConsoleLoggingService(pt);
    }

}

ConsoleLoggingService::ConsoleLoggingService(const ptree& pt) : AbstractLoggingService(pt)
{
    // No dedicated settings at the moment, might be worth supporting some kind of
    // message formatting.
}

void ConsoleLoggingService::outputMessage(const Category& category, const char* message)
{
    auto now = chrono::system_clock::now();

    cerr << date::format("%FT%TZ", date::floor<chrono::milliseconds>(now)) << " - "
        << Priority::getPriorityName(category.getPriority())
        << ' [' << category.getName() << "] - "
        << message
        << endl;
}