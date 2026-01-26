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
 * remoting/impl/AbstractRemotingService.cpp
 *
 * Base class for remoting services.
 */

#include "internal.h"
#include "exceptions.h"
#include "remoting/impl/AbstractRemotingService.h"

#include <sstream>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

AbstractRemotingService::AbstractRemotingService(const ptree&) {}

AbstractRemotingService::~AbstractRemotingService() {}

DDF AbstractRemotingService::send(const DDF& in, bool checkEvent) const
{
    stringstream instream;
    instream << in;

    stringstream outstream;
    send(in.name(), instream, outstream);

    DDF output;
    outstream >> output;

    if (!checkEvent) {
        return output;
    }
    const char* event = output.getmember("event").string();
    if (event && strcmp(event, "success")) {
        string message("Remote operation (");
        message += in.name() ? in.name() : "unknown";
        message += ") failed with event: ";
        message += event;
        OperationException ex(message);
        ex.addProperty(AgentException::EVENT_PROP_NAME, event);
        if (in.name()) {
            ex.addProperty("operation", in.name());
        }
        const char* target = output.getmember("target").string();
        if (target) {
            ex.addProperty(AgentException::TARGET_PROP_NAME, target);
        }
        output.destroy();
        throw ex;
    }
    return output;
}
