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
 * handler/impl/LogoutHandler.cpp
 *
 * Base class for logout-related handlers.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/LogoutHandler.h"
#include "util/URLEncoder.h"

#include <fstream>
#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

LogoutHandler::LogoutHandler() : m_initiator(true)
{
}

LogoutHandler::~LogoutHandler()
{
}

pair<bool,long> LogoutHandler::run(SPRequest& request, bool isHandler) const
{
    // If this isn't a LogoutInitiator, we only "continue" a notification loop, rather than starting one.
    if (!m_initiator && !request.getParameter("notifying"))
        return make_pair(false,0L);

    // Try another front-channel notification. No extra parameters and the session is implicit.
    return notifyFrontChannel(request);
}

pair<bool,long> LogoutHandler::notifyFrontChannel(SPRequest& request, const map<string,string>* params) const
{
    // Index of notification point starts at 0.
    unsigned int index = 0;
    const char* param = request.getParameter("index");
    if (param && isdigit(*param)) {
        index = atoi(param);
    }

    // "return" is a backwards-compatible "eventual destination" to go back to after logout completes.
    param = request.getParameter("return");

    // Fetch the next front notification URL and bump the index for the next round trip.
    string loc = request.getNotificationURL(true, index++);
    if (loc.empty()) {
        return make_pair(false,0L);
    }

    const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();

    // Start with an "action" telling the application what this is about.
    loc = loc + (strchr(loc.c_str(),'?') ? '&' : '?') + "action=logout";

    // Now we create a second URL representing the return location back to us.
    const char* start = request.getRequestURL();
    const char* end = strchr(start, '?');
    string locstr(start, end ? end - start : strlen(start));

    // Add a signal that we're coming back from notification and the next index.
    locstr = locstr + "?notifying=1&index=" + boost::lexical_cast<string>(index);

    // Add return if set.
    if (param) {
        locstr = locstr + "&return=" + encoder.encode(param);
    }

    // We preserve anything we're instructed to directly.
    if (params) {
        for (const auto& p : *params) {
            locstr = locstr + '&' + p.first + '=' + encoder.encode(p.second.c_str());
        }
    }
    else {
        for (const auto& q : m_preserve) {
            param = request.getParameter(q.c_str());
            if (param) {
                locstr = locstr + '&' + q + '=' + encoder.encode(param);
            }
        }
    }

    // Add the notifier's return parameter to the destination location and redirect.
    // This is NOT the same as the return parameter that might be embedded inside it ;-)
    loc = loc + "&return=" + encoder.encode(locstr.c_str());
    return make_pair(true, request.sendRedirect(loc.c_str()));
}
