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
 * LogoutInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating logout.
 */

#include "internal.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/LogoutInitiator.h"
#include "session/SessionCache.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL LogoutInitiatorFactory(const pair<ptree&,const char*>& p, bool)
    {
        return new LogoutInitiator(p.first);
    }
}

LogoutInitiator::LogoutInitiator(const ptree& pt)
{
}

LogoutInitiator::~LogoutInitiator()
{
}

pair<bool,long> LogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class first; this will initiate, continue, or complete notification.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first) {
        return ret;
    }

    unique_lock<Session> session;
    try {
        session = request.getSession(false, true);  // don't cache it and ignore all checks
    }
    catch (const exception& ex) {
        request.error("error accessing current session: %s", ex.what());
    }

    if (session) {
        session.unlock();
        request.getAgent().getSessionCache()->remove(request);
    }

    // Determine return location.
    const char* dest = request.getParameter("return");
    if (!dest) {
        dest = request.getRequestSettings().first->getString(RequestMapper::LOGOUT_URL_PROP_NAME);
        if (!dest) {
            stringstream s;
            s << "<html><title>Logout Complete</title><body><h1>Logout Complete</h1>"
                "<p>If you're seeing this page, the deployer failed to set a logoutURL setting "
                "to redirect to a custom page for this application.</p>"
                "</body></html>";
            return make_pair(true, request.sendResponse(s));
        }
    }

    // Relative URLs get promoted, absolutes get validated.
    if (*dest == '/') {
        string d(dest);
        request.absolutize(d);
        return make_pair(true, request.sendRedirect(d.c_str()));
    } else {
        request.limitRedirect(dest);
        return make_pair(true, request.sendRedirect(dest));
    }
}
