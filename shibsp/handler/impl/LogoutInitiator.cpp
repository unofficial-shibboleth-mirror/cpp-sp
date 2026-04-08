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
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/LogoutInitiator.h"
#include "remoting/ddf.h"
#include "remoting/RemotingService.h"
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

LogoutInitiator::LogoutInitiator(const ptree& pt) : AbstractHandler(pt), LogoutHandler(pt)
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

    bool localOnly = getBool("localOnly", false);

    unique_lock<Session> session;
    try {
        session = request.getSession(false, true);  // don't cache it and ignore all checks
    }
    catch (const exception& ex) {
        request.error("error accessing current session: %s", ex.what());
    }

    DDF opaqueData;
    if (session) {
        if (!localOnly) {
            // Before disposing of session, we need to copy out the opaque portion for the Hub.
            opaqueData = session.mutex()->getOpaqueData().copy();
            if (opaqueData.isnull()) {
                request.info("session (%s) contains no Hub-supplied data, bypassing non-local logout",
                    session.mutex()->getID());
                localOnly = true;
            }
        }
        request.info("logging out session (%s)", session.mutex()->getID());
        session.unlock();
        request.getAgent().getSessionCache()->remove(request);
    }

    // Determine return location.
    const char* dest = request.getParameter("return");

    if (!localOnly) {
        DDF input = request.getAgent().getRemotingService()->build("logout-initiator", request);
        DDFJanitor inputJanitor(input);
        input.addmember("session").structure().add(opaqueData);
        if (dest) {
            input.addmember("target").unsafe_string(dest);
        }
        
        static set<string> emptyHeaderSet;
        DDF wrapped = wrapRequest(request, emptyHeaderSet, false);
        input.add(wrapped);

        try {
            DDF output = request.getAgent().getRemotingService()->send(input);
            DDFJanitor outputJanitor(output);
            return unwrapResponse(request, output);
        }
        catch (exception& ex) {
            AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
            const char* event = agent_ex ? agent_ex->getProperty(AgentException::EVENT_PROP_NAME) : nullptr;
            if (!event && strcmp(event, "NoPotentialFlow")) {
                if (agent_ex) {
                    agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, LOGOUT_INITIATOR_HANDLER);
                }
                throw;
            }
        }
    }

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
