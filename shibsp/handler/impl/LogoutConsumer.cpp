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
 * LogoutConsumer.cpp
 * 
 * Pluggable runtime functionality that handles consuming logout messages.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/LogoutHandler.h"
#include "remoting/ddf.h"
#include "remoting/RemotingService.h"
#include "session/SessionCache.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL LogoutConsumer : public virtual LogoutHandler
    {
    public:
        LogoutConsumer(const ptree& pt);
        virtual ~LogoutConsumer() {}

        void init(const char* location);    // encapsulates actions that need to run either in the c'tor or setParent

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        const char* getHomeURL(SPRequest& request) const;
        pair <bool,long> completeLogout(SPRequest& request, bool removeSession, const char* token) const;

        bool m_matchRequired;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL LogoutConsumerFactory(const pair<ptree&,const char*>& p, bool)
    {
        return new LogoutConsumer(p.first);
    }
}

LogoutConsumer::LogoutConsumer(const ptree& pt) : AbstractHandler(pt), LogoutHandler(pt), m_matchRequired(false)
{
    m_matchRequired = getBool("matchRequired", false);
}

pair<bool,long> LogoutConsumer::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first, but only to continue/finish the loop.
    pair<bool,long> ret = notifyFrontChannel(request);
    if (ret.first) {
        return ret;
    }

    // Check for a notifying parameter indicating we are completing a notification loop.
    // In this scenario, we call a completion method to set up the final call to the Hub
    // to produce a logout response message or local redirect.
    if (request.getParameter("notifying")) {
        return completeLogout(request, true, request.getParameter("token"));
    }

    // With a fresh message inbound from an IdP, we check for an active session to supply the
    // necessary opaque data to the Hub to match against in processing a logout request.

    unique_lock<Session> session;
    try {
        session = request.getSession(false, true);  // don't cache it and ignore all checks
    }
    catch (const exception& ex) {
        request.error("error accessing current session: %s", ex.what());
    }

    DDF input = request.getAgent().getRemotingService()->build("logout-consumer", request);
    DDFJanitor inputJanitor(input);

    if (session) {
        DDF opaqueData = session.mutex()->getOpaqueData().copy();
        if (opaqueData.isnull()) {
            request.debug("session (%s) contains no Hub-supplied data", session.mutex()->getID());
        } else {
            input.addmember("session").structure().add(opaqueData);
        }
    }

    static set<string> emptyHeaderSet;
    DDF wrapped = wrapRequest(request, emptyHeaderSet, false);
    input.add(wrapped);

    input.addmember("home_url").unsafe_string(getHomeURL(request));

    // Call the Hub to process the message, suppressing any errors that occur.

    DDF output;
    try {
        output = request.getAgent().getRemotingService()->send(input);
    }
    catch (exception& ex) {
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, LOGOUT_CONSUMER_HANDLER);
        }

        if (m_matchRequired) {
            throw;
        } else {
            request.error("error invoking logout-consumer operation");
            request.log(Priority::SHIB_ERROR, ex);
        }
    }
    DDFJanitor outputJanitor(output);

    // There are two cases here, a logout request or a response being processed
    // from an IdP, allowing that a dozen or more different errors can take place.
    // The request case will potentially feed back a "token" member for use later
    // while the response case will provide a "status" and generally a wrapped response.
    
    if (output["status"].isint()) {
        // Finish up a logout response. The session should be gone and if it wasn't
        // this is a spurious logout message so we don't act on it.
        return completeLogout(request, false, nullptr);
    }

    // If we actually have a session in hand, we may need to initiate the notification loop.
    // Any token provided by the Hub call will be attached to that process.
    // We won't notify, however, if a match was required but not achieved.

    bool effectiveMatch = !m_matchRequired || output["matched"].integer() == 1;
    if (m_matchRequired) {
        request.debug("LogoutRequest %s active session", effectiveMatch ? "matched" : "did not match");
    }
    else {
        request.debug("ignoring processing of LogoutRequest for matching purposes");
    }

    if (session && effectiveMatch) {
        ret = notifyFrontChannel(request, false, output.getmember("token").string());
        if (ret.first) {
            // A loop was started, so we are finished at this stage until we're called back.
            return ret;
        }

        // We unlock the session here as we are done using it and will need to remove it shortly.
        session.unlock();
    }

    // If we get here, either no session existed or no notification was required.
    // We invoke our completion operation with the token from the Hub, if any.
    return completeLogout(request, effectiveMatch, output.getmember("token").string());
}

pair <bool,long> LogoutConsumer::completeLogout(SPRequest& request, bool removeSession, const char* token) const
{
    if (removeSession) {
        // Dispose of any active session.
        request.getAgent().getSessionCache()->remove(request);
    }

    DDF output;

    // Check for a token parameter, signifying we need to call the Hub to finish
    // processing a logout request from an IdP.
    if (token) {
        DDF input = request.getAgent().getRemotingService()->build("logout-consumer", request);
        DDFJanitor inputJanitor(input);
        input.addmember("token").string(token);
        if (removeSession) {
            input.addmember("success").integer(1);
        }

        try {
            output = request.getAgent().getRemotingService()->send(input);
        }
        catch (exception& ex) {
            AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
            if (agent_ex) {
                agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, LOGOUT_CONSUMER_HANDLER);
            }
            if (removeSession) {
                request.error("error invoking logout-consumer operation to complete logout request processing");
                request.log(Priority::SHIB_ERROR, ex);
            }
            else {
                throw;
            }
        }
    }

    // At this point, output may contain a wrapped response to relay, or it may be null due to
    // errors, or because we're processing a logout response from an IdP, or...reasons.
    // We either relay the wrapped response, or we generate a final redirect locally.

    DDFJanitor outputJanitor(output);

    DDF wrapped = output.getmember("http");
    if (wrapped.isstruct()) {
        pair<bool,long> ret = unwrapResponse(request, output, token == nullptr);
        if (ret.first) {
            return ret;
        }
    }

    // If no explicit response from Hub, pull "target" from output if available.
    const char* dest = output.getmember("target").string();

    // If no target from Hub we fall back to our own determination that favors
    // the logoutURL setting over homeURL.
    if (!dest) {
        dest = getHomeURL(request);
    }

    request.limitRedirect(dest);
    return make_pair(true, request.sendRedirect(dest));
}

const char* LogoutConsumer::getHomeURL(SPRequest& request) const
{
    const char* dest = request.getRequestSettings().first->getString(RequestMapper::LOGOUT_URL_PROP_NAME);
    if (dest) {
        return dest;
    }

    return request.getRequestSettings().first->getString(RequestMapper::HOME_URL_PROP_NAME,
        RequestMapper::HOME_URL_PROP_DEFAULT);
}
