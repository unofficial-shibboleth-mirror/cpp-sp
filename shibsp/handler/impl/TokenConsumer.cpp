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
 * handler/impl/TokenCOnsumer.cpp
 *
 * SSO protocol response handler.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "remoting/RemotingService.h"
#include "util/CGIParser.h"
#include "util/Misc.h"
#include "util/URLEncoder.h"

#include <ctime>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL TokenConsumer : public virtual AbstractHandler {
    public:
        TokenConsumer(const ptree& pt, const char* path);
        virtual ~TokenConsumer() {}

        pair<bool,long> run(SPRequest& request, bool isHandler) const;

    private:
        string m_path;
        set<string> m_remotedHeaders;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL TokenConsumerFactory(const pair<ptree&,const char*>& p, bool) {
        return new TokenConsumer(p.first, p.second);
    }
};

TokenConsumer::TokenConsumer(const ptree& pt, const char* path)
    : AbstractHandler(pt), m_path(path), m_remotedHeaders({ "Cookie" })
{
    static const char REMOTED_HEADERS_PROP_NAME[] = "remotedHeaders";

    const char* headers = getString(REMOTED_HEADERS_PROP_NAME);
    if (headers) {
        split_to_container(m_remotedHeaders, headers);
        m_remotedHeaders.insert("Cookie");
    }
}

pair<bool,long> TokenConsumer::run(SPRequest& request, bool isHandler) const
{
    string target;

    // Check for a message back to the handler from a session hook.
    if (request.getQueryString() && strstr(request.getQueryString(), "shibsp_hook=1")) {
        // Parse the query string only, to preserve any POST data in case this is
        // *not* a hook roundtrip but an actual token response that has that parameter
        // for whatever odd reason.
        CGIParser cgi(request, true);
        pair<CGIParser::walker,CGIParser::walker> param = cgi.getParameters("shibsp_hook");
        if (param.first != param.second && param.first->second && !strcmp(param.first->second, "1")) {
            // This is a hook return, so we extract the target parameter and redirect to it.
            param = cgi.getParameters("target");
            if (param.first != param.second && param.first->second) {
                target = param.first->second;
            }
            else {
                target = getString(RequestMapper::HOME_URL_PROP_NAME, request, RequestMapper::HOME_URL_PROP_DEFAULT, HANDLER_PROPERTY_MAP);
            }
            request.limitRedirect(target.c_str());
            return make_pair(true, request.sendRedirect(target.c_str()));
        }
    }

    // Not a hook response, so process as a token-consumer operation.

    try {
        DDF input("token-consumer");
        DDFJanitor inputJanitor(input);    
        input.structure();
        input.addmember("application").string(
            request.getRequestSettings().first->getString(
                RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT));

        DDF wrapped = wrapRequest(request, m_remotedHeaders);
        input.add(wrapped);

        DDF output = request.getAgent().getRemotingService()->send(input);
        DDFJanitor outputJanitor(output);

        const char* s = output.getmember("http.redirect").string();
        if (s) {
            target = s;
        }
        else if (!output.getmember("http.response.data").string()) {
            // Shouldn't happen, but we can route ourselves to homeURL.
            target = getString(RequestMapper::HOME_URL_PROP_NAME, request, RequestMapper::HOME_URL_PROP_DEFAULT, HANDLER_PROPERTY_MAP);
            output.addmember("http.redirect").unsafe_string(target.c_str());
        }

        // If target is still empty, then this is a POST recovery attempt with the reesource
        // buried in the form action. Assuming it's non-empty, we must sanitize it.
        // TODO: we have to have some way to sanitize it anyway...
        if (!target.empty()) {
            request.limitRedirect(target.c_str());
        }

        SessionCache* cache = request.getAgent().getSessionCache();
        DDF sessionData = output["session"];
        // Ownership of sessionData transfers on input to create call (will be detached from output).
        cache->create(request, sessionData);
        
        const char* sessionHook = request.getRequestSettings().first->getString(RequestMapper::SESSION_HOOK_PROP_NAME);

        if (target.empty() && sessionHook) {
            request.warn("response contained recovered POST data, ignoring configured sessionHook");
            sessionHook = nullptr;
        }

        if (sessionHook) {
            string hook(sessionHook);
            request.absolutize(hook);

            // Compute the return URL. We use a self-referential link plus a hook indicator to break the cycle.
            // The target also must be included.
            const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();
            string returnURL = request.getRequestURL();
            returnURL = returnURL.substr(0, returnURL.find('?')) + "?shibsp_hook=1";

            string encodedTarget;
            if (!target.empty()) {
                encodedTarget = encoder.encode(target.c_str());
                returnURL += "&target=" + encodedTarget;
            }
            if (hook.find('?') == string::npos) {
                hook += '?';
            }
            else {
                hook += '&';
            }
            hook += "return=" + encoder.encode(returnURL.c_str());

            // Add the translated target resource explicitly in case it's of interest.
            if (!encodedTarget.empty()) {
                hook += "&target=" + encodedTarget;
            }

            // Overrwrite the original redirection target and issue.
            // This is necessary to ensure any Set-Cookie headers placed by the hub will reach the client.
            output.addmember("http.redirect").unsafe_string(hook.c_str());
        }

        // Handles all normal cases, including POST recovery.
        return unwrapResponse(request, output);
    }
    catch (exception& ex) {
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, TOKEN_CONSUMER_HANDLER);
        }
        
        // This is a mess to allow for "ignoring" errors during passive SSO and routing back
        // to the original resource. Notably, we do NOT handle POST recovery here, even in the
        // passive case, because passive SSO doesn't make any sense together with POST recovery.
        // Passive implies requireSession is off, and POST recovery implies it's on.

        const char* event = agent_ex ? agent_ex->getProperty(AgentException::EVENT_PROP_NAME) : nullptr;
        if (event && !strcmp(event, "NoPassive")) {
            const char* error_target = target.empty() ? agent_ex->getProperty(AgentException::TARGET_PROP_NAME) : target.c_str();

            if (error_target) {
                agent_ex->log(request, Priority::SHIB_WARN);
                request.limitRedirect(error_target);
                // Make sure the target isn't a prefix of this handler, to avoid a loop.
                if (boost::starts_with(error_target, request.getRequestURL())) {
                    request.warn("TokenConsumer target location matched handler, not trapping passive request error");
                } else {
                    request.info("trapping TokenConsumer failure and returning to target location for passive request");
                    return make_pair(true, request.sendRedirect(error_target));
                }
            }
            else {
                request.warn("TokenConsumer caught NoPassive error but had no target to redirect to");
            }
        }
        throw;
    }
}
