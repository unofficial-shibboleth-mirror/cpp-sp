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
#include "util/URLEncoder.h"

#include <ctime>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/algorithm/string.hpp>>

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
        vector<string> m_remotedHeaders;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL TokenConsumerFactory(const pair<ptree&,const char*>& p, bool) {
        return new TokenConsumer(p.first, p.second);
    }
};

TokenConsumer::TokenConsumer(const ptree& pt, const char* path)
    : AbstractHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".Handler.TokenConsumer")),
        m_path(path), m_remotedHeaders({ "Cookie" })
{
}

pair<bool,long> TokenConsumer::run(SPRequest& request, bool isHandler) const
{
    bool wasPassive;
    string target;

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

        wasPassive = output["passive"].integer() == 1;
        const char* s = output.getmember("http.redirect").string();
        if (s) {
            target = s;
        }
        

        SessionCache* cache = request.getAgent().getSessionCache();
        DDF sessionData = output["session"];
        // Ownership of sessionData transfers on input to create call.
        cache->create(request, sessionData);
        
        const char* sessionHook = request.getRequestSettings().first->getString(RequestMapper::SESSION_HOOK_PROP_NAME);
        if (sessionHook) {
            string hook(sessionHook);
            request.absolutize(hook);

            // Compute the return URL. We use a self-referential link plus a hook indicator to break the cycle.
            // The target also must be included.
            const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();
            string returnURL = request.getRequestURL();
            returnURL = returnURL.substr(0, returnURL.find('?')) + "?hook=1";

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
            return unwrapResponse(request, output);
        }

        // TODO: POST restoration...

        return unwrapResponse(request, output);
    }
    catch (exception& ex) {
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty("handlerType", TOKEN_CONSUMER_HANDLER);
        }
        
        // THis is a mess to allow for "ignoring" errors during passive SSO and routing back
        // to the original resource.

        // The passive and target values can come from the output message or the exception.
        // When the cache throws, the error typically would not carry that information but the
        // output would have.

        const char* passive = agent_ex ? agent_ex->getProperty("passive") : nullptr;
        if (wasPassive || (passive && !strcmp(passive, "1"))) {
            agent_ex->log(request, Priority::SHIB_WARN);
            const char* error_target = target.empty() ? agent_ex->getProperty("target") : target.c_str();

            // TODO: either recover POST data or clean up recovery state?

            if (error_target) {
                request.limitRedirect(error_target);
                // Make sure the target isn't a prefix of this handler, to avoid a loop.
                if (boost::starts_with(error_target, request.getRequestURL())) {
                    request.log(Priority::SHIB_WARN,
                        "TokenConsumer target location matched handler, not trapping passive request error");
                } else {
                    request.log(Priority::SHIB_INFO,
                        "trapping TokenConsumer failure and returning to target location for passive request");
                    return make_pair(true, request.sendRedirect(error_target));
                }
            }
        }
        throw;
    }
}
