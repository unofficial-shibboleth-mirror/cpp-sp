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
#include "remoting/RemotingService.h"
#include "util/URLEncoder.h"

#include <ctime>
#include <sstream>
#include <boost/property_tree/ptree.hpp>

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
    try {
        DDF input("token-consumer");
        DDFJanitor inputJanitor(input);    
        input.structure();
        input.addmember("application").string(
            request.getRequestSettings().first->getString("applicationId", "default"));

        DDF wrapped = wrapRequest(request, m_remotedHeaders);
        input.add(wrapped);

        DDF output = request.getAgent().getRemotingService()->send(input);
        DDFJanitor outputJanitor(output);

        // TODO: process outbound session data

        const char* sessionHook = request.getRequestSettings().first->getString("sessionHook");
        if (sessionHook) {
            string hook(sessionHook);
            request.absolutize(hook);

            // Compute the return URL. We use a self-referential link plus a hook indicator to break the cycle.
            // The target also must be included.
            const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();
            string returnURL = request.getRequestURL();
            returnURL = returnURL.substr(0, returnURL.find('?')) + "?hook=1";

            const char* target = output.getmember("http.redirect").string();
            string encodedTarget;
            if (target) {
                encodedTarget = encoder.encode(target);
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

        // TODO: remove POC debugging code...
        stringstream dump;
        dump << output;
        return make_pair(true,request.sendResponse(dump));
        
        //return unwrapResponse(request, output);
    }
    catch (exception& ex) {
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty("handlerType", TOKEN_CONSUMER_HANDLER);
        }
        
        const char* passive = agent_ex ? agent_ex->getProperty("passive") : nullptr;
        if (passive && !strcmp(passive, "1")) {
            agent_ex->log(request, Priority::SHIB_WARN);
            const char* error_target = agent_ex->getProperty("target");

            // TODO: either recover POST data or clean up recovery state?

            // Make sure the target isn't the same as this handler, so avoid a loop.
            request.log(Priority::SHIB_INFO,
                "trapping TokenConsumer failure and returning to target location for passive request");
            request.limitRedirect(error_target);
            return make_pair(true, request.sendRedirect(error_target));
        }
        throw;
    }
}
