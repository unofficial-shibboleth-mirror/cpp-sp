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
 * handler/impl/SessionInitiator.cpp
 * 
 * Handler for initiating sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/HandlerConfiguration.h"
#include "logging/Category.h"
#include "remoting/RemotingService.h"
#include "util/Misc.h"

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL SessionInitiator : public virtual AbstractHandler {
    public:
        SessionInitiator(const ptree& pt, const char* path);
        virtual ~SessionInitiator() {}

        pair<bool,long> run(SPRequest& request, bool isHandler) const;

    private:
        string m_path;
        vector<string> m_remotedHeaders;
        vector<string> m_requestMapperSettings;
        vector<string> m_querySettings;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL SessionInitiatorFactory(const pair<ptree&,const char*>& p, bool) {
        return new SessionInitiator(p.first, p.second);
    }
};

SessionInitiator::SessionInitiator(const ptree& pt, const char* path)
    : AbstractHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".Handler.SessionInitiator")),
        m_path(path), m_remotedHeaders({ "Cookie" })
{
    const char* settings = getString("requestMapperSettings");
    if (settings) {
        split_to_container(m_requestMapperSettings, settings);
    }
    else {
        // Legacy SAML defaults.
        m_requestMapperSettings = {
            "entityID",
            "authority",
            "forceAuthn",
            "isPassive",
            "authnContextClassRef",
            "authnContextComparison",
            "NameIDFormat",
            "SPNameQualifier",
            "attributeIndex"
        };
    }

    settings = getString("querySettings");
    if (settings) {
        split_to_container(m_querySettings, settings);
    }
    else {
        // Same defaults for now.
        m_querySettings = m_requestMapperSettings;
    }
}

pair<bool,long> SessionInitiator::run(SPRequest& request, bool isHandler) const
{
    try {
        string state, target, handler;
        const char* handlerBaseURL = nullptr;

        if (isHandler) {
            // Check for a state parameter in the query string.
            const char* param = request.getParameter("state");
            if (param) {
                // We'll pass state as is and target will be omitted.
                state = param;
                // handler can be derived from "this" URL since this is a re-entrant call to this handler,
                // i.e., we know this is the right URL to use because "it already was" originally.
                handlerBaseURL = request.getHandlerURL(request.getRequestURL());
                handler = handlerBaseURL + m_path;
            }
            else {
                // target will come from query string, map, or handler or fall back to this request.
                target = getString("target", request, request.getRequestURL());
                // handler is derived from the target resource.
                handlerBaseURL = request.getHandlerURL(target.c_str());
                handler = handlerBaseURL + m_path;
            }
        }
        else {
            // Check for a hardwired target value in the map or handler.
            target = getString("target", request, request.getRequestURL(),
                HANDLER_PROPERTY_FIXED | HANDLER_PROPERTY_MAP);
            // state is empty since this is a direct resource request.
            // handler is derived from the target resource
            handlerBaseURL = request.getHandlerURL(target.c_str());
            handler = handlerBaseURL + m_path;
        }

        const PropertySet* settings = request.getRequestSettings().first;

        DDF input("session-initiator");
        DDFJanitor inputJanitor(input);

        input.structure();
        input.addmember("application").string(settings->getString("applicationId", "default"));
        input.addmember("handler").unsafe_string(handler.c_str());
        if (state.empty()) {
            input.addmember("target").unsafe_string(target.c_str());
        }
        else {
            input.addmember("state").string(state.c_str());
        }

        // Add copy of token consumer structure.
        DDF dup = request.getAgent().getHandlerConfiguration(
            settings->getString("handlerConfigID")).getTokenConsumerInfo(handlerBaseURL);
        input.add(dup);

        DDF wrapped = wrapRequest(request, m_remotedHeaders,
            !isHandler &&
                getBool("preservePostData", request, false, HANDLER_PROPERTY_FIXED | HANDLER_PROPERTY_MAP));
        input.add(wrapped);

        for (const string& propname : m_requestMapperSettings) {
            const char* prop = getString(propname.c_str(), request, nullptr,
                HANDLER_PROPERTY_FIXED | HANDLER_PROPERTY_MAP);
            if (prop) {
                input.addmember(propname.c_str()).string(prop);
            }
        }

        // If there's an overlap with the previous set, this will overwrite.

        for (const string& propname : m_querySettings) {
            const char* prop = getString(propname.c_str(), request, nullptr,
                HANDLER_PROPERTY_REQUEST);
            if (prop) {
                input.addmember(propname.c_str()).string(prop);
            }
        }

        DDF output = request.getAgent().getRemotingService()->send(input);
        DDFJanitor outputJanitor(output);

        return unwrapResponse(request, output);
    }
    catch (exception& ex) {
        // If it's a handler operation, and isPassive is used or returnOnError is set, we trap the error.
        if (isHandler) {
            bool returnOnError = getBool("isPassive", request, false);
            if (!returnOnError) {
                returnOnError = getBool("returnOnError", request, false);
            }

            if (returnOnError) {
                m_log.warn(ex.what());
                const agent_exception* agent_ex = dynamic_cast<const agent_exception*>(&ex);
                const char* target = agent_ex ? agent_ex->getProperty("target") : nullptr;
                if (target) {
                    m_log.info("trapping SessionInitiator failure and returning to target location");
                    request.limitRedirect(target);
                    return make_pair(true, request.sendRedirect(target));
                }
            }
        }
        throw;
    }
}
