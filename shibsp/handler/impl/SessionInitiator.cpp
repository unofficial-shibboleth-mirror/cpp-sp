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
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/HandlerConfiguration.h"
#include "logging/Category.h"
#include "remoting/RemotingService.h"
#include "util/Misc.h"
#include "util/URLEncoder.h"

#include <cstring>

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
        // This sets up the proper query string for discovery to work properly.
        void populateDiscoveryReturnURL(SPRequest& request, bool isHandler, string& returnURL) const;

        string m_path;
        bool m_discoveryEnabled;
        set<string> m_remotedHeaders;
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
    : AbstractHandler(pt), m_path(path), m_discoveryEnabled(true), m_remotedHeaders({ "Cookie" })
{
    static const char DISCOVERY_ENABLED_PROP_NAME[] = "discoveryEnabled";
    static const char REQUEST_MAPPER_SETTINGS_PROP_NAME[] = "requestMapperSettings";
    static const char QUERY_SETTINGS_PROP_NAME[] = "querySettings";

    static bool DISCOVERY_ENABLED_PROP_DEFAULT = true;

    m_discoveryEnabled = getBool(DISCOVERY_ENABLED_PROP_NAME, DISCOVERY_ENABLED_PROP_DEFAULT);

    const char* settings = getString(REQUEST_MAPPER_SETTINGS_PROP_NAME);
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

    settings = getString(QUERY_SETTINGS_PROP_NAME);
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
    string state, target, handler;
    const char* handlerBaseURL = nullptr;

    try {
        if (isHandler) {
            // Check for a DS parameter in the query string. This is a loop-breaking indicator
            // that this is a request in resoonse to a discovery round trip and will impact how
            // the request to the hub is made, to ensure a loop back to a DS is avoided.
            const char* param = request.getParameter("DS");
            bool discoveryDone = param && !strcmp(param, "1");

            // Check for a state parameter in the query string.
            param = request.getParameter("state");
            if (param) {
                // We'll pass state as is and target will be omitted.
                state = param;
                
                // handler can be derived from "this" URL since this is a re-entrant call to this handler,
                // i.e., we know this is the right URL to use because "it already was" originally.
                handlerBaseURL = request.getHandlerURL(request.getRequestURL());
                if (!discoveryDone) {
                    handler = handlerBaseURL + m_path;
                }
            }
            else {
                // target will come from query string, map, or handler or fall back to homeURL.
                target = getString("target", request,
                    request.getRequestSettings().first->getString(
                        RequestMapper::HOME_URL_PROP_NAME, RequestMapper::HOME_URL_PROP_DEFAULT));

                // handler is derived from the target resource.
                handlerBaseURL = request.getHandlerURL(target.c_str());
                if (!discoveryDone) {
                    handler = handlerBaseURL + m_path;
                }
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
        input.addmember("application").string(settings->getString(
            RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT));
        
        // Will be set unless discovery was already attempted.
        if (m_discoveryEnabled && !handler.empty()) {
            // Decorate the handler URL with the signal parameter and then any recognized/allowed custom parameters.
            populateDiscoveryReturnURL(request, isHandler, handler);
            input.addmember("disco_return_url").string(AgentConfig::getConfig().getURLEncoder().encode(handler.c_str()));
        }

        if (state.empty()) {
            input.addmember("target").unsafe_string(target.c_str());
        }
        else {
            input.addmember("state").string(state.c_str());
        }

        // Add copy of token consumer structure.
        DDF dup = request.getAgent().getHandlerConfiguration(
            settings->getString(RequestMapper::HANDLER_CONFIG_ID_PROP_NAME)).getTokenConsumerInfo(handlerBaseURL);
        input.add(dup);

        DDF wrapped = wrapRequest(request, m_remotedHeaders,
            !isHandler && getBool(RequestMapper::PRESERVE_POST_DATA_PROP_NAME,
                                    request,
                                    RequestMapper::PRESERVE_POST_DATA_PROP_DEFAULT,
                                    HANDLER_PROPERTY_FIXED | HANDLER_PROPERTY_MAP));
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
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, SESSION_INITIATOR_HANDLER);
        }

        // If it's a handler operation, and isPassive is used or returnOnError is set, we trap the error.
        if (isHandler) {
            bool returnOnError = getBool("isPassive", request, false);
            if (!returnOnError) {
                returnOnError = getBool("returnOnError", request, false);
            }

            if (returnOnError) {
                request.warn(ex.what());
                const char* error_target = agent_ex ? agent_ex->getProperty("target") : nullptr;
                // Make sure the target isn't the same as this handler, to avoid a loop.
                if (error_target && strstr(error_target, handlerBaseURL) != error_target) {
                    request.info("trapping SessionInitiator failure and returning to target location");
                    request.limitRedirect(error_target);
                    return make_pair(true, request.sendRedirect(error_target));
                }
            }
        }
        throw;
    }
}

void SessionInitiator::populateDiscoveryReturnURL(SPRequest& request, bool isHandler, string& returnURL) const
{
    returnURL += "?DS=1";

    const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();

    // In the old SP, we did this by conducting surgery on the query string to elide the target parameter.
    // This is not only nasty, but not even correct since the name of the parameter could be encoded inside
    // the query string to defeat that check, so the new code is going to build up a new query string by
    // hand and re-encode all the parrameters it decides to allow.

    // We have parameter name sets defined for both the query parameter case (isHandler is true) and the
    // RequestMap case (isHandler is false). That case is necessary so that settings applicable to the
    // original target parameter get preserved even though the handler is the subsequently "active" URL
    // mapped into the configuration.

    if (isHandler) {
        for (const string& opt : m_querySettings) {
             const char* optval = request.getParameter(opt.c_str());
             if (optval) {
                 returnURL = returnURL + '&' + opt + '=' + encoder.encode(optval);
             }
         }
    }
    else {
         // Preserve designated request settings on the URL.
        const PropertySet* props = request.getRequestSettings().first;
        for (const string& opt : m_requestMapperSettings) {
             const char* optval = props->getString(opt.c_str());
             if (optval) {
                 returnURL = returnURL + '&' + opt + '=' + encoder.encode(optval);
             }
         }
    }
    
}
