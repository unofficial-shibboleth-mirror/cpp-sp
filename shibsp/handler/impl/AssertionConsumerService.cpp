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
 * handler/impl/AssertionConsumerService.cpp
 *
 * Base class for handlers that create sessions by consuming SSO protocol responses.
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AssertionConsumerService.h"
#include "logging/Category.h"
#include "util/CGIParser.h"

#include <ctime>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

AssertionConsumerService::AssertionConsumerService(const ptree& pt, Category& log)
    : AbstractHandler(pt, log)
{
}

AssertionConsumerService::~AssertionConsumerService()
{
}

pair<bool,long> AssertionConsumerService::run(SPRequest& request, bool isHandler) const
{
    // Check for a message back to the ACS from a post-session hook.
    if (request.getQueryString() && strstr(request.getQueryString(), "hook=1")) {
        // Parse the query string only to preserve any POST data.
        CGIParser cgi(request, true);
        pair<CGIParser::walker,CGIParser::walker> param = cgi.getParameters("hook");
        if (param.first != param.second && param.first->second && !strcmp(param.first->second, "1")) {
            string target;
            param = cgi.getParameters("target");
            if (param.first != param.second && param.first->second)
                target = param.first->second;
            return finalizeResponse(request, target);
        }
    }

#ifndef SHIBSP_LITE
    // Locate policy key.
    pair<bool,const char*> prop = getString("policyId", shibspconstants::ASCII_SHIBSPCONFIG_NS);  // may be namespace-qualified if inside handler element
    if (!prop.first)
        prop = getString("policyId");   // try unqualified
    if (!prop.first)
        prop = application.getString("policyId");   // unqualified in Application(s) element

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    scoped_ptr<opensaml::SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(
            getProfile(), application, &IDPSSODescriptor::ELEMENT_QNAME, prop.second
            )
        );

    string relayState;
    scoped_ptr<XMLObject> msg;
    try {
        // Decode the message and process it in a protocol-specific way.
        msg.reset(m_decoder->decode(relayState, httpRequest, &httpResponse, *(policy.get())));
        if (!msg)
            throw BindingException("Failed to decode an SSO protocol response.");
        implementProtocol(application, httpRequest, httpResponse, *policy, nullptr, *msg);

        // History cookie.
        auto_ptr_char issuer(policy->getIssuer() ? policy->getIssuer()->getName() : nullptr);
        if (issuer.get() && *issuer.get())
            maintainHistory(application, httpRequest, httpResponse, issuer.get());

        const EntityDescriptor* entity =
            dynamic_cast<const EntityDescriptor*>(policy->getIssuerMetadata() ? policy->getIssuerMetadata()->getParent() : nullptr);
        prop = application.getRelyingParty(entity)->getString("sessionHook");
        if (prop.first) {
            string hook(prop.second);
            httpRequest.absolutize(hook);

            // Compute the return URL. We use a self-referential link plus a hook indicator to break the cycle
            // and the relay state.
            const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();
            string returnURL = httpRequest.getRequestURL();
            returnURL = returnURL.substr(0, returnURL.find('?')) + "?hook=1";
            if (!relayState.empty())
                returnURL += "&target=" + encoder->encode(relayState.c_str());
            if (hook.find('?') == string::npos)
                hook += '?';
            else
                hook += '&';
            hook += "return=" + encoder->encode(returnURL.c_str());

            // Add the translated target resource in case it's of interest.
            if (!relayState.empty()) {
                try {
                    recoverRelayState(application, httpRequest, httpResponse, relayState, false);
                    hook += "&target=" + encoder->encode(relayState.c_str());
                }
                catch (const std::exception& ex) {
                    m_log.warn("error recovering relay state: %s", ex.what());
                }
            }

            return make_pair(true, httpResponse.sendRedirect(hook.c_str()));
        }

        return finalizeResponse(application, httpRequest, httpResponse, relayState);
    }
    catch (XMLToolingException& ex) {
        m_log.warn("error processing incoming assertion: %s", ex.what());

        // Recover relay state.
        if (!relayState.empty()) {
            try {
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
            catch (const std::exception& rsex) {
                m_log.warn("error recovering relay state: %s", rsex.what());
                relayState.erase();
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
        }

        // Check for isPassive error condition.
        const char* sc2 = ex.getProperty("statusCode2");
        if (sc2 && !strcmp(sc2, "urn:oasis:names:tc:SAML:2.0:status:NoPassive")) {
            pair<bool,bool> ignore = getBool("ignoreNoPassive", shibspconstants::ASCII_SHIBSPCONFIG_NS);  // may be namespace-qualified inside handler element
            if (!ignore.first)
                ignore = getBool("ignoreNoPassive");    // try unqualified
            if (ignore.first && ignore.second && !relayState.empty()) {
                m_log.debug("ignoring SAML status of NoPassive and redirecting to resource...");
                return make_pair(true, httpResponse.sendRedirect(relayState.c_str()));
            }
        }
        
        if (!relayState.empty()) {
            ex.addProperty("RelayState", relayState.c_str());
        }

        // If no sign of annotation, try to annotate it now.
        if (!ex.getProperty("statusCode")) {
            annotateException(&ex, policy->getIssuerMetadata(), nullptr, false);    // wait to throw it
        }

        throw;
    }
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

pair<bool,long> AssertionConsumerService::finalizeResponse(SPRequest& request, string& relayState) const
{
    DDF postData = recoverPostData(request, relayState.c_str());
    DDFJanitor postjan(postData);
    recoverRelayState(request, relayState);
    request.limitRedirect(relayState.c_str());

    // Now redirect to the state value. By now, it should be set to *something* usable.
    // First check for POST data.
    if (!postData.islist()) {
        m_log.debug("ACS returning via redirect to: %s", relayState.c_str());
        return make_pair(true, request.sendRedirect(relayState.c_str()));
    }
    else {
        m_log.debug("ACS returning via POST to: %s", relayState.c_str());
        return make_pair(true, sendPostResponse(request, relayState.c_str(), postData));
    }
}

void AssertionConsumerService::checkAddress(const SPRequest& request, const char* issuedTo) const
{
    if (!issuedTo || !*issuedTo)
        return;

    if (request.getRequestSettings().first->getBool("checkAddress", true)) {
        m_log.debug("checking client address");
        if (request.getRemoteAddr() != issuedTo) {
            throw agent_exception(
               string("Your client's current address (") + request.getRemoteAddr() +
                ") differs from the one used when you authenticated to your home organization. "
                "To correct this problem, you may need to bypass a proxy server. "
                "Please contact your local support staff or help desk for assistance."
                );
        }
    }
}
