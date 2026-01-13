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
 * ServiceProvider.cpp
 *
 * Interface to a Shibboleth ServiceProvider instance.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "AccessControl.h"
#include "SPRequest.h"
#include "attribute/AttributeConfiguration.h"
#include "handler/Handler.h"
#include "handler/HandlerConfiguration.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "util/Date.h"
#include "util/PathResolver.h"
#include "util/URLEncoder.h"

#include <fstream>
#include <sstream>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace std;

const char Agent::UNSET_HEADER_VALUE_PROP_NAME[] = "unsetHeaderValue";
const char Agent::CHECK_SPOOFING_PROP_NAME[] = "checkSpoofing";
const char Agent::SPOOF_KEY_PROP_NAME[] = "spoofKey";
const char Agent::CATCH_ALL_PROP_NAME[] = "catchAll";
const char Agent::PARTIAL_REGEX_MATCHING_PROP_NAME[] = "partialRegexMatching";

bool Agent::CHECK_SPOOFING_PROP_DEFAULT = true;
bool Agent::CATCH_ALL_PROP_DEFAULT = false;
bool Agent::PARTIAL_REGEX_MATCHING_PROP_DEFAULT = false;

Agent::Agent()
{
    m_authTypes = {"shibboleth"};
}

Agent::~Agent()
{
}

long Agent::handleError(SPRequest& request, const Session* session, exception* ex, bool mayRedirect) const
{
    bool externalParameters = false;
    const char* redirectErrors = nullptr;

    AgentException* richEx = dynamic_cast<AgentException*>(ex);
    if (richEx) {
        // Populate target if needed.
        if (!richEx->getProperty("target")) {
            richEx->addProperty("target", request.getRequestURL());
        }
        richEx->log(request);
    }
    else if (ex) {
        request.error(ex->what());
    }

    // Now look for settings in the request map.
    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        // Not using this yet, probably TBD.
        externalParameters = settings.first->getBool("externalParameters", false);
        if (mayRedirect)
            redirectErrors = settings.first->getString(RequestMapper::REDIRECT_ERRORS_PROP_NAME);
    }
    catch (const exception& nested) {
        request.error(nested.what());
    }

    // Check for redirection on errors.
    if (mayRedirect && redirectErrors) {
        string loc(redirectErrors);
        request.absolutize(loc);
        if (richEx) {
            // TODO: alter how this works or what's included.
            loc = loc + '?' + richEx->toQueryString();
        }
        return request.sendRedirect(loc.c_str());
    }

    // TODO: this probably changes significantly. The status code isn't all that material,
    // but we could potentially use a custom code to facilitate custom error pages.
    // The big addition would be exporting exception propertties into the request
    // so Apache can surface them using its error redirection feature.

    istringstream msg("Internal Server Error. Please contact the site administrator.");
    return request.sendResponse(msg, richEx ? richEx->getStatusCode() : HTTPResponse::SHIBSP_HTTP_STATUS_ERROR);
}

pair<bool,long> Agent::doAuthentication(SPRequest& request, bool handler) const
{
    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            const char* redirectToSSL = settings.first->getString(RequestMapper::REDIRECT_TO_SSL_PROP_NAME);
            if (redirectToSSL) {
                if (!strcasecmp("GET",request.getMethod()) || !strcasecmp("HEAD",request.getMethod())) {
                    // Compute the new target URL
                    string redirectURL = string("https://") + request.getHostname();
                    if (strcmp(redirectToSSL,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL;
                    }
                    redirectURL += request.getRequestURI();
                    return make_pair(true, request.sendRedirect(redirectURL.c_str()));
                }
                else {
                    AgentException ex("Access via unencrypted HTTP was blocked.");
                    return make_pair(true, handleError(request, nullptr, &ex, false));
                }
            }
        }

        // First check if this is a request to an absolute handler location.
        const HandlerConfiguration& handlerConfig = request.getAgent().getHandlerConfiguration(
            request.getRequestSettings().first->getString(RequestMapper::HANDLER_CONFIG_ID_PROP_NAME));
        const Handler* absolute = handlerConfig.getAbsoluteHandler(request);
        if (absolute) {
            // Either dispatch directly or just pass back control based on parameter to this method.
            if (handler) {
                pair<bool,long> hret = absolute->run(request);
                // Did the handler run successfully?
                if (hret.first) {
                    return hret;
                }
                throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
            }
            else {
                return make_pair(true, request.returnOK());
            }
        }

        const char* targetURL = request.getRequestURL();
        const char* handlerURL=request.getHandlerURL(targetURL);
        if (!handlerURL) {
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");
        }

        // If the request URL contains the handler base URL for this application, either dispatch
        // directly or just pass back control based on parameter to this method.
        if (boost::contains(targetURL, handlerURL)) {
            if (handler) {
                // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
                // so the path info is the next character (or null).
                const Handler* relative = handlerConfig.getRelativeHandler(targetURL + strlen(handlerURL));
                if (!relative) {
                    throw ConfigurationException("Shibboleth handler invoked at an unconfigured location.");
                }

                pair<bool,long> hret = relative->run(request);
                // Did the handler run successfully?
                if (hret.first) {
                    return hret;
                }
                throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
            }
            else {
                return make_pair(true, request.returnOK());
            }
        }

        // These settings dictate how to proceed.
        const char* authType = settings.first->getString(RequestMapper::AUTH_TYPE_PROP_NAME);
        bool requireSession = settings.first->getBool(
            RequestMapper::REQUIRE_SESSION_PROP_NAME, RequestMapper::REQUIRE_SESSION_PROP_DEFAULT);
        const char* requireLogoutWith = settings.first->getString(RequestMapper::REQUIRE_LOGOUT_WITH_PROP_NAME);

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if (!requireSession &&
                (!authType || m_authTypes.find(boost::to_lower_copy(string(authType))) == m_authTypes.end())) {
            return make_pair(true, request.returnDecline());
        }

        request.getAgent().getAttributeConfiguration(
            request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME)
            ).clearHeaders(request);

        bool sessionExists = false;
        try {
            unique_lock<Session> session = request.getSession();   // don't cache it but enforce policy
            sessionExists = session.owns_lock();
            // Lock will release here.
        }
        catch (const exception& e) {
            request.warn("error during session lookup: %s", e.what());
            // If it's not a retryable session failure, we throw to the outer handler for reporting.
            if (!dynamic_cast<const SessionValidationException*>(&e)) {
                throw;
            }
        }

        if (sessionExists) {
            // Check for logout interception.
            if (requireLogoutWith) {
                // Check for a completion parameter on the query string.
                const char* qstr = request.getQueryString();
                if (!qstr || !strstr(qstr, "shiblogoutdone=1")) {
                    // First leg of circuit, so we redirect to the logout endpoint specified with this URL as a return location.
                    string selfurl = request.getRequestURL();
                    if (qstr)
                        selfurl += '&';
                    else
                        selfurl += '?';
                    selfurl += "shiblogoutdone=1";
                    string loc(requireLogoutWith);
                    request.absolutize(loc);
                    if (loc.find('?') != string::npos)
                        loc += '&';
                    else
                        loc += '?';
                    loc += "return=" + AgentConfig::getConfig().getURLEncoder().encode(selfurl.c_str());
                    return make_pair(true, request.sendRedirect(loc.c_str()));
                }
            }
            request.setHeader("Shib-Handler", handlerURL);
        }
        else {
            // No session.  Maybe that's acceptable?
            if (!requireSession) {
                request.setHeader("Shib-Handler", handlerURL);
                return make_pair(true, request.returnOK());
            }

            // No session, but we require one.
            // Dispatch to SessionInitiator. This MUST handle the request, or we want to fail here.
            // Used to fall through into doExport, but this is a cleaner exit path.
            pair<bool,long> ret = handlerConfig.getSessionInitiator().run(request, false);
            if (ret.first) {
                return ret;
            }
            throw ConfigurationException("Session initiator did not handle request for a new session, check configuration.");
        }

        request.setAuthType(authType);

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        return make_pair(false, 0L);
    }
    catch (exception& e) {
        return make_pair(true, handleError(request, nullptr, &e));
    }
}

pair<bool,long> Agent::doAuthorization(SPRequest& request) const
{
    unique_lock<Session> session;
    
    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // Three settings dictate how to proceed.
        const char* authType = settings.first->getString(RequestMapper::AUTH_TYPE_PROP_NAME);
        bool requireSession = settings.first->getBool(
            RequestMapper::REQUIRE_SESSION_PROP_NAME, RequestMapper::REQUIRE_SESSION_PROP_DEFAULT);

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if (!requireSession &&
                (!authType || m_authTypes.find(boost::to_lower_copy(string(authType))) == m_authTypes.end())) {
            return make_pair(true, request.returnDecline());
        }

        // Do we have an access control plugin?
        if (settings.second) {
            try {
                session = request.getSession(false, false);  // ignore timeout and do not cache
            }
            catch (const exception& e) {
                request.warn("unable to obtain session to pass to access control provider: %s", e.what());
            }

#ifdef HAVE_CXX14
            shared_lock<AccessControl> acllock(*settings.second);
#endif
            switch (settings.second->authorized(request, session.mutex())) {
                case AccessControl::shib_acl_true:
                    request.debug("access control provider granted access");
                    return make_pair(true, request.returnOK());

                case AccessControl::shib_acl_false:
                {
                    request.warn("access control provider denied access");
                    AgentException ex("Access to resource denied.");
                    ex.setStatusCode(HTTPResponse::SHIBSP_HTTP_STATUS_FORBIDDEN);
                    return make_pair(true, handleError(request, session.mutex(), &ex, false));
                }

                default:
                    // Use the "DECLINE" interface to signal we don't know what to do.
                    return make_pair(true, request.returnDecline());
            }
        }
        else {
            return make_pair(true, request.returnDecline());
        }
    }
    catch (exception& e) {
        return make_pair(true, handleError(request, nullptr, &e));
    }
}

pair<bool,long> Agent::doExport(SPRequest& request, bool requireSession) const
{
    unique_lock<Session> session;

    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        try {
            session = request.getSession(false, false);  // ignore timeout and address check here
        }
        catch (const exception& e) {
            request.warn("unable to obtain session to export to request: %s", e.what());
        	// If we have to have a session, then this is a fatal error.
        	if (requireSession) {
        		throw;
            }
        }

		// Still no data?
        if (!session) {
        	if (requireSession) {
                throw SessionException("Unable to obtain session to export to request.");
            }
        	else {
        		return make_pair(false, 0L);	// just bail silently
            }
        }

        request.setHeader("Shib-Session-ID", session.mutex()->getID());
        request.setHeader("Shib-Application-ID", session.mutex()->getApplicationID());

        unsigned int lifetime = settings.first->getUnsignedInt(RequestMapper::LIFETIME_PROP_NAME, RequestMapper::LIFETIME_PROP_DEFAULT);
        request.setHeader( "Shib-Session-Expires", boost::lexical_cast<string>(session.mutex()->getCreation() + lifetime).c_str());
        unsigned int timeout = settings.first->getUnsignedInt(RequestMapper::TIMEOUT_PROP_NAME, RequestMapper::TIMEOUT_PROP_DEFAULT);
        if (timeout > 0) {
            request.setHeader( "Shib-Session-Inactivity", boost::lexical_cast<string>(session.mutex()->getLastAccess() + timeout).c_str());
        }

        // Export the attributes.
        request.getAgent().getAttributeConfiguration(
            request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME)
            ).exportAttributes(request, *(session.mutex()));

        return make_pair(false,0L);
    }
    catch (exception& e) {
        return make_pair(true, handleError(request, session.mutex(), &e));
    }
}

pair<bool,long> Agent::doHandler(SPRequest& request) const
{
    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            const char* redirectToSSL = settings.first->getString(RequestMapper::REDIRECT_TO_SSL_PROP_NAME);
            if (redirectToSSL) {
                if (!strcasecmp("GET",request.getMethod()) || !strcasecmp("HEAD",request.getMethod())) {
                    // Compute the new target URL
                    string redirectURL = string("https://") + request.getHostname();
                    if (strcmp(redirectToSSL,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL;
                    }
                    redirectURL += request.getRequestURI();
                    return make_pair(true, request.sendRedirect(redirectURL.c_str()));
                }
                else {
                    throw IOException("Blocked non-SSL access to Shibboleth handler.");
                }
            }
        }

        const HandlerConfiguration& handlerConfig = request.getAgent().getHandlerConfiguration(
            request.getRequestSettings().first->getString(RequestMapper::HANDLER_CONFIG_ID_PROP_NAME));

        // First check if this is a request to an absolute handler location.
        const Handler* handler = handlerConfig.getAbsoluteHandler(request);
        if (handler) {
            pair<bool,long> hret = handler->run(request);
            // Did the handler run successfully?
            if (hret.first) {
                return hret;
            }
            throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
        }

        // Otherwise check for a relative handler.
        const char* targetURL = request.getRequestURL();
        const char* handlerURL = request.getHandlerURL(targetURL);
        if (!handlerURL) {
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");
        }

        // Make sure we only process handler requests and advance into the URL to find the handler's path.
        if (!boost::contains(targetURL, handlerURL)) {
            return make_pair(true, request.returnDecline());
        }

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).
        handler = handlerConfig.getRelativeHandler(targetURL + strlen(handlerURL));
        if (!handler) {
            throw ConfigurationException("Shibboleth handler invoked at an unconfigured location.");
        }

        pair<bool,long> hret = handler->run(request);
        // Did the handler run successfully?
        if (hret.first) {
            return hret;
        }
        throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
    }
    catch (exception& e) {
        unique_lock<Session> session;
        try {
            session = request.getSession(false, true);   // do not cache
        }
        catch (const exception&) {
        }
        return make_pair(true, handleError(request, session.mutex(), &e));
    }
}
