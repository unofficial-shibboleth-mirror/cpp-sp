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
#include "attribute/Attribute.h"
#include "handler/SessionInitiator.h"
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
bool Agent::CHECK_SPOOFING_PROP_DEFAULT = true;

const char Agent::SPOOF_KEY_PROP_NAME[] = "spoofKey";

const char Agent::CATCH_ALL_PROP_NAME[] = "catchAll";
bool Agent::CATCH_ALL_PROP_DEFAULT = false;

Agent::Agent()
{
    m_authTypes.insert("shibboleth");
}

Agent::~Agent()
{
}

long Agent::handleError(Category& log, SPRequest& request, const Session* session, const exception* ex, bool mayRedirect) const
{
    // The properties we need can be set in the RequestMap, or the Errors element.
    bool externalParameters = false;
    const char* redirectErrors = nullptr;

    const agent_exception* richEx = dynamic_cast<const agent_exception*>(ex);

    // Now look for settings in the request map.
    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        externalParameters = settings.first->getBool("externalParameters", false);
        if (mayRedirect)
            redirectErrors = settings.first->getString("redirectErrors");
    }
    catch (const exception& ex) {
        log.error(ex.what());
    }

    // Check for redirection on errors.
    if (mayRedirect && redirectErrors) {
        string loc(redirectErrors);
        request.absolutize(loc);
        const agent_exception* richEx = dynamic_cast<const agent_exception*>(ex);
        if (richEx) {
            // TODO: probably alter how this works or what's included.
            loc = loc + '?' + richEx->toQueryString();
        }
        return request.sendRedirect(loc.c_str());
    }

    // TODO: this probably changes significantly, but ultimately we're trying to pass
    // back a status code.

    istringstream msg("Internal Server Error. Please contact the site administrator.");
    return request.sendResponse(msg, richEx ? richEx->getStatusCode() : HTTPResponse::SHIBSP_HTTP_STATUS_ERROR);
}

void Agent::clearHeaders(SPRequest& request) const {
    request.clearHeader("Shib-Cookie-Name", "HTTP_SHIB_COOKIE_NAME");
    request.clearHeader("Shib-Session-ID", "HTTP_SHIB_SESSION_ID");
    request.clearHeader("Shib-Session-Index", "HTTP_SHIB_SESSION_INDEX");
    request.clearHeader("Shib-Session-Expires", "HTTP_SHIB_SESSION_EXPIRES");
    request.clearHeader("Shib-Session-Inactivity", "HTTP_SHIB_SESSION_INACTIVITY");
    request.clearHeader("Shib-Identity-Provider", "HTTP_SHIB_IDENTITY_PROVIDER");
    request.clearHeader("Shib-Authentication-Method", "HTTP_SHIB_AUTHENTICATION_METHOD");
    request.clearHeader("Shib-Authentication-Instant", "HTTP_SHIB_AUTHENTICATION_INSTANT");
    request.clearHeader("Shib-AuthnContext-Class", "HTTP_SHIB_AUTHNCONTEXT_CLASS");
    request.clearHeader("Shib-AuthnContext-Decl", "HTTP_SHIB_AUTHNCONTEXT_DECL");
    request.clearHeader("Shib-Assertion-Count", "HTTP_SHIB_ASSERTION_COUNT");
    request.clearHeader("Shib-Handler", "HTTP_SHIB_HANDLER");
    request.clearHeader("REMOTE_USER", "HTTP_REMOTE_USER");
    // TODO: Redo the handling of attribute headers in the code, likely supplanting all of the above...
    //request.clearAttributeHeaders();
}

void Agent::exportAttributes(SPRequest& request, const Session* session) const {

    RequestMapper::Settings settings = request.getRequestSettings();

    const char* enc = settings.first->getString("encoding");
    if (enc && strcmp(enc, "URL"))
        throw ConfigurationException(string("Unsupported value for 'encoding' content setting: ") + enc);

    const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();

    // Default delimiter is semicolon but is now configurable.
    const char* delim = settings.first->getString("attributeValueDelimiter", ";");
    size_t delim_len = strlen(delim);

    bool exportDups = settings.first->getBool("exportDuplicateValues", true);
    const multimap<string,const Attribute*>& attributes = session->getIndexedAttributes();

    // Default export strategy will include duplicates.
    if (exportDups) {
        for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
            if (a->second->isInternal())
                continue;
            string header(request.getSecureHeader(a->first.c_str()));
            const vector<string>& vals = a->second->getSerializedValues();
            for (vector<string>::const_iterator v = vals.begin(); v != vals.end(); ++v) {
                if (!header.empty())
                    header += delim;
                if (enc) {
                    // If URL-encoding, any semicolons will get escaped anyway.
                    header += encoder.encode(v->c_str());
                }
                else {
                    string::size_type pos = v->find(delim, string::size_type(0));
                    if (pos != string::npos) {
                        string value(*v);
                        for (; pos != string::npos; pos = value.find(delim, pos)) {
                            value.insert(pos, "\\");
                            pos += delim_len + 1;
                        }
                        header += value;
                    }
                    else {
                        header += (*v);
                    }
                }
            }
            request.setHeader(a->first.c_str(), header.c_str());
        }
    }
    else {
        // Capture values in a map of sets to check for duplicates on the fly.
        map< string,set<string> > valueMap;
        for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
            if (a->second->isInternal())
                continue;
            const vector<string>& vals = a->second->getSerializedValues();
            valueMap[a->first].insert(vals.begin(), vals.end());
        }

        // Export the mapped sets to the headers.
        for (map< string,set<string> >::const_iterator deduped = valueMap.begin(); deduped != valueMap.end(); ++deduped) {
            string header;
            for (set<string>::const_iterator v = deduped->second.begin(); v != deduped->second.end(); ++v) {
                if (!header.empty())
                    header += delim;
                if (enc) {
                    // If URL-encoding, any semicolons will get escaped anyway.
                    header += encoder.encode(v->c_str());
                }
                else {
                    string::size_type pos = v->find(delim, string::size_type(0));
                    if (pos != string::npos) {
                        string value(*v);
                        for (; pos != string::npos; pos = value.find(delim, pos)) {
                            value.insert(pos, "\\");
                            pos += delim_len + 1;
                        }
                        header += value;
                    }
                    else {
                        header += (*v);
                    }
                }
            }
            request.setHeader(deduped->first.c_str(), header.c_str());
        }
    }

    // Check for REMOTE_USER.
    bool remoteUserSet = false;
    vector<string> dummy;
    const vector<string>& rmids = dummy; // app.getRemoteUserAttributeIds(); TODO: re implement this elsewhere
    for (vector<string>::const_iterator rmid = rmids.begin(); !remoteUserSet && rmid != rmids.end(); ++rmid) {
        pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> matches =
            attributes.equal_range(*rmid);
        for (; matches.first != matches.second; ++matches.first) {
            const vector<string>& vals = matches.first->second->getSerializedValues();
            if (!vals.empty()) {
                if (enc)
                    request.setRemoteUser(encoder.encode(vals.front().c_str()).c_str());
                else
                    request.setRemoteUser(vals.front().c_str());
                remoteUserSet = true;
                break;
            }
        }
    }
}

pair<bool,long> Agent::doAuthentication(SPRequest& request, bool handler) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            const char* redirectToSSL = settings.first->getString("redirectToSSL");
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
                    agent_exception ex("Access via unencrypted HTTP was blocked.");
                    return make_pair(true, handleError(log, request, nullptr, &ex, false));
                }
            }
        }

        const char* handlerURL=request.getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // If the request URL contains the handler base URL for this application, either dispatch
        // directly (mainly Apache 2.0) or just pass back control.
        if (boost::contains(targetURL, handlerURL)) {
            if (handler)
                return doHandler(request);
            else
                return make_pair(true, request.returnOK());
        }

        // These settings dictate how to proceed.
        const char* authType = settings.first->getString("authType");
        bool requireSession = settings.first->getBool("requireSession", false);
        const char* requireSessionWith = settings.first->getString("requireSessionWith");
        const char* requireLogoutWith = settings.first->getString("requireLogoutWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if (!requireSession && !requireSessionWith &&
            (!authType || m_authTypes.find(boost::to_lower_copy(string(authType))) == m_authTypes.end()))
            return make_pair(true, request.returnDecline());

        // Fix for secadv 20050901
        clearHeaders(request);

        Session* session = nullptr;
        try {
            session = request.getSession(true, false, false);   // don't cache it
        }
        catch (const exception& e) {
            log.warn("error during session lookup: %s", e.what());
            // If it's not a retryable session failure, we throw to the outer handler for reporting.
            throw;
        }

        lock_guard<Session> slocker(*session, adopt_lock); // pop existing lock on exit
        if (session) {
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
            if (!requireSession && !requireSessionWith) {
                request.setHeader("Shib-Handler", handlerURL);
                return make_pair(true, request.returnOK());
            }

            // No session, but we require one. Initiate a new session using the indicated method.

            // TODO: replace with new handler infra

            const SessionInitiator* initiator=nullptr;
            if (requireSessionWith) {
                AgentConfig::getConfig().deprecation().warn("requireSessionWith");
                //initiator = app->getSessionInitiatorById(requireSessionWith);
                if (!initiator) {
                    throw ConfigurationException(string("No session initiator found with id: ") + requireSessionWith);
                }
            }
            else {
                //initiator = app->getDefaultSessionInitiator();
                if (!initiator)
                    throw ConfigurationException("No default session initiator found, check configuration.");
            }

            // Dispatch to SessionInitiator. This MUST handle the request, or we want to fail here.
            // Used to fall through into doExport, but this is a cleaner exit path.
            pair<bool, long> ret = initiator->run(request, false);
            if (ret.first)
                return ret;
            throw ConfigurationException("Session initiator did not handle request for a new session, check configuration.");
        }

        request.setAuthType(authType);

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        log.debug("doAuthentication succeeded");
        return make_pair(false,0L);
    }
    catch (const exception& e) {
        request.log(Priority::SHIB_ERROR, e.what());
        return make_pair(true, handleError(log, request, nullptr, &e));
    }
}

pair<bool,long> Agent::doAuthorization(SPRequest& request) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    Session* session = nullptr;
    unique_lock<Session> slocker;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // Three settings dictate how to proceed.
        const char* authType = settings.first->getString("authType");
        bool requireSession = settings.first->getBool("requireSession", false);
        const char* requireSessionWith = settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if (!requireSession && !requireSessionWith &&
                (!authType || m_authTypes.find(boost::to_lower_copy(string(authType))) == m_authTypes.end()))
            return make_pair(true, request.returnDecline());

        // Do we have an access control plugin?
        if (settings.second) {
            try {
                session = request.getSession(false, false, false);  // ignore timeout and do not cache
                if (session) {
                    unique_lock<Session> slocker2(*session, adopt_lock);
                    slocker.swap(slocker2); // assign to lock popper
                }
            }
            catch (const exception& e) {
                log.warn("unable to obtain session to pass to access control provider: %s", e.what());
            }

#ifdef HAVE_CXX14
            shared_lock<AccessControl> acllock(*settings.second);
#endif
            switch (settings.second->authorized(request, session)) {
                case AccessControl::shib_acl_true:
                    log.debug("access control provider granted access");
                    return make_pair(true, request.returnOK());

                case AccessControl::shib_acl_false:
                {
                    log.warn("access control provider denied access");
                    agent_exception ex("Access to resource denied.");
                    ex.setStatusCode(HTTPResponse::SHIBSP_HTTP_STATUS_FORBIDDEN);
                    return make_pair(true, handleError(log, request, session, nullptr, false));
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
    catch (const exception& e) {
        request.log(Priority::SHIB_ERROR, e.what());
        return make_pair(true, handleError(log, request, nullptr, &e));
    }
}

pair<bool,long> Agent::doExport(SPRequest& request, bool requireSession) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    Session* session = nullptr;
    unique_lock<Session> slocker;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        try {
            session = request.getSession(false, false, false);  // ignore timeout and do not cache
            if (session) {
                unique_lock<Session> slocker2(*session, adopt_lock);
                slocker.swap(slocker2); // assign to lock popper
            }
        }
        catch (const exception& e) {
            log.warn("unable to obtain session to export to request: %s", e.what());
        	// If we have to have a session, then this is a fatal error.
        	if (requireSession)
        		throw;
        }

		// Still no data?
        if (!session) {
        	if (requireSession)
                throw SessionException("Unable to obtain session to export to request.");
        	else
        		return make_pair(false, 0L);	// just bail silently
        }

        request.setHeader("Shib-Application-ID", settings.first->getString("applicationId", "default"));
        request.setHeader("Shib-Session-ID", session->getID());

        // Check for export of "standard" variables.
        // A 3.0 release would switch this default to false and rely solely on the
        // Assertion extractor plugin and ship out of the box with the same defaults.
        bool stdvars = settings.first->getBool("exportStdVars", true);
        if (stdvars) {
            const char* hval = session->getEntityID();
            if (hval)
                request.setHeader("Shib-Identity-Provider", hval);
            time_t ts = session->getAuthnInstant();
            if (ts > 0) {
                // TODO: Need to see what the output format of this really is.
                ostringstream os;
                os << date::format("%FT%TZ", chrono::system_clock::from_time_t(ts));
                request.setHeader("Shib-Authentication-Instant", os.str().c_str());
            }
            hval = session->getAuthnContextClassRef();
            if (hval) {
                request.setHeader("Shib-Authentication-Method", hval);
                request.setHeader("Shib-AuthnContext-Class", hval);
            }

            request.setHeader( "Shib-Session-Expires", boost::lexical_cast<string>(session->getExpiration()).c_str());
            unsigned int timeout = settings.first->getUnsignedInt("timeout", 3600);
            if (timeout > 0) {
                request.setHeader( "Shib-Session-Inactivity", boost::lexical_cast<string>(session->getLastAccess() + timeout).c_str());
            }
        }

        // Check for export of algorithmically-derived portion of cookie names.
        bool exportCookie = settings.first->getBool("exportCookie", false);
        if (exportCookie) {
            pair<string,const char*> cookieprops = request.getCookieNameProps(nullptr);
            request.setHeader("Shib-Cookie-Name", cookieprops.first.c_str());
        }

        // Export the attributes.
        exportAttributes(request, session);

        return make_pair(false,0L);
    }
    catch (const exception& e) {
        request.log(Priority::SHIB_ERROR, e.what());
        return make_pair(true, handleError(log, request, session, &e));
    }
}

pair<bool,long> Agent::doHandler(SPRequest& request) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            const char* redirectToSSL = settings.first->getString("redirectToSSL");
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

        const char* handlerURL = request.getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // Make sure we only process handler requests.
        if (!boost::contains(targetURL, handlerURL))
            return make_pair(true, request.returnDecline());

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).

        // TODO: replace with new handler infra
        const Handler* handler = nullptr; // app->getHandler(targetURL.c_str() + strlen(handlerURL));
        if (!handler)
            throw ConfigurationException("Shibboleth handler invoked at an unconfigured location.");

        pair<bool, long> hret = handler->run(request);
        // Did the handler run successfully?
        if (hret.first)
            return hret;
        throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
    }
    catch (const exception& e) {
        request.log(Priority::SHIB_ERROR, e.what());
        Session* session = nullptr;
        try {
            session = request.getSession(false, true, false);   // do not cache
        }
        catch (const exception&) {
        }
        lock_guard<Session> slocker(*session, adopt_lock); // pop existing lock on exit
        return make_pair(true, handleError(log, request, session, &e));
    }
}
