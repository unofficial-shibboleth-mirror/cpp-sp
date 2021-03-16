/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * ServiceProvider.cpp
 *
 * Interface to a Shibboleth ServiceProvider instance.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/SessionInitiator.h"
#include "util/TemplateParameters.h"

#include <fstream>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
# include <saml/saml2/metadata/MetadataProvider.h>
#endif
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<ServiceProvider,string,const DOMElement*>::Factory XMLServiceProviderFactory;

    long SHIBSP_DLLLOCAL sendError(
        Category& log, SPRequest& request, const Application* app, const char* page, TemplateParameters& tp, bool mayRedirect=true
        )
    {
        // The properties we need can be set in the RequestMap, or the Errors element.
        bool mderror = dynamic_cast<const opensaml::saml2md::MetadataException*>(tp.getRichException())!=nullptr;
        bool accesserror = (strcmp(page, "access")==0);
        pair<bool,const char*> redirectErrors = pair<bool,const char*>(false,nullptr);
        pair<bool,const char*> pathname = pair<bool,const char*>(false,nullptr);

        // Strictly for error handling, detect a nullptr application and point at the default.
        if (!app)
            app = request.getServiceProvider().getApplication(nullptr);

        const PropertySet* props = app->getPropertySet("Errors");

        // If the externalParameters option isn't set, clear out the request field.
        pair<bool,bool> externalParameters =
                props ? props->getBool("externalParameters") : pair<bool,bool>(false,false);
        if (!externalParameters.first || !externalParameters.second) {
            tp.m_request = nullptr;
        }

        // Now look for settings in the request map of the form pageError.
        try {
            RequestMapper::Settings settings = request.getRequestSettings();
            if (mderror)
                pathname = settings.first->getString("metadataError");
            if (!pathname.first) {
                string pagename(page);
                pagename += "Error";
                pathname = settings.first->getString(pagename.c_str());
            }
            if (mayRedirect)
                redirectErrors = settings.first->getString("redirectErrors");
        }
        catch (const exception& ex) {
            log.error(ex.what());
        }

        // Check for redirection on errors instead of template.
        if (mayRedirect) {
            if (!redirectErrors.first && props)
                redirectErrors = props->getString("redirectErrors");
            if (redirectErrors.first) {
                string loc(redirectErrors.second);
                request.absolutize(loc);
                loc = loc + '?' + tp.toQueryString();
                return request.sendRedirect(loc.c_str());
            }
        }

        request.setContentType("text/html");
        request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
        request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");

        // Nothing in the request map, so check for a property named "page" in the Errors property set.
        if (!pathname.first && props) {
            if (mderror)
                pathname=props->getString("metadata");
            if (!pathname.first)
                pathname=props->getString(page);
        }

        // If there's still no template to use, just use pageError.html unless it's an access issue.
        string fname;
        if (!pathname.first) {
            if (!accesserror) {
                fname = string(mderror ? "metadata" : page) + "Error.html";
                pathname.second = fname.c_str();
            }
        }
        else {
            fname = pathname.second;
        }

        // If we have a template to use, use it.
        if (!fname.empty()) {
            ifstream infile(XMLToolingConfig::getConfig().getPathResolver()->resolve(fname, PathResolver::XMLTOOLING_CFG_FILE).c_str());
            if (infile) {
                tp.setPropertySet(props);
                stringstream str;
                XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, tp, tp.getRichException());
                return request.sendError(str);
            }
        }

        // If we got here, then either it's an access error or a template failed.
        if (accesserror) {
            istringstream msg("Access Denied");
            return request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_FORBIDDEN);
        }

        log.error("sendError could not process error template (%s)", pathname.second);
        istringstream msg("Internal Server Error. Please contact the site administrator.");
        return request.sendError(msg);
    }

    void SHIBSP_DLLLOCAL clearHeaders(SPRequest& request) {
        const Application& app = request.getApplication();
        app.clearHeader(request, "Shib-Cookie-Name", "HTTP_SHIB_COOKIE_NAME");
        app.clearHeader(request, "Shib-Session-ID", "HTTP_SHIB_SESSION_ID");
        app.clearHeader(request, "Shib-Session-Index", "HTTP_SHIB_SESSION_INDEX");
        app.clearHeader(request, "Shib-Session-Expires", "HTTP_SHIB_SESSION_EXPIRES");
        app.clearHeader(request, "Shib-Session-Inactivity", "HTTP_SHIB_SESSION_INACTIVITY");
        app.clearHeader(request, "Shib-Identity-Provider", "HTTP_SHIB_IDENTITY_PROVIDER");
        app.clearHeader(request, "Shib-Authentication-Method", "HTTP_SHIB_AUTHENTICATION_METHOD");
        app.clearHeader(request, "Shib-Authentication-Instant", "HTTP_SHIB_AUTHENTICATION_INSTANT");
        app.clearHeader(request, "Shib-AuthnContext-Class", "HTTP_SHIB_AUTHNCONTEXT_CLASS");
        app.clearHeader(request, "Shib-AuthnContext-Decl", "HTTP_SHIB_AUTHNCONTEXT_DECL");
        app.clearHeader(request, "Shib-Assertion-Count", "HTTP_SHIB_ASSERTION_COUNT");
        app.clearHeader(request, "Shib-Handler", "HTTP_SHIB_HANDLER");
        app.clearAttributeHeaders(request);
        request.clearHeader("REMOTE_USER", "HTTP_REMOTE_USER");
    }

    void SHIBSP_DLLLOCAL exportAttributes(SPRequest& request, const Session* session, RequestMapper::Settings settings) {

        pair<bool,const char*> enc = settings.first->getString("encoding");
        if (enc.first && strcmp(enc.second, "URL"))
            throw ConfigurationException("Unsupported value for 'encoding' content setting ($1).", params(1,enc.second));

        const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();

        // Default delimiter is semicolon but is now configurable.
        pair<bool,const char*> delim = settings.first->getString("attributeValueDelimiter");
        if (enc.first || !delim.first) {
            delim.second = ";";
        }
        size_t delim_len = strlen(delim.second);

        pair<bool,bool> exportDups = settings.first->getBool("exportDuplicateValues");
        const multimap<string,const Attribute*>& attributes = session->getIndexedAttributes();

        // Default export strategy will include duplicates.
        if (!exportDups.first || exportDups.second) {
            for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
                if (a->second->isInternal())
                    continue;
                string header(request.getApplication().getSecureHeader(request, a->first.c_str()));
                const vector<string>& vals = a->second->getSerializedValues();
                for (vector<string>::const_iterator v = vals.begin(); v != vals.end(); ++v) {
                    if (!header.empty())
                        header += delim.second;
                    if (enc.first) {
                        // If URL-encoding, any semicolons will get escaped anyway.
                        header += encoder->encode(v->c_str());
                    }
                    else {
                        string::size_type pos = v->find(delim.second, string::size_type(0));
                        if (pos != string::npos) {
                            string value(*v);
                            for (; pos != string::npos; pos = value.find(delim.second, pos)) {
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
                request.getApplication().setHeader(request, a->first.c_str(), header.c_str());
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
                        header += delim.second;
                    if (enc.first) {
                        // If URL-encoding, any semicolons will get escaped anyway.
                        header += encoder->encode(v->c_str());
                    }
                    else {
                        string::size_type pos = v->find(delim.second, string::size_type(0));
                        if (pos != string::npos) {
                            string value(*v);
                            for (; pos != string::npos; pos = value.find(delim.second, pos)) {
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
                request.getApplication().setHeader(request, deduped->first.c_str(), header.c_str());
            }
        }

        // Check for REMOTE_USER.
        bool remoteUserSet = false;
        const vector<string>& rmids = request.getApplication().getRemoteUserAttributeIds();
        for (vector<string>::const_iterator rmid = rmids.begin(); !remoteUserSet && rmid != rmids.end(); ++rmid) {
            pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> matches =
                attributes.equal_range(*rmid);
            for (; matches.first != matches.second; ++matches.first) {
                const vector<string>& vals = matches.first->second->getSerializedValues();
                if (!vals.empty()) {
                    if (enc.first)
                        request.setRemoteUser(encoder->encode(vals.front().c_str()).c_str());
                    else
                        request.setRemoteUser(vals.front().c_str());
                    remoteUserSet = true;
                    break;
                }
            }
        }
    }
};

void SHIBSP_API shibsp::registerServiceProviders()
{
    SPConfig::getConfig().ServiceProviderManager.registerFactory(XML_SERVICE_PROVIDER, XMLServiceProviderFactory);
}

ServiceProvider::ServiceProvider()
{
    m_authTypes.insert("shibboleth");
}

ServiceProvider::~ServiceProvider()
{
}

pair<bool,long> ServiceProvider::doAuthentication(SPRequest& request, bool handler) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doAuthentication");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        string appid(string("[") + app->getId() + "]");
        xmltooling::NDC ndc(appid.c_str());

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            pair<bool,const char*> redirectToSSL = settings.first->getString("redirectToSSL");
            if (redirectToSSL.first) {
#ifdef HAVE_STRCASECMP
                if (!strcasecmp("GET",request.getMethod()) || !strcasecmp("HEAD",request.getMethod())) {
#else
                if (!stricmp("GET",request.getMethod()) || !stricmp("HEAD",request.getMethod())) {
#endif
                    // Compute the new target URL
                    string redirectURL = string("https://") + request.getHostname();
                    if (strcmp(redirectToSSL.second,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL.second;
                    }
                    redirectURL += request.getRequestURI();
                    return make_pair(true, request.sendRedirect(redirectURL.c_str()));
                }
                else {
                    TemplateParameters tp;
                    tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
                    return make_pair(true, sendError(log, request, app, "ssl", tp, false));
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
        pair<bool,const char*> authType = settings.first->getString("authType");
        pair<bool,bool> requireSession = settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = settings.first->getString("requireSessionWith");
        pair<bool,const char*> requireLogoutWith = settings.first->getString("requireLogoutWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
                (!authType.first || m_authTypes.find(boost::to_lower_copy(string(authType.second))) == m_authTypes.end()))
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
            if (dynamic_cast<const opensaml::RetryableProfileException*>(&e) == nullptr)
                throw;
        }

        Locker slocker(session, false); // pop existing lock on exit
        if (session) {
            // Check for logout interception.
            if (requireLogoutWith.first) {
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
                    string loc = requireLogoutWith.second;
                    request.absolutize(loc);
                    if (loc.find('?') != string::npos)
                        loc += '&';
                    else
                        loc += '?';
                    loc += "return=" + XMLToolingConfig::getConfig().getURLEncoder()->encode(selfurl.c_str());
                    return make_pair(true, request.sendRedirect(loc.c_str()));
                }
            }
            app->setHeader(request, "Shib-Handler", handlerURL);
        }
        else {
            // No session.  Maybe that's acceptable?
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first) {
                app->setHeader(request, "Shib-Handler", handlerURL);
                return make_pair(true, request.returnOK());
            }

            // No session, but we require one. Initiate a new session using the indicated method.
            const SessionInitiator* initiator=nullptr;
            if (requireSessionWith.first) {
                initiator=app->getSessionInitiatorById(requireSessionWith.second);
                if (!initiator) {
                    throw ConfigurationException(
                        "No session initiator found with id ($1), check requireSessionWith setting.", params(1, requireSessionWith.second)
                        );
                }
            }
            else {
                initiator=app->getDefaultSessionInitiator();
                if (!initiator)
                    throw ConfigurationException("No default session initiator found, check configuration.");
            }

            // Dispatch to SessionInitiator. This MUST handle the request, or we want to fail here.
            // Used to fall through into doExport, but this is a cleaner exit path.
            try {
                pair<bool, long> ret = initiator->run(request, false);
                if (ret.first)
                    return ret;
                throw ConfigurationException("Session initiator did not handle request for a new session, check configuration.");
            }
            catch (XMLToolingException& ex) {
                if (!ex.getProperty("eventType") && initiator->getEventType())
                    ex.addProperty("eventType", initiator->getEventType());
                throw;
            }
        }

        request.setAuthType(authType.second);

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        log.debug("doAuthentication succeeded");
        return make_pair(false,0L);
    }
    catch (const exception& e) {
        request.log(SPRequest::SPError, e.what());
        TemplateParameters tp(&e);
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true, sendError(log, request, app, "session", tp));
    }
}

pair<bool,long> ServiceProvider::doAuthorization(SPRequest& request) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doAuthorization");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    Session* session = nullptr;
    Locker slocker;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        string appid(string("[") + app->getId() + "]");
        xmltooling::NDC ndc(appid.c_str());

        // Three settings dictate how to proceed.
        pair<bool,const char*> authType = settings.first->getString("authType");
        pair<bool,bool> requireSession = settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't recognized,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
                (!authType.first || m_authTypes.find(boost::to_lower_copy(string(authType.second))) == m_authTypes.end()))
            return make_pair(true, request.returnDecline());

        // Do we have an access control plugin?
        if (settings.second) {
            try {
                session = request.getSession(false, false, false);  // ignore timeout and do not cache
                if (session)
                    slocker.assign(session, false); // assign to lock popper
            }
            catch (const exception& e) {
                log.warn("unable to obtain session to pass to access control provider: %s", e.what());
            }

            Locker acllock(settings.second);
            switch (settings.second->authorized(request, session)) {
                case AccessControl::shib_acl_true:
                    log.debug("access control provider granted access");
                    return make_pair(true, request.returnOK());

                case AccessControl::shib_acl_false:
                {
                    log.warn("access control provider denied access");
                    TemplateParameters tp(nullptr, nullptr, session);
                    tp.m_map["requestURL"] = targetURL;
                    return make_pair(true, sendError(log, request, app, "access", tp, false));
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
        request.log(SPRequest::SPError, e.what());
        TemplateParameters tp(&e, nullptr, session);
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true, sendError(log, request, app, "access", tp));
    }
}

pair<bool,long> ServiceProvider::doExport(SPRequest& request, bool requireSession) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doExport");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    Session* session = nullptr;
    Locker slocker;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        string appid(string("[") + app->getId() + "]");
        xmltooling::NDC ndc(appid.c_str());

        try {
            session = request.getSession(false, false, false);  // ignore timeout and do not cache
            if (session)
                slocker.assign(session, false); // assign to lock popper
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
                throw opensaml::RetryableProfileException("Unable to obtain session to export to request.");
        	else
        		return make_pair(false, 0L);	// just bail silently
        }

        app->setHeader(request, "Shib-Application-ID", app->getId());
        app->setHeader(request, "Shib-Session-ID", session->getID());

        const PropertySet* sessionProps = app->getPropertySet("Sessions");

        // Check for export of "standard" variables.
        // A 3.0 release would switch this default to false and rely solely on the
        // Assertion extractor plugin and ship out of the box with the same defaults.
        pair<bool,bool> stdvars = settings.first->getBool("exportStdVars");
        if (!stdvars.first || stdvars.second) {
            const char* hval = session->getEntityID();
            if (hval)
                app->setHeader(request, "Shib-Identity-Provider", hval);
            hval = session->getAuthnInstant();
            if (hval)
                app->setHeader(request, "Shib-Authentication-Instant", hval);
            hval = session->getAuthnContextClassRef();
            if (hval) {
                app->setHeader(request, "Shib-Authentication-Method", hval);
                app->setHeader(request, "Shib-AuthnContext-Class", hval);
            }
            hval = session->getAuthnContextDeclRef();
            if (hval)
                app->setHeader(request, "Shib-AuthnContext-Decl", hval);
            hval = session->getSessionIndex();
            if (hval)
                app->setHeader(request, "Shib-Session-Index", hval);

            app->setHeader(request, "Shib-Session-Expires", boost::lexical_cast<string>(session->getExpiration()).c_str());
            pair<bool,unsigned int> timeout = sessionProps ? sessionProps->getUnsignedInt("timeout") : pair<bool,unsigned int>(false, 0);
            if (timeout.first && timeout.second > 0) {
                app->setHeader(request, "Shib-Session-Inactivity", boost::lexical_cast<string>(session->getLastAccess() + timeout.second).c_str());
            }
        }

        // Check for export of algorithmically-derived portion of cookie names.
        stdvars = settings.first->getBool("exportCookie");
        if (stdvars.first && stdvars.second) {
            pair<string,const char*> cookieprops = app->getCookieNameProps(nullptr);
            app->setHeader(request, "Shib-Cookie-Name", cookieprops.first.c_str());
        }

        // Maybe export the assertion keys.
        pair<bool,bool> exp = settings.first->getBool("exportAssertion");
        if (exp.first && exp.second) {
            pair<bool,const char*> exportLocation = sessionProps ? sessionProps->getString("exportLocation") : pair<bool,const char*>(false,nullptr);
            if (!exportLocation.first)
                log.warn("can't export assertions without an exportLocation Sessions property");
            else {
                string exportName = "Shib-Assertion-00";
                string baseURL;
                if (!strncmp(exportLocation.second, "http", 4))
                    baseURL = exportLocation.second;
                else
                    baseURL = string(request.getHandlerURL(targetURL.c_str())) + exportLocation.second;
                baseURL = baseURL + "?key=" + session->getID() + "&ID=";
                const vector<const char*>& tokens = session->getAssertionIDs();
                vector<const char*>::size_type count = 0;
                for (vector<const char*>::const_iterator tokenids = tokens.begin(); tokenids!=tokens.end(); ++tokenids) {
                    count++;
                    *(exportName.rbegin()) = '0' + (count%10);
                    *(++exportName.rbegin()) = '0' + (count/10);
                    string fullURL = baseURL + XMLToolingConfig::getConfig().getURLEncoder()->encode(*tokenids);
                    app->setHeader(request, exportName.c_str(), fullURL.c_str());
                }
                app->setHeader(request, "Shib-Assertion-Count", exportName.c_str() + 15);
            }
        }

        // Export the attributes.
        exportAttributes(request, session, settings);

        return make_pair(false,0L);
    }
    catch (const exception& e) {
        request.log(SPRequest::SPError, e.what());
        TemplateParameters tp(&e, nullptr, session);
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true, sendError(log, request, app, "session", tp));
    }
}

pair<bool,long> ServiceProvider::doHandler(SPRequest& request) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doHandler");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ServiceProvider");

    const Application* app = nullptr;
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        string appid(string("[") + app->getId() + "]");
        xmltooling::NDC ndc(appid.c_str());

        // If not SSL, check to see if we should block or redirect it.
        if (!request.isSecure()) {
            pair<bool,const char*> redirectToSSL = settings.first->getString("redirectToSSL");
            if (redirectToSSL.first) {
#ifdef HAVE_STRCASECMP
                if (!strcasecmp("GET",request.getMethod()) || !strcasecmp("HEAD",request.getMethod())) {
#else
                if (!stricmp("GET",request.getMethod()) || !stricmp("HEAD",request.getMethod())) {
#endif
                    // Compute the new target URL
                    string redirectURL = string("https://") + request.getHostname();
                    if (strcmp(redirectToSSL.second,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL.second;
                    }
                    redirectURL += request.getRequestURI();
                    return make_pair(true, request.sendRedirect(redirectURL.c_str()));
                }
                else {
                    TemplateParameters tp;
                    tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
                    return make_pair(true,sendError(log, request, app, "ssl", tp, false));
                }
            }
        }

        const char* handlerURL = request.getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // Make sure we only process handler requests.
        if (!boost::contains(targetURL, handlerURL))
            return make_pair(true, request.returnDecline());

        const PropertySet* sessionProps = app->getPropertySet("Sessions");
        if (!sessionProps)
            throw ConfigurationException("Unable to map request to application session settings, check configuration.");

        // Process incoming request.
        pair<bool,bool> handlerSSL = sessionProps->getBool("handlerSSL");

        // Make sure this is SSL, if it should be
        if ((!handlerSSL.first || handlerSSL.second) && !request.isSecure())
            throw opensaml::FatalProfileException("Blocked non-SSL access to Shibboleth handler.");

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).
        const Handler* handler = app->getHandler(targetURL.c_str() + strlen(handlerURL));
        if (!handler)
            throw ConfigurationException("Shibboleth handler invoked at an unconfigured location.");

        try {
            pair<bool, long> hret = handler->run(request);
            // Did the handler run successfully?
            if (hret.first)
                return hret;
            throw ConfigurationException("Configured Shibboleth handler failed to process the request.");
        }
        catch (XMLToolingException& ex) {
            if (!ex.getProperty("eventType") && handler->getEventType())
                ex.addProperty("eventType", handler->getEventType());
            throw;
        }
    }
    catch (const exception& e) {
        request.log(SPRequest::SPError, e.what());
        Session* session = nullptr;
        try {
            session = request.getSession(false, true, false);   // do not cache
        }
        catch (const exception&) {
        }
        Locker slocker(session, false); // pop existing lock on exit
        TemplateParameters tp(&e, nullptr, session);
        tp.m_map["requestURL"] = targetURL.substr(0, targetURL.find('?'));
        tp.m_request = &request;
        return make_pair(true, sendError(log, request, app, "session", tp));
    }
}
