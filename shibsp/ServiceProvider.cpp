/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
#include "AccessControl.h"
#include "Application.h"
#include "Handler.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "util/TemplateParameters.h"

#include <fstream>
#include <sstream>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    //SHIBSP_DLLLOCAL PluginManager<ServiceProvider,const DOMElement*>::Factory XMLServiceProviderFactory;

    long SHIBSP_DLLLOCAL sendError(
        SPRequest& request, const Application* app, const char* page, TemplateParameters& tp, const XMLToolingException* ex=NULL
        )
    {
        request.setContentType("text/html");
        request.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
        request.setResponseHeader("Cache-Control","private,no-store,no-cache");
    
        const PropertySet* props=app ? app->getPropertySet("Errors") : NULL;
        if (props) {
            pair<bool,const char*> p=props->getString(page);
            if (p.first) {
                ifstream infile(p.second);
                if (infile) {
                    tp.setPropertySet(props);
                    stringstream str;
                    XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, tp, ex);
                    return request.sendResponse(str);
                }
            }
            else if (!strcmp(page,"access")) {
                istringstream msg("Access Denied");
                return static_cast<opensaml::GenericResponse&>(request).sendResponse(msg, HTTPResponse::SAML_HTTP_STATUS_FORBIDDEN);
            }
        }
    
        string errstr = string("sendError could not process error template (") + page + ")";
        request.log(SPRequest::SPError, errstr);
        istringstream msg("Internal Server Error. Please contact the site administrator.");
        return request.sendError(msg);
    }
    
    void SHIBSP_DLLLOCAL clearHeaders(SPRequest& request) {
        // Clear invariant stuff.
        request.clearHeader("Shib-Origin-Site");
        request.clearHeader("Shib-Identity-Provider");
        request.clearHeader("Shib-Authentication-Method");
        request.clearHeader("Shib-NameIdentifier-Format");
        request.clearHeader("Shib-Attributes");
        request.clearHeader("Shib-Application-ID");
    
        // Clear out the list of mapped attributes
        /* TODO: port
        Iterator<IAAP*> provs=dynamic_cast<const IApplication&>(getApplication()).getAAPProviders();
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            xmltooling::Locker locker(aap);
            Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
            while (rules.hasNext()) {
                const char* header=rules.next()->getHeader();
                if (header)
                    request.clearHeader(header);
            }
        }
        */
    }

    static const XMLCh SessionInitiator[] =     UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
};

void SHIBSP_API shibsp::registerServiceProviders()
{
    //SPConfig::getConfig().ServiceProviderManager.registerFactory(XML_SERVICE_PROVIDER, XMLServiceProviderFactory);
}

pair<bool,long> ServiceProvider::doAuthentication(SPRequest& request, bool handler) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doAuthentication");
#endif

    const Application* app=NULL;
    const char* procState = "Request Processing Error";
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

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
                    return make_pair(true,sendError(request, app, "ssl", tp));
                }
            }
        }
        
        const char* handlerURL=request.getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // If the request URL contains the handler base URL for this application, either dispatch
        // directly (mainly Apache 2.0) or just pass back control.
        if (strstr(targetURL.c_str(),handlerURL)) {
            if (handler)
                return doHandler(request);
            else
                return make_pair(true, request.returnOK());
        }

        // Three settings dictate how to proceed.
        pair<bool,const char*> authType = settings.first->getString("authType");
        pair<bool,bool> requireSession = settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't shibboleth,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
#ifdef HAVE_STRCASECMP
                (!authType.first || strcasecmp(authType.second,"shibboleth")))
#else
                (!authType.first || _stricmp(authType.second,"shibboleth")))
#endif
            return make_pair(true,request.returnDecline());

        // Fix for secadv 20050901
        clearHeaders(request);

        pair<string,const char*> shib_cookie = app->getCookieNameProps("_shibsession_");
        const char* session_id = request.getCookie(shib_cookie.first.c_str());
        if (!session_id || !*session_id) {
            // No session.  Maybe that's acceptable?
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                return make_pair(true,request.returnOK());

            // No cookie, but we require a session. Initiate a new session using the indicated method.
            procState = "Session Initiator Error";
            const Handler* initiator=NULL;
            if (requireSessionWith.first) {
                initiator=app->getSessionInitiatorById(requireSessionWith.second);
                if (!initiator)
                    throw ConfigurationException(
                        "No session initiator found with id ($1), check requireSessionWith command.",
                        params(1,requireSessionWith.second)
                        );
            }
            else {
                initiator=app->getDefaultSessionInitiator();
                if (!initiator)
                    throw ConfigurationException("No default session initiator found, check configuration.");
            }

            return initiator->run(request,false);
        }

        procState = "Session Processing Error";
        const Session* session=NULL;
        try {
            session=request.getSession();
            // Make a localized exception throw if the session isn't valid.
            if (!session)
                throw RetryableProfileException("Session no longer valid.");
        }
        catch (exception& e) {
            request.log(SPRequest::SPWarn, string("session processing failed: ") + e.what());

            // If no session is required, bail now.
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                // Has to be OK because DECLINED will just cause Apache
                // to fail when it can't locate anything to process the
                // AuthType.  No session plus requireSession false means
                // do not authenticate the user at this time.
                return make_pair(true, request.returnOK());

            // Try and cast down.
            exception* base = &e;
            RetryableProfileException* trycast=dynamic_cast<RetryableProfileException*>(base);
            if (trycast) {
                // Session is invalid but we can retry -- initiate a new session.
                procState = "Session Initiator Error";
                const Handler* initiator=NULL;
                if (requireSessionWith.first) {
                    initiator=app->getSessionInitiatorById(requireSessionWith.second);
                    if (!initiator)
                        throw ConfigurationException(
                            "No session initiator found with id ($1), check requireSessionWith command.",
                            params(1,requireSessionWith.second)
                            );
                }
                else {
                    initiator=app->getDefaultSessionInitiator();
                    if (!initiator)
                        throw ConfigurationException("No default session initiator found, check configuration.");
                }
                return initiator->run(request,false);
            }
            throw;    // send it to the outer handler
        }

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        request.log(SPRequest::SPDebug, "doAuthentication succeeded");
        return make_pair(false,0);
    }
    catch (XMLToolingException& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp, &e));
    }
    catch (exception& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp));
    }
#ifndef _DEBUG
    catch (...) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp));
    }
#endif
}

pair<bool,long> ServiceProvider::doAuthorization(SPRequest& request) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doAuthorization");
#endif

    const Application* app=NULL;
    const char* procState = "Authorization Processing Error";
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        // Three settings dictate how to proceed.
        pair<bool,const char*> authType = settings.first->getString("authType");
        pair<bool,bool> requireSession = settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't shibboleth,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
#ifdef HAVE_STRCASECMP
                (!authType.first || strcasecmp(authType.second,"shibboleth")))
#else
                (!authType.first || _stricmp(authType.second,"shibboleth")))
#endif
            return make_pair(true,request.returnDecline());

        // Do we have an access control plugin?
        if (settings.second) {
            const Session* session =NULL;
	        pair<string,const char*> shib_cookie=app->getCookieNameProps("_shibsession_");
            const char *session_id = request.getCookie(shib_cookie.first.c_str());
            try {
	        	if (session_id && *session_id) {
                    session = request.getSession();
	        	}
            }
            catch (exception&) {
                request.log(SPRequest::SPWarn, "unable to obtain session information to pass to access control provider");
            }
	
            Locker acllock(settings.second);
            if (settings.second->authorized(request,session)) {
                // Let the caller decide how to proceed.
                request.log(SPRequest::SPDebug, "access control provider granted access");
                return make_pair(false,0);
            }
            else {
                request.log(SPRequest::SPWarn, "access control provider denied access");
                TemplateParameters tp;
                tp.m_map["requestURL"] = targetURL;
                return make_pair(true,sendError(request, app, "access", tp));
            }
            return make_pair(false,0);
        }
        else
            return make_pair(true,request.returnDecline());
    }
    catch (XMLToolingException& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp, &e));
    }
    catch (exception& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "access", tp));
    }
#ifndef _DEBUG
    catch (...) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "access", tp));
    }
#endif
}

pair<bool,long> ServiceProvider::doExport(SPRequest& request, bool requireSession) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doExport");
#endif

    const Application* app=NULL;
    const char* procState = "Attribute Processing Error";
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        const Session* session=NULL;
        pair<string,const char*> shib_cookie=app->getCookieNameProps("_shibsession_");
        const char *session_id = request.getCookie(shib_cookie.first.c_str());
        try {
        	if (session_id && *session_id) {
                session = request.getSession();
        	}
        }
        catch (exception&) {
            request.log(SPRequest::SPWarn, "unable to obtain session information to export into request headers");
        	// If we have to have a session, then this is a fatal error.
        	if (requireSession)
        		throw;
        }

		// Still no data?
        if (!session) {
        	if (requireSession)
        		throw RetryableProfileException("Unable to obtain session information for request.");
        	else
        		return make_pair(false,0);	// just bail silently
        }
        
        /*
        TODO: port to new cache API
        // Extract data from session.
        pair<const char*,const SAMLSubject*> sub=m_cacheEntry->getSubject(false,true);
        pair<const char*,const SAMLResponse*> unfiltered=m_cacheEntry->getTokens(true,false);
        pair<const char*,const SAMLResponse*> filtered=m_cacheEntry->getTokens(false,true);

        // Maybe export the tokens.
        pair<bool,bool> exp=m_settings.first->getBool("exportAssertion");
        if (exp.first && exp.second && unfiltered.first && *unfiltered.first) {
            unsigned int outlen;
            XMLByte* serialized =
                Base64::encode(reinterpret_cast<XMLByte*>((char*)unfiltered.first), XMLString::stringLen(unfiltered.first), &outlen);
            XMLByte *pos, *pos2;
            for (pos=serialized, pos2=serialized; *pos2; pos2++)
                if (isgraph(*pos2))
                    *pos++=*pos2;
            *pos=0;
            setHeader("Shib-Attributes", reinterpret_cast<char*>(serialized));
            XMLString::release(&serialized);
        }

        // Export the SAML AuthnMethod and the origin site name, and possibly the NameIdentifier.
        setHeader("Shib-Origin-Site", m_cacheEntry->getProviderId());
        setHeader("Shib-Identity-Provider", m_cacheEntry->getProviderId());
        setHeader("Shib-Authentication-Method", m_cacheEntry->getAuthnContext());
        
        // Get the AAP providers, which contain the attribute policy info.
        Iterator<IAAP*> provs=m_app->getAAPProviders();

        // Export NameID?
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            xmltooling::Locker locker(aap);
            const XMLCh* format = sub.second->getNameIdentifier()->getFormat();
            const IAttributeRule* rule=aap->lookup(format ? format : SAMLNameIdentifier::UNSPECIFIED);
            if (rule && rule->getHeader()) {
                auto_ptr_char form(format ? format : SAMLNameIdentifier::UNSPECIFIED);
                auto_ptr_char nameid(sub.second->getNameIdentifier()->getName());
                setHeader("Shib-NameIdentifier-Format", form.get());
                if (!strcmp(rule->getHeader(),"REMOTE_USER"))
                    setRemoteUser(nameid.get());
                else
                    setHeader(rule->getHeader(), nameid.get());
            }
        }
        
        setHeader("Shib-Application-ID", m_app->getId());
    
        // Export the attributes.
        Iterator<SAMLAssertion*> a_iter(filtered.second ? filtered.second->getAssertions() : EMPTY(SAMLAssertion*));
        while (a_iter.hasNext()) {
            SAMLAssertion* assert=a_iter.next();
            Iterator<SAMLStatement*> statements=assert->getStatements();
            while (statements.hasNext()) {
                SAMLAttributeStatement* astate=dynamic_cast<SAMLAttributeStatement*>(statements.next());
                if (!astate)
                    continue;
                Iterator<SAMLAttribute*> attrs=astate->getAttributes();
                while (attrs.hasNext()) {
                    SAMLAttribute* attr=attrs.next();
            
                    // Are we supposed to export it?
                    provs.reset();
                    while (provs.hasNext()) {
                        IAAP* aap=provs.next();
                        xmltooling::Locker locker(aap);
                        const IAttributeRule* rule=aap->lookup(attr->getName(),attr->getNamespace());
                        if (!rule || !rule->getHeader())
                            continue;
                    
                        Iterator<string> vals=attr->getSingleByteValues();
                        if (!strcmp(rule->getHeader(),"REMOTE_USER") && vals.hasNext())
                            setRemoteUser(vals.next().c_str());
                        else {
                            int it=0;
                            string header = getSecureHeader(rule->getHeader());
                            if (!header.empty())
                                it++;
                            for (; vals.hasNext(); it++) {
                                string value = vals.next();
                                for (string::size_type pos = value.find_first_of(";", string::size_type(0));
                                        pos != string::npos;
                                        pos = value.find_first_of(";", pos)) {
                                    value.insert(pos, "\\");
                                    pos += 2;
                                }
                                if (it)
                                    header += ";";
                                header += value;
                            }
                            setHeader(rule->getHeader(), header.c_str());
                        }
                    }
                }
            }
        }
        */
    
        return make_pair(false,0);
    }
    catch (XMLToolingException& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "rm", tp, &e));
    }
    catch (exception& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "rm", tp));
    }
#ifndef _DEBUG
    catch (...) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "rm", tp));
    }
#endif
}

pair<bool,long> ServiceProvider::doHandler(SPRequest& request) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doHandler");
#endif

    const Application* app=NULL;
    const char* procState = "Shibboleth Handler Error";
    string targetURL = request.getRequestURL();

    try {
        RequestMapper::Settings settings = request.getRequestSettings();
        app = &(request.getApplication());

        const char* handlerURL=request.getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // Make sure we only process handler requests.
        if (!strstr(targetURL.c_str(),handlerURL))
            return make_pair(true, request.returnDecline());

        const PropertySet* sessionProps=app->getPropertySet("Sessions");
        if (!sessionProps)
            throw ConfigurationException("Unable to map request to application session settings, check configuration.");

        // Process incoming request.
        pair<bool,bool> handlerSSL=sessionProps->getBool("handlerSSL");
      
        // Make sure this is SSL, if it should be
        if ((!handlerSSL.first || handlerSSL.second) && strcmp(request.getScheme(),"https"))
            throw FatalProfileException("Blocked non-SSL access to Shibboleth handler.");

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).
        const Handler* handler=app->getHandler(targetURL.c_str() + strlen(handlerURL));
        if (!handler)
            throw BindingException("Shibboleth handler invoked at an unconfigured location.");

        if (XMLHelper::isNodeNamed(handler->getElement(),samlconstants::SAML20MD_NS,AssertionConsumerService::LOCAL_NAME))
            procState = "Session Creation Error";
        else if (XMLString::equals(handler->getElement()->getLocalName(),SessionInitiator))
            procState = "Session Initiator Error";
        else if (XMLHelper::isNodeNamed(handler->getElement(),samlconstants::SAML20MD_NS,SingleLogoutService::LOCAL_NAME))
            procState = "Session Termination Error";
        else
            procState = "Protocol Handler Error";
        pair<bool,long> hret=handler->run(request);

        // Did the handler run successfully?
        if (hret.first)
            return hret;
       
        throw BindingException("Configured Shibboleth handler failed to process the request.");
    }
    catch (MetadataException& e) {
        TemplateParameters tp;
        tp.m_map["errorText"] = e.what();
        // See if a metadata error page is installed.
        const PropertySet* props=app->getPropertySet("Errors");
        if (props) {
            pair<bool,const char*> p=props->getString("metadata");
            if (p.first) {
                tp.m_map["errorType"] = procState;
                tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
                return make_pair(true,sendError(request, app, "metadata", tp, &e));
            }
        }
        throw;
    }
    catch (XMLToolingException& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp, &e));
    }
    catch (exception& e) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp));
    }
#ifndef _DEBUG
    catch (...) {
        TemplateParameters tp;
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,sendError(request, app, "session", tp));
    }
#endif
}
