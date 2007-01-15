/*
 *  Copyright 2001-2005 Internet2
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

/*
 * shib-target.cpp -- The ShibTarget class, a superclass for general
 *		      target code
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <fstream>

#include <saml/SAMLConfig.h>
#include <xercesc/util/Base64.hpp>
#include <shibsp/AccessControl.h>
#include <shibsp/RequestMapper.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/XMLHelper.h>

#ifndef HAVE_STRCASECMP
# define strcasecmp stricmp
#endif

using namespace shibsp;
using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml2md;
using namespace log4cpp;
using namespace std;

using xmltooling::TemplateEngine;
using xmltooling::XMLToolingException;
using xmltooling::XMLToolingConfig;
using xmltooling::XMLHelper;

namespace shibtarget {

    class ExtTemplateParameters : public TemplateEngine::TemplateParameters
    {
        const PropertySet* m_props;
    public:
        ExtTemplateParameters() : m_props(NULL) {}
        ~ExtTemplateParameters() {}

        void setPropertySet(const PropertySet* props) {
            m_props = props;

            // Create a timestamp.
            time_t now = time(NULL);
#ifdef HAVE_CTIME_R
            char timebuf[32];
            m_map["now"] = ctime_r(&now,timebuf);
#else
            m_map["now"] = ctime(&now);
#endif
        }

        const char* getParameter(const char* name) const {
            const char* pch = TemplateParameters::getParameter(name);
            if (pch || !m_props)
                return pch;
            pair<bool,const char*> p = m_props->getString(name);
            return p.first ? p.second : NULL;
        }
    };

    long _sendError(SPRequest* st, const char* page, ExtTemplateParameters& tp, const XMLToolingException* ex=NULL);

    static const XMLCh SessionInitiator[] =     UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh DiagnosticService[] =    UNICODE_LITERAL_17(D,i,a,g,n,o,s,t,i,c,S,e,r,v,i,c,e);
}


/*************************************************************************
 * Shib Target implementation
 */



// These functions implement the server-agnostic shibboleth engine
// The web server modules implement a subclass and then call into 
// these methods once they instantiate their request object.

pair<bool,long> ShibTarget::doCheckAuthN(bool handler)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doCheckAuthN");
#endif

    const char* procState = "Request Processing Error";
    string targetURL = getRequestURL();
    ExtTemplateParameters tp;

    try {
        RequestMapper::Settings settings = getRequestSettings();
        const IApplication& app = dynamic_cast<const IApplication&>(getApplication());

        // If not SSL, check to see if we should block or redirect it.
        if (!strcmp("http",getScheme())) {
            pair<bool,const char*> redirectToSSL = settings.first->getString("redirectToSSL");
            if (redirectToSSL.first) {
                if (!strcasecmp("GET",getMethod()) || !strcasecmp("HEAD",getMethod())) {
                    // Compute the new target URL
                    string redirectURL = string("https://") + getHostname();
                    if (strcmp(redirectToSSL.second,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL.second;
                    }
                    redirectURL += getRequestURI();
                    return make_pair(true, sendRedirect(redirectURL.c_str()));
                }
                else {
                    tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
                    return make_pair(true,_sendError(this, "ssl", tp));
                }
            }
        }
        
        const char* handlerURL=getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // If the request URL contains the handler base URL for this application, either dispatch
        // directly (mainly Apache 2.0) or just pass back control.
        if (strstr(targetURL.c_str(),handlerURL)) {
            if (handler)
                return doHandler();
            else
                return make_pair(true, returnOK());
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
            return make_pair(true,returnDecline());

        // Fix for secadv 20050901
        clearHeaders();

        pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");
        const char* session_id = getCookie(shib_cookie.first.c_str());
        if (!session_id || !*session_id) {
            // No session.  Maybe that's acceptable?
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                return make_pair(true,returnOK());

            // No cookie, but we require a session. Initiate a new session using the indicated method.
            procState = "Session Initiator Error";
            const IHandler* initiator=NULL;
            if (requireSessionWith.first) {
                initiator=app.getSessionInitiatorById(requireSessionWith.second);
                if (!initiator)
                    throw ConfigurationException(
                        "No session initiator found with id ($1), check requireSessionWith command.",
                        xmltooling::params(1,requireSessionWith.second)
                        );
            }
            else {
                initiator=app.getDefaultSessionInitiator();
                if (!initiator)
                    throw ConfigurationException("No default session initiator found, check configuration.");
            }

            return initiator->run(this,false);
        }

        procState = "Session Processing Error";
        const Session* session=NULL;
        try {
            session=getSession();
            // Make a localized exception throw if the session isn't valid.
            if (!session)
                throw RetryableProfileException("Session no longer valid.");
        }
        catch (exception& e) {
            log(SPWarn, string("session processing failed: ") + e.what());

            // If no session is required, bail now.
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                // Has to be OK because DECLINED will just cause Apache
                // to fail when it can't locate anything to process the
                // AuthType.  No session plus requireSession false means
                // do not authenticate the user at this time.
                return make_pair(true, returnOK());

            // Try and cast down.
            exception* base = &e;
            RetryableProfileException* trycast=dynamic_cast<RetryableProfileException*>(base);
            if (trycast) {
                // Session is invalid but we can retry -- initiate a new session.
                procState = "Session Initiator Error";
                const IHandler* initiator=NULL;
                if (requireSessionWith.first) {
                    initiator=app.getSessionInitiatorById(requireSessionWith.second);
                    if (!initiator)
                        throw ConfigurationException(
                            "No session initiator found with id ($1), check requireSessionWith command.",
                            xmltooling::params(1,requireSessionWith.second)
                            );
                }
                else {
                    initiator=app.getDefaultSessionInitiator();
                    if (!initiator)
                        throw ConfigurationException("No default session initiator found, check configuration.");
                }
                return initiator->run(this,false);
            }
            throw;    // send it to the outer handler
        }

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        log(SPDebug, "doCheckAuthN succeeded");
        return make_pair(false,0);
    }
    catch (XMLToolingException& e) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "session", tp, &e));
    }
#ifndef _DEBUG
    catch (...) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "session", tp));
    }
#endif
}

pair<bool,long> ShibTarget::doHandler(void)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doHandler");
#endif

    const IApplication* app=NULL;
    ExtTemplateParameters tp;
    const char* procState = "Shibboleth Handler Error";
    string targetURL = getRequestURL();

    try {
        RequestMapper::Settings settings = getRequestSettings();
        app = dynamic_cast<const IApplication*>(&getApplication());

        const char* handlerURL=getHandlerURL(targetURL.c_str());
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // Make sure we only process handler requests.
        if (!strstr(targetURL.c_str(),handlerURL))
            return make_pair(true, returnDecline());

        const PropertySet* sessionProps=app->getPropertySet("Sessions");
        if (!sessionProps)
            throw ConfigurationException("Unable to map request to application session settings, check configuration.");

        // Process incoming request.
        pair<bool,bool> handlerSSL=sessionProps->getBool("handlerSSL");
      
        // Make sure this is SSL, if it should be
        if ((!handlerSSL.first || handlerSSL.second) && strcmp(getScheme(),"https"))
            throw FatalProfileException("Blocked non-SSL access to Shibboleth handler.");

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).
        const IHandler* handler=app->getHandler(targetURL.c_str() + strlen(handlerURL));
        if (!handler)
            throw opensaml::BindingException("Shibboleth handler invoked at an unconfigured location.");

        if (XMLHelper::isNodeNamed(handler->getProperties()->getElement(),samlconstants::SAML20MD_NS,AssertionConsumerService::LOCAL_NAME))
            procState = "Session Creation Error";
        else if (XMLString::equals(handler->getProperties()->getElement()->getLocalName(),SessionInitiator))
            procState = "Session Initiator Error";
        else if (XMLHelper::isNodeNamed(handler->getProperties()->getElement(),samlconstants::SAML20MD_NS,SingleLogoutService::LOCAL_NAME))
            procState = "Session Termination Error";
        else if (XMLString::equals(handler->getProperties()->getElement()->getLocalName(),DiagnosticService))
            procState = "Diagnostics Error";
        else
            procState = "Extension Service Error";
        pair<bool,long> hret=handler->run(this);

        // Did the handler run successfully?
        if (hret.first)
            return hret;
       
        throw opensaml::BindingException("Configured Shibboleth handler failed to process the request.");
    }
    catch (MetadataException& e) {
        tp.m_map["errorText"] = e.what();
        // See if a metadata error page is installed.
        const PropertySet* props=app->getPropertySet("Errors");
        if (props) {
            pair<bool,const char*> p=props->getString("metadata");
            if (p.first) {
                tp.m_map["errorType"] = procState;
                tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
                return make_pair(true,_sendError(this, "metadata", tp));
            }
        }
        throw;
    }
    catch (XMLToolingException& e) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "session", tp, &e));
    }
#ifndef _DEBUG
    catch (...) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "session", tp));
    }
#endif
}

pair<bool,long> ShibTarget::doCheckAuthZ(void)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doCheckAuthZ");
#endif

    const IApplication* app=NULL;
    ExtTemplateParameters tp;
    const char* procState = "Authorization Processing Error";
    string targetURL = getRequestURL();

    try {
        RequestMapper::Settings settings = getRequestSettings();
        app = dynamic_cast<const IApplication*>(&getApplication());

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
            return make_pair(true,returnDecline());

        // Do we have an access control plugin?
        if (settings.second) {
            const Session* session =NULL;
	        pair<string,const char*> shib_cookie=app->getCookieNameProps("_shibsession_");
            const char *session_id = getCookie(shib_cookie.first.c_str());
            try {
	        	if (session_id && *session_id) {
                    session = getSession();
	        	}
            }
            catch (exception&) {
            	log(SPWarn, "doCheckAuthZ: unable to obtain session information to pass to access control provider");
            }
	
            xmltooling::Locker acllock(settings.second);
            if (settings.second->authorized(*this,session)) {
                // Let the caller decide how to proceed.
                log(SPDebug, "doCheckAuthZ: access control provider granted access");
                return make_pair(false,0);
            }
            else {
                log(SPWarn, "doCheckAuthZ: access control provider denied access");
                tp.m_map["requestURL"] = targetURL;
                return make_pair(true,_sendError(this, "access", tp));
            }
            return make_pair(false,0);
        }
        else
            return make_pair(true,returnDecline());
    }
    catch (exception& e) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "access", tp));
    }
#ifndef _DEBUG
    catch (...) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "access", tp));
    }
#endif
}

pair<bool,long> ShibTarget::doExportAssertions(bool requireSession)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doExportAssertions");
#endif

    const IApplication* app=NULL;
    ExtTemplateParameters tp;
    const char* procState = "Attribute Processing Error";
    string targetURL = getRequestURL();

    try {
        RequestMapper::Settings settings = getRequestSettings();
        app = dynamic_cast<const IApplication*>(&getApplication());

        const Session* session=NULL;
        pair<string,const char*> shib_cookie=app->getCookieNameProps("_shibsession_");
        const char *session_id = getCookie(shib_cookie.first.c_str());
        try {
        	if (session_id && *session_id) {
                session = getSession();
        	}
        }
        catch (exception&) {
        	log(SPWarn, "unable to obtain session information to export into request headers");
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
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = e.what();
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "rm", tp, &e));
    }
#ifndef _DEBUG
    catch (...) {
        tp.m_map["errorType"] = procState;
        tp.m_map["errorText"] = "Caught an unknown exception.";
        tp.m_map["requestURL"] = targetURL.substr(0,targetURL.find('?'));
        return make_pair(true,_sendError(this, "rm", tp));
    }
#endif
}

/*************************************************************************
 * Shib Target Private implementation
 */

long shibtarget::_sendError(
    SPRequest* st, const char* page, ExtTemplateParameters& tp, const XMLToolingException* ex
    )
{
    st->setContentType("text/html");
    st->setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
    st->setResponseHeader("Cache-Control","private,no-store,no-cache");

    TemplateEngine* engine = XMLToolingConfig::getConfig().getTemplateEngine();
    const PropertySet* props=st->getApplication().getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (infile) {
                tp.setPropertySet(props);
                stringstream str;
                engine->run(infile, str, tp, ex);
                return st->sendResponse(str);
            }
        }
        else if (!strcmp(page,"access")) {
            istringstream msg("Access Denied");
            return static_cast<opensaml::GenericResponse*>(st)->sendResponse(msg, opensaml::HTTPResponse::SAML_HTTP_STATUS_FORBIDDEN);
        }
    }

    string errstr = string("sendError could not process error template (") + page + ")";
    st->log(SPRequest::SPError, errstr);
    istringstream msg("Internal Server Error. Please contact the site administrator.");
    return st->sendError(msg);
}

void ShibTarget::clearHeaders()
{
    // Clear invariant stuff.
    clearHeader("Shib-Origin-Site");
    clearHeader("Shib-Identity-Provider");
    clearHeader("Shib-Authentication-Method");
    clearHeader("Shib-NameIdentifier-Format");
    clearHeader("Shib-Attributes");
    clearHeader("Shib-Application-ID");

    // Clear out the list of mapped attributes
    Iterator<IAAP*> provs=dynamic_cast<const IApplication&>(getApplication()).getAAPProviders();
    while (provs.hasNext()) {
        IAAP* aap=provs.next();
        xmltooling::Locker locker(aap);
        Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
        while (rules.hasNext()) {
            const char* header=rules.next()->getHeader();
            if (header)
                clearHeader(header);
        }
    }
}
