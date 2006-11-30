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

#include <sstream>
#include <fstream>
#include <stdexcept>

#include <shib/shib-threads.h>
#include <xercesc/util/Base64.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp stricmp
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

namespace shibtarget {
    class CgiParse
    {
    public:
        CgiParse(const ShibTarget* st);
        ~CgiParse();

        typedef multimap<string,char*>::const_iterator walker;
        pair<walker,walker> get_values(const char* name) const;
        
    private:
        char* fmakeword(char stop, unsigned int *cl, const char** ppch);
        char* makeword(char *line, char stop);
        void plustospace(char *str);

        multimap<string,char*> kvp_map;
    };

    class ShibTargetPriv
    {
    public:
        ShibTargetPriv();
        ~ShibTargetPriv();

        // Helper functions
        void get_application(ShibTarget* st, const string& protocol, const string& hostname, int port, const string& uri);
        void* sendError(ShibTarget* st, const char* page, ShibMLP &mlp);
        void clearHeaders(ShibTarget* st);
    
    private:
        friend class ShibTarget;
        IRequestMapper::Settings m_settings;
        const IApplication *m_app;
        mutable string m_handlerURL;
        mutable map<string,string> m_cookieMap;
        mutable CgiParse* m_cgiParser;

        ISessionCacheEntry* m_cacheEntry;

        ShibTargetConfig* m_Config;

        IConfig* m_conf;
        IRequestMapper* m_mapper;
    };
}


/*************************************************************************
 * Shib Target implementation
 */

ShibTarget::ShibTarget() : m_priv(new ShibTargetPriv()) {}

ShibTarget::ShibTarget(const IApplication *app) : m_priv(new ShibTargetPriv())
{
    m_priv->m_app = app;
}

ShibTarget::~ShibTarget(void)
{
    delete m_priv;
}

void ShibTarget::init(
    const char* protocol,
    const char* hostname,
    int port,
    const char* uri,
    const char* content_type,
    const char* remote_addr,
    const char* method
    )
{
#ifdef _DEBUG
    saml::NDC ndc("init");
#endif

    if (m_priv->m_app)
        throw SAMLException("Request initialization occurred twice!");

    if (method) m_method = method;
    if (protocol) m_protocol = protocol;
    if (hostname) m_hostname = hostname;
    if (uri) m_uri = uri;
    if (content_type) m_content_type = content_type;
    if (remote_addr) m_remote_addr = remote_addr;
    m_port = port;
    m_priv->m_Config = &ShibTargetConfig::getConfig();
    m_priv->get_application(this, protocol, hostname, port, uri);
}


// These functions implement the server-agnostic shibboleth engine
// The web server modules implement a subclass and then call into 
// these methods once they instantiate their request object.

pair<bool,void*> ShibTarget::doCheckAuthN(bool handler)
{
#ifdef _DEBUG
    saml::NDC ndc("doCheckAuthN");
#endif

    const char* procState = "Request Processing Error";
    const char* targetURL = m_url.c_str();
    ShibMLP mlp;

    try {
        if (!m_priv->m_app)
            throw ConfigurationException("System uninitialized, application did not supply request information.");

        // If not SSL, check to see if we should block or redirect it.
        if (!strcmp("http",getProtocol())) {
            pair<bool,const char*> redirectToSSL = m_priv->m_settings.first->getString("redirectToSSL");
            if (redirectToSSL.first) {
                if (!strcasecmp("GET",getRequestMethod()) || !strcasecmp("HEAD",getRequestMethod())) {
                    // Compute the new target URL
                    string redirectURL = string("https://") + getHostname();
                    if (strcmp(redirectToSSL.second,"443")) {
                        redirectURL = redirectURL + ':' + redirectToSSL.second;
                    }
                    redirectURL += getRequestURI();
                    return make_pair(true, sendRedirect(redirectURL));
                }
                else {
                    mlp.insert("requestURL", m_url.substr(0,m_url.find('?')));
                    return make_pair(true,m_priv->sendError(this,"ssl", mlp));
                }
            }
        }
        
        string hURL = getHandlerURL(targetURL);
        const char* handlerURL=hURL.c_str();
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // If the request URL contains the handler base URL for this application, either dispatch
        // directly (mainly Apache 2.0) or just pass back control.
        if (strstr(targetURL,handlerURL)) {
            if (handler)
                return doHandler();
            else
                return pair<bool,void*>(true, returnOK());
        }

        // Three settings dictate how to proceed.
        pair<bool,const char*> authType = m_priv->m_settings.first->getString("authType");
        pair<bool,bool> requireSession = m_priv->m_settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = m_priv->m_settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't shibboleth,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
#ifdef HAVE_STRCASECMP
                (!authType.first || strcasecmp(authType.second,"shibboleth")))
#else
                (!authType.first || _stricmp(authType.second,"shibboleth")))
#endif
            return pair<bool,void*>(true,returnDecline());

        // Fix for secadv 20050901
        m_priv->clearHeaders(this);

        pair<string,const char*> shib_cookie = getCookieNameProps("_shibsession_");
        const char* session_id = getCookie(shib_cookie.first);
        if (!session_id || !*session_id) {
            // No session.  Maybe that's acceptable?
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                return pair<bool,void*>(true,returnOK());

            // No cookie, but we require a session. Initiate a new session using the indicated method.
            procState = "Session Initiator Error";
            const IHandler* initiator=NULL;
            if (requireSessionWith.first) {
                initiator=m_priv->m_app->getSessionInitiatorById(requireSessionWith.second);
                if (!initiator)
                    throw ConfigurationException(
                        "No session initiator found with id ($1), check requireSessionWith command.",
                        params(1,requireSessionWith.second)
                        );
            }
            else {
                initiator=m_priv->m_app->getDefaultSessionInitiator();
                if (!initiator)
                    throw ConfigurationException("No default session initiator found, check configuration.");
            }

            return initiator->run(this,false);
        }

        procState = "Session Processing Error";
        try {
            m_priv->m_cacheEntry=m_priv->m_conf->getSessionCache()->find(
                session_id,
                m_priv->m_app,
                m_remote_addr.c_str()
                );
            // Make a localized exception throw if the session isn't valid.
            if (!m_priv->m_cacheEntry)
                throw InvalidSessionException("Session no longer valid.");
        }
        catch (SAMLException& e) {
            log(LogLevelError, string("session processing failed: ") + e.what());

            // If no session is required, bail now.
            if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first)
                // Has to be OK because DECLINED will just cause Apache
                // to fail when it can't locate anything to process the
                // AuthType.  No session plus requireSession false means
                // do not authenticate the user at this time.
                return pair<bool,void*>(true, returnOK());

            // Try and cast down.
            SAMLException* base = &e;
            RetryableProfileException* trycast=dynamic_cast<RetryableProfileException*>(base);
            if (trycast) {
                // Session is invalid but we can retry -- initiate a new session.
                procState = "Session Initiator Error";
                const IHandler* initiator=NULL;
                if (requireSessionWith.first) {
                    initiator=m_priv->m_app->getSessionInitiatorById(requireSessionWith.second);
                    if (!initiator)
                        throw ConfigurationException(
                            "No session initiator found with id ($1), check requireSessionWith command.",
                            params(1,requireSessionWith.second)
                            );
                }
                else {
                    initiator=m_priv->m_app->getDefaultSessionInitiator();
                    if (!initiator)
                        throw ConfigurationException("No default session initiator found, check configuration.");
                }
                return initiator->run(this,false);
            }
            throw;    // send it to the outer handler
        }

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        log(LogLevelDebug, "doCheckAuthN succeeded");
        return pair<bool,void*>(false,NULL);
    }
    catch (SAMLException& e) {
        mlp.insert(e);
    }
#ifndef _DEBUG
    catch (...) {
        mlp.insert("errorText", "Caught an unknown exception.");
    }
#endif

    // If we get here then we've got an error.
    mlp.insert("errorType", procState);
    if (targetURL)
        mlp.insert("requestURL", m_url.substr(0,m_url.find('?')));

    return pair<bool,void*>(true,m_priv->sendError(this,"session", mlp));
}

pair<bool,void*> ShibTarget::doHandler(void)
{
#ifdef _DEBUG
    saml::NDC ndc("doHandler");
#endif

    const char* procState = "Shibboleth Handler Error";
    const char* targetURL = m_url.c_str();
    ShibMLP mlp;

    try {
        if (!m_priv->m_app)
            throw ConfigurationException("System uninitialized, application did not supply request information.");

        string hURL = getHandlerURL(targetURL);
        const char* handlerURL=hURL.c_str();
        if (!handlerURL)
            throw ConfigurationException("Cannot determine handler from resource URL, check configuration.");

        // Make sure we only process handler requests.
        if (!strstr(targetURL,handlerURL))
            return pair<bool,void*>(true, returnDecline());

        const IPropertySet* sessionProps=m_priv->m_app->getPropertySet("Sessions");
        if (!sessionProps)
            throw ConfigurationException("Unable to map request to application session settings, check configuration.");

        // Process incoming request.
        pair<bool,bool> handlerSSL=sessionProps->getBool("handlerSSL");
      
        // Make sure this is SSL, if it should be
        if ((!handlerSSL.first || handlerSSL.second) && m_protocol != "https")
            throw FatalProfileException("Blocked non-SSL access to Shibboleth handler.");

        // We dispatch based on our path info. We know the request URL begins with or equals the handler URL,
        // so the path info is the next character (or null).
        const IHandler* handler=m_priv->m_app->getHandler(targetURL + strlen(handlerURL));
        if (!handler)
            throw SAMLException("Shibboleth handler invoked at an unconfigured location.");

        if (saml::XML::isElementNamed(handler->getProperties()->getElement(),shibtarget::XML::SAML2META_NS,SHIBT_L(AssertionConsumerService)))
            procState = "Session Creation Error";
        else if (saml::XML::isElementNamed(handler->getProperties()->getElement(),shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SessionInitiator)))
            procState = "Session Initiator Error";
        else if (saml::XML::isElementNamed(handler->getProperties()->getElement(),shibtarget::XML::SAML2META_NS,SHIBT_L(SingleLogoutService)))
            procState = "Session Termination Error";
        else if (saml::XML::isElementNamed(handler->getProperties()->getElement(),shibtarget::XML::SHIBTARGET_NS,SHIBT_L(DiagnosticService)))
            procState = "Diagnostics Error";
        else
            procState = "Extension Service Error";
        pair<bool,void*> hret=handler->run(this);

        // Did the handler run successfully?
        if (hret.first)
            return hret;
       
        throw SAMLException("Configured Shibboleth handler failed to process the request.");
    }
    catch (MetadataException& e) {
        mlp.insert(e);
        // See if a metadata error page is installed.
        const IPropertySet* props=m_priv->m_app->getPropertySet("Errors");
        if (props) {
            pair<bool,const char*> p=props->getString("metadata");
            if (p.first) {
                mlp.insert("errorType", procState);
                if (targetURL)
                    mlp.insert("requestURL", targetURL);
                return make_pair(true,m_priv->sendError(this,"metadata", mlp));
            }
        }
    }
    catch (SAMLException& e) {
        mlp.insert(e);
    }
#ifndef _DEBUG
    catch (...) {
        mlp.insert("errorText", "Caught an unknown exception.");
    }
#endif

    // If we get here then we've got an error.
    mlp.insert("errorType", procState);

    if (targetURL)
        mlp.insert("requestURL", m_url.substr(0,m_url.find('?')));

    return make_pair(true,m_priv->sendError(this,"session", mlp));
}

pair<bool,void*> ShibTarget::doCheckAuthZ(void)
{
#ifdef _DEBUG
    saml::NDC ndc("doCheckAuthZ");
#endif

    ShibMLP mlp;
    const char* procState = "Authorization Processing Error";
    const char* targetURL = m_url.c_str();

    try {
        if (!m_priv->m_app)
            throw ConfigurationException("System uninitialized, application did not supply request information.");

        // Three settings dictate how to proceed.
        pair<bool,const char*> authType = m_priv->m_settings.first->getString("authType");
        pair<bool,bool> requireSession = m_priv->m_settings.first->getBool("requireSession");
        pair<bool,const char*> requireSessionWith = m_priv->m_settings.first->getString("requireSessionWith");

        // If no session is required AND the AuthType (an Apache-derived concept) isn't shibboleth,
        // then we ignore this request and consider it unprotected. Apache might lie to us if
        // ShibBasicHijack is on, but that's up to it.
        if ((!requireSession.first || !requireSession.second) && !requireSessionWith.first &&
#ifdef HAVE_STRCASECMP
                (!authType.first || strcasecmp(authType.second,"shibboleth")))
#else
                (!authType.first || _stricmp(authType.second,"shibboleth")))
#endif
            return pair<bool,void*>(true,returnDecline());

        // Do we have an access control plugin?
        if (m_priv->m_settings.second) {
        	
	        if (!m_priv->m_cacheEntry) {
	            // No data yet, so we may need to try and get the session.
		        pair<string,const char*> shib_cookie=getCookieNameProps("_shibsession_");
		        const char *session_id = getCookie(shib_cookie.first);
	            try {
		        	if (session_id && *session_id) {
                        m_priv->m_cacheEntry=m_priv->m_conf->getSessionCache()->find(
                            session_id,
                            m_priv->m_app,
                            m_remote_addr.c_str()
                            );
		        	}
	            }
	            catch (SAMLException&) {
	            	log(LogLevelError, "doCheckAuthZ: unable to obtain session information to pass to access control provider");
	            }
	        }
	
            Locker acllock(m_priv->m_settings.second);
            if (m_priv->m_settings.second->authorized(this,m_priv->m_cacheEntry)) {
                // Let the caller decide how to proceed.
                log(LogLevelDebug, "doCheckAuthZ: access control provider granted access");
                return pair<bool,void*>(false,NULL);
            }
            else {
                log(LogLevelWarn, "doCheckAuthZ: access control provider denied access");
                if (targetURL)
                    mlp.insert("requestURL", targetURL);
                return make_pair(true,m_priv->sendError(this, "access", mlp));
            }
        }
        else
            return make_pair(true,returnDecline());
    }
    catch (SAMLException& e) {
        mlp.insert(e);
    }
#ifndef _DEBUG
    catch (...) {
        mlp.insert("errorText", "Caught an unknown exception.");
    }
#endif

    // If we get here then we've got an error.
    mlp.insert("errorType", procState);

    if (targetURL)
        mlp.insert("requestURL", m_url.substr(0,m_url.find('?')));

    return make_pair(true,m_priv->sendError(this, "access", mlp));
}

pair<bool,void*> ShibTarget::doExportAssertions(bool requireSession)
{
#ifdef _DEBUG
    saml::NDC ndc("doExportAssertions");
#endif

    ShibMLP mlp;
    const char* procState = "Attribute Processing Error";
    const char* targetURL = m_url.c_str();

    try {
        if (!m_priv->m_app)
            throw ConfigurationException("System uninitialized, application did not supply request information.");

        if (!m_priv->m_cacheEntry) {
            // No data yet, so we need to get the session. This can only happen
            // if the call to doCheckAuthn doesn't happen in the same object lifetime.
	        pair<string,const char*> shib_cookie=getCookieNameProps("_shibsession_");
	        const char *session_id = getCookie(shib_cookie.first);
            try {
	        	if (session_id && *session_id) {
                    m_priv->m_cacheEntry=m_priv->m_conf->getSessionCache()->find(
                        session_id,
                        m_priv->m_app,
                        m_remote_addr.c_str()
                        );
	        	}
            }
            catch (SAMLException&) {
            	log(LogLevelError, "unable to obtain session information to export into request headers");
            	// If we have to have a session, then this is a fatal error.
            	if (requireSession)
            		throw;
            }
        }

		// Still no data?
        if (!m_priv->m_cacheEntry) {
        	if (requireSession)
        		throw InvalidSessionException("Unable to obtain session information for request.");
        	else
        		return pair<bool,void*>(false,NULL);	// just bail silently
        }
        
        // Extract data from session.
        pair<const char*,const SAMLSubject*> sub=m_priv->m_cacheEntry->getSubject(false,true);
        pair<const char*,const SAMLResponse*> unfiltered=m_priv->m_cacheEntry->getTokens(true,false);
        pair<const char*,const SAMLResponse*> filtered=m_priv->m_cacheEntry->getTokens(false,true);

        // Maybe export the tokens.
        pair<bool,bool> exp=m_priv->m_settings.first->getBool("exportAssertion");
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
        setHeader("Shib-Origin-Site", m_priv->m_cacheEntry->getProviderId());
        setHeader("Shib-Identity-Provider", m_priv->m_cacheEntry->getProviderId());
        setHeader("Shib-Authentication-Method", m_priv->m_cacheEntry->getAuthnContext());
        
        // Get the AAP providers, which contain the attribute policy info.
        Iterator<IAAP*> provs=m_priv->m_app->getAAPProviders();

        // Export NameID?
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            Locker locker(aap);
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
        
        setHeader("Shib-Application-ID", m_priv->m_app->getId());
    
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
                        Locker locker(aap);
                        const IAttributeRule* rule=aap->lookup(attr->getName(),attr->getNamespace());
                        if (!rule || !rule->getHeader())
                            continue;
                    
                        Iterator<string> vals=attr->getSingleByteValues();
                        if (!strcmp(rule->getHeader(),"REMOTE_USER") && vals.hasNext())
                            setRemoteUser(vals.next());
                        else {
                            int it=0;
                            string header = getHeader(rule->getHeader());
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
                            setHeader(rule->getHeader(), header);
                        }
                    }
                }
            }
        }
    
        return pair<bool,void*>(false,NULL);
    }
    catch (SAMLException& e) {
        mlp.insert(e);
    }
#ifndef _DEBUG
    catch (...) {
        mlp.insert("errorText", "Caught an unknown exception.");
    }
#endif

    // If we get here then we've got an error.
    mlp.insert("errorType", procState);

    if (targetURL)
        mlp.insert("requestURL", m_url.substr(0,m_url.find('?')));

    return make_pair(true,m_priv->sendError(this, "rm", mlp));
}

const char* ShibTarget::getRequestParameter(const char* param, size_t index) const
{
    if (!m_priv->m_cgiParser)
        m_priv->m_cgiParser=new CgiParse(this);
    
    pair<CgiParse::walker,CgiParse::walker> bounds=m_priv->m_cgiParser->get_values(param);
    
    // Advance to the right index.
    while (index && bounds.first!=bounds.second) {
        index--;
        bounds.first++;
    }

    return (bounds.first==bounds.second) ? NULL : bounds.first->second;
}

const char* ShibTarget::getCookie(const string& name) const
{
    if (m_priv->m_cookieMap.empty()) {
        string cookies=getCookies();

        string::size_type pos=0,cname,namelen,val,vallen;
        while (pos !=string::npos && pos < cookies.length()) {
            while (isspace(cookies[pos])) pos++;
            cname=pos;
            pos=cookies.find_first_of("=",pos);
            if (pos == string::npos)
                break;
            namelen=pos-cname;
            pos++;
            if (pos==cookies.length())
                break;
            val=pos;
            pos=cookies.find_first_of(";",pos);
            if (pos != string::npos) {
                vallen=pos-val;
                pos++;
                m_priv->m_cookieMap.insert(make_pair(cookies.substr(cname,namelen),cookies.substr(val,vallen)));
            }
            else
                m_priv->m_cookieMap.insert(make_pair(cookies.substr(cname,namelen),cookies.substr(val)));
        }
    }
    map<string,string>::const_iterator lookup=m_priv->m_cookieMap.find(name);
    return (lookup==m_priv->m_cookieMap.end()) ? NULL : lookup->second.c_str();
}

pair<string,const char*> ShibTarget::getCookieNameProps(const char* prefix) const
{
    static const char* defProps="; path=/";
    
    const IPropertySet* props=m_priv->m_app ? m_priv->m_app->getPropertySet("Sessions") : NULL;
    if (props) {
        pair<bool,const char*> p=props->getString("cookieProps");
        if (!p.first)
            p.second=defProps;
        pair<bool,const char*> p2=props->getString("cookieName");
        if (p2.first)
            return make_pair(string(prefix) + p2.second,p.second);
        return make_pair(string(prefix) + m_priv->m_app->getHash(),p.second);
    }
    
    // Shouldn't happen, but just in case..
    return pair<string,const char*>(prefix,defProps);
}

string ShibTarget::getHandlerURL(const char* resource) const
{
    if (!m_priv->m_handlerURL.empty() && resource && !strcmp(getRequestURL(),resource))
        return m_priv->m_handlerURL;
        
    if (!m_priv->m_app)
        throw ConfigurationException("Internal error in ShibTargetPriv::getHandlerURL, missing application pointer.");

    bool ssl_only=false;
    const char* handler=NULL;
    const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> p=props->getBool("handlerSSL");
        if (p.first)
            ssl_only=p.second;
        pair<bool,const char*> p2=props->getString("handlerURL");
        if (p2.first)
            handler=p2.second;
    }
    
    // Should never happen...
    if (!handler || (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)))
        throw ConfigurationException(
            "Invalid handlerURL property ($1) in Application ($2)",
            params(2, handler ? handler : "null", m_priv->m_app->getId())
            );

    // The "handlerURL" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler
    //
    // note: if ssl_only is true, make sure the protocol is https

    const char* path = NULL;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store in member.
    if (ssl_only)
        m_priv->m_handlerURL.assign("https://");
    else
        m_priv->m_handlerURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the handler URL
    m_priv->m_handlerURL+=host + path;
    return m_priv->m_handlerURL;
}

void ShibTarget::log(ShibLogLevel level, const string& msg)
{
    Category::getInstance("shibtarget.ShibTarget").log(
        (level == LogLevelDebug ? Priority::DEBUG :
        (level == LogLevelInfo ? Priority::INFO :
        (level == LogLevelWarn ? Priority::WARN : Priority::ERROR))),
        msg
    );
}

const IApplication* ShibTarget::getApplication() const
{
    return m_priv->m_app;
}

const IConfig* ShibTarget::getConfig() const
{
    return m_priv->m_conf;
}

void* ShibTarget::returnDecline(void)
{
    return NULL;
}

void* ShibTarget::returnOK(void)
{
    return NULL;
}

static char x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void ShibTarget::url_decode(char* s)
{
    register int x,y;

    for(x=0,y=0;s[y];++x,++y)
    {
        if((s[x] = s[y]) == '%')
        {
            s[x] = x2c(&s[y+1]);
            y+=2;
        }
    }
    s[x] = '\0';
}

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

string ShibTarget::url_encode(const char* s)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";

    string ret;
    for (; *s; s++) {
        if (strchr(badchars,*s) || *s<=0x20 || *s>=0x7F) {
            ret+='%';
        ret+=hexchar(*s >> 4);
        ret+=hexchar(*s & 0x0F);
        }
        else
            ret+=*s;
    }
    return ret;
}

/*************************************************************************
 * Shib Target Private implementation
 */

ShibTargetPriv::ShibTargetPriv()
    : m_app(NULL), m_mapper(NULL), m_conf(NULL), m_Config(NULL), m_cacheEntry(NULL), m_cgiParser(NULL) {}

ShibTargetPriv::~ShibTargetPriv()
{
    if (m_cacheEntry) {
        m_cacheEntry->unlock();
        m_cacheEntry = NULL;
    }

    if (m_mapper) {
        m_mapper->unlock();
        m_mapper = NULL;
    }
    
    if (m_conf) {
        m_conf->unlock();
        m_conf = NULL;
    }

    delete m_cgiParser;
    m_app = NULL;
    m_Config = NULL;
}

void ShibTargetPriv::get_application(ShibTarget* st, const string& protocol, const string& hostname, int port, const string& uri)
{
  if (m_app)
    return;

  // XXX: Do we need to keep conf and mapper locked while we hold m_app?
  // TODO: No, should be able to hold the conf but release the mapper.

  // We lock the configuration system for the duration.
  m_conf=m_Config->getINI();
  m_conf->lock();
    
  // Map request to application and content settings.
  m_mapper=m_conf->getRequestMapper();
  m_mapper->lock();

  // Obtain the application settings from the parsed URL
  m_settings = m_mapper->getSettings(st);

  // Now find the application from the URL settings
  pair<bool,const char*> application_id=m_settings.first->getString("applicationId");
  m_app=m_conf->getApplication(application_id.second);
  if (!m_app) {
    m_mapper->unlock();
    m_mapper = NULL;
    m_conf->unlock();
    m_conf = NULL;
    throw ConfigurationException("Unable to map request to application settings, check configuration.");
  }

  // Compute the full target URL
  st->m_url = protocol + "://" + hostname;
  if ((protocol == "http" && port != 80) || (protocol == "https" && port != 443)) {
  	ostringstream portstr;
  	portstr << port;
    st->m_url += ":" + portstr.str();
  }
  st->m_url += uri;
}

void* ShibTargetPriv::sendError(ShibTarget* st, const char* page, ShibMLP &mlp)
{
    ShibTarget::header_t hdrs[] = {
        ShibTarget::header_t("Expires","01-Jan-1997 12:00:00 GMT"),
        ShibTarget::header_t("Cache-Control","private,no-store,no-cache")
        };
    
    const IPropertySet* props=m_app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res)
                    return st->sendPage(res, 200, "text/html", ArrayIterator<ShibTarget::header_t>(hdrs,2));
            }
        }
        else if (!strcmp(page,"access"))
            return st->sendPage("Access Denied", 403, "text/html", ArrayIterator<ShibTarget::header_t>(hdrs,2));
    }

    string errstr = string("sendError could not process error template (") + page + ") for application (";
    errstr += m_app->getId();
    errstr += ")";
    st->log(ShibTarget::LogLevelError, errstr);
    return st->sendPage(
        "Internal Server Error. Please contact the site administrator.", 500, "text/html", ArrayIterator<ShibTarget::header_t>(hdrs,2)
        );
}

void ShibTargetPriv::clearHeaders(ShibTarget* st)
{
    // Clear invariant stuff.
    st->clearHeader("Shib-Origin-Site");
    st->clearHeader("Shib-Identity-Provider");
    st->clearHeader("Shib-Authentication-Method");
    st->clearHeader("Shib-NameIdentifier-Format");
    st->clearHeader("Shib-Attributes");
    st->clearHeader("Shib-Application-ID");

    // Clear out the list of mapped attributes
    Iterator<IAAP*> provs=m_app->getAAPProviders();
    while (provs.hasNext()) {
        IAAP* aap=provs.next();
        Locker locker(aap);
        Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
        while (rules.hasNext()) {
            const char* header=rules.next()->getHeader();
            if (header)
                st->clearHeader(header);
        }
    }
}

/*************************************************************************
 * CGI Parser implementation
 */

CgiParse::CgiParse(const ShibTarget* st)
{
    const char* pch=NULL;
    if (!strcmp(st->getRequestMethod(),"POST"))
        pch=st->getRequestBody();
    else
        pch=st->getQueryString();
    size_t cl=pch ? strlen(pch) : 0;
    
        
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&',&cl,&pch);
        plustospace(value);
        ShibTarget::url_decode(value);
        name=makeword(value,'=');
        kvp_map.insert(pair<string,char*>(name,value));
        free(name);
    }
}

CgiParse::~CgiParse()
{
    for (multimap<string,char*>::iterator i=kvp_map.begin(); i!=kvp_map.end(); i++)
        free(i->second);
}

pair<CgiParse::walker,CgiParse::walker> CgiParse::get_values(const char* name) const
{
    return kvp_map.equal_range(name);
}

/* Parsing routines modified from NCSA source. */
char* CgiParse::makeword(char *line, char stop)
{
    int x = 0,y;
    char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

    for(x=0;((line[x]) && (line[x] != stop));x++)
        word[x] = line[x];

    word[x] = '\0';
    if(line[x])
        ++x;
    y=0;

    while(line[x])
      line[y++] = line[x++];
    line[y] = '\0';
    return word;
}

char* CgiParse::fmakeword(char stop, size_t *cl, const char** ppch)
{
    int wsize;
    char *word;
    int ll;

    wsize = 1024;
    ll=0;
    word = (char *) malloc(sizeof(char) * (wsize + 1));

    while(1)
    {
        word[ll] = *((*ppch)++);
        if(ll==wsize-1)
        {
            word[ll+1] = '\0';
            wsize+=1024;
            word = (char *)realloc(word,sizeof(char)*(wsize+1));
        }
        --(*cl);
        if((word[ll] == stop) || word[ll] == EOF || (!(*cl)))
        {
            if(word[ll] != stop)
                ll++;
            word[ll] = '\0';
            return word;
        }
        ++ll;
    }
}

void CgiParse::plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}
