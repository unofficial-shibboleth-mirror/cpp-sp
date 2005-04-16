/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

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
    CgiParse(const char* data, unsigned int len);
    ~CgiParse();
    const char* get_value(const char* name) const;
    
    static char x2c(char *what);
    static void url_decode(char *url);
    static string url_encode(const char* s);
  private:
    char * fmakeword(char stop, unsigned int *cl, const char** ppch);
    char * makeword(char *line, char stop);
    void plustospace(char *str);

    map<string,char*> kvp_map;
  };

  class ShibTargetPriv
  {
  public:
    ShibTargetPriv();
    ~ShibTargetPriv();

    // Helper functions
    void get_application(ShibTarget* st, const string& protocol, const string& hostname, int port, const string& uri);
    const char* getCookie(ShibTarget* st, const string& name) const;
    pair<string,const char*> getCookieNameProps(const char* prefix) const;
    const char* getHandlerURL(const char* resource) const;
    void* sendError(ShibTarget* st, const char* page, ShibMLP &mlp);
    
    // Handlers do the real Shibboleth work
    pair<bool,void*> doSessionInitiator(ShibTarget* st, const IPropertySet* handler, bool isHandler=true) const;
    pair<bool,void*> doAssertionConsumer(ShibTarget* st, const IPropertySet* handler) const;
    pair<bool,void*> doLogout(ShibTarget* st, const IPropertySet* handler) const;

    // And the binding/profile handlers do the low level packing and unpacking.
    pair<bool,void*> ShibAuthnRequest(
        ShibTarget* st,
        const IPropertySet* shire,
        const char* dest,
        const char* target,
        const char* providerId
        ) const;

  private:
    friend class ShibTarget;
    IRequestMapper::Settings m_settings;
    const IApplication *m_app;
    mutable string m_handlerURL;
    mutable map<string,string> m_cookieMap;

    ShibProfile m_sso_profile;
    string m_provider_id;
    SAMLAuthenticationStatement* m_sso_statement;
    SAMLResponse* m_pre_response;
    SAMLResponse* m_post_response;
    
    ShibTargetConfig* m_Config;

    IConfig* m_conf;
    IRequestMapper* m_mapper;
  };
}


/*************************************************************************
 * Shib Target implementation
 */

ShibTarget::ShibTarget(void) : m_priv(NULL)
{
  m_priv = new ShibTargetPriv();
}

ShibTarget::ShibTarget(const IApplication *app) : m_priv(NULL)
{
  m_priv = new ShibTargetPriv();
  m_priv->m_app = app;
}

ShibTarget::~ShibTarget(void)
{
  if (m_priv) delete m_priv;
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

        const char* handlerURL = m_priv->getHandlerURL(targetURL);
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
                (!authType.first || stricmp(authType.second,"shibboleth")))
#endif
            return pair<bool,void*>(true,returnDecline());

        pair<string,const char*> shib_cookie = m_priv->getCookieNameProps("_shibsession_");
        const char* session_id = m_priv->getCookie(this,shib_cookie.first);
        if (!session_id || !*session_id) {
            // No session.  Maybe that's acceptable?
            if (!requireSession.first || !requireSession.second)
                return pair<bool,void*>(true,returnOK());

            // No cookie, but we require a session. Initiate a new session using the default method.
            procState = "Session Initiator Error";
            const IPropertySet* initiator=m_priv->m_app->getDefaultSessionInitiator();
            return m_priv->doSessionInitiator(this, initiator ? initiator : m_priv->m_app->getPropertySet("Sessions"), false);
        }

        procState = "Session Processing Error";
        try {
            // Localized exception throw if the session isn't valid.
            sessionGet(
                session_id,
                m_remote_addr.c_str(),
                m_priv->m_sso_profile,
                m_priv->m_provider_id,
                &m_priv->m_sso_statement,
                &m_priv->m_pre_response,
                &m_priv->m_post_response
                );
        }
        catch (SAMLException& e) {
            log(LogLevelError, string("session processing failed: ") + e.what());

            // If no session is required, bail now.
            if (!requireSession.first || !requireSession.second)
                // Has to be OK because DECLINED will just cause Apache
                // to fail when it can't locate anything to process the
                // AuthType.  No session plus requireSession false means
                // do not authenticate the user at this time.
                return pair<bool,void*>(true, returnOK());

            // Try and cast down. This should throw an exception if it fails.
            bool retryable=false;
            try {
                RetryableProfileException& trycast=dynamic_cast<RetryableProfileException&>(e);
                retryable=true;
            }
            catch (exception&) {
            }
            if (retryable) {
                // Session is invalid but we can retry -- initiate a new session.
                procState = "Session Initiator Error";
                const IPropertySet* initiator=m_priv->m_app->getDefaultSessionInitiator();
                return m_priv->doSessionInitiator(this, initiator ? initiator : m_priv->m_app->getPropertySet("Sessions"), false);
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

        const char* handlerURL = m_priv->getHandlerURL(targetURL);
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
        const IPropertySet* handler=m_priv->m_app->getHandler(targetURL + strlen(handlerURL));
        if (handler) {
            if (saml::XML::isElementNamed(handler->getElement(),shibtarget::XML::SAML2META_NS,SHIBT_L(AssertionConsumerService))) {
                procState = "Session Creation Error";
                return m_priv->doAssertionConsumer(this,handler);
            }
            else if (saml::XML::isElementNamed(handler->getElement(),shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SessionInitiator))) {
                procState = "Session Initiator Error";
                return m_priv->doSessionInitiator(this,handler);
            }
            else if (saml::XML::isElementNamed(handler->getElement(),shibtarget::XML::SAML2META_NS,SHIBT_L(SingleLogoutService))) {
                procState = "Session Termination Error";
                return m_priv->doLogout(this,handler);
            }
            else
                throw ConfigurationException("Endpoint is mapped to unrecognized handler element.");
        }
        
        if (strlen(targetURL)>strlen(handlerURL) && targetURL[strlen(handlerURL)]!='?')
            throw SAMLException("Shibboleth handler invoked at an unconfigured location.");
        
        // This is a legacy direct execution of the handler (the old shireURL).
        // If this is a GET, we see if it's a lazy session request, otherwise
        // assume it's a SAML 1.x POST profile response and process it.
        if (!strcasecmp(m_method.c_str(), "GET")) {
            procState = "Session Initiator Error";
            return m_priv->doSessionInitiator(this, sessionProps);
        }
        
        procState = "Session Creation Error";
        return m_priv->doAssertionConsumer(this, sessionProps);
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
                (!authType.first || stricmp(authType.second,"shibboleth")))
#endif
            return pair<bool,void*>(true,returnDecline());

        // Do we have an access control plugin?
        if (m_priv->m_settings.second) {
            Locker acllock(m_priv->m_settings.second);
            if (m_priv->m_settings.second->authorized(this,m_priv->m_provider_id.c_str(), m_priv->m_sso_statement, m_priv->m_post_response)) {
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

pair<bool,void*> ShibTarget::doExportAssertions()
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

        pair<string,const char*> shib_cookie=m_priv->getCookieNameProps("_shibsession_");
        const char *session_id = m_priv->getCookie(this,shib_cookie.first);

        if (!m_priv->m_sso_statement) {
            // No data yet, so we need to get the session. This can only happen
            // if the call to doCheckAuthn doesn't happen in the same object lifetime.
            sessionGet(
                session_id,
                m_remote_addr.c_str(),
                m_priv->m_sso_profile,
                m_priv->m_provider_id,
                &m_priv->m_sso_statement,
                &m_priv->m_pre_response,
                &m_priv->m_post_response
                );
        }

        // Get the AAP providers, which contain the attribute policy info.
        Iterator<IAAP*> provs=m_priv->m_app->getAAPProviders();

        // Clear out the list of mapped attributes
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            Locker locker(aap);
            Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
            while (rules.hasNext()) {
                const char* header=rules.next()->getHeader();
                if (header)
                    clearHeader(header);
            }
        }
        
        // Maybe export the first assertion.
        clearHeader("Shib-Attributes");
        pair<bool,bool> exp=m_priv->m_settings.first->getBool("exportAssertion");
        if (exp.first && exp.second && m_priv->m_pre_response) {
            ostringstream os;
            os << *(m_priv->m_pre_response);
            unsigned int outlen;
            XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>((char*)os.str().c_str()), os.str().length(), &outlen);
            XMLByte *pos, *pos2;
            for (pos=serialized, pos2=serialized; *pos2; pos2++)
                if (isgraph(*pos2))
                    *pos++=*pos2;
            *pos=0;
            setHeader("Shib-Attributes", reinterpret_cast<char*>(serialized));
            XMLString::release(&serialized);
        }
    
        // Export the SAML AuthnMethod and the origin site name, and possibly the NameIdentifier.
        clearHeader("Shib-Origin-Site");
        clearHeader("Shib-Identity-Provider");
        clearHeader("Shib-Authentication-Method");
        clearHeader("Shib-NameIdentifier-Format");
        setHeader("Shib-Origin-Site", m_priv->m_provider_id.c_str());
        setHeader("Shib-Identity-Provider", m_priv->m_provider_id.c_str());
        auto_ptr_char am(m_priv->m_sso_statement->getAuthMethod());
        setHeader("Shib-Authentication-Method", am.get());
        
        // Export NameID?
        provs.reset();
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            Locker locker(aap);
            const IAttributeRule* rule=aap->lookup(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getFormat());
            if (rule && rule->getHeader()) {
                auto_ptr_char form(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getFormat());
                auto_ptr_char nameid(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getName());
                setHeader("Shib-NameIdentifier-Format", form.get());
                if (!strcmp(rule->getHeader(),"REMOTE_USER"))
                    setRemoteUser(nameid.get());
                else
                    setHeader(rule->getHeader(), nameid.get());
            }
        }
        
        clearHeader("Shib-Application-ID");
        setHeader("Shib-Application-ID", m_priv->m_app->getId());
    
        // Export the attributes.
        Iterator<SAMLAssertion*> a_iter(m_priv->m_post_response ? m_priv->m_post_response->getAssertions() : EMPTY(SAMLAssertion*));
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


void ShibTarget::sessionNew(
    int supported_profiles,
    const string& recipient,
    const char* packet,
    const char* ip,
    string& target,
    string& cookie,
    string& provider_id
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionNew");
#endif
    Category& log = Category::getInstance("shibtarget.ShibTarget");

    if (!packet || !*packet) {
        log.error("missing profile response");
        throw FatalProfileException("Profile response missing.");
    }

    if (!ip || !*ip) {
        log.error("missing client address");
        throw FatalProfileException("Invalid client address.");
    }
  
    if (supported_profiles <= 0) {
        log.error("no profile support indicated");
        throw FatalProfileException("No profile support indicated.");
    }
  
    shibrpc_new_session_args_2 arg;
    arg.recipient = (char*)recipient.c_str();
    arg.application_id = (char*)m_priv->m_app->getId();
    arg.packet = (char*)packet;
    arg.client_addr = (char*)ip;
    arg.supported_profiles = supported_profiles;

    log.info("create session for user at (%s) for application (%s)", ip, arg.application_id);

    shibrpc_new_session_ret_2 ret;
    memset(&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT* clnt;
    RPC rpc;
    do {
        clnt = rpc->connect();
        clnt_stat status = shibrpc_new_session_2 (&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and retry
            log.error("RPC Failure: %p (%p) (%d): %s", this, clnt, status, clnt_spcreateerror("shibrpc_new_session_2"));
            rpc->disconnect();
            if (retry)
                retry--;
            else
                throw ListenerException("Failure passing session setup information to listener.");
        }
        else {
            // SUCCESS.  Pool and continue
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log.debug("RPC completed with exception: %s", ret.status);
    else
        log.debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log.error("caught SAML Exception while building the SAMLException: %s", e.what());
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while creating your session.");
        }
#ifndef _DEBUG
        catch (...) {
            log.error("caught unknown exception building SAMLException");
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#endif
    }
    else {
        log.debug("new session from IdP (%s) with key (%s)", ret.provider_id, ret.cookie);
        cookie = ret.cookie;
        provider_id = ret.provider_id;
        if (ret.target)
            target = ret.target;
    }

    clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

void ShibTarget::sessionGet(
    const char* cookie,
    const char* ip,
    ShibProfile& profile,
    string& provider_id,
    SAMLAuthenticationStatement** auth_statement,
    SAMLResponse** attr_response_pre,
    SAMLResponse** attr_response_post
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionGet");
#endif
    Category& log = Category::getInstance("shibtarget.ShibTarget");

    if (!cookie || !*cookie) {
        log.error("no session key provided");
        throw InvalidSessionException("No session key was provided.");
    }
    else if (strchr(cookie,'=')) {
        log.error("cookie value not extracted successfully, probably overlapping cookies across domains");
        throw InvalidSessionException("The session key wasn't extracted successfully from the browser cookie.");
    }

    if (!ip || !*ip) {
        log.error("invalid client Address");
        throw FatalProfileException("Invalid client address.");
    }

    log.info("getting session for client at (%s)", ip);
    log.debug("session cookie (%s)", cookie);

    shibrpc_get_session_args_2 arg;
    arg.cookie = (char*)cookie;
    arg.client_addr = (char*)ip;
    arg.application_id = (char*)m_priv->m_app->getId();

    shibrpc_get_session_ret_2 ret;
    memset (&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT *clnt;
    RPC rpc;
    do {
        clnt = rpc->connect();
        clnt_stat status = shibrpc_get_session_2(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and try again...
            log.error("RPC Failure: %p (%p) (%d) %s", this, clnt, status, clnt_spcreateerror("shibrpc_get_session_2"));
            rpc->disconnect();
            if (retry)
                retry--;
            else
                throw ListenerException("Failure requesting session information from listener.");
        }
        else {
            // SUCCESS
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log.debug("RPC completed with exception: %s", ret.status);
    else
        log.debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log.error("caught SAML Exception while building the SAMLException: %s", e.what());
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while accessing your session.");
        }
        catch (...) {
            log.error("caught unknown exception building SAMLException");
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
    }
    else {
        try {
            profile = ret.profile;
            provider_id = ret.provider_id;
        
            // return the Authentication Statement
            if (auth_statement) {
                istringstream authstream(ret.auth_statement);
                log.debugStream() << "trying to decode authentication statement: "
                    << ret.auth_statement << CategoryStream::ENDLINE;
                *auth_statement = new SAMLAuthenticationStatement(authstream);
            }
    
            // return the unfiltered Response
            if (attr_response_pre) {
                istringstream prestream(ret.attr_response_pre);
                log.debugStream() << "trying to decode unfiltered attribute response: "
                    << ret.attr_response_pre << CategoryStream::ENDLINE;
                *attr_response_pre = new SAMLResponse(prestream);
            }
    
            // return the filtered Response
            if (attr_response_post) {
                istringstream poststream(ret.attr_response_post);
                log.debugStream() << "trying to decode filtered attribute response: "
                    << ret.attr_response_post << CategoryStream::ENDLINE;
                *attr_response_post = new SAMLResponse(poststream);
            }
        }
        catch (SAMLException& e) {
            log.error("caught SAML exception while reconstituting session objects: %s", e.what());
            clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#ifndef _DEBUG
        catch (...) {
            log.error("caught unknown exception while reconstituting session objects");
            clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
#endif
    }

    clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_get_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

void ShibTarget::sessionEnd(const char* cookie) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionEnd");
#endif
    Category& log = Category::getInstance("shibtarget.ShibTarget");

    if (!cookie || !*cookie) {
        log.error("no session key provided");
        throw InvalidSessionException("No session key was provided.");
    }
    else if (strchr(cookie,'=')) {
        log.error("cookie value not extracted successfully, probably overlapping cookies across domains");
        throw InvalidSessionException("The session key wasn't extracted successfully from the browser cookie.");
    }

    log.debug("ending session with cookie (%s)", cookie);

    shibrpc_end_session_args_2 arg;
    arg.cookie = (char*)cookie;

    shibrpc_end_session_ret_2 ret;
    memset (&ret, 0, sizeof(ret));

    // Loop on the RPC in case we lost contact the first time through
    int retry = 1;
    CLIENT *clnt;
    RPC rpc;
    do {
        clnt = rpc->connect();
        clnt_stat status = shibrpc_end_session_2(&arg, &ret, clnt);
        if (status != RPC_SUCCESS) {
            // FAILED.  Release, disconnect, and try again...
            log.error("RPC Failure: %p (%p) (%d) %s", this, clnt, status, clnt_spcreateerror("shibrpc_end_session_2"));
            rpc->disconnect();
            if (retry)
                retry--;
            else
                throw ListenerException("Failure ending session through listener.");
        }
        else {
            // SUCCESS
            retry = -1;
        }
    } while (retry>=0);

    if (ret.status && *ret.status)
        log.debug("RPC completed with exception: %s", ret.status);
    else
        log.debug("RPC completed successfully");

    SAMLException* except=NULL;
    if (ret.status && *ret.status) {
        // Reconstitute exception object.
        try { 
            istringstream estr(ret.status);
            except=SAMLException::getInstance(estr);
        }
        catch (SAMLException& e) {
            log.error("caught SAML Exception while building the SAMLException: %s", e.what());
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw FatalProfileException("An unrecoverable error occurred while accessing your session.");
        }
        catch (...) {
            log.error("caught unknown exception building SAMLException");
            log.error("XML was: %s", ret.status);
            clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
            rpc.pool();
            throw;
        }
    }

    clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_end_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        wrapper->raise();
    }
}

/*************************************************************************
 * Shib Target Private implementation
 */

ShibTargetPriv::ShibTargetPriv() : m_app(NULL), m_mapper(NULL), m_conf(NULL), m_Config(NULL),
    m_sso_profile(PROFILE_UNSPECIFIED), m_sso_statement(NULL), m_pre_response(NULL), m_post_response(NULL) {}

ShibTargetPriv::~ShibTargetPriv()
{
  delete m_sso_statement;
  m_sso_statement = NULL;

  delete m_pre_response;
  m_pre_response = NULL;
  
  delete m_post_response;
  m_post_response = NULL;

  if (m_mapper) {
    m_mapper->unlock();
    m_mapper = NULL;
  }
  if (m_conf) {
    m_conf->unlock();
    m_conf = NULL;
  }
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
  if ((protocol == "http" && port != 80) || (protocol == "https" && port != 443))
    st->m_url += ":" + port;
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

const char* ShibTargetPriv::getCookie(ShibTarget* st, const string& name) const
{
    if (m_cookieMap.empty()) {
        string cookies=st->getCookies();

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
                m_cookieMap.insert(make_pair(cookies.substr(cname,namelen),cookies.substr(val,vallen)));
            }
            else
                m_cookieMap.insert(make_pair(cookies.substr(cname,namelen),cookies.substr(val)));
        }
    }
    map<string,string>::const_iterator lookup=m_cookieMap.find(name);
    return (lookup==m_cookieMap.end()) ? NULL : lookup->second.c_str();
}

// Get the session cookie name and properties for the application
pair<string,const char*> ShibTargetPriv::getCookieNameProps(const char* prefix) const
{
    static const char* defProps="; path=/";
    
    const IPropertySet* props=m_app ? m_app->getPropertySet("Sessions") : NULL;
    if (props) {
        pair<bool,const char*> p=props->getString("cookieProps");
        if (!p.first)
            p.second=defProps;
        pair<bool,const char*> p2=props->getString("cookieName");
        if (p2.first)
            return make_pair(string(prefix) + p2.second,p.second);
        return make_pair(string(prefix) + m_app->getHash(),p.second);
    }
    
    // Shouldn't happen, but just in case..
    return make_pair(prefix,defProps);
}

const char* ShibTargetPriv::getHandlerURL(const char* resource) const
{
    if (!m_handlerURL.empty())
        return m_handlerURL.c_str();

    if (!m_app)
        throw ConfigurationException("Internal error in ShibTargetPriv::getHandlerURL, missing application pointer.");

    bool ssl_only=false;
    const char* handler=NULL;
    const IPropertySet* props=m_app->getPropertySet("Sessions");
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
            params(2, handler ? handler : "null", m_app->getId())
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
        m_handlerURL.assign("https://");
    else
        m_handlerURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, slash-colon);

    // Build the shire URL
    m_handlerURL+=host + path;
    return m_handlerURL.c_str();
}

pair<bool,void*> ShibTargetPriv::doSessionInitiator(ShibTarget* st, const IPropertySet* handler, bool isHandler) const
{
    string dupresource;
    const char* resource=NULL;
    const IPropertySet* ACS=NULL;
    
    if (isHandler) {
        // We're running as an actual handler, so check to see if we understand the binding.
        pair<bool,const XMLCh*> binding=handler->getXMLString("Binding");
        if (binding.first && XMLString::compareString(binding.second,Constants::SHIB_SESSIONINIT_PROFILE_URI))
            throw UnsupportedProfileException(
                "Unsupported session initiator binding ($1).", params(1,handler->getString("Binding").second)
                );
        
        /* 
         * Binding is CGI query string with:
         *  target      the resource to direct back to later
         *  acsIndex    optional index of an ACS to use on the way back in
         *  providerId  optional direct invocation of a specific IdP
         */
        string query=st->getArgs();
        CgiParse parser(query.c_str(),query.length());

        const char* option=parser.get_value("acsIndex");
        if (option)
            ACS=m_app->getAssertionConsumerServiceByIndex(atoi(option));
        option=parser.get_value("providerId");
        
        resource=parser.get_value("target");
        if (!resource || !*resource) {
            pair<bool,const char*> home=m_app->getString("homeURL");
            if (home.first)
                resource=home.second;
            else
                throw FatalProfileException("Session initiator requires a target parameter or a homeURL application property.");
        }
        else if (!option) {
            dupresource=resource;
            resource=dupresource.c_str();
        }
        
        if (option) {
            // Here we actually use metadata to invoke the SSO service directly.
            // The only currently understood binding is the Shibboleth profile.
            Metadata m(m_app->getMetadataProviders());
            const IEntityDescriptor* entity=m.lookup(option);
            if (!entity)
                throw MetadataException("Session initiator unable to locate metadata for provider ($1).", params(1,option));
            const IIDPSSODescriptor* role=entity->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
            if (!role)
                throw MetadataException(
                    "Session initiator unable to locate SAML identity provider role for provider ($1).", params(1,option)
                    );
            const IEndpointManager* SSO=role->getSingleSignOnServiceManager();
            const IEndpoint* ep=SSO->getEndpointByBinding(Constants::SHIB_AUTHNREQUEST_PROFILE_URI);
            if (!ep)
                throw MetadataException(
                    "Session initiator unable to locate compatible SSO service for provider ($1).", params(1,option)
                    );
            auto_ptr_char dest(ep->getLocation());
            return ShibAuthnRequest(
                st,ACS ? ACS : m_app->getDefaultAssertionConsumerService(),dest.get(),resource,m_app->getString("providerId").second
                );
        }
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        resource=st->m_url.c_str();
    }
    
    if (!ACS) ACS=m_app->getDefaultAssertionConsumerService();
    
    // For now, we only support external session initiation via a wayfURL
    pair<bool,const char*> wayfURL=handler->getString("wayfURL");
    if (!wayfURL.first)
        throw ConfigurationException("Session initiator is missing wayfURL property.");

    pair<bool,const XMLCh*> wayfBinding=handler->getXMLString("wayfBinding");
    if (!wayfBinding.first || !XMLString::compareString(wayfBinding.second,Constants::SHIB_AUTHNREQUEST_PROFILE_URI))
        // Standard Shib 1.x
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,m_app->getString("providerId").second);
    else if (!XMLString::compareString(wayfBinding.second,Constants::SHIB_LEGACY_AUTHNREQUEST_PROFILE_URI))
        // Shib pre-1.2
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,NULL);
    else if (!strcmp(handler->getString("wayfBinding").second,"urn:mace:shibboleth:1.0:profiles:EAuth")) {
        // TODO: Finalize E-Auth profile URI
        pair<bool,bool> localRelayState=m_conf->getPropertySet("Local")->getBool("localRelayState");
        if (!localRelayState.first || !localRelayState.second)
            throw ConfigurationException("Federal E-Authn requests cannot include relay state, so localRelayState must be enabled.");

        // Here we store the state in a cookie.
        pair<string,const char*> shib_cookie=getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(resource) + shib_cookie.second);
        return make_pair(true, st->sendRedirect(wayfURL.second));
    }
   
    throw UnsupportedProfileException("Unsupported WAYF binding ($1).", params(1,handler->getString("wayfBinding").second));
}

// Handles Shib 1.x AuthnRequest profile.
pair<bool,void*> ShibTargetPriv::ShibAuthnRequest(
    ShibTarget* st,
    const IPropertySet* shire,
    const char* dest,
    const char* target,
    const char* providerId
    ) const
{
    // Compute the ACS URL. We add the ACS location to the handler baseURL.
    // Legacy configs will not have an ACS specified, so no suffix will be added.
    string ACSloc=getHandlerURL(target);
    if (shire) ACSloc+=shire->getString("Location").second;
    
    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    string req=string(dest) + "?shire=" + CgiParse::url_encode(ACSloc.c_str()) + "&time=" + timebuf;

    // How should the resource value be preserved?
    pair<bool,bool> localRelayState=m_conf->getPropertySet("Local")->getBool("localRelayState");
    if (!localRelayState.first || !localRelayState.second) {
        // The old way, just send it along.
        req+="&target=" + CgiParse::url_encode(target);
    }
    else {
        // Here we store the state in a cookie and send a fixed
        // value to the IdP so we can recognize it on the way back.
        pair<string,const char*> shib_cookie=getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(target) + shib_cookie.second);
        req+="&target=cookie";
    }
    
    // Only omitted for 1.1 style requests.
    if (providerId)
        req+="&providerId=" + CgiParse::url_encode(providerId);

    return make_pair(true, st->sendRedirect(req));
}

pair<bool,void*> ShibTargetPriv::doAssertionConsumer(ShibTarget* st, const IPropertySet* handler) const
{
    int profile=0;
    string input,cookie,target,providerId;

    // Right now, this only handles SAML 1.1.
    pair<bool,const XMLCh*> binding=handler->getXMLString("Binding");
    if (!binding.first || !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_POST)) {
        if (strcasecmp(st->m_method.c_str(), "POST"))
            throw FatalProfileException(
                "SAML 1.1 Browser/POST handler does not support HTTP method ($1).", params(1,st->m_method.c_str())
                );
        
        if (st->m_content_type.empty() || strcasecmp(st->m_content_type.c_str(),"application/x-www-form-urlencoded"))
            throw FatalProfileException(
                "Blocked invalid content-type ($1) submitted to SAML 1.1 Browser/POST handler.", params(1,st->m_content_type.c_str())
                );
        input=st->getPostData();
        profile|=SAML11_POST;
    }
    else if (!XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_ARTIFACT)) {
        if (strcasecmp(st->m_method.c_str(), "GET"))
            throw FatalProfileException(
                "SAML 1.1 Browser/Artifact handler does not support HTTP method ($1).", params(1,st->m_method.c_str())
                );
        input=st->getArgs();
        profile|=SAML11_ARTIFACT;
    }
    
    if (input.empty())
        throw FatalProfileException("SAML 1.1 Browser Profile handler received no data from browser.");
            
    pair<bool,const char*> loc=handler->getString("Location");
    st->sessionNew(
        profile,
        loc.first ? m_handlerURL + loc.second : m_handlerURL,
        input.c_str(),
        st->m_remote_addr.c_str(),
        target,
        cookie,
        providerId
        );

    st->log(ShibTarget::LogLevelDebug, string("profile processing succeeded, new session created (") + cookie + ")");

    if (target=="default") {
        pair<bool,const char*> homeURL=m_app->getString("homeURL");
        target=homeURL.first ? homeURL.second : "/";
    }
    else if (target=="cookie") {
        // Pull the target value from the "relay state" cookie.
        pair<string,const char*> relay_cookie = getCookieNameProps("_shibstate_");
        const char* relay_state = getCookie(st,relay_cookie.first);
        if (!relay_state || !*relay_state) {
            // No apparent relay state value to use, so fall back on the default.
            pair<bool,const char*> homeURL=m_app->getString("homeURL");
            target=homeURL.first ? homeURL.second : "/";
        }
        else {
            char* rscopy=strdup(relay_state);
            CgiParse::url_decode(rscopy);
            target=rscopy;
            free(rscopy);
        }
    }

    // We've got a good session, set the session cookie.
    pair<string,const char*> shib_cookie=getCookieNameProps("_shibsession_");
    st->setCookie(shib_cookie.first, cookie + shib_cookie.second);

    const IPropertySet* sessionProps=m_app->getPropertySet("Sessions");
    pair<bool,bool> idpHistory=sessionProps->getBool("idpHistory");
    if (!idpHistory.first || idpHistory.second) {
        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(getCookie(st,CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days=sessionProps->getUnsignedInt("idpHistoryDays");
            if (!days.first || days.second==0)
                st->setCookie(CommonDomainCookie::CDCName,string(cdc.set(providerId.c_str())) + shib_cookie.second);
            else {
                time_t now=time(NULL) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
                struct tm res;
                struct tm* ptime=gmtime_r(&now,&res);
#else
                struct tm* ptime=gmtime(&now);
#endif
                char timebuf[64];
                strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT",ptime);
                st->setCookie(
                    CommonDomainCookie::CDCName,
                    string(cdc.set(providerId.c_str())) + shib_cookie.second + "; expires=" + timebuf
                    );
        }
    }

    // Now redirect to the target.
    return make_pair(true, st->sendRedirect(target));
}

pair<bool,void*> ShibTargetPriv::doLogout(ShibTarget* st, const IPropertySet* handler) const
{
    pair<bool,const XMLCh*> binding=handler->getXMLString("Binding");
    if (!binding.first || XMLString::compareString(binding.second,Constants::SHIB_LOGOUT_PROFILE_URI)) {
        if (!binding.first)
            throw UnsupportedProfileException("Missing Logout binding.");
        throw UnsupportedProfileException("Unsupported Logout binding ($1).", params(1,handler->getString("Binding").second));
    }

    // Recover the session key.
    pair<string,const char*> shib_cookie = getCookieNameProps("_shibsession_");
    const char* session_id = getCookie(st,shib_cookie.first);
    
    // Logout is best effort.
    if (session_id && *session_id) {
        try {
            st->sessionEnd(session_id);
        }
        catch (SAMLException& e) {
            st->log(ShibTarget::LogLevelError, string("logout processing failed with exception: ") + e.what());
        }
#ifndef _DEBUG
        catch (...) {
            st->log(ShibTarget::LogLevelError, "logout processing failed with unknown exception");
        }
#endif
        st->setCookie(shib_cookie.first,"");
    }
    
    string query=st->getArgs();
    CgiParse parser(query.c_str(),query.length());

    const char* ret=parser.get_value("return");
    if (!ret)
        ret=handler->getString("ResponseLocation").second;
    if (!ret)
        ret=m_app->getString("homeURL").second;
    if (!ret)
        ret="/";
    return make_pair(true, st->sendRedirect(ret));
}

/*************************************************************************
 * CGI Parser implementation
 */

CgiParse::CgiParse(const char* data, unsigned int len)
{
    const char* pch = data;
    unsigned int cl = len;
        
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&',&cl,&pch);
        plustospace(value);
        url_decode(value);
        name=makeword(value,'=');
        kvp_map[name]=value;
        free(name);
    }
}

CgiParse::~CgiParse()
{
    for (map<string,char*>::iterator i=kvp_map.begin(); i!=kvp_map.end(); i++)
        free(i->second);
}

const char*
CgiParse::get_value(const char* name) const
{
    map<string,char*>::const_iterator i=kvp_map.find(name);
    if (i==kvp_map.end())
        return NULL;
    return i->second;
}

/* Parsing routines modified from NCSA source. */
char *
CgiParse::makeword(char *line, char stop)
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

char *
CgiParse::fmakeword(char stop, unsigned int *cl, const char** ppch)
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

void
CgiParse::plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}

char
CgiParse::x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void
CgiParse::url_decode(char *url)
{
    register int x,y;

    for(x=0,y=0;url[y];++x,++y)
    {
        if((url[x] = url[y]) == '%')
        {
            url[x] = x2c(&url[y+1]);
            y+=2;
        }
    }
    url[x] = '\0';
}

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

string CgiParse::url_encode(const char* s)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";

    string ret;
    for (; *s; s++) {
        if (strchr(badchars,*s) || *s<=0x1F || *s>=0x7F) {
            ret+='%';
        ret+=hexchar(*s >> 4);
        ret+=hexchar(*s & 0x0F);
        }
        else
            ret+=*s;
    }
    return ret;
}
// Subclasses may not need to override these particular virtual methods.
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
void* ShibTarget::returnDecline(void)
{
    return NULL;
}
void* ShibTarget::returnOK(void)
{
    return NULL;
}

// CDC implementation

const char CommonDomainCookie::CDCName[] = "_saml_idp";

CommonDomainCookie::CommonDomainCookie(const char* cookie) : m_decoded(NULL)
{
    if (!cookie)
        return;
        
    // Copy it so we can URL-decode it.
    char* b64=strdup(cookie);
    CgiParse::url_decode(b64);
    
    // Now Base64 decode it into the decoded delimited list.
    unsigned int len;
    m_decoded=Base64::decode(reinterpret_cast<XMLByte*>(b64),&len);
    free(b64);
    if (!m_decoded) {
        Category::getInstance("CommonDomainCookie").warn("cookie does not appear to be base64-encoded");
        return;
    }
    
    // Chop it up and save off pointers.
    char* ptr=reinterpret_cast<char*>(m_decoded);
    while (*ptr) {
        while (isspace(*ptr)) ptr++;
        m_list.push_back(ptr);
        while (*ptr && !isspace(*ptr)) ptr++;
        if (*ptr)
            *ptr++='\0';
    }
}

CommonDomainCookie::~CommonDomainCookie()
{
    if (m_decoded)
        XMLString::release(&m_decoded);
}

const char* CommonDomainCookie::set(const char* providerId)
{
    // First scan the list for this IdP.
    for (vector<const char*>::iterator i=m_list.begin(); i!=m_list.end(); i++) {
        if (!strcmp(providerId,*i)) {
            m_list.erase(i);
            break;
        }
    }
    
    // Append it to the end, after storing locally.
    m_additions.push_back(providerId);
    m_list.push_back(m_additions.back().c_str());
    
    // Now rebuild the delimited list.
    string delimited;
    for (vector<const char*>::const_iterator j=m_list.begin(); j!=m_list.end(); j++) {
        if (!delimited.empty()) delimited += ' ';
        delimited += *j;
    }
    
    // Base64 and URL encode it.
    unsigned int len;
    XMLByte* b64=Base64::encode(reinterpret_cast<const XMLByte*>(delimited.c_str()),delimited.length(),&len);
    XMLByte *pos, *pos2;
    for (pos=b64, pos2=b64; *pos2; pos2++)
        if (isgraph(*pos2))
            *pos++=*pos2;
    *pos=0;
    m_encoded=CgiParse::url_encode(reinterpret_cast<char*>(b64));
    XMLString::release(&b64);
    return m_encoded.c_str();
}
