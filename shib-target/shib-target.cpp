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

    string url_encode(const char* s);
    void get_application(const string& protocol, const string& hostname, int port, const string& uri);
    void* sendError(ShibTarget* st, string page, ShibMLP &mlp);
    const char* getSessionId(ShibTarget* st);
    const char* getRelayState(ShibTarget* st);

  private:
    friend class ShibTarget;
    IRequestMapper::Settings m_settings;
    const IApplication *m_app;
    string m_shireURL;

    string m_cookies;
    const char* session_id;
    const char* relay_state;

    ShibProfile m_sso_profile;
    string m_provider_id;
    SAMLAuthenticationStatement* m_sso_statement;
    SAMLResponse* m_pre_response;
    SAMLResponse* m_post_response;
    
    // These are the actual request parameters set via the init method.
    string m_url;
    string m_method;
    string m_protocol;
    string m_content_type;
    string m_remote_addr;

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
    ShibTargetConfig *config,
    string protocol,
    string hostname,
    int port,
    string uri,
    string content_type,
    string remote_host,
    string method
    )
{
#ifdef _DEBUG
  saml::NDC ndc("ShibTarget::init");
#endif

  if (m_priv->m_app)
    throw runtime_error("ShibTarget Already Initialized");
  if (!config)
    throw runtime_error("config is NULL.  Oops.");

  m_priv->m_protocol = protocol;
  m_priv->m_content_type = content_type;
  m_priv->m_remote_addr = remote_host;
  m_priv->m_Config = config;
  m_priv->m_method = method;
  m_priv->get_application(protocol, hostname, port, uri);
}


// These functions implement the server-agnostic shibboleth engine
// The web server modules implement a subclass and then call into 
// these methods once they instantiate their request object.
pair<bool,void*>
ShibTarget::doCheckAuthN(bool requireSessionFlag, bool handleProfile)
{
#ifdef _DEBUG
    saml::NDC ndc("ShibTarget::doCheckAuthN");
#endif

    const char *targetURL = NULL;
    const char *procState = "Request Setup Error";
    ShibMLP mlp;

    try {
        if (!m_priv->m_app)
            throw SAMLException("System uninitialized, application did not supply request information.");

        targetURL = m_priv->m_url.c_str();
        const char *shireURL = getShireURL(targetURL);
        if (!shireURL)
            throw SAMLException("Cannot determine assertion consumer service from resource URL, check configuration.");

        if (strstr(targetURL,shireURL)) {
            if (handleProfile)
                return doHandleProfile();
            else
                return pair<bool,void*>(true, returnOK());
        }

        string auth_type = getAuthType();
        if (strcasecmp(auth_type.c_str(),"shibboleth"))
            return pair<bool,void*>(true,returnDecline());

        pair<bool,bool> requireSession = m_priv->m_settings.first->getBool("requireSession");
        if (!requireSession.first || !requireSession.second) {
            // Web server might override.
            if (requireSessionFlag)
                requireSession.second=true;
        }

        const char* session_id = m_priv->getSessionId(this);
        if (!session_id || !*session_id) {
            // No session.  Maybe that's acceptable?
            if (!requireSession.second)
                return pair<bool,void*>(true,returnOK());

            // No cookie, but we require a session.  Generate an AuthnRequest.
            return pair<bool,void*>(true,sendRedirect(getAuthnRequest(targetURL)));
        }

        procState = "Session Processing Error";
        try {
            // Localized exception throw if the session isn't valid.
            sessionGet(
                session_id,
                m_priv->m_remote_addr.c_str(),
                m_priv->m_sso_profile,
                m_priv->m_provider_id,
                &m_priv->m_sso_statement,
                &m_priv->m_pre_response,
                &m_priv->m_post_response
                );
        }
        catch (SAMLException& e) {
            // If no session is required, bail now.
            if (!requireSession.second)
                // Has to be OK because DECLINED will just cause Apache
                // to fail when it can't locate anything to process the
                // AuthType.  No session plus requireSession false means
                // do not authenticate the user at this time.
                return pair<bool,void*>(true, returnOK());
            
            // TODO: need to test this...may need an actual reference cast
            if (typeid(e)==typeid(RetryableProfileException)) {
                // Session is invalid but we can retry -- generate an AuthnRequest
                return pair<bool,void*>(true,sendRedirect(getAuthnRequest(targetURL)));
            }
            throw;    // send it to the outer handler
        }

        // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
        // Let the caller decide how to proceed.
        log(LogLevelInfo, "doCheckAuthN succeeded");
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
        mlp.insert("requestURL", targetURL);

    return pair<bool,void*>(true,m_priv->sendError(this, "session", mlp));
}

pair<bool,void*>
ShibTarget::doHandleProfile(void)
{
#ifdef _DEBUG
    saml::NDC ndc("ShibTarget::doHandleProfile");
#endif

    const char *targetURL = NULL;
    const char *procState = "Session Creation Service Error";
    ShibMLP mlp;

    try {
        if (!m_priv->m_app)
            throw SAMLException("System uninitialized, application did not supply request information.");

        targetURL = m_priv->m_url.c_str();
        const char* shireURL = getShireURL(targetURL);

        if (!shireURL)
            throw SAMLException("Cannot determine assertion consumer service, check configuration.");

        // Make sure we only process the SHIRE requests.
        if (!strstr(targetURL, shireURL))
            return pair<bool,void*>(true, returnDecline());

        const IPropertySet* sessionProps=m_priv->m_app->getPropertySet("Sessions");
        if (!sessionProps)
            throw SAMLException("Unable to map request to application session settings, check configuration.");

        // Process incoming request.
        pair<bool,bool> shireSSL=sessionProps->getBool("shireSSL");
      
        // Make sure this is SSL, if it should be
        if ((!shireSSL.first || shireSSL.second) && m_priv->m_protocol != "https")
            throw FatalProfileException("Blocked non-SSL access to session creation service.");

        // If this is a GET, we see if it's a lazy session request, otherwise
        // assume it's a profile response and process it.
        string cgistr;
        if (!strcasecmp(m_priv->m_method.c_str(), "GET")) {
            cgistr = getArgs();
            string areq;
            if (!cgistr.empty())
                areq=getLazyAuthnRequest(cgistr.c_str());
            if (!areq.empty())
                return pair<bool,void*>(true, sendRedirect(areq));
        }
        else if (!strcasecmp(m_priv->m_method.c_str(), "POST")) {
            if (m_priv->m_content_type.empty() || strcasecmp(m_priv->m_content_type.c_str(),"application/x-www-form-urlencoded")) {
                throw FatalProfileException(
                    "Blocked invalid POST content-type ($1) to session creation service.",
                    params(1,m_priv->m_content_type.c_str())
                    );
            }
            // Read the POST Data
            cgistr = getPostData();
        }
	
        // Process the submission
        string cookie,target;
        try {
            sessionNew(
                SAML11_POST | SAML11_ARTIFACT,
                cgistr.c_str(),
                m_priv->m_remote_addr.c_str(),
                cookie,
                target
                );
        }
        catch (SAMLException& e) {
            log(LogLevelError, string("profile processing failed: ") + e.what());
    
            // TODO: need to test this...may need an actual reference cast
            if (typeid(e)==typeid(RetryableProfileException)) {
                return pair<bool,void*>(true, sendRedirect(getAuthnRequest(target.c_str())));
            }
            throw;    // send it to the outer handler
        }

        log(LogLevelDebug, string("profile processing succeeded, new session created (") + cookie + ")");

        if (target=="default") {
            pair<bool,const char*> homeURL=m_priv->m_app->getString("homeURL");
            target=homeURL.first ? homeURL.second : "/";
        }
        else if (target=="cookie") {
            // Pull the target value from the "relay state" cookie.
            const char* relay_state = m_priv->getRelayState(this);
            if (!relay_state || !*relay_state) {
                // No apparent relay state value to use, so fall back on the default.
                pair<bool,const char*> homeURL=m_priv->m_app->getString("homeURL");
                target=homeURL.first ? homeURL.second : "/";
            }
            else {
                CgiParse::url_decode((char*)relay_state);
                target=relay_state;
            }
        }
    
        // We've got a good session, set the cookie...
        pair<string,const char*> shib_cookie=getCookieNameProps("_shibsession_");
        cookie += shib_cookie.second;
        setCookie(shib_cookie.first, cookie);
    
        // ... and redirect to the target
        return pair<bool,void*>(true, sendRedirect(target));
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
        mlp.insert("requestURL", targetURL);

    return pair<bool,void*>(true,m_priv->sendError(this, "session", mlp));
}

pair<bool,void*>
ShibTarget::doCheckAuthZ(void)
{
#ifdef _DEBUG
    saml::NDC ndc("ShibTarget::doCheckAuthZ");
#endif

    ShibMLP mlp;
    const char *procState = "Authorization Processing Error";
    const char *targetURL = NULL;

    try {
        if (!m_priv->m_app)
            throw SAMLException("System uninitialized, application did not supply request information.");

        targetURL = m_priv->m_url.c_str();
        const char *session_id = m_priv->getSessionId(this);

        // Do we have an access control plugin?
        if (m_priv->m_settings.second) {
            Locker acllock(m_priv->m_settings.second);
            if (!m_priv->m_settings.second->authorized(*m_priv->m_sso_statement,
                m_priv->m_post_response ? m_priv->m_post_response->getAssertions() : EMPTY(SAMLAssertion*))) {
                log(LogLevelError, "doCheckAuthZ() access control provider denied access");
                if (targetURL)
                    mlp.insert("requestURL", targetURL);
                // TODO: check setting and return 403
                return pair<bool,void*>(true,m_priv->sendError(this, "access", mlp));
            }
        }

        // Perform HTAccess Checks
        auto_ptr<HTAccessInfo> ht(getAccessInfo());

        // No Info means OK.  Just return
        if (!ht.get())
            return pair<bool,void*>(false, NULL);

        vector<bool> auth_OK(ht->elements.size(), false);
        bool method_restricted=false;
        string remote_user = getRemoteUser();

#define CHECK_OK \
    do { \
        if (!ht->requireAll) { \
            return pair<bool,void*>(false, NULL); \
        } \
        auth_OK[x] = true; \
        continue; \
    } while (0)

        for (int x = 0; x < ht->elements.size(); x++) {
            auth_OK[x] = false;
            HTAccessInfo::RequireLine *line = ht->elements[x];
            if (! line->use_line)
                continue;
            method_restricted = true;

            const char *w = line->tokens[0].c_str();

            if (!strcasecmp(w,"Shibboleth")) {
                // This is a dummy rule needed because Apache conflates authn and authz.
                // Without some require rule, AuthType is ignored and no check_user hooks run.
                CHECK_OK;
            }
            else if (!strcmp(w,"valid-user")) {
                log(LogLevelDebug, "doCheckAuthZ accepting valid-user");
                CHECK_OK;
            }
            else if (!strcmp(w,"user") && !remote_user.empty()) {
                bool regexp=false;
                for (int i = 1; i < line->tokens.size(); i++) {
                    w = line->tokens[i].c_str();
                    if (*w == '~') {
                        regexp = true;
                        continue;
                    }
                
                    if (regexp) {
                        try {
                            // To do regex matching, we have to convert from UTF-8.
                            auto_ptr<XMLCh> trans(fromUTF8(w));
                            RegularExpression re(trans.get());
                            auto_ptr<XMLCh> trans2(fromUTF8(remote_user.c_str()));
                            if (re.matches(trans2.get())) {
                                log(LogLevelDebug, string("doCheckAuthZ accepting user: ") + w);
                                CHECK_OK;
                            }
                        }
                        catch (XMLException& ex) {
                            auto_ptr_char tmp(ex.getMessage());
                            log(LogLevelError, string("doCheckAuthZ caught exception while parsing regular expression (")
                    	       + w + "): " + tmp.get());
                        }
                    }
                    else if (!strcmp(remote_user.c_str(), w)) {
                        log(LogLevelDebug, string("doCheckAuthZ accepting user: ") + w);
                        CHECK_OK;
                    }
                }
            }
            else if (!strcmp(w,"group")) {
                auto_ptr<HTGroupTable> grpstatus(getGroupTable(remote_user));
                if (!grpstatus.get()) {
                    return pair<bool,void*>(true, returnDecline());
                }
    
                for (int i = 1; i < line->tokens.size(); i++) {
                    w = line->tokens[i].c_str();
                    if (grpstatus->lookup(w)) {
                        log(LogLevelDebug, string("doCheckAuthZ accepting group: ") + w);
                        CHECK_OK;
                    }
                }
            }
            else {
                Iterator<IAAP*> provs = m_priv->m_app->getAAPProviders();
                AAP wrapper(provs, w);
                if (wrapper.fail()) {
                    log(LogLevelWarn, string("doCheckAuthZ didn't recognize require rule: ") + w);
                    continue;
                }

                bool regexp = false;
                string vals = getHeader(wrapper->getHeader());
                for (int i = 1; i < line->tokens.size() && !vals.empty(); i++) {
                    w = line->tokens[i].c_str();
                    if (*w == '~') {
                        regexp = true;
                        continue;
                    }

                    try {
                        auto_ptr<RegularExpression> re;
                        if (regexp) {
                            delete re.release();
                            auto_ptr<XMLCh> trans(fromUTF8(w));
                            auto_ptr<RegularExpression> temp(new RegularExpression(trans.get()));
                            re=temp;
                        }
                    
                        string vals_str(vals);
                        int j = 0;
                        for (int i = 0;  i < vals_str.length();  i++) {
                            if (vals_str.at(i) == ';') {
                                if (i == 0) {
                                    log(LogLevelError, string("doCheckAuthZ invalid header encoding") +
                                        vals + ": starts with a semicolon");
                                    throw SAMLException("Invalid information supplied to authorization module.");
                                }

                                if (vals_str.at(i-1) == '\\') {
                                    vals_str.erase(i-1, 1);
                                    i--;
                                    continue;
                                }

                                string val = vals_str.substr(j, i-j);
                                j = i+1;
                                if (regexp) {
                                    auto_ptr<XMLCh> trans(fromUTF8(val.c_str()));
                                    if (re->matches(trans.get())) {
                                        log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                    	   ", got " + val + ": authorization granted");
                                        CHECK_OK;
                                    }
                                }
                                else if ((wrapper->getCaseSensitive() && val==w) ||
                                        (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                                    log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                        ", got " + val + ": authorization granted.");
                                    CHECK_OK;
                                }
                                else {
                                    log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                        ", got " + val + ": authoritzation not granted.");
                                }
                            }
                        }
    
                        string val = vals_str.substr(j, vals_str.length()-j);
                        if (regexp) {
                            auto_ptr<XMLCh> trans(fromUTF8(val.c_str()));
                            if (re->matches(trans.get())) {
                                log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                    ", got " + val + ": authorization granted.");
                                CHECK_OK;
                            }
                        }
                        else if ((wrapper->getCaseSensitive() && val==w) ||
                                (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                            log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                ", got " + val + ": authorization granted");
                            CHECK_OK;
                        }
                        else {
                            log(LogLevelDebug, string("doCheckAuthZ expecting ") + w +
                                ", got " + val + ": authorization not granted");
                        }
                    }
                    catch (XMLException& ex) {
                        auto_ptr_char tmp(ex.getMessage());
                            log(LogLevelError, string("doCheckAuthZ caught exception while parsing regular expression (")
                                + w + "): " + tmp.get());
                    }
                }
            }
        } // for x


        // check if all require directives are true
        bool auth_all_OK = true;
        for (int i = 0; i < ht->elements.size(); i++) {
            auth_all_OK &= auth_OK[i];
        }

        if (auth_all_OK || !method_restricted)
            return pair<bool,void*>(false, NULL);

        // If we get here there's an access error, so just fall through
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
        mlp.insert("requestURL", targetURL);

    return pair<bool,void*>(true,m_priv->sendError(this, "access", mlp));
}

pair<bool,void*>
ShibTarget::doExportAssertions(bool exportAssertion)
{
#ifdef _DEBUG
    saml::NDC ndc("ShibTarget::doExportAssertions");
#endif

    ShibMLP mlp;
    const char *procState = "Attribute Processing Error";
    const char *targetURL = NULL;
    char *page = "rm";

    try {
        if (!m_priv->m_app)
            throw SAMLException("System uninitialized, application did not supply request information.");

        targetURL = m_priv->m_url.c_str();
        const char *session_id = m_priv->getSessionId(this);

        if (!m_priv->m_sso_statement) {
            // No data yet, so we need to get the session. This can only happen
            // if the call to doCheckAuthn doesn't happen in the same object lifetime.
            sessionGet(
                session_id,
                m_priv->m_remote_addr.c_str(),
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
        if (!exp.first || !exp.second)
            if (exportAssertion)
                exp.second=true;
        if (exp.second && m_priv->m_pre_response) {
            ostringstream os;
            os << *(m_priv->m_pre_response);
            unsigned int outlen;
            char* resp = (char*)os.str().c_str();
            XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(resp), os.str().length(), &outlen);
            // TODO: strip linefeeds
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
        mlp.insert("requestURL", targetURL);

    return pair<bool,void*>(true,m_priv->sendError(this, page, mlp));
}


// Low level APIs

// Get the session cookie name and properties for the application
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
    return make_pair(prefix,defProps);
}
        
// Find the default assertion consumer service for the resource
const char*
ShibTarget::getShireURL(const char* resource) const
{
    if (!m_priv->m_shireURL.empty())
        return m_priv->m_shireURL.c_str();

    // XXX: what to do is m_app is NULL?

    bool shire_ssl_only=false;
    const char* shire=NULL;
    const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> p=props->getBool("shireSSL");
        if (p.first)
            shire_ssl_only=p.second;
        pair<bool,const char*> p2=props->getString("shireURL");
        if (p2.first)
            shire=p2.second;
    }
    
    // Should never happen...
    if (!shire || (*shire!='/' && strncmp(shire,"http:",5) && strncmp(shire,"https:",6)))
        return NULL;

    // The "shireURL" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  shire     shire       shire
    // 2  shire     resource    shire
    // 3  resource  resource    shire
    //
    // note: if shire_ssl_only is true, make sure the protocol is https

    const char* path = NULL;

    // Decide whether to use the shire or the resource for the "protocol"
    const char* prot;
    if (*shire != '/') {
        prot = shire;
    }
    else {
        prot = resource;
        path = shire;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store in member.
    if (shire_ssl_only)
        m_priv->m_shireURL.assign("https://");
    else
        m_priv->m_shireURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == shire then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != shire || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, slash-colon);

    // Build the shire URL
    m_priv->m_shireURL+=host + path;
    return m_priv->m_shireURL.c_str();
}
        
// Generate a Shib 1.x AuthnRequest redirect URL for the resource,
// using whatever relay state mechanism is specified for the app.
string ShibTarget::getAuthnRequest(const char* resource)
{
    // XXX: what to do if m_app is NULL?

    string req;
    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    
    const IPropertySet* props=m_priv->m_app ? m_priv->m_app->getPropertySet("Sessions") : NULL;
    if (props) {
        pair<bool,const char*> wayf=props->getString("wayfURL");
        if (wayf.first) {
            req=req + wayf.second + "?shire=" + m_priv->url_encode(getShireURL(resource)) + "&time=" + timebuf;
            
            // How should the target value be preserved?
            pair<bool,bool> localRelayState=m_priv->m_conf->getPropertySet("Local")->getBool("localRelayState");
            if (!localRelayState.first || !localRelayState.second) {
                // The old way, just send it along.
                req = req + "&target=" + m_priv->url_encode(resource);
            }
            else {
                // Here we store the state in a cookie and send a fixed
                // value to the IdP so we can recognize it on the way back.
                pair<string,const char*> shib_cookie=getCookieNameProps("_shibstate_");
                setCookie(shib_cookie.first,m_priv->url_encode(resource) + shib_cookie.second);
                req += "&target=cookie";
            }
            
            pair<bool,bool> old=m_priv->m_app->getBool("oldAuthnRequest");
            if (!old.first || !old.second) {
                wayf=m_priv->m_app->getString("providerId");
                if (wayf.first)
                    req=req + "&providerId=" + m_priv->url_encode(wayf.second);
            }
        }
    }
    return req;
}
        
// Process a lazy session setup request and turn it into an AuthnRequest
string ShibTarget::getLazyAuthnRequest(const char* query_string)
{
    CgiParse parser(query_string,strlen(query_string));
    const char* target=parser.get_value("target");
    if (!target || !*target)
        return "";
    return getAuthnRequest(target);
}

void ShibTarget::sessionNew(
    int supported_profiles,
    const char* packet,
    const char* ip,
    string& cookie,
    string& target
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
    arg.recipient = (char*) m_priv->m_shireURL.c_str();
    arg.application_id = (char*) m_priv->m_app->getId();
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
        log.debug("new session cookie: %s", ret.cookie);
        cookie = ret.cookie;
        if (ret.target)
            target = ret.target;
    }

    clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_2, (caddr_t)&ret);
    rpc.pool();
    if (except) {
        auto_ptr<SAMLException> wrapper(except);
        throw *wrapper;
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
        throw *wrapper;
    }
}

/*************************************************************************
 * Shib Target Private implementation
 */

ShibTargetPriv::ShibTargetPriv() : m_app(NULL), m_mapper(NULL), m_conf(NULL), m_Config(NULL), session_id(NULL), relay_state(NULL),
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

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

string
ShibTargetPriv::url_encode(const char* s)
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

void
ShibTargetPriv::get_application(const string& protocol, const string& hostname, int port, const string& uri)
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
  m_settings = m_mapper->getSettingsFromParsedURL(protocol.c_str(),
						  hostname.c_str(),
						  port, uri.c_str());

  // Now find the application from the URL settings
  pair<bool,const char*> application_id=m_settings.first->getString("applicationId");
  const IApplication* application=m_conf->getApplication(application_id.second);
  if (!application) {
    m_mapper->unlock();
    m_mapper = NULL;
    m_conf->unlock();
    m_conf = NULL;
    throw SAMLException("Unable to map request to application settings, check configuration.");
  }

  // Store the application for later use
  m_app = application;

  // Compute the target URL
  m_url = protocol + "://" + hostname;
  if ((protocol == "http" && port != 80) || (protocol == "https" && port != 443))
    m_url += ":" + port;
  m_url += uri;
}


void*
ShibTargetPriv::sendError(ShibTarget* st, string page, ShibMLP &mlp)
{
    const IPropertySet* props=m_app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page.c_str());
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res)
                    return st->sendPage(res);
            }
        }
    }

    string errstr = "sendError could not process the error template for application (";
    errstr += m_app->getId();
    errstr += ")";
    st->log(ShibTarget::LogLevelError, errstr);
    return st->sendPage("Internal Server Error. Please contact the site administrator.");
}

const char* ShibTargetPriv::getSessionId(ShibTarget* st)
{
  if (session_id) {
    //string m = string("getSessionId returning precreated session_id: ") + session_id;
    //st->log(ShibTarget::LogLevelDebug, m);
    return session_id;
  }

  char *sid;
  pair<string,const char*> shib_cookie = st->getCookieNameProps("_shibsession_");
  if (m_cookies.empty())
      m_cookies = st->getCookies();
  if (!m_cookies.empty()) {
    if (sid = strstr(m_cookies.c_str(), shib_cookie.first.c_str())) {
      // We found a cookie.  pull it out (our session_id)
      sid += shib_cookie.first.length() + 1; // skip over the '='
      char *cookieend = strchr(sid, ';');
      if (cookieend)
        *cookieend = '\0';
      session_id = sid;
    }
  }

  //string m = string("getSessionId returning new session_id: ") + session_id;
  //st->log(ShibTarget::LogLevelDebug, m);
  return session_id;
}

const char* ShibTargetPriv::getRelayState(ShibTarget* st)
{
  if (relay_state)
    return relay_state;

  char *sid;
  pair<string,const char*> shib_cookie = st->getCookieNameProps("_shibstate_");
  if (m_cookies.empty())
      m_cookies = st->getCookies();
  if (!m_cookies.empty()) {
    if (sid = strstr(m_cookies.c_str(), shib_cookie.first.c_str())) {
      // We found a cookie.  pull it out
      sid += shib_cookie.first.length() + 1; // skip over the '='
      char *cookieend = strchr(sid, ';');
      if (cookieend)
        *cookieend = '\0';
      relay_state = sid;
    }
  }

  return relay_state;
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

// Subclasses may not need to override these particular virtual methods.
string ShibTarget::getAuthType(void)
{
  return string("shibboleth");
}
void* ShibTarget::returnDecline(void)
{
  return NULL;
}
void* ShibTarget::returnOK(void)
{
  return NULL;
}
HTAccessInfo* ShibTarget::getAccessInfo(void)
{
  return NULL;
}
HTGroupTable* ShibTarget::getGroupTable(string &user)
{
  return NULL;
}
