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
    
  private:
    char * fmakeword(char stop, unsigned int *cl, const char** ppch);
    char * makeword(char *line, char stop);
    void plustospace(char *str);
    char x2c(char *what);
    void url_decode(char *url);

    map<string,char*> kvp_map;
  };

  class ShibTargetPriv
  {
  public:
    ShibTargetPriv();
    ~ShibTargetPriv();

    string url_encode(const char* s);
    void get_application(string protocol, string hostname, int port, string uri);
    void* sendError(ShibTarget* st, string page, ShibMLP &mlp);
    const char *getSessionId(ShibTarget* st);
    bool get_assertions(ShibTarget *st, const char *session_id, ShibMLP &mlp);

    IRequestMapper::Settings m_settings;
    const IApplication *m_app;
    string m_cookieName;
    string m_shireURL;
    string m_authnRequest;
    CgiParse* m_parser;

    const char *session_id;
    string m_cookies;

    vector<SAMLAssertion*> m_assertions;
    SAMLAuthenticationStatement* m_sso_statement;
    
    // These are the actual request parameters set via the init method.
    string m_url;
    string m_method;
    string m_protocol;
    string m_content_type;
    string m_remote_addr;

    ShibTargetConfig* m_Config;

  private:
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

void ShibTarget::init(ShibTargetConfig *config,
		      string protocol, string hostname, int port,
		      string uri, string content_type, string remote_host,
		      string method)
{
  saml::NDC ndc("ShibTarget::init");

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
ShibTarget::doCheckAuthN(bool requireSessionFlag)
{
  saml::NDC ndc("ShibTarget::doCheckAuthN");

  const char *targetURL = NULL;
  const char *procState = "Process Initialization Error";
  ShibMLP mlp;

  try {
    if (! m_priv->m_app)
      throw ShibTargetException(SHIBRPC_OK, "ShibTarget Uninitialized.  Application did not supply request information.");

    targetURL = m_priv->m_url.c_str();
    const char *shireURL = getShireURL(targetURL);
    if (! shireURL)
      throw ShibTargetException(SHIBRPC_OK, "Cannot map target URL to Shire URL.  Check configuration");

    if (strstr(targetURL,shireURL))
      return doHandlePOST();

    string auth_type = getAuthType();
#ifdef HAVE_STRCASECMP
    if (strcasecmp(auth_type.c_str(),"shibboleth"))
#else
    if (stricmp(auth_type.c_str(),"shibboleth"))
#endif
      return pair<bool,void*>(true,returnDecline());

    pair<bool,bool> requireSession =
      m_priv->m_settings.first->getBool("requireSession");
    if (!requireSession.first || !requireSession.second)
      if (requireSessionFlag)
	requireSession.second=true;

    const char *session_id = m_priv->getSessionId(this);
    
    if (!session_id || !*session_id) {
      // No session.  Maybe that's acceptable?

      if (!requireSession.second)
	return pair<bool,void*>(true,returnOK());

      // No cookie, but we require a session.  Generate an AuthnRequest.
      return pair<bool,void*>(true,sendRedirect(getAuthnRequest(targetURL)));
    }

    procState = "Session Processing Error";
    RPCError *status = sessionIsValid(session_id, m_priv->m_remote_addr.c_str());

    if (status->isError()) {

      // If no session is required, bail now.
      if (!requireSession.second)
	return pair<bool,void*>(true, returnOK());
      			   // XXX: Or should this be DECLINED?
			   // Has to be OK because DECLINED will just cause Apache
      			   // to fail when it can't locate anything to process the
      			   // AuthType.  No session plus requireSession false means
      			   // do not authenticate the user at this time.
      else if (status->isRetryable()) {
	// Session is invalid but we can retry the auth -- generate an AuthnRequest
	delete status;
	return pair<bool,void*>(true,sendRedirect(getAuthnRequest(targetURL)));

      } else {

	string er = "Unretryable error: " ;
	er += status->getText();
	log(LogLevelError, er);
	mlp.insert(*status);
	delete status;
	goto out;
      }

      delete status;
      
    }

    // We're done.  Everything is okay.  Nothing to report.  Nothing to do..
    // Let the caller decide how to proceed.
    log(LogLevelInfo, "doCheckAuthN Succeeded\n");
    return pair<bool,void*>(false,NULL);

  } catch (ShibTargetException &e) {
    mlp.insert("errorText", e.what());

#ifndef _DEBUG
  } catch (...) {
    mlp.insert("errorText", "Unexpected Exception");
#endif
  }

  // If we get here then we've got an error.
  mlp.insert("errorType", procState);
  mlp.insert("errorDesc", "An error occurred while processing your request.");

 out:
  if (targetURL)
    mlp.insert("requestURL", targetURL);

  return pair<bool,void*>(true,m_priv->sendError(this, "shire", mlp));
}

pair<bool,void*>
ShibTarget::doHandlePOST(void)
{
  saml::NDC ndc("ShibTarget::doHandlePOST");

  const char *targetURL = NULL;
  const char *procState = "Session Creation Service Error";
  ShibMLP mlp;

  try {
    if (! m_priv->m_app)
      throw ShibTargetException(SHIBRPC_OK, "ShibTarget Uninitialized.  Application did not supply request information.");

    targetURL = m_priv->m_url.c_str();
    const char *shireURL = getShireURL(targetURL);

    if (!shireURL)
      throw ShibTargetException(SHIBRPC_OK, "doHandlePOST: unable to map request to a proper shireURL setting.  Check Configuration.");


    // Make sure we only process the SHIRE requests.
    if (!strstr(targetURL, shireURL))
      return pair<bool,void*>(true, returnDecline());

    const IPropertySet* sessionProps=m_priv->m_app->getPropertySet("Sessions");
    if (!sessionProps)
      throw ShibTargetException(SHIBRPC_OK, "doHandlePOST: unable to map request to application session settings.  Check configuration");

    // this always returns something
    pair<const char*,const char*> shib_cookie=getCookieNameProps();

    // Process SHIRE request
      
    pair<bool,bool> shireSSL=sessionProps->getBool("shireSSL");
      
    // Make sure this is SSL, if it should be
    if ((!shireSSL.first || shireSSL.second) && m_priv->m_protocol == "https")
      throw ShibTargetException(SHIBRPC_OK, "blocked non-SSL access to session creation service");

    // If this is a GET, we manufacture an AuthnRequest.
    if (!strcasecmp(m_priv->m_method.c_str(), "GET")) {
      string args = getArgs();
      const char* areq=args.empty() ? NULL : getLazyAuthnRequest(args.c_str());
      if (!areq)
	throw ShibTargetException(SHIBRPC_OK, "malformed GET arguments to request a new session");
      return pair<bool,void*>(true, sendRedirect(areq));
    }
    else if (strcasecmp(m_priv->m_method.c_str(), "POST")) {
      throw ShibTargetException(SHIBRPC_OK, "blocked non-POST to SHIRE POST processor");
    }

    // Make sure this POST is an appropriate content type
    if (m_priv->m_content_type.empty() ||
	strcasecmp(m_priv->m_content_type.c_str(),
		   "application/x-www-form-urlencoded")) {
      string er = string("blocked bad content-type to SHIRE POST processor: ") +
	m_priv->m_content_type;
      throw ShibTargetException(SHIBRPC_OK, er.c_str());
    }
	
    // Read the POST Data
    string cgistr = getPostData();

    // Parse the submission.
    pair<const char*,const char*> elements =
      getFormSubmission(cgistr.c_str(),cgistr.length());
    
    // Make sure the SAML Response parameter exists
    if (!elements.first || !*elements.first)
      throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find SAMLResponse form element");
    
    // Make sure the target parameter exists
    if (!elements.second || !*elements.second)
      throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find TARGET form element");
    
    // process the post
    string cookie;
    RPCError* status = sessionCreate(elements.first, m_priv->m_remote_addr.c_str(),
				     cookie);

    if (status->isError()) {
      char buf[25];
      sprintf(buf, "(%d): ", status->getCode());
      string er = string("doHandlePost() POST process failed ") + buf +
			 status->getText();
      log(LogLevelError, er);

      if (status->isRetryable()) {
	delete status;

	return pair<bool,void*>(true, sendRedirect(getAuthnRequest(elements.second)));
      }

      // return this error to the user.
      mlp.insert(*status);
      delete status;
      goto out;
    }
    delete status;

    log(LogLevelDebug,
	string("doHandlePost() POST process succeeded. New session: ") + cookie);

    // We've got a good session, set the cookie...
    cookie += shib_cookie.second;
    setCookie(shib_cookie.first, cookie);

    // ... and redirect to the target
    return pair<bool,void*>(true, sendRedirect(elements.second));

  } catch (ShibTargetException &e) {
    mlp.insert("errorText", e.what());

#ifndef _DEBUG
  } catch (...) {
    mlp.insert("errorText", "Unexpected Exception");
#endif
  }

  // If we get here then we've got an error.
  mlp.insert("errorType", procState);
  mlp.insert("errorDesc", "An error occurred while processing your request.");

 out:
  if (targetURL)
    mlp.insert("requestURL", targetURL);

  return pair<bool,void*>(true,m_priv->sendError(this, "shire", mlp));
}

pair<bool,void*>
ShibTarget::doCheckAuthZ(void)
{
  saml::NDC ndc("ShibTarget::doCheckAuthZ");

  ShibMLP mlp;
  const char *procState = "Authorization Processing Error";
  const char *targetURL = NULL;
  HTAccessInfo *ht = NULL;
  HTGroupTable* grpstatus = NULL;

  try {
    if (! m_priv->m_app)
      throw ShibTargetException(SHIBRPC_OK, "ShibTarget Uninitialized.  Application did not supply request information.");

    targetURL = m_priv->m_url.c_str();
    const char *session_id = m_priv->getSessionId(this);

    // XXX: need to make sure that export assertions was already called.
    //if (m_priv->get_assertions(this, session_id, mlp))
    //goto out;

    // Do we have an access control plugin?
    if (m_priv->m_settings.second) {
      Locker acllock(m_priv->m_settings.second);
      if (!m_priv->m_settings.second->authorized(*m_priv->m_sso_statement,
						 m_priv->m_assertions)) {
	log(LogLevelError, "doCheckAuthZ: access control provider denied access");
	goto out;
      }
    }

    // Perform HTAccess Checks
    ht = getAccessInfo();

    // No Info means OK.  Just return
    if (!ht)
      return pair<bool,void*>(false, NULL);

    vector<bool> auth_OK(ht->elements.size(), false);
    bool method_restricted=false;
    string remote_user = getRemoteUser();

    #define CHECK_OK { \
      if (ht->requireAll) { \
	delete ht; \
	if (grpstatus) delete grpstatus; \
	return pair<bool,void*>(false, NULL); \
      } \
      auth_OK[x] = true; \
      continue; \
    }

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
	sleep(60);
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
	grpstatus = getGroupTable(remote_user);

	if (!grpstatus) {
	  delete ht;
	  return pair<bool,void*>(true, returnDecline());
	}
    
	for (int i = 1; i < line->tokens.size(); i++) {
	  w = line->tokens[i].c_str();
	  if (grpstatus->lookup(w)) {
	    log(LogLevelDebug, string("doCheckAuthZ accepting group: ") + w);
	    CHECK_OK;
	  }
	}
	delete grpstatus;
	grpstatus = NULL;
      }
      else {
	Iterator<IAAP*> provs = m_priv->m_app->getAAPProviders();
	AAP wrapper(provs, w);
	if (wrapper.fail()) {
	  log(LogLevelWarn, string("doCheckAuthZ didn't recognize require rule: ")
				   + w);
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
		  log(LogLevelError, string("doCheckAuthZ invalid header encoding")+
		      vals + ": starts with a semicolon");
		  goto out;
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

    delete ht;
    if (grpstatus) delete grpstatus;
    if (auth_all_OK || !method_restricted)
      return pair<bool,void*>(false, NULL);

    // If we get here there's an access error, so just fall through

  } catch (ShibTargetException &e) {
    mlp.insert("errorText", e.what());

#ifndef _DEBUG
  } catch (...) {
    mlp.insert("errorText", "Unexpected Exception");
#endif
  }

  // If we get here then we've got an error.
  mlp.insert("errorType", procState);
  mlp.insert("errorDesc", "An error occurred while processing your request.");

 out:
  if (targetURL)
    mlp.insert("requestURL", targetURL);

  if (ht)
    delete ht;

  return pair<bool,void*>(true,m_priv->sendError(this, "access", mlp));
}

pair<bool,void*>
ShibTarget::doExportAssertions(bool exportAssertion)
{
  saml::NDC ndc("ShibTarget::doExportAssertions");

  ShibMLP mlp;
  const char *procState = "Attribute Processing Error";
  const char *targetURL = NULL;
  char *page = "rm";

  try {
    if (! m_priv->m_app)
      throw ShibTargetException(SHIBRPC_OK, "ShibTarget Uninitialized.  Application did not supply request information.");

    targetURL = m_priv->m_url.c_str();
    const char *session_id = m_priv->getSessionId(this);

    if (m_priv->get_assertions(this, session_id, mlp))
      goto out;

    // Get the AAP providers, which contain the attribute policy info.
    Iterator<IAAP*> provs=m_priv->m_app->getAAPProviders();

    // Clear out the list of mapped attributes
    while (provs.hasNext()) {
      IAAP* aap=provs.next();
      aap->lock();
      try {
	Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
	while (rules.hasNext()) {
	  const char* header=rules.next()->getHeader();
	  if (header)
	    clearHeader(header);
	}
      }
      catch(...) {
	aap->unlock();
	log(LogLevelError, "caught unexpected error while clearing headers");
	throw;
      }
      aap->unlock();
    }
    provs.reset();
    
    // Maybe export the first assertion.
    clearHeader("Shib-Attributes");
    pair<bool,bool> exp=m_priv->m_settings.first->getBool("exportAssertion");
    if (!exp.first || !exp.second)
      if (exportAssertion)
	exp.second=true;
    if (exp.second && m_priv->m_assertions.size()) {
      string assertion;
      RM::serialize(*(m_priv->m_assertions[0]), assertion);
      setHeader("Shib-Attributes", assertion.c_str());
    }

    // Export the SAML AuthnMethod and the origin site name, and possibly the NameIdentifier.
    clearHeader("Shib-Origin-Site");
    clearHeader("Shib-Authentication-Method");
    clearHeader("Shib-NameIdentifier-Format");
    auto_ptr_char os(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getNameQualifier());
    auto_ptr_char am(m_priv->m_sso_statement->getAuthMethod());
    setHeader("Shib-Origin-Site", os.get());
    setHeader("Shib-Authentication-Method", am.get());
    
    // Export NameID?
    AAP wrapper(provs,
		m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getFormat(),
		Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
    if (!wrapper.fail() && wrapper->getHeader()) {
      auto_ptr_char form(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getFormat());
      auto_ptr_char nameid(m_priv->m_sso_statement->getSubject()->getNameIdentifier()->getName());
      setHeader("Shib-NameIdentifier-Format", form.get());
      if (!strcmp(wrapper->getHeader(),"REMOTE_USER"))
	setRemoteUser(nameid.get());
      else
	setHeader(wrapper->getHeader(), nameid.get());
    }
    
    clearHeader("Shib-Application-ID");
    setHeader("Shib-Application-ID", m_priv->m_app->getId());

    // Export the attributes.
    Iterator<SAMLAssertion*> a_iter(m_priv->m_assertions);
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
	  AAP wrapper(provs,attr->getName(),attr->getNamespace());
	  if (wrapper.fail() || !wrapper->getHeader())
	    continue;
                
	  Iterator<string> vals=attr->getSingleByteValues();
	  if (!strcmp(wrapper->getHeader(),"REMOTE_USER") && vals.hasNext())
	    setRemoteUser(vals.next());
	  else {
	    int it=0;
	    string header = getHeader(wrapper->getHeader());
	    if (! header.empty())
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
	    setHeader(wrapper->getHeader(), header);
	  }
	}
      }
    }

    return pair<bool,void*>(false,NULL);

  } catch (ShibTargetException &e) {
    mlp.insert("errorText", e.what());

#ifndef _DEBUG
  } catch (...) {
    mlp.insert("errorText", "Unexpected Exception");
#endif

  }

  // If we get here then we've got an error.
  mlp.insert("errorType", procState);
  mlp.insert("errorDesc", "An error occurred while processing your request.");

 out:
  if (targetURL)
    mlp.insert("requestURL", targetURL);

  return pair<bool,void*>(true,m_priv->sendError(this, page, mlp));
}


// SHIRE APIs

// Get the session cookie name and properties for the application
std::pair<const char*,const char*>
ShibTarget::getCookieNameProps() const
{
    static const char* defProps="; path=/";
    static const char* defName="_shibsession_";
    
    // XXX: What to do if m_app isn't set?

    const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> p=props->getString("cookieProps");
        if (!p.first)
            p.second=defProps;
        if (!m_priv->m_cookieName.empty())
            return pair<const char*,const char*>(m_priv->m_cookieName.c_str(),
						 p.second);
        pair<bool,const char*> p2=props->getString("cookieName");
        if (p2.first) {
            m_priv->m_cookieName=p2.second;
            return pair<const char*,const char*>(p2.second,p.second);
        }
        m_priv->m_cookieName=defName;
        m_priv->m_cookieName+=m_priv->m_app->getId();
        return pair<const char*,const char*>(m_priv->m_cookieName.c_str(),p.second);
    }
    m_priv->m_cookieName=defName;
    m_priv->m_cookieName+=m_priv->m_app->getId();
    return pair<const char*,const char*>(m_priv->m_cookieName.c_str(),defProps);
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
        
// Generate a Shib 1.x AuthnRequest redirect URL for the resource
const char*
ShibTarget::getAuthnRequest(const char* resource) const
{
    if (!m_priv->m_authnRequest.empty())
        return m_priv->m_authnRequest.c_str();
        
    // XXX: what to do if m_app is NULL?

    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    
    const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> wayf=props->getString("wayfURL");
        if (wayf.first) {
            m_priv->m_authnRequest=m_priv->m_authnRequest + wayf.second + "?shire=" + m_priv->url_encode(getShireURL(resource)) +
                "&target=" + m_priv->url_encode(resource) + "&time=" + timebuf;
            pair<bool,bool> old=m_priv->m_app->getBool("oldAuthnRequest");
            if (!old.first || !old.second) {
                wayf=m_priv->m_app->getString("providerId");
                if (wayf.first)
                    m_priv->m_authnRequest=m_priv->m_authnRequest + "&providerId=" + m_priv->url_encode(wayf.second);
            }
        }
    }
    return m_priv->m_authnRequest.c_str();
}
        
// Process a lazy session setup request and turn it into an AuthnRequest
const char*
ShibTarget::getLazyAuthnRequest(const char* query_string) const
{
    CgiParse parser(query_string,strlen(query_string));
    const char* target=parser.get_value("target");
    if (!target || !*target)
        return NULL;
    return getAuthnRequest(target);
}
        
// Process a POST profile submission, and return (SAMLResponse,TARGET) pair.
std::pair<const char*,const char*>
ShibTarget::getFormSubmission(const char* post, unsigned int len) const
{
    m_priv->m_parser = new CgiParse(post,len);
    return pair<const char*,const char*>(m_priv->m_parser->get_value("SAMLResponse"),m_priv->m_parser->get_value("TARGET"));
}
        
RPCError* 
ShibTarget::sessionCreate(const char* response, const char* ip, std::string &cookie)
  const
{
  saml::NDC ndc("sessionCreate");
  Category& log = Category::getInstance("shibtarget.SHIRE");

  if (!response || !*response) {
    log.error ("Empty SAML response content");
    return new RPCError(-1,  "Empty SAML response content");
  }

  if (!ip || !*ip) {
    log.error ("Invalid IP address");
    return new RPCError(-1, "Invalid IP address");
  }
  
  shibrpc_new_session_args_1 arg;
  arg.shire_location = (char*) m_priv->m_shireURL.c_str();
  arg.application_id = (char*) m_priv->m_app->getId();
  arg.saml_post = (char*)response;
  arg.client_addr = (char*)ip;
  arg.checkIPAddress = true;

  log.info ("create session for user at %s for application %s", ip, arg.application_id);

  const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
  if (props) {
      pair<bool,bool> pcheck=props->getBool("checkAddress");
      if (pcheck.first)
          arg.checkIPAddress = pcheck.second;
  }

  shibrpc_new_session_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT* clnt;
  RPC rpc;
  do {
    clnt = rpc->connect();
    clnt_stat status = shibrpc_new_session_1 (&arg, &ret, clnt);
    if (status != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and retry
      log.error("RPC Failure: %p (%p) (%d): %s", this, clnt, status, clnt_spcreateerror("shibrpc_new_session_1"));
      rpc->disconnect();
      if (retry)
        retry--;
      else
        return new RPCError(-1, "RPC Failure");
    }
    else {
      // SUCCESS.  Pool and continue
      retry = -1;
    }
  } while (retry>=0);

  log.debug("RPC completed with status %d (%p)", ret.status.status, this);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else {
    log.debug ("new cookie: %s", ret.cookie);
    cookie = ret.cookie;
    retval = new RPCError();
  }

  clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_1, (caddr_t)&ret);
  rpc.pool();

  log.debug("returning");
  return retval;
}

RPCError*
ShibTarget::sessionIsValid(const char* session_id, const char* ip) const
{
  saml::NDC ndc("sessionIsValid");
  Category& log = Category::getInstance("shibtarget.SHIRE");

  if (!session_id || !*session_id) {
    log.error ("No cookie value was provided");
    return new RPCError(SHIBRPC_NO_SESSION, "No cookie value was provided");
  }
  else if (strchr(session_id,'=')) {
    log.error ("The cookie value wasn't extracted successfully, use a more unique cookie name for your installation.");
    return new RPCError(SHIBRPC_INTERNAL_ERROR, "The cookie value wasn't extracted successfully, use a more unique cookie name for your installation.");
  }

  if (!ip || !*ip) {
    log.error ("Invalid IP Address");
    return new RPCError(SHIBRPC_IPADDR_MISSING, "Invalid IP Address");
  }

  log.info ("is session valid: %s", ip);
  log.debug ("session cookie: %s", session_id);

  shibrpc_session_is_valid_args_1 arg;

  arg.cookie.cookie = (char*)session_id;
  arg.cookie.client_addr = (char *)ip;
  arg.application_id = (char *)m_priv->m_app->getId();
  
  // Get rest of input from the application Session properties.
  arg.lifetime = 3600;
  arg.timeout = 1800;
  arg.checkIPAddress = true;
  const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
  if (props) {
      pair<bool,unsigned int> p=props->getUnsignedInt("lifetime");
      if (p.first)
          arg.lifetime = p.second;
      p=props->getUnsignedInt("timeout");
      if (p.first)
          arg.timeout = p.second;
      pair<bool,bool> pcheck=props->getBool("checkAddress");
      if (pcheck.first)
          arg.checkIPAddress = pcheck.second;
  }
  
  shibrpc_session_is_valid_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  RPC rpc;
  do {
    clnt = rpc->connect();
    clnt_stat status = shibrpc_session_is_valid_1(&arg, &ret, clnt);
    if (status != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and try again...
      log.error("RPC Failure: %p (%p) (%d) %s", this, clnt, status, clnt_spcreateerror("shibrpc_session_is_valid_1"));
      rpc->disconnect();
      if (retry)
          retry--;
      else
          return new RPCError(-1, "RPC Failure");
    }
    else {
      // SUCCESS
      retry = -1;
    }
  } while (retry>=0);

  log.debug("RPC completed with status %d, %p", ret.status.status, this);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else
    retval = new RPCError();

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_session_is_valid_ret_1, (caddr_t)&ret);
  rpc.pool();

  log.debug("returning");
  return retval;
}

// RM APIS

RPCError*
ShibTarget::getAssertions(const char* cookie, const char* ip,
			  std::vector<saml::SAMLAssertion*>& assertions,
			  saml::SAMLAuthenticationStatement **statement
			  ) const
{
  saml::NDC ndc("getAssertions");
  Category& log=Category::getInstance("shibtarget.RM");
  log.info("get assertions...");

  if (!cookie || !*cookie) {
    log.error ("No cookie value provided.");
    return new RPCError(-1, "No cookie value provided.");
  }

  if (!ip || !*ip) {
    log.error ("Invalid ip address");
    return new RPCError(-1, "Invalid IP address");
  }

  log.debug("session cookie: %s", cookie);

  shibrpc_get_assertions_args_1 arg;
  arg.cookie.cookie = (char*)cookie;
  arg.cookie.client_addr = (char*)ip;
  arg.checkIPAddress = true;
  arg.application_id = (char *)m_priv->m_app->getId();

  log.info("request from %s for \"%s\"", ip, arg.application_id);

  const IPropertySet* props=m_priv->m_app->getPropertySet("Sessions");
  if (props) {
      pair<bool,bool> pcheck=props->getBool("checkAddress");
      if (pcheck.first)
          arg.checkIPAddress = pcheck.second;
  }

  shibrpc_get_assertions_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  RPC rpc;
  do {
    clnt = rpc->connect();
    clnt_stat status = shibrpc_get_assertions_1(&arg, &ret, clnt);
    if (status != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and try again.
      log.debug("RPC Failure: %p (%p) (%d): %s", this, clnt, status, clnt_spcreateerror("shibrpc_get_assertions_1"));
      rpc->disconnect();
      if (retry)
        retry--;
      else
        return new RPCError(-1, "RPC Failure");
    }
    else {
      // SUCCESS.  Release back into pool
      retry = -1;
    }
  } while (retry>=0);

  log.debug("RPC completed with status %d (%p)", ret.status.status, this);

  RPCError* retval = NULL;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else {
    try {
      try {
        for (u_int i = 0; i < ret.assertions.assertions_len; i++) {
          istringstream attrstream(ret.assertions.assertions_val[i].xml_string);
          SAMLAssertion *as = NULL;
          log.debugStream() << "Trying to decode assertion " << i << ": " <<
                ret.assertions.assertions_val[i].xml_string << CategoryStream::ENDLINE;
          assertions.push_back(new SAMLAssertion(attrstream));
        }

        // return the Authentication Statement
        if (statement) {
          istringstream authstream(ret.auth_statement.xml_string);
          SAMLAuthenticationStatement *auth = NULL;
          
          log.debugStream() << "Trying to decode authentication statement: " <<
                ret.auth_statement.xml_string << CategoryStream::ENDLINE;
            auth = new SAMLAuthenticationStatement(authstream);
        
            // Save off the statement
            *statement = auth;
        }
      }
      catch (SAMLException& e) {
      	log.error ("SAML Exception: %s", e.what());
      	ostringstream os;
       	os << e;
       	throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str().c_str());
      }
      catch (XMLException& e) {
       	log.error ("XML Exception: %s", e.getMessage());
       	auto_ptr_char msg(e.getMessage());
       	throw ShibTargetException (SHIBRPC_XML_EXCEPTION, msg.get());
      }
    }
    catch (ShibTargetException &e) {
      retval = new RPCError(e);
    }

    if (!retval)
      retval = new RPCError();
  }

  clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_get_assertions_ret_1, (caddr_t)&ret);
  rpc.pool();

  log.debug ("returning..");
  return retval;
}

void
ShibTarget::serialize(saml::SAMLAssertion &assertion, std::string &result)
{
  saml::NDC ndc("serialize");
  Category& log=Category::getInstance("shibtarget.RM");

  ostringstream os;
  os << assertion;
  unsigned int outlen;
  char* assn = (char*) os.str().c_str();
  XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(assn), os.str().length(), &outlen);
  result = (char*) serialized;
  XMLString::release(&serialized);
}


/*************************************************************************
 * Shib Target Private implementation
 */

ShibTargetPriv::ShibTargetPriv() : m_parser(NULL), m_app(NULL), m_mapper(NULL),
				   m_conf(NULL), m_Config(NULL), m_assertions()
{
  session_id = NULL;
  m_sso_statement = NULL;
}

ShibTargetPriv::~ShibTargetPriv()
{
  if (m_sso_statement) {
    delete m_sso_statement;
    m_sso_statement = NULL;
  }
  for (int k = 0; k < m_assertions.size(); k++)
    delete m_assertions[k];
  m_assertions = vector<SAMLAssertion*>(); 

  if (m_parser) {
    delete m_parser;
    m_parser = NULL;
  }
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
ShibTargetPriv::get_application(string protocol, string hostname, int port,
				string uri)
{
  if (m_app)
    return;

  // XXX: Do we need to keep conf and mapper locked while we hold m_app?

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
    throw ShibTargetException(SHIBRPC_OK, "unable to map request to application settings.  Check configuration");
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

  string errstr = "sendError could not process the error template for application ";
  errstr += m_app->getId();
  st->log(ShibTarget::LogLevelError, errstr);
  return st->sendPage("Internal Server Error.  Please contact the server administrator.");
}

const char *
ShibTargetPriv::getSessionId(ShibTarget* st)
{
  if (session_id) {
    //string m = string("getSessionId returning precreated session_id: ") + session_id;
    //st->log(ShibTarget::LogLevelDebug, m);
    return session_id;
  }

  char *sid;
  pair<const char*, const char *> shib_cookie = st->getCookieNameProps();
  m_cookies = st->getCookies();
  if (!m_cookies.empty()) {
    if (sid = strstr(m_cookies.c_str(), shib_cookie.first)) {
      // We found a cookie.  pull it out (our session_id)
      sid += strlen(shib_cookie.first) + 1; // skip over the '='
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

bool
ShibTargetPriv::get_assertions(ShibTarget* st, const char *session_id, ShibMLP &mlp)
{
  if (m_sso_statement)
    return false;

  RPCError *status = NULL;
  status = st->getAssertions(session_id, m_remote_addr.c_str(),
			     m_assertions, &m_sso_statement);

  if (status->isError()) {
    string er = "getAssertions failed: ";
    er += status->getText();
    st->log(ShibTarget::LogLevelError, er);
    mlp.insert(*status);
    delete status;
    return true;
  }
  delete status;
  return false;
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

/*
 * We need to implement this so the SHIRE (and RM) recodes work
 * in terms of the ShibTarget
 */
void ShibTarget::log(ShibLogLevel level, const string &msg)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getCookies(void)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::setCookie(const string &name, const string &value)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::clearHeader(const string &name)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::setHeader(const string &name, const string &value)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getHeader(const string &name)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::setRemoteUser(const string &name)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getRemoteUser(void)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getArgs(void)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getPostData(void)
{
  throw runtime_error("Invalid Usage");
}
//virtual HTAccessInfo& getAccessInfo(void);
void* ShibTarget::sendPage(const string &msg, const string content_type, const pair<string,string> headers[], int code)
{
  throw runtime_error("Invalid Usage");
}
void* ShibTarget::sendRedirect(const std::string url)
{
  throw runtime_error("Invalid Usage");
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
