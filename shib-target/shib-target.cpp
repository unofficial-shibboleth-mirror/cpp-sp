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
#include <stdexcept>

#include <shib/shib-threads.h>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <xercesc/util/Base64.hpp>

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

    IRequestMapper::Settings m_settings;
    const IApplication *m_app;
    string m_cookieName;
    string m_shireURL;
    string m_authnRequest;
    CgiParse* m_parser;

    // These are the actual request parameters set via the init method.
    string m_url;
    string m_method;
    string m_content_type;
    string m_remote_addr;
    int m_total_bytes;

    ShibTargetConfig* m_Config;
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
		      int total_bytes)
{
  m_priv->m_method = protocol;
  m_priv->m_content_type = content_type;
  m_priv->m_remote_addr = remote_host;
  m_priv->m_total_bytes = total_bytes;
  m_priv->m_Config = config;
  m_priv->get_application(protocol, hostname, port, uri);
}


// These functions implement the server-agnostic shibboleth engine
// The web server modules implement a subclass and then call into 
// these methods once they instantiate their request object.
void*
ShibTarget::doCheckAuthN(void)
{

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
      return returnDecline();

    pair<bool,bool> requireSession = getRequireSession(m_priv->m_settings);
    pair<const char*, const char *> shib_cookie = getCookieNameProps();

    const char *session_id = NULL;
    string cookies = getCookies();
    if (!cookies.empty()) {
      if (session_id = strstr(cookies.c_str(), shib_cookie.first)) {
	// We found a cookie.  pull it out (our session_id)
	session_id += strlen(shib_cookie.first) + 1; // skip over the '='
	char *cookieend = strchr(session_id, ';');
	if (cookieend)
	  *cookieend = '\0';
      }
    }
    
    if (!session_id || !*session_id) {
      // No session.  Maybe that's acceptable?

      if (!requireSession.second)
	return returnOK();

      // No cookie, but we require a session.  Generate an AuthnRequest.
      return sendRedirect(getAuthnRequest(targetURL));
    }

    procState = "Session Processing Error";
    RPCError *status = sessionIsValid(session_id, m_priv->m_remote_addr.c_str());

    if (status->isError()) {

      // If no session is required, bail now.
      if (!requireSession.second)
	return returnOK(); // XXX: Or should this be DECLINED?
			   // Has to be OK because DECLINED will just cause Apache
      			   // to fail when it can't locate anything to process the
      			   // AuthType.  No session plus requireSession false means
      			   // do not authenticate the user at this time.
      else if (status->isRetryable()) {
	// Session is invalid but we can retry the auth -- generate an AuthnRequest
	delete status;
	return sendRedirect(getAuthnRequest(targetURL));

      } else {

	mlp.insert(*status);
	delete status;
	goto out;
      }

      delete status;
      
    }

  } catch (ShibTargetException &e) {
    mlp.insert("errorText", e.what());

  } catch (...) {
    mlp.insert("errorText", "Unexpected Exception");

  }

  // If we get here then we've got an error.
  mlp.insert("errorType", procState);
  mlp.insert("errorDesc", "An error occurred while processing your request.");

 out:
  if (targetURL)
    mlp.insert("requestURL", targetURL);

  string res = "xxx";
  return sendPage(res);
}

void*
ShibTarget::doHandlePOST(void)
{
  return NULL;
}

void*
ShibTarget::doCheckAuthZ(void)
{
  return NULL;
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

ShibTargetPriv::ShibTargetPriv() : m_parser(NULL), m_app(NULL)
{
  m_total_bytes = 0;
}

ShibTargetPriv::~ShibTargetPriv()
{
  if (m_parser) delete m_parser;
  //if (m_app) delete m_app;
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

  // We lock the configuration system for the duration.
  IConfig* conf=m_Config->getINI();
  Locker locker(conf);
    
  // Map request to application and content settings.
  IRequestMapper* mapper=conf->getRequestMapper();
  Locker locker2(mapper);

  // Obtain the application settings from the parsed URL
  m_settings = mapper->getSettingsFromParsedURL(protocol.c_str(), hostname.c_str(),
						port, uri.c_str());

  // Now find the application from the URL settings
  pair<bool,const char*> application_id=m_settings.first->getString("applicationId");
  const IApplication* application=conf->getApplication(application_id.second);
  if (!application) {
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
void ShibTarget::log(ShibLogLevel level, string &msg)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getCookies(void)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::setCookie(string &name, string &value)
{
  throw runtime_error("Invalid Usage");
}
string ShibTarget::getPostData(void)
{
  throw runtime_error("Invalid Usage");
}
void ShibTarget::setAuthType(std::string)
{
  throw runtime_error("Invalid Usage");
}
//virtual HTAccessInfo& getAccessInfo(void);
void* ShibTarget::sendPage(string &msg, pair<string,string> headers[], int code)
{
  throw runtime_error("Invalid Usage");
}
void* ShibTarget::sendRedirect(std::string url)
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
pair<bool,bool>
ShibTarget::getRequireSession(IRequestMapper::Settings &settings)
{
  return settings.first->getBool("requireSession");
}
