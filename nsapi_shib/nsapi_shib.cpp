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

/* nsapi_shib.cpp - Shibboleth NSAPI filter

   Scott Cantor
   12/13/04
*/

#include "config_win32.h"

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>

#include <log4cpp/Category.hh>

#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>

#ifdef WIN32
# define XP_WIN32
#else
# define XP_UNIX
#endif

#define MCC_HTTPD
#define NET_SSL

extern "C"
{
#include <nsapi.h>
}

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

// macros to output text to client
#define NET_WRITE(str) \
    if (IO_ERROR==net_write(sn->csd,str,strlen(str))) return REQ_EXIT

#if 0
/**************************************************************************/
/* This isn't used anywhere -- why have it? */
#define NET_WRITE1(buf,fmstr,param) \
    do { sprintf(buf,fmstr,param); NET_WRITE(buf); } while(0)

#define NET_WRITE2(buf,fmstr,param1,param2) \
    do { sprintf(buf,fmstr,param1,param2); NET_WRITE(buf); } while(0)

#define NET_WRITE3(buf,fmstr,param1,param2,param3) \
    do { sprintf(buf,fmstr,param1,param2,param3); NET_WRITE(buf); } while(0)

#define NET_WRITE4(buf,fmstr,param1,param2,param3,param4) \
    do { sprintf(buf,fmstr,param1,param2,param3,param4); NET_WRITE(buf); } while(0)
/**************************************************************************/
#endif

namespace {
    ShibTargetConfig* g_Config=NULL;
    string g_ServerName;
    string g_ServerScheme;
}

extern "C" NSAPI_PUBLIC void nsapi_shib_exit(void*)
{
    if (g_Config)
        g_Config->shutdown();
    g_Config = NULL;
}

extern "C" NSAPI_PUBLIC int nsapi_shib_init(pblock* pb, Session* sn, Request* rq)
{
    // Save off a default hostname for this virtual server.
    char* name=pblock_findval("server-name",pb);
    if (name)
        g_ServerName=name;
    else {
        name=server_hostname;
        if (name)
            g_ServerName=name;
        else {
            name=util_hostname();
            if (name) {
                g_ServerName=name;
                FREE(name);
            }
            else {
                pblock_nvinsert("error","unable to determine web server hostname",pb);
                return REQ_ABORTED;
            }
        }
    }
    name=pblock_findval("server-scheme",pb);
    if (name)
        g_ServerScheme=name;

    log_error(LOG_INFORM,"nsapi_shib_init",sn,rq,"nsapi_shib loaded for host (%s)",g_ServerName.c_str());

    try
    {
        const char* schemadir=pblock_findval("shib-schemas",pb);
        if (!schemadir)
            schemadir=getenv("SHIBSCHEMAS");
        if (!schemadir)
            schemadir=SHIB_SCHEMAS;
        const char* config=pblock_findval("shib-config",pb);
        if (!config)
            config=getenv("SHIBCONFIG");
        if (!config)
            config=SHIB_CONFIG;
        g_Config=&ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::SHIREExtensions |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(schemadir,config)) {
            g_Config=NULL;
            pblock_nvinsert("error","unable to initialize Shibboleth libraries",pb);
            return REQ_ABORTED;
        }

        daemon_atrestart(nsapi_shib_exit,NULL);
    }
    catch (...)
    {
#ifdef _DEBUG
        throw;
#endif
        g_Config=NULL;
        pblock_nvinsert("error","caught exception, unable to initialize Shibboleth libraries",pb);
        return REQ_ABORTED;
    }
    return REQ_PROCEED;
}

/********************************************************************************/
// NSAPI Shib Target Subclass

class ShibTargetNSAPI : public ShibTarget
{
public:
  ShibTargetNSAPI(pblock* pb, Session* sn, Request* rq) {
    // Get everything but hostname...
    const char* uri=pblock_findval("uri", rq->reqpb);
    const char* qstr=pblock_findval("query", rq->reqpb);
    int port=server_portnum;
    const char* scheme=security_active ? "https" : "http";
    const char* host=NULL;

    string url;
    if (uri)
        url=uri;
    if (qstr)
        url=url + '?' + qstr;
    
#ifdef vs_is_default_vs
    // This is 6.0 or later, so we can distinguish requests to name-based vhosts.
    if (!vs_is_default_vs)
        // The beauty here is, a non-default vhost can *only* be accessed if the client
        // specified the exact name in the Host header. So we can trust the Host header.
        host=pblock_findval("host", rq->headers);
    else
#endif
    // In other cases, we're going to rely on the initialization process...
    host=g_ServerName.c_str();

    char *content_type = NULL;
    if (request_header("content-type", &content_type, sn, rq) != REQ_PROCEED)
      throw("Bad Content Type");
      
    const char *remote_ip = pblock_findval("ip", sn->client);
    const char *method = pblock_findval("method", rq->reqpb);

    init(
	 g_Config, scheme, host, port, url.c_str(), content_type,
	 remote_ip, method
	 );

    m_pb = pb;
    m_sn = sn;
    m_rq = rq;
  }
  ~ShibTargetNSAPI() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    log_error((level == LogLevelDebug ? LOG_INFORM :
		   (level == LogLevelInfo ? LOG_INFORM :
		    (level == LogLevelWarn ? LOG_FAILURE :
		     LOG_FAILURE))),
	      "NSAPI_SHIB", m_sn, m_rq, msg.c_str());
  }
  virtual string getCookies(void) {
    char *cookies = NULL;
    if (request_header("cookie", &cookies, m_sn, m_rq) == REQ_ABORTED)
      throw("error accessing cookie header");
    return string(cookies ? cookies : "");
  }
  virtual void setCookie(const string &name, const string &value) {
    string cookie = name + '=' + value;
    pblock_nvinsert("Set-Cookie", cookie.c_str(), m_rq->srvhdrs);
  }
  virtual string getArgs(void) { 
    const char *q = pblock_findval("query", m_rq->reqpb);
    return string(q ? q : "");
  }
  virtual string getPostData(void) {
    char* content_length=NULL;
    if (request_header("content-length", &content_length, m_sn, m_rq)
	!=REQ_PROCEED || atoi(content_length) > 1024*1024) // 1MB?
      throw FatalProfileException("Blocked too-large a submittion to profile endpoint.");
    else {
      char ch=IO_EOF+1;
      int cl=atoi(content_length);
      string cgistr;
      while (cl && ch != IO_EOF) {
	ch=netbuf_getc(m_sn->inbuf);
      
	// Check for error.
	if(ch==IO_ERROR)
	  break;
	cgistr += ch;
	cl--;
      }
      if (cl)
	throw FatalProfileException("error reading POST data from browser");
      return cgistr;
    }
  }
  virtual void clearHeader(const string &name) {
    // srvhdrs or headers?
    param_free(pblock_remove(name.c_str(), m_rq->headers));
  }
  virtual void setHeader(const string &name, const string &value) {
    // srvhdrs or headers?
    pblock_nvinsert(name.c_str(), value.c_str() ,m_rq->srvhdrs);
  }
  virtual string getHeader(const string &name) {
    const char *hdr = NULL;
    if (request_header(name.c_str(), &hdr, m_sn, m_rq) != REQ_PROCEED)
      hdr = NULL;		// XXX: throw an exception here?
    return string(hdr ? hdr : "");
  }
  virtual void setRemoteUser(const string &user) {
    pblock_nvinsert("remote-user", user.c_str(), m_rq->headers);
    pblock_nvinsert("auth-user", user.c_str(), m_rq->vars);
  }
  virtual string getRemoteUser(void) {
    return getHeader("remote-user");
  }
  // Override this function because we want to add the NSAPI Directory override
  virtual pair<bool,bool> getRequireSession(IRequestMapper::Settings &settings) {
    pair<bool,bool> requireSession=settings.first->getBool("requireSession");
    if (!requireSession.first || !requireSession.second) {
      const char* param=pblock_findval("require-session",pb);
      if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
	requireSession.second=true;
    }
    return requireSession;
  }

  virtual void* sendPage(
    const string& msg,
    const string& content_type,
    const saml::Iterator<header_t>& headers=EMPTY(header_t),
    int code=200
    ) {
    pblock_nvinsert("Content-Type", content_type.c_str(), m_rq->srvhdrs);
    // XXX: Do we need content-length: or connection: close headers?
    while (headers.hasNext()) {
        const header_t& h=headers.next();
	pblock_nvinsert(h.first.c_str(), h.second.c_str(), m_rq->srvhdrs);
    }
    protocol_status(m_sn, m_rq, PROTOCOL_OK, NULL);
    NET_WRITE(const_cast<char*>(msg.c_str()));
    return (VOID*)REQ_EXIT;
  }
  virtual void* sendRedirect(const string& url) {
    pblock_nvinsert("Content-Type", "text/html", m_rq->srvhdrs);
    pblock_nvinsert("Content-Length", "40", m_rq->srvhdrs);
    pblock_nvinsert("Expires", "01-Jan-1997 12:00:00 GMT", m_rq->srvhdrs);
    pblock_nvinsert("Cache-Control", "private,no-store,no-cache", m_rq->srvhdrs);
    pblock_nvinsert("Location", url.c_str(), m_rq->srvhdrs);
    protocol_status(m_sn, m_rq, PROTOCOL_REDIRECT, "302 Please wait");
    protocol_start_response(m_sn, m_rq);
    NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
    return (void*)REQ_EXIT;
  }
  virtual void* returnDecline(void) { return (void*)REQ_PROCEED; } // XXX?
  virtual void* returnOK(void) { return (void*)REQ_PROCEED; }

  pblock* m_pb;
  Session* m_sn;
  Request* m_rq;
};

/********************************************************************************/

int WriteClientError(Session* sn, Request* rq, char* func, char* msg)
{
    log_error(LOG_FAILURE,func,sn,rq,msg);
    protocol_status(sn,rq,PROTOCOL_SERVER_ERROR,msg);
    return REQ_ABORTED;
}

#undef FUNC
#define FUNC "shibboleth"
extern "C" NSAPI_PUBLIC int nsapi_shib(pblock* pb, Session* sn, Request* rq)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] nsapi_shib" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef _DEBUG
  try {
#endif
    ShibTargetNSAPI stn(pb, sn, rq);

    // Check user authentication
    pair<bool,void*> res = stn.doCheckAuthN();
    if (res.first) return (int)res.second;

    // user authN was okay -- export the assertions now
    const char* param=pblock_findval("export-assertion", pb);
    bool doExportAssn = false;
    if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
      doExportAssn = true;
    res = stn.doExportAssertions(doExportAssn);
    if (res.first) return (int)res.second;

    // Check the Authorization
    res = stf.doCheckAuthZ();
    if (res.first) return (int)res.second;

    // this user is ok.
    return REQ_PROCEED;

#ifndef _DEBUG
  } catch (...) {
    return WriteClientError(sn, rq, FUNC, "threw an uncaught exception.");
  }
#endif
}


#undef FUNC
#define FUNC "shib_handler"
extern "C" NSAPI_PUBLIC int shib_handler(pblock* pb, Session* sn, Request* rq)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_handler" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef _DEBUG
  try {
#endif
    ShibTargetNSAPI stn(pb, sn, rq);

    pair<bool,void*> res = stn.doHandleProfile();
    if (res.first) return (int)res.second;

    return WriteClientError(sn, rq, FUNC, "doHandleProfile() did not do anything.")

#ifndef _DEBUG
  } catch (...) {
    return WriteClientError(sn, rq, FUNC, "threw an uncaught exception.");
  }
#endif
}


#if 0


IRequestMapper::Settings map_request(pblock* pb, Session* sn, Request* rq, IRequestMapper* mapper, string& target)
{
    // Get everything but hostname...
    const char* uri=pblock_findval("uri",rq->reqpb);
    const char* qstr=pblock_findval("query",rq->reqpb);
    int port=server_portnum;
    const char* scheme=security_active ? "https" : "http";
    const char* host=NULL;

    string url;
    if (uri)
        url=uri;
    if (qstr)
        url=url + '?' + qstr;
    
#ifdef vs_is_default_vs
    // This is 6.0 or later, so we can distinguish requests to name-based vhosts.
    if (!vs_is_default_vs)
        // The beauty here is, a non-default vhost can *only* be accessed if the client
        // specified the exact name in the Host header. So we can trust the Host header.
        host=pblock_findval("host", rq->headers);
    else
#endif
    // In other cases, we're going to rely on the initialization process...
    host=g_ServerName.c_str();
        
    target=(g_ServerScheme.empty() ? string(scheme) : g_ServerScheme) + "://" + host;
    
    // If port is non-default, append it.
    if ((!security_active && port!=80) || (security_active && port!=443)) {
        char portbuf[10];
        util_snprintf(portbuf,9,"%d",port);
        target = target + ':' + portbuf;
    }

    target+=url;
        
    return mapper->getSettingsFromParsedURL(scheme,host,port,url.c_str());
}

int WriteClientError(Session* sn, Request* rq, const IApplication* app, const char* page, ShibMLP& mlp)
{
    const IPropertySet* props=app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res) {
                    pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
                    pblock_nninsert("Content-Length",strlen(res),rq->srvhdrs);
                    pblock_nvinsert("Connection","close",rq->srvhdrs);
                    protocol_status(sn,rq,PROTOCOL_OK,NULL);
                    NET_WRITE(const_cast<char*>(res));
                    return REQ_EXIT;
                }
            }
        }
    }

    log_error(LOG_FAILURE,"WriteClientError",sn,rq,"Unable to open error template, check settings.");
    protocol_status(sn,rq,PROTOCOL_SERVER_ERROR,"Unable to open error template, check settings.");
    return REQ_ABORTED;
}

int WriteRedirectPage(Session* sn, Request* rq, const IApplication* app, const char* file, ShibMLP& mlp)
{
    ifstream infile(file);
    if (!infile.fail()) {
        const char* res = mlp.run(infile,app->getPropertySet("Errors"));
        if (res) {
            pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
            pblock_nninsert("Content-Length",strlen(res),rq->srvhdrs);
            protocol_status(sn,rq,PROTOCOL_OK,NULL);
            NET_WRITE(const_cast<char*>(res));
            return REQ_EXIT;
        }
    }
    log_error(LOG_FAILURE,"WriteRedirectPage",sn,rq,"Unable to open redirect template, check settings.");
    protocol_status(sn,rq,PROTOCOL_SERVER_ERROR,"Unable to open redirect template, check settings.");
    return REQ_ABORTED;
}

#undef FUNC
#define FUNC "shibboleth"
extern "C" NSAPI_PUBLIC int nsapi_shib(pblock* pb, Session* sn, Request* rq)
{
    try
    {
        ostringstream threadid;
        threadid << "[" << getpid() << "] nsapi_shib" << '\0';
        saml::NDC ndc(threadid.str().c_str());
        
        // We lock the configuration system for the duration.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        
        // Map request to application and content settings.
        string targeturl;
        IRequestMapper* mapper=conf->getRequestMapper();
        Locker locker2(mapper);
        IRequestMapper::Settings settings=map_request(pb,sn,rq,mapper,targeturl);
        pair<bool,const char*> application_id=settings.first->getString("applicationId");
        const IApplication* application=conf->getApplication(application_id.second);
        if (!application)
            return WriteClientError(sn,rq,FUNC,"Unable to map request to application settings, check configuration.");
        
        // Declare SHIRE object for this request.
        SHIRE shire(application);
        
        const char* shireURL=shire.getShireURL(targeturl.c_str());
        if (!shireURL)
            return WriteClientError(sn,rq,FUNC,"Unable to map request to proper shireURL setting, check configuration.");

        // If the user is accessing the SHIRE acceptance point, pass it on.
        if (targeturl.find(shireURL)!=string::npos)
            return REQ_PROCEED;

        // Now check the policy for this request.
        pair<bool,bool> requireSession=settings.first->getBool("requireSession");
        if (!requireSession.first || !requireSession.second) {
            const char* param=pblock_findval("require-session",pb);
            if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
                requireSession.second=true;
        }
        pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();
        pair<bool,bool> httpRedirects=application->getPropertySet("Sessions")->getBool("httpRedirects");
        pair<bool,const char*> redirectPage=application->getPropertySet("Sessions")->getString("redirectPage");
        if (httpRedirects.first && !httpRedirects.second && !redirectPage.first)
            return WriteClientError(sn,rq,FUNC,"HTML-based redirection requires a redirectPage property.");

        // Check for session cookie.
        const char* session_id=NULL;
        string cookie;
        if (request_header("cookie",(char**)&session_id,sn,rq)==REQ_ABORTED)
            return WriteClientError(sn,rq,FUNC,"error accessing cookie header");

        Category::getInstance("nsapi_shib."FUNC).debug("cookie header is {%s}",session_id ? session_id : "NULL");
        if (session_id && (session_id=strstr(session_id,shib_cookie.first))) {
            session_id+=strlen(shib_cookie.first) + 1;   /* Skip over the '=' */
            char* cookieend=strchr(session_id,';');
            if (cookieend) {
                // Chop out just the value portion.
                cookie.assign(session_id,cookieend-session_id-1);
                session_id=cookie.c_str();
            }
        }
        
        if (!session_id || !*session_id) {
            // If no session required, bail now.
            if (!requireSession.second)
                return REQ_PROCEED;
    
            // No acceptable cookie, and we require a session.  Generate an AuthnRequest.
            const char* areq = shire.getAuthnRequest(targeturl.c_str());
            if (!httpRedirects.first || httpRedirects.second) {
                pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
                pblock_nvinsert("Content-Length","40",rq->srvhdrs);
                pblock_nvinsert("Expires","01-Jan-1997 12:00:00 GMT",rq->srvhdrs);
                pblock_nvinsert("Cache-Control","private,no-store,no-cache",rq->srvhdrs);
                pblock_nvinsert("Location",areq,rq->srvhdrs);
                protocol_status(sn,rq,PROTOCOL_REDIRECT,"302 Please wait");
                protocol_start_response(sn,rq);
                NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
                return REQ_EXIT;
            }
            else {
                ShibMLP markupProcessor;
                markupProcessor.insert("requestURL",areq);
                return WriteRedirectPage(sn, rq, application, redirectPage.second, markupProcessor);
            }
        }

        // Make sure this session is still valid.
        RPCError* status = NULL;
        ShibMLP markupProcessor;
        markupProcessor.insert("requestURL", targeturl);
    
        try {
            status = shire.sessionIsValid(session_id, pblock_findval("ip",sn->client));
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Session Processing Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "shire", markupProcessor);
        }
#ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Session Processing Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "shire", markupProcessor);
        }
#endif

        // Check the status
        if (status->isError()) {
            if (!requireSession.second)
                return REQ_PROCEED;
            else if (status->isRetryable()) {
                // Oops, session is invalid. Generate AuthnRequest.
                delete status;
                const char* areq = shire.getAuthnRequest(targeturl.c_str());
                if (!httpRedirects.first || httpRedirects.second) {
                    pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
                    pblock_nvinsert("Content-Length","40",rq->srvhdrs);
                    pblock_nvinsert("Expires","01-Jan-1997 12:00:00 GMT",rq->srvhdrs);
                    pblock_nvinsert("Cache-Control","private,no-store,no-cache",rq->srvhdrs);
                    pblock_nvinsert("Location",areq,rq->srvhdrs);
                    protocol_status(sn,rq,PROTOCOL_REDIRECT,"302 Please wait");
                    protocol_start_response(sn,rq);
                    NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
                    return REQ_EXIT;
                }
                else {
                    markupProcessor.insert("requestURL",areq);
                    return WriteRedirectPage(sn, rq, application, redirectPage.second, markupProcessor);
                }
            }
            else {
                // return the error page to the user
                markupProcessor.insert(*status);
                delete status;
                return WriteClientError(sn, rq, application, "shire", markupProcessor);
            }
        }
        delete status;
    
        // Move to RM phase.
        RM rm(application);
        vector<SAMLAssertion*> assertions;
        SAMLAuthenticationStatement* sso_statement=NULL;

        try {
            status = rm.getAssertions(session_id, pblock_findval("ip",sn->client), assertions, &sso_statement);
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Attribute Processing Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "rm", markupProcessor);
        }
    #ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Attribute Processing Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "rm", markupProcessor);
        }
    #endif
    
        if (status->isError()) {
            markupProcessor.insert(*status);
            delete status;
            return WriteClientError(sn, rq, application, "rm", markupProcessor);
        }
        delete status;

        // Do we have an access control plugin?
        if (settings.second) {
            Locker acllock(settings.second);
            if (!settings.second->authorized(*sso_statement,assertions)) {
                for (int k = 0; k < assertions.size(); k++)
                    delete assertions[k];
                delete sso_statement;
                return WriteClientError(sn, rq, application, "access", markupProcessor);
            }
        }

        // Get the AAP providers, which contain the attribute policy info.
        Iterator<IAAP*> provs=application->getAAPProviders();
    
        // Clear out the list of mapped attributes
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            aap->lock();
            try {
                Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
                while (rules.hasNext()) {
                    const char* header=rules.next()->getHeader();
                    if (header)
                        param_free(pblock_remove(header,rq->headers));
                }
            }
            catch(...) {
                aap->unlock();
                for (int k = 0; k < assertions.size(); k++)
                  delete assertions[k];
                delete sso_statement;
                markupProcessor.insert("errorType", "Attribute Processing Error");
                markupProcessor.insert("errorText", "Unexpected Exception");
                markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
                return WriteClientError(sn, rq, application, "rm", markupProcessor);
            }
            aap->unlock();
        }
        provs.reset();

        // Maybe export the first assertion.
        param_free(pblock_remove("remote-user",rq->headers));
        param_free(pblock_remove("auth-user",rq->vars));
        param_free(pblock_remove("Shib-Attributes",rq->headers));
        pair<bool,bool> exp=settings.first->getBool("exportAssertion");
        if (!exp.first || !exp.second) {
            const char* param=pblock_findval("export-assertion",pb);
            if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
                exp.second=true;
        }
        if (exp.second && assertions.size()) {
            string assertion;
            RM::serialize(*(assertions[0]), assertion);
            string::size_type lfeed;
            while ((lfeed=assertion.find('\n'))!=string::npos)
                assertion.erase(lfeed,1);
            pblock_nvinsert("Shib-Attributes",assertion.c_str(),rq->headers);
        }
        
        pblock_nvinsert("auth-type","shibboleth",rq->vars);
        param_free(pblock_remove("Shib-Origin-Site",rq->headers));
        param_free(pblock_remove("Shib-Authentication-Method",rq->headers));
        param_free(pblock_remove("Shib-NameIdentifier-Format",rq->headers));

        // Export the SAML AuthnMethod and the origin site name.
        auto_ptr_char os(sso_statement->getSubject()->getNameIdentifier()->getNameQualifier());
        auto_ptr_char am(sso_statement->getAuthMethod());
        pblock_nvinsert("Shib-Origin-Site",os.get(),rq->headers);
        pblock_nvinsert("Shib-Authentication-Method",am.get(),rq->headers);

        // Export NameID?
        AAP wrapper(provs,sso_statement->getSubject()->getNameIdentifier()->getFormat(),Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        if (!wrapper.fail() && wrapper->getHeader()) {
            auto_ptr_char form(sso_statement->getSubject()->getNameIdentifier()->getFormat());
            auto_ptr_char nameid(sso_statement->getSubject()->getNameIdentifier()->getName());
            pblock_nvinsert("Shib-NameIdentifier-Format",form.get(),pb);
            if (!strcmp(wrapper->getHeader(),"REMOTE_USER")) {
                pblock_nvinsert("remote-user",nameid.get(),rq->headers);
                pblock_nvinsert("auth-user",nameid.get(),rq->vars);
            }
            else {
                pblock_nvinsert(wrapper->getHeader(),nameid.get(),rq->headers);
            }
        }

        param_free(pblock_remove("Shib-Application-ID",rq->headers));
        pblock_nvinsert("Shib-Application-ID",application_id.second,rq->headers);

        // Export the attributes.
        Iterator<SAMLAssertion*> a_iter(assertions);
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
                    if (!strcmp(wrapper->getHeader(),"REMOTE_USER") && vals.hasNext()) {
                        char* principal=const_cast<char*>(vals.next().c_str());
                        pblock_nvinsert("remote-user",principal,rq->headers);
                        pblock_nvinsert("auth-user",principal,rq->vars);
                    }
                    else {
                        int it=0;
                        string header;
                        const char* h=pblock_findval(wrapper->getHeader(),rq->headers);
                        if (h) {
                            header=h;
                            param_free(pblock_remove(wrapper->getHeader(),rq->headers));
                            it++;
                        }
                        for (; vals.hasNext(); it++) {
                            string value = vals.next();
                            for (string::size_type pos = value.find_first_of(";", string::size_type(0));
                                    pos != string::npos;
                                    pos = value.find_first_of(";", pos)) {
                                value.insert(pos, "\\");
                                pos += 2;
                            }
                            if (it == 0)
                                header=value;
                            else
                                header=header + ';' + value;
                        }
                        pblock_nvinsert(wrapper->getHeader(),header.c_str(),rq->headers);
        	        }
                }
            }
        }
    
        // clean up memory
        for (int k = 0; k < assertions.size(); k++)
          delete assertions[k];
        delete sso_statement;

        return REQ_PROCEED;
    }
    catch(bad_alloc) {
        return WriteClientError(sn, rq, FUNC,"Out of Memory");
    }
#ifndef _DEBUG
    catch(...) {
        return WriteClientError(sn, rq, FUNC,"Server caught an unknown exception.");
    }
#endif

    return WriteClientError(sn, rq, FUNC,"Server reached unreachable code, save my walrus!");
}

#undef FUNC
#define FUNC "shib_handler"
extern "C" NSAPI_PUBLIC int shib_handler(pblock* pb, Session* sn, Request* rq)
{
    string targeturl;
    const IApplication* application=NULL;
    try
    {
        ostringstream threadid;
        threadid << "[" << getpid() << "] shib_handler" << '\0';
        saml::NDC ndc(threadid.str().c_str());

        // We lock the configuration system for the duration.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        
        // Map request to application and content settings.
        IRequestMapper* mapper=conf->getRequestMapper();
        Locker locker2(mapper);
        IRequestMapper::Settings settings=map_request(pb,sn,rq,mapper,targeturl);
        pair<bool,const char*> application_id=settings.first->getString("applicationId");
        application=conf->getApplication(application_id.second);
        const IPropertySet* sessionProps=application ? application->getPropertySet("Sessions") : NULL;
        if (!application || !sessionProps)
            return WriteClientError(sn,rq,FUNC,"Unable to map request to application settings, check configuration.");

        SHIRE shire(application);
        
        const char* shireURL=shire.getShireURL(targeturl.c_str());
        if (!shireURL)
            return WriteClientError(sn,rq,FUNC,"Unable to map request to proper shireURL setting, check configuration.");

        // Make sure we only process the SHIRE requests.
        if (!strstr(targeturl.c_str(),shireURL))
            return WriteClientError(sn,rq,FUNC,"NSAPI service function can only be invoked to process incoming sessions."
                "Make sure the mapped file extension or URL doesn't match actual content.");

        pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();

        // Make sure this is SSL, if it should be
        pair<bool,bool> shireSSL=sessionProps->getBool("shireSSL");
        if (!shireSSL.first || shireSSL.second) {
            if (!security_active)
                throw ShibTargetException(SHIBRPC_OK,"blocked non-SSL access to Shibboleth session processor");
        }
        
        pair<bool,bool> httpRedirects=sessionProps->getBool("httpRedirects");
        pair<bool,const char*> redirectPage=sessionProps->getString("redirectPage");
        if (httpRedirects.first && !httpRedirects.second && !redirectPage.first)
            return WriteClientError(sn,rq,FUNC,"HTML-based redirection requires a redirectPage property.");
                
        // If this is a GET, we manufacture an AuthnRequest.
        if (!strcasecmp(pblock_findval("method",rq->reqpb),"GET")) {
            const char* areq=pblock_findval("query",rq->reqpb) ? shire.getLazyAuthnRequest(pblock_findval("query",rq->reqpb)) : NULL;
            if (!areq)
                throw ShibTargetException(SHIBRPC_OK, "malformed arguments to request a new session");
            if (!httpRedirects.first || httpRedirects.second) {
                pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
                pblock_nvinsert("Content-Length","40",rq->srvhdrs);
                pblock_nvinsert("Expires","01-Jan-1997 12:00:00 GMT",rq->srvhdrs);
                pblock_nvinsert("Cache-Control","private,no-store,no-cache",rq->srvhdrs);
                pblock_nvinsert("Location",areq,rq->srvhdrs);
                protocol_status(sn,rq,PROTOCOL_REDIRECT,"302 Please wait");
                protocol_start_response(sn,rq);
                NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
                return REQ_EXIT;
            }
            else {
                ShibMLP markupProcessor;
                markupProcessor.insert("requestURL",areq);
                return WriteRedirectPage(sn, rq, application, redirectPage.second, markupProcessor);
            }
        }
        else if (strcasecmp(pblock_findval("method",rq->reqpb),"POST"))
            throw ShibTargetException(SHIBRPC_OK,"blocked non-POST to Shibboleth session processor");

        // Make sure this POST is an appropriate content type
        char* content_type=NULL;
        if (request_header("content-type",&content_type,sn,rq)!=REQ_PROCEED ||
                !content_type || strcasecmp(content_type,"application/x-www-form-urlencoded"))
            throw ShibTargetException(SHIBRPC_OK,"blocked bad content-type to Shibboleth session processor");
    
        // Read the data.
        pair<const char*,const char*> elements=pair<const char*,const char*>(NULL,NULL);
        char* content_length=NULL;
        if (request_header("content-length",&content_length,sn,rq)!=REQ_PROCEED ||
                atoi(content_length) > 1024*1024) // 1MB?
            throw ShibTargetException(SHIBRPC_OK,"blocked too-large a post to Shibboleth session processor");
        else {
            char ch=IO_EOF+1;
            int cl=atoi(content_length);
            string cgistr;
            while (cl && ch!=IO_EOF) {
                ch=netbuf_getc(sn->inbuf);
        
                // Check for error.
                if(ch==IO_ERROR)
                    break;
                cgistr+=ch;
                cl--;
            }
            if (cl)
                throw ShibTargetException(SHIBRPC_OK,"error reading POST data from browser");
            elements=shire.getFormSubmission(cgistr.c_str(),cgistr.length());
        }
    
        // Make sure the SAML Response parameter exists
        if (!elements.first || !*elements.first)
            throw ShibTargetException(SHIBRPC_OK, "Shibboleth POST failed to find SAMLResponse form element");
    
        // Make sure the target parameter exists
        if (!elements.second || !*elements.second)
            throw ShibTargetException(SHIBRPC_OK, "Shibboleth POST failed to find TARGET form element");
            
        // Process the post.
        string cookie;
        RPCError* status=NULL;
        ShibMLP markupProcessor;
        markupProcessor.insert("requestURL", targeturl.c_str());
        try {
            status = shire.sessionCreate(elements.first,pblock_findval("ip",sn->client),cookie);
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "shire", markupProcessor);
        }
#ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn, rq, application, "shire", markupProcessor);
        }
#endif

        if (status->isError()) {
            if (status->isRetryable()) {
                delete status;
                const char* loc=shire.getAuthnRequest(elements.second);
                if (!httpRedirects.first || httpRedirects.second) {
                    pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
                    pblock_nvinsert("Content-Length","40",rq->srvhdrs);
                    pblock_nvinsert("Expires","01-Jan-1997 12:00:00 GMT",rq->srvhdrs);
                    pblock_nvinsert("Cache-Control","private,no-store,no-cache",rq->srvhdrs);
                    pblock_nvinsert("Location",loc,rq->srvhdrs);
                    protocol_status(sn,rq,PROTOCOL_REDIRECT,"302 Please wait");
                    protocol_start_response(sn,rq);
                    NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
                    return REQ_EXIT;
                }
                else {
                    markupProcessor.insert("requestURL",loc);
                    return WriteRedirectPage(sn, rq, application, redirectPage.second, markupProcessor);
                }
            }
    
            // Return this error to the user.
            markupProcessor.insert(*status);
            delete status;
            return WriteClientError(sn,rq,application,"shire",markupProcessor);
        }
        delete status;
    
        // We've got a good session, set the cookie and redirect to target.
        cookie = string(shib_cookie.first) + '=' + cookie + shib_cookie.second;
        pblock_nvinsert("Set-Cookie",cookie.c_str(),rq->srvhdrs);
        if (!httpRedirects.first || httpRedirects.second) {
            pblock_nvinsert("Content-Type","text/html",rq->srvhdrs);
            pblock_nvinsert("Content-Length","40",rq->srvhdrs);
            pblock_nvinsert("Expires","01-Jan-1997 12:00:00 GMT",rq->srvhdrs);
            pblock_nvinsert("Cache-Control","private,no-store,no-cache",rq->srvhdrs);
            pblock_nvinsert("Location",elements.second,rq->srvhdrs);
            protocol_status(sn,rq,PROTOCOL_REDIRECT,"302 Please wait");
            protocol_start_response(sn,rq);
            NET_WRITE("<HTML><BODY>Redirecting...</BODY></HTML>");
            return REQ_EXIT;
        }
        else {
            markupProcessor.insert("requestURL",elements.second);
            return WriteRedirectPage(sn, rq, application, redirectPage.second, markupProcessor);
        }
    }
    catch (ShibTargetException &e) {
        if (application) {
            ShibMLP markupProcessor;
            markupProcessor.insert("requestURL", targeturl.c_str());
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn,rq,application,"shire",markupProcessor);
        }
    }
#ifndef _DEBUG
    catch (...) {
        if (application) {
            ShibMLP markupProcessor;
            markupProcessor.insert("requestURL", targeturl.c_str());
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(sn,rq,application,"shire",markupProcessor);
        }
    }
#endif    
    return REQ_EXIT;
}

#endif
