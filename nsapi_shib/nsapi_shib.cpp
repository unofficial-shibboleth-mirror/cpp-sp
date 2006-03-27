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

/* nsapi_shib.cpp - Shibboleth NSAPI filter

   Scott Cantor
   12/13/04
*/

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif


// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>

#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>

#ifdef WIN32
# include <process.h>
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
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

// macros to output text to client
#define NET_WRITE(str) \
    if (IO_ERROR==net_write(sn->csd,str,strlen(str))) return REQ_EXIT

namespace {
    ShibTargetConfig* g_Config=NULL;
    string g_ServerName;
    string g_ServerScheme;
}

PlugManager::Factory SunRequestMapFactory;

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

#ifndef _DEBUG
    try {
#endif
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
            ShibTargetConfig::Caching |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::InProcess |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(schemadir)) {
            g_Config=NULL;
            pblock_nvinsert("error","unable to initialize Shibboleth libraries",pb);
            return REQ_ABORTED;
        }

        SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::NativeRequestMapType,&SunRequestMapFactory);
        // We hijack the legacy type so that 1.2 config files will load this plugin
        SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::LegacyRequestMapType,&SunRequestMapFactory);

        if (!g_Config->load(config)) {
            g_Config=NULL;
            pblock_nvinsert("error","unable to initialize load Shibboleth configuration",pb);
            return REQ_ABORTED;
        }

        daemon_atrestart(nsapi_shib_exit,NULL);
#ifndef _DEBUG
    }
    catch (...) {
        g_Config=NULL;
        pblock_nvinsert("error","caught exception, unable to initialize Shibboleth libraries",pb);
        return REQ_ABORTED;
    }
#endif
    return REQ_PROCEED;
}

/********************************************************************************/
// NSAPI Shib Target Subclass

class ShibTargetNSAPI : public ShibTarget
{
    mutable string m_body;
    mutable bool m_gotBody;
public:
  ShibTargetNSAPI(pblock* pb, Session* sn, Request* rq) : m_gotBody(false) {
    m_pb = pb;
    m_sn = sn;
    m_rq = rq;

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

    char* content_type = "";
    request_header("content-type", &content_type, sn, rq);
      
    const char *remote_ip = pblock_findval("ip", sn->client);
    const char *method = pblock_findval("method", rq->reqpb);

    init(scheme, host, port, url.c_str(), content_type, remote_ip, method);
  }
  ~ShibTargetNSAPI() {}

  virtual void log(ShibLogLevel level, const string &msg) {
    ShibTarget::log(level,msg);
    if (level==LogLevelError)
        log_error(LOG_FAILURE, "nsapi_shib", m_sn, m_rq, const_cast<char*>(msg.c_str()));
  }
  virtual string getCookies(void) const {
    char *cookies = NULL;
    if (request_header("cookie", &cookies, m_sn, m_rq) == REQ_ABORTED)
      throw("error accessing cookie header");
    return string(cookies ? cookies : "");
  }
  virtual void setCookie(const string &name, const string &value) {
    string cookie = name + '=' + value;
    pblock_nvinsert("Set-Cookie", cookie.c_str(), m_rq->srvhdrs);
  }
  virtual const char* getQueryString() const { 
    return pblock_findval("query", m_rq->reqpb);
  }
  virtual const char* getRequestBody() const {
    if (m_gotBody)
        return m_body.c_str();
    char* content_length=NULL;
    if (request_header("content-length", &content_length, m_sn, m_rq)!=REQ_PROCEED ||
         atoi(content_length) > 1024*1024) // 1MB?
      throw SAMLException("Blocked POST request body exceeding size limit.");
    else {
      char ch=IO_EOF+1;
      int cl=atoi(content_length);
      m_gotBody=true;
      while (cl && ch != IO_EOF) {
        ch=netbuf_getc(m_sn->inbuf);
        // Check for error.
        if(ch==IO_ERROR)
          break;
        m_body += ch;
        cl--;
      }
      if (cl)
        throw SAMLException("Error reading POST request body from browser.");
      return m_body.c_str();
    }
  }
  virtual void clearHeader(const string &name) {
    if (name=="REMOTE_USER") {
        param_free(pblock_remove("auth-user",m_rq->vars));
        param_free(pblock_remove("remote-user",m_rq->headers));
    }
    else
        param_free(pblock_remove(name.c_str(), m_rq->headers));
  }
  virtual void setHeader(const string &name, const string &value) {
    pblock_nvinsert(name.c_str(), value.c_str() ,m_rq->headers);
  }
  virtual string getHeader(const string &name) {
    char *hdr = NULL;
    if (request_header(const_cast<char*>(name.c_str()), &hdr, m_sn, m_rq) != REQ_PROCEED)
      hdr = NULL;
    return string(hdr ? hdr : "");
  }
  virtual void setRemoteUser(const string &user) {
    pblock_nvinsert("remote-user", user.c_str(), m_rq->headers);
    pblock_nvinsert("auth-user", user.c_str(), m_rq->vars);
  }
  virtual string getRemoteUser(void) {
    return getHeader("remote-user");
  }

  virtual void* sendPage(
    const string& msg,
    int code=200,
    const string& content_type="text/html",
    const saml::Iterator<header_t>& headers=EMPTY(header_t)
    ) {
    param_free(pblock_remove("content-type", m_rq->srvhdrs));
    pblock_nvinsert("content-type", content_type.c_str(), m_rq->srvhdrs);
    pblock_nninsert("content-length", msg.length(), m_rq->srvhdrs);
    pblock_nvinsert("connection","close",m_rq->srvhdrs);
    while (headers.hasNext()) {
        const header_t& h=headers.next();
        pblock_nvinsert(h.first.c_str(), h.second.c_str(), m_rq->srvhdrs);
    }
    protocol_status(m_sn, m_rq, code, NULL);
    protocol_start_response(m_sn, m_rq);
    net_write(m_sn->csd,const_cast<char*>(msg.c_str()),msg.length());
    return (void*)REQ_EXIT;
  }
  virtual void* sendRedirect(const string& url) {
    param_free(pblock_remove("content-type", m_rq->srvhdrs));
    pblock_nninsert("content-length", 0, m_rq->srvhdrs);
    pblock_nvinsert("expires", "01-Jan-1997 12:00:00 GMT", m_rq->srvhdrs);
    pblock_nvinsert("cache-control", "private,no-store,no-cache", m_rq->srvhdrs);
    pblock_nvinsert("location", url.c_str(), m_rq->srvhdrs);
    pblock_nvinsert("connection","close",m_rq->srvhdrs);
    protocol_status(m_sn, m_rq, PROTOCOL_REDIRECT, NULL);
    protocol_start_response(m_sn, m_rq);
    return (void*)REQ_ABORTED;
  }
  virtual void* returnDecline(void) { return (void*)REQ_NOACTION; }
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

  try {
    ShibTargetNSAPI stn(pb, sn, rq);

    // Check user authentication
    pair<bool,void*> res = stn.doCheckAuthN();
    if (res.first) return (int)res.second;

    // user authN was okay -- export the assertions now
    param_free(pblock_remove("auth-user",rq->vars));
    // This seems to be required in order to eventually set
    // the auth-user var.
    pblock_nvinsert("auth-type","shibboleth",rq->vars);
    res = stn.doExportAssertions();
    if (res.first) return (int)res.second;

    // Check the Authorization
    res = stn.doCheckAuthZ();
    if (res.first) return (int)res.second;

    // this user is ok.
    return REQ_PROCEED;
  }
  catch (SAMLException& e) {
    log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
    return WriteClientError(sn, rq, FUNC, "Shibboleth filter threw an exception, see web server log for error.");
  }
#ifndef _DEBUG
  catch (...) {
    return WriteClientError(sn, rq, FUNC, "Shibboleth filter threw an uncaught exception.");
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

  try {
    ShibTargetNSAPI stn(pb, sn, rq);

    pair<bool,void*> res = stn.doHandler();
    if (res.first) return (int)res.second;

    return WriteClientError(sn, rq, FUNC, "Shibboleth handler did not do anything.");
  }
  catch (SAMLException& e) {
    log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
    return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an exception, see web server log for error.");
  }
#ifndef _DEBUG
  catch (...) {
    return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an unknown exception.");
  }
#endif
}


class SunRequestMapper : public virtual IRequestMapper, public virtual IPropertySet
{
public:
    SunRequestMapper(const DOMElement* e);
    ~SunRequestMapper() { delete m_mapper; delete m_stKey; delete m_propsKey; }
    void lock() { m_mapper->lock(); }
    void unlock() { m_stKey->setData(NULL); m_propsKey->setData(NULL); m_mapper->unlock(); }
    Settings getSettings(ShibTarget* st) const;
    
    pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
    pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
    pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
    pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
    pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
    const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;
    const DOMElement* getElement() const;

private:
    IRequestMapper* m_mapper;
    ThreadKey* m_stKey;
    ThreadKey* m_propsKey;
};

IPlugIn* SunRequestMapFactory(const DOMElement* e)
{
    return new SunRequestMapper(e);
}

SunRequestMapper::SunRequestMapper(const DOMElement* e) : m_mapper(NULL), m_stKey(NULL), m_propsKey(NULL)
{
    IPlugIn* p=SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::XMLRequestMapType,e);
    m_mapper=dynamic_cast<IRequestMapper*>(p);
    if (!m_mapper) {
        delete p;
        throw UnsupportedExtensionException("Embedded request mapper plugin was not of correct type.");
    }
    m_stKey=ThreadKey::create(NULL);
    m_propsKey=ThreadKey::create(NULL);
}

IRequestMapper::Settings SunRequestMapper::getSettings(ShibTarget* st) const
{
    Settings s=m_mapper->getSettings(st);
    m_stKey->setData(dynamic_cast<ShibTargetNSAPI*>(st));
    m_propsKey->setData((void*)s.first);
    return pair<const IPropertySet*,IAccessControl*>(this,s.second);
}

pair<bool,bool> SunRequestMapper::getBool(const char* name, const char* ns) const
{
    ShibTargetNSAPI* stn=reinterpret_cast<ShibTargetNSAPI*>(m_stKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override boolean properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param && (!strcmp(param,"1") || !strcasecmp(param,"true")))
            return make_pair(true,true);
    }
    return s ? s->getBool(name,ns) : make_pair(false,false);
}

pair<bool,const char*> SunRequestMapper::getString(const char* name, const char* ns) const
{
    ShibTargetNSAPI* stn=reinterpret_cast<ShibTargetNSAPI*>(m_stKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override string properties.
        if (!strcmp(name,"authType"))
            return pair<bool,const char*>(true,"shibboleth");
        else {
            const char* param=pblock_findval(name,stn->m_pb);
            if (param)
                return make_pair(true,param);
        }
    }
    return s ? s->getString(name,ns) : pair<bool,const char*>(false,NULL);
}

pair<bool,const XMLCh*> SunRequestMapper::getXMLString(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getXMLString(name,ns) : pair<bool,const XMLCh*>(false,NULL);
}

pair<bool,unsigned int> SunRequestMapper::getUnsignedInt(const char* name, const char* ns) const
{
    ShibTargetNSAPI* stn=reinterpret_cast<ShibTargetNSAPI*>(m_stKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override int properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param)
            return pair<bool,unsigned int>(true,strtol(param,NULL,10));
    }
    return s ? s->getUnsignedInt(name,ns) : pair<bool,unsigned int>(false,0);
}

pair<bool,int> SunRequestMapper::getInt(const char* name, const char* ns) const
{
    ShibTargetNSAPI* stn=reinterpret_cast<ShibTargetNSAPI*>(m_stKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (stn && !ns && name) {
        // Override int properties.
        const char* param=pblock_findval(name,stn->m_pb);
        if (param)
            return pair<bool,int>(true,atoi(param));
    }
    return s ? s->getInt(name,ns) : pair<bool,int>(false,0);
}

const IPropertySet* SunRequestMapper::getPropertySet(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getPropertySet(name,ns) : NULL;
}

const DOMElement* SunRequestMapper::getElement() const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getElement() : NULL;
}
