/*
 *  Copyright 2001-2009 Internet2
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
    string g_unsetHeaderValue;
    set<string> g_allowedSchemes;
    bool g_checkSpoofing = false;
    bool g_catchAll = true;
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

    log_error(LOG_INFORM,"nsapi_shib_init",sn,rq,"nsapi_shib loaded for host (%s)",g_ServerName.c_str());

    try {
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
            ShibTargetConfig::LocalExtensions |
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

        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        const IPropertySet* props=conf->getPropertySet("Local");
        if (props) {
            pair<bool,const char*> str=props->getString("unsetHeaderValue");
            if (str.first)
                g_unsetHeaderValue = str.second;

            str=props->getString("allowedSchemes");
            if (str.first) {
                string schemes=str.second;
                unsigned int j=0;
                for (unsigned int i=0;  i < schemes.length();  i++) {
                    if (schemes.at(i)==' ') {
                        g_allowedSchemes.insert(schemes.substr(j, i-j));
                        j = i+1;
                    }
                }
                g_allowedSchemes.insert(schemes.substr(j, schemes.length()-j));
            }

            pair<bool,bool> flag=props->getBool("checkSpoofing");
            g_checkSpoofing = !flag.first || flag.second;
            flag=props->getBool("catchAll");
            g_catchAll = !flag.first || flag.second;
        }
        if (g_allowedSchemes.empty()) {
            g_allowedSchemes.insert("https");
            g_allowedSchemes.insert("http");
        }
    }
    catch (exception&) {
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
  void checkString(const string& s, const char* msg) {
    string::const_iterator e = s.end();
    for (string::const_iterator i=s.begin(); i!=e; ++i) {
        if (iscntrl(*i))
            throw FatalProfileException(msg);
    }
  }

public:
  ShibTargetNSAPI(pblock* pb, Session* sn, Request* rq) : m_pb(pb), m_sn(sn), m_rq(rq), m_firsttime(true) {

      // To determine whether SSL is active or not, we're supposed to rely
      // on the security_active macro. For iPlanet 4.x, this works.
      // For Sun 7.x, it's useless and appears to be on or off based
      // on whether ANY SSL support is enabled for a vhost. Sun 6.x is unknown.
      // As a fix, there's a conf variable called $security that can be mapped
      // into a function parameter: security_active="$security"
      // We check for this parameter, and rely on the macro if it isn't set.
      // This doubles as a scheme virtualizer for load balanced scenarios
      // since you can set the parameter to 1 or 0 as needed.
      const char* scheme;
      const char* sa = pblock_findval("security_active", pb);
      if (sa)
          scheme = (*sa == '1') ? "https" : "http";
      else if (security_active)
          scheme = "https";
      else
          scheme = "http";

      // A similar issue exists for the port. server_portnum is no longer
      // working on at least Sun 7.x, and returns the first listener's port
      // rather than whatever port is actually used for the request. Nice job, Sun.
      sa = pblock_findval("server_portnum", pb);
      int port = (sa && *sa) ? atoi(sa) : server_portnum;

    // Get everything else but hostname...
    const char* uri=pblock_findval("uri", rq->reqpb);
    const char* qstr=pblock_findval("query", rq->reqpb);
    const char* host=NULL;

    string url;
    if (uri)
        url=uri;
    if (qstr)
        url=url + '?' + qstr;

#ifdef vs_is_default_vs
    // This is 6.0 or later, so we can distinguish requests to name-based vhosts.
    if (!vs_is_default_vs(request_get_vs(m_rq)))
        // The beauty here is, a non-default vhost can *only* be accessed if the client
        // specified the exact name in the Host header. So we can trust the Host header.
        host=pblock_findval("host", rq->headers);
    else
#endif
    // In other cases, we're going to rely on the initialization process...
    host=g_ServerName.c_str();

    char* content_type = "";
    request_header("content-type", &content_type, sn, rq);

    const char* remote_ip = pblock_findval("ip", sn->client);
    const char* method = pblock_findval("method", rq->reqpb);

    init(scheme, host, port, url.c_str(), content_type, remote_ip, method);

    // See if this is the first time we've run.
    method = pblock_findval("auth-type", rq->vars);
    if (method && !strcmp(method, "shibboleth"))
        m_firsttime = false;
    if (!m_firsttime || rq->orig_rq)
        log(LogLevelDebug, "nsapi_shib function running more than once");
  }
  ~ShibTargetNSAPI() {
  }

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
  virtual string getArgs(void) {
    const char *q = pblock_findval("query", m_rq->reqpb);
    return string(q ? q : "");
  }
  virtual string getPostData(void) {
    char* content_length=NULL;
    if (request_header("content-length", &content_length, m_sn, m_rq)!=REQ_PROCEED ||
         atoi(content_length) > 1024*1024) // 1MB?
      throw FatalProfileException("Blocked too-large a submission to profile endpoint.");
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
        throw FatalProfileException("Error reading profile submission from browser.");
      return cgistr;
    }
  }
  virtual void clearHeader(const string &name) {
    if (g_checkSpoofing && m_firsttime && !m_rq->orig_rq && m_allhttp.empty()) {
      // Populate the set of client-supplied headers for spoof checking.
      const pb_entry* entry;
      for (int i=0; i<m_rq->headers->hsize; ++i) {
          entry = m_rq->headers->ht[i];
          while (entry) {
              string cgiversion("HTTP_");
              const char* pch = entry->param->name;
              while (*pch) {
                  cgiversion += (isalnum(*pch) ? toupper(*pch) : '_');
                  pch++;
              }
              m_allhttp.insert(cgiversion);
              entry = entry->next;
          }
      }
    }
    if (name=="REMOTE_USER") {
        if (g_checkSpoofing && m_firsttime && !m_rq->orig_rq && m_allhttp.count("HTTP_REMOTE_USER") > 0)
            throw SAMLException("Attempt to spoof header ($1) was detected.", params(1, name.c_str()));
        param_free(pblock_remove("auth-user",m_rq->vars));
        param_free(pblock_remove("remote-user",m_rq->headers));
        pblock_nvinsert("remote-user", g_unsetHeaderValue.c_str(), m_rq->headers);
    }
    else {
        if (g_checkSpoofing && m_firsttime && !m_rq->orig_rq) {
            // Map to the expected CGI variable name.
            string transformed("HTTP_");
            const char* pch = name.c_str();
            while (*pch) {
                transformed += (isalnum(*pch) ? toupper(*pch) : '_');
                pch++;
            }
            if (m_allhttp.count(transformed) > 0)
                throw SAMLException("Attempt to spoof header ($1) was detected.", params(1, name.c_str()));
        }
        param_free(pblock_remove(name.c_str(), m_rq->headers));
        pblock_nvinsert(name.c_str(), g_unsetHeaderValue.c_str(), m_rq->headers);
    }
  }
  virtual void setHeader(const string &name, const string &value) {
    param_free(pblock_remove(name.c_str(), m_rq->headers));
    pblock_nvinsert(name.c_str(), value.c_str() ,m_rq->headers);
  }
  virtual string getHeader(const string &name) {
    char *hdr = NULL;
    if (request_header(const_cast<char*>(name.c_str()), &hdr, m_sn, m_rq) != REQ_PROCEED) {
      string n;
      const char* pch = name.c_str();
      while (*pch)
          n += tolower(*(pch++));
      if (request_header(const_cast<char*>(n.c_str()), &hdr, m_sn, m_rq) != REQ_PROCEED)
          return "";
    }
    return string(hdr ? hdr : "");
  }
  virtual void setRemoteUser(const string &user) {
    param_free(pblock_remove("remote-user",m_rq->headers));
    pblock_nvinsert("remote-user", user.c_str(), m_rq->headers);
    pblock_nvinsert("auth-user", user.c_str(), m_rq->vars);
  }
  virtual string getRemoteUser(void) {
    const char* ru = pblock_findval("auth-user", m_rq->vars);
    return ru ? ru : "";
  }

  virtual void* sendPage(
    const string& msg,
    int code=200,
    const string& content_type="text/html",
    const saml::Iterator<header_t>& headers=EMPTY(header_t)
    ) {
    checkString(content_type, "Detected control character in a response header.");
    param_free(pblock_remove("content-type", m_rq->srvhdrs));
    pblock_nvinsert("content-type", content_type.c_str(), m_rq->srvhdrs);
    pblock_nninsert("content-length", msg.length(), m_rq->srvhdrs);
    pblock_nvinsert("connection","close",m_rq->srvhdrs);
    while (headers.hasNext()) {
        const header_t& h=headers.next();
        checkString(h.first, "Detected control character in a response header.");
        checkString(h.second, "Detected control character in a response header.");
        pblock_nvinsert(h.first.c_str(), h.second.c_str(), m_rq->srvhdrs);
    }
    protocol_status(m_sn, m_rq, code, NULL);
    protocol_start_response(m_sn, m_rq);
    net_write(m_sn->csd,const_cast<char*>(msg.c_str()),msg.length());
    return (void*)REQ_EXIT;
  }
  virtual void* sendRedirect(const string& url) {
    checkString(url, "Detected control character in an attempted redirect.");
    if (g_allowedSchemes.find(url.substr(0, url.find(':'))) == g_allowedSchemes.end())
        throw FatalProfileException("Invalid scheme in attempted redirect.");
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
  set<string> m_allhttp;
  bool m_firsttime;
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
    catch (exception& e) {
        log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
        return WriteClientError(sn, rq, FUNC, "Shibboleth filter threw an exception, see web server log for error.");
    }
    catch (...) {
        if (g_catchAll)
            return WriteClientError(sn, rq, FUNC, "Shibboleth filter threw an uncaught exception.");
        throw;
    }
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
    catch (exception& e) {
        log_error(LOG_FAILURE,FUNC,sn,rq,const_cast<char*>(e.what()));
        return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an exception, see web server log for error.");
    }
    catch (...) {
        if (g_catchAll)
            return WriteClientError(sn, rq, FUNC, "Shibboleth handler threw an unknown exception.");
        throw;
    }
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
