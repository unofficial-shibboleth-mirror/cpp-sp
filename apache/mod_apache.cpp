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
 * mod_apache.cpp -- the core Apache Module code
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef SOLARIS2
#undef _XOPEN_SOURCE    // causes gethostname conflict in unistd.h
#endif

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>
#include <xercesc/util/regx/RegularExpression.hpp>

#undef _XPG4_2

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>

#ifndef SHIB_APACHE_13
#include <http_request.h>
#include <apr_strings.h>
#include <apr_pools.h>
#endif

#include <fstream>
#include <sstream>

#ifdef HAVE_UNISTD_H
#include <unistd.h>		// for getpid()
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern "C" module MODULE_VAR_EXPORT mod_shib;

namespace {
    char* g_szSHIBConfig = NULL;
    char* g_szSchemaDir = NULL;
    ShibTargetConfig* g_Config = NULL;
    static const char* g_UserDataKey = "_shib_check_user_";
}

/********************************************************************************/
// Basic Apache Configuration code.
//

// per-server module configuration structure
struct shib_server_config
{
    char* szScheme;
};

// creates the per-server configuration
extern "C" void* create_shib_server_config(SH_AP_POOL* p, server_rec* s)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    sc->szScheme = NULL;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shib_server_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    shib_server_config* parent=(shib_server_config*)base;
    shib_server_config* child=(shib_server_config*)sub;

    if (child->szScheme)
        sc->szScheme=ap_pstrdup(p,child->szScheme);
    else if (parent->szScheme)
        sc->szScheme=ap_pstrdup(p,parent->szScheme);
    else
        sc->szScheme=NULL;

    return sc;
}

// per-dir module configuration structure
struct shib_dir_config
{
    // RM Configuration
    char* szAuthGrpFile;    // Auth GroupFile name
    int bRequireAll;        // all require directives must match, otherwise OR logic

    // Content Configuration
    char* szApplicationId;  // Shib applicationId value
    char* szRequireWith;    // require a session using a specific initiator?
    int bOff;               // flat-out disable all Shib processing
    int bBasicHijack;       // activate for AuthType Basic?
    int bRequireSession;    // require a session?
    int bExportAssertion;   // export SAML assertion to the environment?
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (SH_AP_POOL* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    dc->bOff = -1;
    dc->bBasicHijack = -1;
    dc->bRequireSession = -1;
    dc->bExportAssertion = -1;
    dc->bRequireAll = -1;
    dc->szAuthGrpFile = NULL;
    dc->szApplicationId = NULL;
    dc->szRequireWith = NULL;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shib_dir_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    shib_dir_config* parent=(shib_dir_config*)base;
    shib_dir_config* child=(shib_dir_config*)sub;

    if (child->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,child->szAuthGrpFile);
    else if (parent->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,parent->szAuthGrpFile);
    else
        dc->szAuthGrpFile=NULL;

    if (child->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,child->szApplicationId);
    else if (parent->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,parent->szApplicationId);
    else
        dc->szApplicationId=NULL;

    if (child->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,child->szRequireWith);
    else if (parent->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,parent->szRequireWith);
    else
        dc->szRequireWith=NULL;

    dc->bOff=((child->bOff==-1) ? parent->bOff : child->bOff);
    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bRequireSession=((child->bRequireSession==-1) ? parent->bRequireSession : child->bRequireSession);
    dc->bExportAssertion=((child->bExportAssertion==-1) ? parent->bExportAssertion : child->bExportAssertion);
    dc->bRequireAll=((child->bRequireAll==-1) ? parent->bRequireAll : child->bRequireAll);
    return dc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* shib_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&mod_shib);
    size_t offset=(size_t)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* shib_ap_set_file_slot(cmd_parms* parms,
#ifdef SHIB_APACHE_13
					     char* arg1, char* arg2
#else
					     void* arg1, const char* arg2
#endif
					     )
{
  ap_set_file_slot(parms, arg1, arg2);
  return DECLINE_CMD;
}

/********************************************************************************/
// Apache ShibTarget subclass(es) here.

class ShibTargetApache : public ShibTarget
{
public:
  ShibTargetApache(request_rec* req) {
    m_sc = (shib_server_config*)ap_get_module_config(req->server->module_config, &mod_shib);
    m_dc = (shib_dir_config*)ap_get_module_config(req->per_dir_config, &mod_shib);

    init(
        m_sc->szScheme ? m_sc->szScheme : ap_http_method(req),
	    ap_get_server_name(req),
        (int)ap_get_server_port(req),
	    req->unparsed_uri,
        ap_table_get(req->headers_in, "Content-type"),
	    req->connection->remote_ip,
        req->method
        );

    m_req = req;
  }
  ~ShibTargetApache() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    ShibTarget::log(level,msg);
#ifdef SHIB_APACHE_13
    ap_log_rerror(APLOG_MARK,
        (level == LogLevelDebug ? APLOG_DEBUG :
            (level == LogLevelInfo ? APLOG_INFO :
            (level == LogLevelWarn ? APLOG_WARNING : APLOG_ERR)))|APLOG_NOERRNO, SH_AP_R(m_req), msg.c_str());
#else
    if (level == LogLevelError)
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(m_req), msg.c_str());
#endif
  }
  virtual string getCookies(void) const {
    const char *c = ap_table_get(m_req->headers_in, "Cookie");
    return string(c ? c : "");
  }
  virtual void setCookie(const string &name, const string &value) {
    char* val = ap_psprintf(m_req->pool, "%s=%s", name.c_str(), value.c_str());
    ap_table_addn(m_req->err_headers_out, "Set-Cookie", val);
  }
  virtual string getArgs(void) { return string(m_req->args ? m_req->args : ""); }
  virtual string getPostData(void) {
    // Read the posted data
    if (ap_setup_client_block(m_req, REQUEST_CHUNKED_ERROR))
        throw FatalProfileException("Apache function (setup_client_block) failed while reading profile submission.");
    if (!ap_should_client_block(m_req))
        throw FatalProfileException("Apache function (should_client_block) failed while reading profile submission.");
    if (m_req->remaining > 1024*1024)
        throw FatalProfileException("Blocked too-large a submission to profile endpoint.");
    string cgistr;
    char buff[HUGE_STRING_LEN];
    ap_hard_timeout("[mod_shib] getPostData", m_req);
    memset(buff, 0, sizeof(buff));
    while (ap_get_client_block(m_req, buff, sizeof(buff)-1) > 0) {
      ap_reset_timeout(m_req);
      cgistr += buff;
      memset(buff, 0, sizeof(buff));
    }
    ap_kill_timeout(m_req);

    return cgistr;
  }
  virtual void clearHeader(const string &name) {
    ap_table_unset(m_req->headers_in, name.c_str());
  }
  virtual void setHeader(const string &name, const string &value) {
    ap_table_set(m_req->headers_in, name.c_str(), value.c_str());
  }
  virtual string getHeader(const string &name) {
    const char *hdr = ap_table_get(m_req->headers_in, name.c_str());
    return string(hdr ? hdr : "");
  }
  virtual void setRemoteUser(const string &user) {
    SH_AP_USER(m_req) = ap_pstrdup(m_req->pool, user.c_str());
  }
  virtual string getRemoteUser(void) {
    return string(SH_AP_USER(m_req) ? SH_AP_USER(m_req) : "");
  }
  virtual void* sendPage(
    const string& msg,
    int code=200,
    const string& content_type="text/html",
	const Iterator<header_t>& headers=EMPTY(header_t)
    ) {
    m_req->content_type = ap_psprintf(m_req->pool, content_type.c_str());
    while (headers.hasNext()) {
        const header_t& h=headers.next();
        ap_table_set(m_req->headers_out, h.first.c_str(), h.second.c_str());
    }
    ap_send_http_header(m_req);
    ap_rprintf(m_req, msg.c_str());
    return (void*)((code==200) ? DONE : code);
  }
  virtual void* sendRedirect(const string& url) {
    ap_table_set(m_req->headers_out, "Location", url.c_str());
    return (void*)REDIRECT;
  }
  virtual void* returnDecline(void) { return (void*)DECLINED; }
  virtual void* returnOK(void) { return (void*)OK; }

  request_rec* m_req;
  shib_dir_config* m_dc;
  shib_server_config* m_sc;
};

/********************************************************************************/
// Apache handlers

extern "C" int shib_check_user(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;
    
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_check_user(%d): ENTER\n", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_check_user" << '\0';
  saml::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetApache sta(r);

    // Check user authentication and export information, then set the handler bypass
    pair<bool,void*> res = sta.doCheckAuthN(true);
    apr_pool_userdata_setn((const void*)42,g_UserDataKey,NULL,r->pool);
    if (res.first) return (int)res.second;

    // user auth was okay -- export the assertions now
    res = sta.doExportAssertions();
    if (res.first) return (int)res.second;

    // export happened successfully..  this user is ok.
    return OK;
  }
  catch (SAMLException& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
#ifndef _DEBUG
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

extern "C" int shib_handler(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_handler" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef SHIB_APACHE_13
  // With 2.x, this handler always runs, though last.
  // We check if shib_check_user ran, because it will detect a handler request
  // and dispatch it directly.
  void* data;
  apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
  if (data==(const void*)42) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler skipped since check_user ran");
    return DECLINED;
  }
#endif

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler(%d): ENTER: %s", (int)getpid(), r->handler);

  try {
    ShibTargetApache sta(r);

    pair<bool,void*> res = sta.doHandler();
    if (res.first) return (int)res.second;

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "doHandler() did not do anything.");
    return SERVER_ERROR;
  }
  catch (SAMLException& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
#ifndef _DEBUG
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

/*
 * shib_auth_checker() -- a simple resource manager to
 * process the .htaccess settings
 */
extern "C" int shib_auth_checker(request_rec* r)
{
  // Short-circuit entirely?
  if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff==1)
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_auth_checker(%d): ENTER", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_auth_checker" << '\0';
  saml::NDC ndc(threadid.str().c_str());

  try {
    ShibTargetApache sta(r);

    pair<bool,void*> res = sta.doCheckAuthZ();
    if (res.first) return (int)res.second;

    // We're all okay.
    return OK;
  }
  catch (SAMLException& e) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an exception: %s", e.what());
    return SERVER_ERROR;
  }
#ifndef _DEBUG
  catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

// Access control plugin that enforces htaccess rules
class htAccessControl : virtual public IAccessControl
{
public:
    htAccessControl() {}
    ~htAccessControl() {}
    void lock() {}
    void unlock() {}
    bool authorized(
        ShibTarget* st,
        ISessionCacheEntry* entry
    ) const;
};

IPlugIn* htAccessFactory(const DOMElement* e)
{
    return new htAccessControl();
}

class ApacheRequestMapper : public virtual IRequestMapper, public virtual IPropertySet
{
public:
    ApacheRequestMapper(const DOMElement* e);
    ~ApacheRequestMapper() { delete m_mapper; delete m_htaccess; delete m_staKey; delete m_propsKey; }
    void lock() { m_mapper->lock(); }
    void unlock() { m_staKey->setData(NULL); m_propsKey->setData(NULL); m_mapper->unlock(); }
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
    ThreadKey* m_staKey;
    ThreadKey* m_propsKey;
    IAccessControl* m_htaccess;
};

IPlugIn* ApacheRequestMapFactory(const DOMElement* e)
{
    return new ApacheRequestMapper(e);
}

ApacheRequestMapper::ApacheRequestMapper(const DOMElement* e) : m_mapper(NULL), m_htaccess(NULL), m_staKey(NULL), m_propsKey(NULL)
{
    IPlugIn* p=SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::XMLRequestMapType,e);
    m_mapper=dynamic_cast<IRequestMapper*>(p);
    if (!m_mapper) {
        delete p;
        throw UnsupportedExtensionException("Embedded request mapper plugin was not of correct type.");
    }
    m_htaccess=new htAccessControl();
    m_staKey=ThreadKey::create(NULL);
    m_propsKey=ThreadKey::create(NULL);
}

IRequestMapper::Settings ApacheRequestMapper::getSettings(ShibTarget* st) const
{
    Settings s=m_mapper->getSettings(st);
    m_staKey->setData(dynamic_cast<ShibTargetApache*>(st));
    m_propsKey->setData((void*)s.first);
    return pair<const IPropertySet*,IAccessControl*>(this,s.second ? s.second : m_htaccess);
}

pair<bool,bool> ApacheRequestMapper::getBool(const char* name, const char* ns) const
{
    ShibTargetApache* sta=reinterpret_cast<ShibTargetApache*>(m_staKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable boolean properties.
        if (name && !strcmp(name,"requireSession") && sta->m_dc->bRequireSession==1)
            return make_pair(true,true);
        else if (name && !strcmp(name,"exportAssertion") && sta->m_dc->bExportAssertion==1)
            return make_pair(true,true);
    }
    return s ? s->getBool(name,ns) : make_pair(false,false);
}

pair<bool,const char*> ApacheRequestMapper::getString(const char* name, const char* ns) const
{
    ShibTargetApache* sta=reinterpret_cast<ShibTargetApache*>(m_staKey->getData());
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable string properties.
        if (name && !strcmp(name,"authType")) {
            const char *auth_type=ap_auth_type(sta->m_req);
            if (auth_type) {
                // Check for Basic Hijack
                if (!strcasecmp(auth_type, "basic") && sta->m_dc->bBasicHijack == 1)
                    auth_type = "shibboleth";
                return make_pair(true,auth_type);
            }
        }
        else if (name && !strcmp(name,"applicationId") && sta->m_dc->szApplicationId)
            return pair<bool,const char*>(true,sta->m_dc->szApplicationId);
        else if (name && !strcmp(name,"requireSessionWith") && sta->m_dc->szRequireWith)
            return pair<bool,const char*>(true,sta->m_dc->szRequireWith);
    }
    return s ? s->getString(name,ns) : pair<bool,const char*>(false,NULL);
}

pair<bool,const XMLCh*> ApacheRequestMapper::getXMLString(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getXMLString(name,ns) : pair<bool,const XMLCh*>(false,NULL);
}

pair<bool,unsigned int> ApacheRequestMapper::getUnsignedInt(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getUnsignedInt(name,ns) : pair<bool,unsigned int>(false,0);
}

pair<bool,int> ApacheRequestMapper::getInt(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getInt(name,ns) : pair<bool,int>(false,0);
}

const IPropertySet* ApacheRequestMapper::getPropertySet(const char* name, const char* ns) const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getPropertySet(name,ns) : NULL;
}

const DOMElement* ApacheRequestMapper::getElement() const
{
    const IPropertySet* s=reinterpret_cast<const IPropertySet*>(m_propsKey->getData());
    return s ? s->getElement() : NULL;
}

static SH_AP_TABLE* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    SH_AP_CONFIGFILE* f;
    SH_AP_TABLE* grps=ap_make_table(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

#ifdef SHIB_APACHE_13
    if (!(f=ap_pcfg_openfile(r->pool,grpfile))) {
#else
    if (ap_pcfg_openfile(&f,r->pool,grpfile) != APR_SUCCESS) {
#endif
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG,SH_AP_R(r),"groups_for_user() could not open group file: %s\n",grpfile);
        return NULL;
    }

    SH_AP_POOL* sp;
#ifdef SHIB_APACHE_13
    sp=ap_make_sub_pool(r->pool);
#else
    if (apr_pool_create(&sp,r->pool) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
            "groups_for_user() could not create a subpool");
        return NULL;
    }
#endif

    while (!(ap_cfg_getline(l,MAX_STRING_LEN,f))) {
        if ((*l=='#') || (!*l))
            continue;
        ll = l;
        ap_clear_pool(sp);

        group_name=ap_getword(sp,&ll,':');

        while (*ll) {
            w=ap_getword_conf(sp,&ll);
            if (!strcmp(w,user)) {
                ap_table_setn(grps,ap_pstrdup(r->pool,group_name),"in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    ap_destroy_pool(sp);
    return grps;
}

bool htAccessControl::authorized(
    ShibTarget* st,
    ISessionCacheEntry* entry
) const
{
    // Make sure the object is our type.
    ShibTargetApache* sta=dynamic_cast<ShibTargetApache*>(st);
    if (!sta)
        throw ConfigurationException("Request wrapper object was not of correct type.");

    // mod_auth clone

    int m=sta->m_req->method_number;
    bool method_restricted=false;
    const char *t, *w;
    
    const array_header* reqs_arr=ap_requires(sta->m_req);
    if (!reqs_arr)
        return true;

    require_line* reqs=(require_line*)reqs_arr->elts;
    
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(sta->m_req),"REQUIRE nelts: %d", reqs_arr->nelts);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(sta->m_req),"REQUIRE all: %d", sta->m_dc->bRequireAll);

    vector<bool> auth_OK(reqs_arr->nelts,false);

#define SHIB_AP_CHECK_IS_OK {           \
     if (sta->m_dc->bRequireAll < 1)    \
         return true;                   \
     auth_OK[x] = true;                 \
     continue;                          \
}

    for (int x=0; x<reqs_arr->nelts; x++) {
        auth_OK[x] = false;
        if (!(reqs[x].method_mask & (1 << m)))
            continue;
        method_restricted=true;
        string remote_user = st->getRemoteUser();

        t = reqs[x].requirement;
        w = ap_getword_white(sta->m_req->pool, &t);

        if (!strcasecmp(w,"shibboleth")) {
            // This is a dummy rule needed because Apache conflates authn and authz.
            // Without some require rule, AuthType is ignored and no check_user hooks run.
            SHIB_AP_CHECK_IS_OK;
        }
        else if (!strcmp(w,"valid-user") && entry) {
            st->log(ShibTarget::LogLevelDebug,"htAccessControl plugin accepting valid-user based on active session");
            SHIB_AP_CHECK_IS_OK;
        }
        else if (!strcmp(w,"user") && !remote_user.empty()) {
            bool regexp=false;
            while (*t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='~') {
                    regexp=true;
                    continue;
                }
                
                if (regexp) {
                    try {
                        // To do regex matching, we have to convert from UTF-8.
                        auto_ptr<XMLCh> trans(fromUTF8(w));
                        RegularExpression re(trans.get());
                        auto_ptr<XMLCh> trans2(fromUTF8(remote_user.c_str()));
                        if (re.matches(trans2.get())) {
                            st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin accepting user (") + w + ")");
                            SHIB_AP_CHECK_IS_OK;
                        }
                    }
                    catch (XMLException& ex) {
                        auto_ptr_char tmp(ex.getMessage());
                        st->log(ShibTarget::LogLevelError,
                            string("htAccessControl plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
                    }
                }
                else if (remote_user==w) {
                    st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin accepting user (") + w + ")");
                    SHIB_AP_CHECK_IS_OK;
                }
            }
        }
        else if (!strcmp(w,"group")) {
            SH_AP_TABLE* grpstatus=NULL;
            if (sta->m_dc->szAuthGrpFile && !remote_user.empty()) {
                st->log(ShibTarget::LogLevelDebug,string("htAccessControl plugin using groups file: ") + sta->m_dc->szAuthGrpFile);
                grpstatus=groups_for_user(sta->m_req,remote_user.c_str(),sta->m_dc->szAuthGrpFile);
            }
            if (!grpstatus)
                return false;
    
            while (*t) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (ap_table_get(grpstatus,w)) {
                    st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin accepting group (") + w + ")");
                    SHIB_AP_CHECK_IS_OK;
                }
            }
        }
        else {
            Iterator<IAAP*> provs=st->getApplication()->getAAPProviders();
            AAP wrapper(provs,w);
            if (wrapper.fail()) {
                st->log(ShibTarget::LogLevelWarn, string("htAccessControl plugin didn't recognize require rule: ") + w);
                continue;
            }

            bool regexp=false;
            const char* vals=ap_table_get(sta->m_req->headers_in,wrapper->getHeader());
            while (*t && vals) {
                w=ap_getword_conf(sta->m_req->pool,&t);
                if (*w=='~') {
                    regexp=true;
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
                    for (unsigned int i = 0;  i < vals_str.length();  i++) {
                        if (vals_str.at(i) == ';') {
                            if (i == 0) {
                                st->log(ShibTarget::LogLevelError, string("htAccessControl plugin found invalid header encoding (") +
                                    vals + "): starts with a semicolon");
                                throw SAMLException("Invalid information supplied to authorization plugin.");
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
                                    st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                                       ", got " + val + ": authorization granted");
                                    SHIB_AP_CHECK_IS_OK;
                                }
                            }
                            else if ((wrapper->getCaseSensitive() && val==w) || (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                                st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                                    ", got " + val + ": authorization granted.");
                                SHIB_AP_CHECK_IS_OK;
                            }
                            else {
                                st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                                    ", got " + val + ": authoritzation not granted.");
                            }
                        }
                    }
    
                    string val = vals_str.substr(j, vals_str.length()-j);
                    if (regexp) {
                        auto_ptr<XMLCh> trans(fromUTF8(val.c_str()));
                        if (re->matches(trans.get())) {
                            st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                                ", got " + val + ": authorization granted.");
                            SHIB_AP_CHECK_IS_OK;
                        }
                    }
                    else if ((wrapper->getCaseSensitive() && val==w) || (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                        st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                            ", got " + val + ": authorization granted");
                        SHIB_AP_CHECK_IS_OK;
                    }
                    else {
                            st->log(ShibTarget::LogLevelDebug, string("htAccessControl plugin expecting ") + w +
                                ", got " + val + ": authorization not granted");
                    }
                }
                catch (XMLException& ex) {
                    auto_ptr_char tmp(ex.getMessage());
                    st->log(ShibTarget::LogLevelError, string("htAccessControl plugin caught exception while parsing regular expression (")
                        + w + "): " + tmp.get());
                }
            }
        }
    }

    // check if all require directives are true
    bool auth_all_OK = true;
    for (int i= 0; i<reqs_arr->nelts; i++) {
        auth_all_OK &= auth_OK[i];
    }
    if (auth_all_OK || !method_restricted)
        return true;

    return false;
}

#ifndef SHIB_APACHE_13
/*
 * shib_exit()
 *  Empty cleanup hook, Apache 2.x doesn't check NULL very well...
 */
extern "C" apr_status_t shib_exit(void* data)
{
    if (g_Config) {
        g_Config->shutdown();
        g_Config = NULL;
    }
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,NULL,"shib_exit() done\n");
    return OK;
}
#endif


/*
 * shib_child_exit()
 *  Cleanup the (per-process) pool info.
 */
#ifdef SHIB_APACHE_13
extern "C" void shib_child_exit(server_rec* s, SH_AP_POOL* p)
{
#else
extern "C" apr_status_t shib_child_exit(void* data)
{
  server_rec* s = NULL;
#endif

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_exit(%d) dealing with g_Config..", (int)getpid());
    g_Config->shutdown();
    g_Config = NULL;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_exit() done\n");

#ifndef SHIB_APACHE_13
    return OK;
#endif
}

/* 
 * shire_child_init()
 *  Things to do when the child process is initialized.
 *  (or after the configs are read in apache-2)
 */
#ifdef SHIB_APACHE_13
extern "C" void shib_child_init(server_rec* s, SH_AP_POOL* p)
#else
extern "C" void shib_child_init(apr_pool_t* p, server_rec* s)
#endif
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init(%d) starting", (int)getpid());

    if (g_Config) {
        ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() already initialized!");
        exit(1);
    }

    try {
        g_Config=&ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::LocalExtensions |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(g_szSchemaDir)) {
            ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to initialize libraries");
            exit(1);
        }
        SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::htAccessControlType,&htAccessFactory);
        SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::NativeRequestMapType,&ApacheRequestMapFactory);
        // We hijack the legacy type so that 1.2 config files will load this plugin
        SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::LegacyRequestMapType,&ApacheRequestMapFactory);
        
        if (!g_Config->load(g_szSHIBConfig)) {
            ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to load configuration");
            exit(1);
        }
    }
    catch (...) {
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to initialize system");
        exit(1);
    }

    // Set the cleanup handler
    apr_pool_cleanup_register(p, NULL, &shib_exit, &shib_child_exit);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() done");
}

typedef const char* (*config_fn_t)(void);

#ifdef SHIB_APACHE_13

// SHIB Module commands

static command_rec shire_cmds[] = {
  {"SHIREConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
   RSRC_CONF, TAKE1, "Path to shibboleth.xml config file."},
  {"ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
   RSRC_CONF, TAKE1, "Path to shibboleth.xml config file."},
  {"ShibSchemaDir", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
   RSRC_CONF, TAKE1, "Path to Shibboleth XML schema directory."},

  {"ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szScheme),
   RSRC_CONF, TAKE1, "URL scheme to force into generated URLs for a vhost."},
   
  {"ShibDisable", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bOff),
   OR_AUTHCFG, FLAG, "Disable all Shib module activity here to save processing effort"},
  {"ShibApplicationId", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szApplicationId),
   OR_AUTHCFG, FLAG, "Set Shibboleth applicationId property for content"},
  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibRequireSession", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireSession),
   OR_AUTHCFG, FLAG, "Initiates a new session if one does not exist."},
  {"ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szRequireWith),
   OR_AUTHCFG, FLAG, "Initiates a new session if one does not exist using a specific SessionInitiator"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML attribute assertion(s) to Shib-Attributes header?"},
  {"AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
   (void *) XtOffsetOf (shib_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibRequireAll", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireAll),
   OR_AUTHCFG, FLAG, "All require directives must match!"},

  {NULL}
};

extern "C"{
handler_rec shib_handlers[] = {
  { "shib-handler", shib_handler },
  { NULL }
};

module MODULE_VAR_EXPORT mod_shib = {
    STANDARD_MODULE_STUFF,
    NULL,                        /* initializer */
    create_shib_dir_config,	/* dir config creater */
    merge_shib_dir_config,	/* dir merger --- default is to override */
    create_shib_server_config, /* server config */
    merge_shib_server_config,   /* merge server config */
    shire_cmds,			/* command table */
    shib_handlers,		/* handlers */
    NULL,			/* filename translation */
    shib_check_user,		/* check_user_id */
    shib_auth_checker,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shib_child_init,		/* child_init */
    shib_child_exit,		/* child_exit */
    NULL			/* post read-request */
};

#elif defined(SHIB_APACHE_20)

extern "C" void shib_register_hooks (apr_pool_t *p)
{
  ap_hook_child_init(shib_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(shib_check_user, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(shib_auth_checker, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_handler(shib_handler, NULL, NULL, APR_HOOK_LAST);
}

// SHIB Module commands

extern "C" {
static command_rec shib_cmds[] = {
  AP_INIT_TAKE1("ShibConfig",
		(config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
		RSRC_CONF, "Path to shibboleth.xml config file."),
  AP_INIT_TAKE1("ShibSchemaDir",
     (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
      RSRC_CONF, "Path to Shibboleth XML schema directory."),

  AP_INIT_TAKE1("ShibURLScheme",
     (config_fn_t)shib_set_server_string_slot,
     (void *) offsetof (shib_server_config, szScheme),
      RSRC_CONF, "URL scheme to force into generated URLs for a vhost."),

  AP_INIT_FLAG("ShibDisable", (config_fn_t)ap_set_flag_slot,
         (void *) offsetof (shib_dir_config, bOff),
        OR_AUTHCFG, "Disable all Shib module activity here to save processing effort"),
  AP_INIT_TAKE1("ShibApplicationId", (config_fn_t)ap_set_string_slot,
         (void *) offsetof (shib_dir_config, szApplicationId),
        OR_AUTHCFG, "Set Shibboleth applicationId property for content"),
  AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bBasicHijack),
	       OR_AUTHCFG, "Respond to AuthType Basic and convert to shib?"),
  AP_INIT_FLAG("ShibRequireSession", (config_fn_t)ap_set_flag_slot,
         (void *) offsetof (shib_dir_config, bRequireSession),
        OR_AUTHCFG, "Initiates a new session if one does not exist."),
  AP_INIT_TAKE1("ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
         (void *) offsetof (shib_dir_config, szRequireWith),
        OR_AUTHCFG, "Initiates a new session if one does not exist using a specific SessionInitiator"),
  AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
         (void *) offsetof (shib_dir_config, bExportAssertion),
        OR_AUTHCFG, "Export SAML attribute assertion(s) to Shib-Attributes header?"),
  AP_INIT_TAKE1("AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
		(void *) offsetof (shib_dir_config, szAuthGrpFile),
		OR_AUTHCFG, "Text file containing group names and member user IDs"),
  AP_INIT_FLAG("ShibRequireAll", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bRequireAll),
	       OR_AUTHCFG, "All require directives must match!"),

  {NULL}
};

module AP_MODULE_DECLARE_DATA mod_shib = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,     /* create dir config */
    merge_shib_dir_config,      /* merge dir config --- default is to override */
    create_shib_server_config,  /* create server config */
    merge_shib_server_config,   /* merge server config */
    shib_cmds,                  /* command table */
    shib_register_hooks         /* register hooks */
};

#else
#error "undefined APACHE version"
#endif

}
