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
int shib_handler(request_rec* r, const IApplication* application, SHIRE& shire);

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

    // SHIRE Configuration
    int bBasicHijack;       // activate for AuthType Basic?
    int bRequireSession;    // require a session?
    int bExportAssertion;   // export SAML assertion to the environment?
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (SH_AP_POOL* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    dc->bBasicHijack = -1;
    dc->bRequireSession = -1;
    dc->bExportAssertion = -1;
    dc->bRequireAll = -1;
    dc->szAuthGrpFile = NULL;
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
    int offset=(int)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

/********************************************************************************/
// Some other useful helper function(s)

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

/********************************************************************************/
// Apache ShibTarget subclass(es) here.

class HTGroupTableApache : public HTGroupTable
{
public:
  HTGroupTableApache(request_rec* r, const char *user, char *grpfile) {
    groups = groups_for_user(r, user, grpfile);
    if (!groups)
      throw ShibTargetException(SHIBRPC_OK, "EEP");
  }
  ~HTGroupTableApache() {}
  bool lookup(const char *entry) { return (ap_table_get(groups, entry)!=NULL); }
  SH_AP_TABLE* groups;
};

class ShibTargetApache : public ShibTarget
{
public:
  ShibTargetApache(request_rec* req) {
    m_sc = (shib_server_config*)
      ap_get_module_config(req->server->module_config, &mod_shib);

    m_dc = (shib_dir_config*)ap_get_module_config(req->per_dir_config, &mod_shib);

    const char* ct = ap_table_get(req->headers_in, "Content-type");

    init(g_Config, string(m_sc->szScheme ? m_sc->szScheme : ap_http_method(req)),
	 string(ap_get_server_name(req)), (int)ap_get_server_port(req),
	 string(req->unparsed_uri), string(ct ? ct : ""),
	 string(req->connection->remote_ip), string(req->method));

    m_req = req;
  }
  ~ShibTargetApache() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    ap_log_rerror(APLOG_MARK,
		  (level == LogLevelDebug ? APLOG_DEBUG :
		   (level == LogLevelInfo ? APLOG_INFO :
		    (level == LogLevelWarn ? APLOG_WARNING :
		     APLOG_ERR)))|APLOG_NOERRNO, SH_AP_R(m_req),
		  msg.c_str());
  }
  virtual string getCookies(void) {
    const char *c = ap_table_get(m_req->headers_in, "Cookie");
    return string(c ? c : "");
  }
  virtual void setCookie(const string &name, const string &value) {
    char* val = ap_psprintf(m_req->pool, "%s=%s", name.c_str(), value.c_str());
    ap_table_setn(m_req->err_headers_out, "Set-Cookie", val);
  }
  virtual string getArgs(void) { return string(m_req->args ? m_req->args : ""); }
  virtual string getPostData(void) {
    // Read the posted data
    if (ap_setup_client_block(m_req, REQUEST_CHUNKED_ERROR))
      throw ShibTargetException(SHIBRPC_OK, "CGI setup_client_block failed");
    if (!ap_should_client_block(m_req))
      throw ShibTargetException(SHIBRPC_OK, "CGI should_client_block failed");
    if (m_req->remaining > 1024*1024)
      throw ShibTargetException (SHIBRPC_OK, "CGI length too long...");

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
  // override so we can look at the actual auth type and maybe override it.
  virtual string getAuthType(void) {
    const char *auth_type=ap_auth_type(m_req);
    if (!auth_type)
        return string("");
    if (strcasecmp(auth_type, "shibboleth")) {
      if (!strcasecmp(auth_type, "basic") && m_dc->bBasicHijack == 1) {
	core_dir_config* conf= (core_dir_config*)
	  ap_get_module_config(m_req->per_dir_config,
			       ap_find_linked_module("http_core.c"));
	auth_type = conf->ap_auth_type = "shibboleth";
      }
    }
    return string(auth_type);
  }
  // Override this function because we want to add the Apache Directory override
  virtual pair<bool,bool> getRequireSession(IRequestMapper::Settings &settings) {
    pair<bool,bool> requireSession = settings.first->getBool("requireSession");
    if (!requireSession.first || !requireSession.second)
      if (m_dc->bRequireSession == 1)
	requireSession.second=true;

    return requireSession;
  }

  virtual HTAccessInfo* getAccessInfo(void) { 
    int m = m_req->method_number;
    const array_header* reqs_arr = ap_requires(m_req);
    if (!reqs_arr)
      return NULL;

    require_line* reqs = (require_line*) reqs_arr->elts;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req),
		  "REQUIRE nelts: %d", reqs_arr->nelts);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req),
		  "REQUIRE all: %d", m_dc->bRequireAll);

    HTAccessInfo* ht = new HTAccessInfo();
    ht->requireAll = (m_dc->bRequireAll >= 0);
    ht->elements.reserve(reqs_arr->nelts);
    for (int x = 0; x < reqs_arr->nelts; x++) {
      HTAccessInfo::RequireLine* rline = new HTAccessInfo::RequireLine();
      rline->use_line = (reqs[x].method_mask & (1 << m));
      rline->tokens.reserve(6);	// No reason to reserve specifically 6 tokens
      const char* t = reqs[x].requirement;
      const char* w = ap_getword_white(m_req->pool, &t);
      rline->tokens.push_back(w);
      while (*t) {
	w = ap_getword_conf(m_req->pool, &t);
	rline->tokens.push_back(w);
      }
      ht->elements.push_back(rline);
    }
    return ht;
  }
  virtual HTGroupTable* getGroupTable(string &user) {
    if (m_dc->szAuthGrpFile && !user.empty()) {
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req),
		    "getGroupTable() using groups file: %s\n",
		    m_dc->szAuthGrpFile);
      try {
	HTGroupTableApache *gt = new HTGroupTableApache(m_req, user.c_str(),
							m_dc->szAuthGrpFile);
	return gt;
      } catch (...) { }
    }
    return NULL;
  }

  virtual void* sendPage(const string &msg, const string content_type,
			 const pair<string, string> headers[], int code) {
    m_req->content_type = ap_psprintf(m_req->pool, content_type.c_str());
    // XXX: push headers and code into the response
    ap_send_http_header(m_req);
    ap_rprintf(m_req, msg.c_str());
    return (void*)DONE;
  }
  virtual void* sendRedirect(const string url) {
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
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
		"shib_check_user(%d): ENTER\n", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_check_user" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef _DEBUG
  try {
#endif
    ShibTargetApache sta(r);

    // Check user authentication, the set the post handler bypass
    pair<bool,void*> res = sta.doCheckAuthN((sta.m_dc->bRequireSession == 1), true);
    apr_pool_userdata_setn((const void*)42,g_UserDataKey,NULL,r->pool);
    if (res.first) return (int)res.second;

    // user auth was okay -- export the assertions now
    res = sta.doExportAssertions((sta.m_dc->bExportAssertion == 1));
    if (res.first) return (int)res.second;

    // export happened successfully..  this user is ok.
    return OK;

#ifndef _DEBUG
  } catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r),
		  "shib_check_user threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

extern "C" int shib_post_handler(request_rec* r)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_post_handler" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef SHIB_APACHE_13
  // With 2.x, this handler always runs, though last.
  // We check if shib_check_user ran, because it will detect a SHIRE request
  // and dispatch it directly.
  void* data;
  apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
  if (data==(const void*)42) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_post_handler skipped since check_user ran");
    return DECLINED;
  }
#endif

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
		"shib_post_handler(%d): ENTER", (int)getpid());

#ifndef _DEBUG
  try {
#endif
    ShibTargetApache sta(r);

    pair<bool,void*> res = sta.doHandlePOST();
    if (res.first) return (int)res.second;

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r),
		  "doHandlePOST() did not do anything.");
    return SERVER_ERROR;

#ifndef _DEBUG
  } catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r),
		  "shib_post_handler threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

/*
 * shib_auth_checker() -- a simple resource manager to
 * process the .htaccess settings and copy attributes
 * into the HTTP headers.
 */
extern "C" int shib_auth_checker(request_rec* r)
{
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
		"shib_check_user(%d): ENTER", (int)getpid());

  ostringstream threadid;
  threadid << "[" << getpid() << "] shib_auth_checker" << '\0';
  saml::NDC ndc(threadid.str().c_str());

#ifndef _DEBUG
  try {
#endif
    ShibTargetApache sta(r);

    pair<bool,void*> res = sta.doCheckAuthZ();
    if (res.first) return (int)res.second;

    // We're all okay.
    return OK;

#ifndef _DEBUG
  } catch (...) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r),
		  "shib_auth_checker threw an uncaught exception!");
    return SERVER_ERROR;
  }
#endif
}

#if 0
static char* shib_get_targeturl(request_rec* r, const char* scheme=NULL)
{
    // On 1.3, this is always canonical, but on 2.0, UseCanonicalName comes into play.
    // However, we also have a setting to forcibly replace the scheme for esoteric cases.
    if (scheme) {
        unsigned port = ap_get_server_port(r);
        if ((!strcmp(scheme,"http") && port==80) || (!strcmp(scheme,"https") && port==443)) {
            return ap_pstrcat(r->pool, scheme, "://", ap_get_server_name(r), r->unparsed_uri, NULL);
        }
        return ap_psprintf(r->pool, "%s://%s:%u%s", scheme, ap_get_server_name(r), port, r->unparsed_uri);
    }
    return ap_construct_url(r->pool,r->unparsed_uri,r);
}

extern "C" int shib_check_user(request_rec* r)
{
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user: ENTER");
    shib_dir_config* dc=(shib_dir_config*)ap_get_module_config(r->per_dir_config,&mod_shib);
    shib_server_config* sc=(shib_server_config*)ap_get_module_config(r->server->module_config,&mod_shib);

    ostringstream threadid;
    threadid << "[" << getpid() << "] shib_check_user" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    const char* targeturl=shib_get_targeturl(r,sc->szScheme);

    // We lock the configuration system for the duration.
    IConfig* conf=g_Config->getINI();
    Locker locker(conf);
    
    // Map request to application and content settings.
    IRequestMapper* mapper=conf->getRequestMapper();
    Locker locker2(mapper);
    IRequestMapper::Settings settings=mapper->getSettingsFromParsedURL(
        (sc-> szScheme ? sc-> szScheme : ap_http_method(r)), ap_get_server_name(r), ap_get_server_port(r), r->unparsed_uri
        );
    pair<bool,const char*> application_id=settings.first->getString("applicationId");
    const IApplication* application=conf->getApplication(application_id.second);
    if (!application) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_check_user: unable to map request to application settings, check configuration");
        return SERVER_ERROR;
    }
    
    // Declare SHIRE object for this request.
    SHIRE shire(application);
    
    const char* shireURL=shire.getShireURL(targeturl);
    if (!shireURL) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_check_user: unable to map request to proper shireURL setting, check configuration");
        return SERVER_ERROR;
    }
    
    // Get location of this application's assertion consumer service and see if this is it.
    if (strstr(targeturl,shireURL)) {
        return shib_handler(r,application,shire);
    }

    // We can short circuit the handler if we run this...
    apr_pool_userdata_setn((const void*)42,g_UserDataKey,NULL,r->pool);

    // Regular access to arbitrary resource...check AuthType
    const char *auth_type=ap_auth_type(r);
    if (!auth_type)
        return DECLINED;

    if (strcasecmp(auth_type,"shibboleth")) {
        if (!strcasecmp(auth_type,"basic") && dc->bBasicHijack==1) {
            core_dir_config* conf=
                (core_dir_config*)ap_get_module_config(r->per_dir_config,
                    ap_find_linked_module("http_core.c"));
            conf->ap_auth_type="shibboleth";
        }
        else
            return DECLINED;
    }

    pair<bool,bool> requireSession = settings.first->getBool("requireSession");
    if (!requireSession.first || !requireSession.second)
        if (dc->bRequireSession==1)
            requireSession.second=true;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user: session check for %s",targeturl);

    pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();   // always returns *something*

    // We're in charge, so check for cookie.
    const char* session_id=NULL;
    const char* cookies=ap_table_get(r->headers_in,"Cookie");

    if (cookies) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user: cookies found: %s",cookies);
        if (session_id=strstr(cookies,shib_cookie.first)) {
            // Yep, we found a cookie -- pull it out (our session_id)
            session_id+=strlen(shib_cookie.first) + 1; /* Skip over the '=' */
            char* cookiebuf = ap_pstrdup(r->pool,session_id);
            char* cookieend = strchr(cookiebuf,';');
            if (cookieend)
                *cookieend = '\0';    /* Ignore anyting after a ; */
            session_id=cookiebuf;
        }
    }

    if (!session_id || !*session_id) {
        // If no session required, bail now.
        if (!requireSession.second)
            return OK;

        // No acceptable cookie, and we require a session.  Generate an AuthnRequest.
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user: no cookie found -- redirecting to WAYF");
        ap_table_setn(r->headers_out,"Location",ap_pstrdup(r->pool,shire.getAuthnRequest(targeturl)));
        return REDIRECT;
    }

    // Make sure this session is still valid.
    RPCError* status = NULL;
    ShibMLP markupProcessor;
    markupProcessor.insert("requestURL", targeturl);

    try {
        status = shire.sessionIsValid(session_id, r->connection->remote_ip);
    }
    catch (ShibTargetException &e) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user(): %s", e.what());
        markupProcessor.insert("errorType", "Session Processing Error");
        markupProcessor.insert("errorText", e.what());
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "shire", markupProcessor);
    }
#ifndef _DEBUG
    catch (...) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user(): caught unexpected error");
        markupProcessor.insert("errorType", "Session Processing Error");
        markupProcessor.insert("errorText", "Unexpected Exception");
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "shire", markupProcessor);
    }
#endif

    // Check the status
    if (status->isError()) {
        ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,SH_AP_R(r),
		      "shib_check_user() session invalid: %s", status->getText());

        // If no session required, bail now.
        if (!requireSession.second)
            return OK;	// XXX: Or should this be DECLINED?
                        // Has to be OK because DECLINED will just cause Apache to fail when it can't locate
                        // anything to process the AuthType. No session plus requireSession false means 
                        // do not authenticate the user.
        else if (status->isRetryable()) {
            // Oops, session is invalid. Generate AuthnRequest.
            ap_table_setn(r->headers_out,"Location",ap_pstrdup(r->pool,shire.getAuthnRequest(targeturl)));
            delete status;
            return REDIRECT;
        }
        else {
            // return the error page to the user
            markupProcessor.insert(*status);
            delete status;
            return shib_error_page(r, application, "shire", markupProcessor);
        }
    }

    delete status;
    // set the authtype
#ifdef SHIB_APACHE_13
    if (r->connection)
        r->connection->ap_auth_type = "shibboleth";
#else
    r->ap_auth_type = "shibboleth";
#endif
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user: session successfully verified");

    // This is code transferred in from the auth check to export the attributes.
    // We could even combine the isSessionValid/getAssertions API...?

    RM rm(application);
    vector<SAMLAssertion*> assertions;
    SAMLAuthenticationStatement* sso_statement=NULL;

    try {
        status = rm.getAssertions(session_id, r->connection->remote_ip, assertions, &sso_statement);
    }
    catch (ShibTargetException &e) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user(): %s", e.what());
        markupProcessor.insert("errorType", "Attribute Processing Error");
        markupProcessor.insert("errorText", e.what());
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "rm", markupProcessor);
    }
#ifndef _DEBUG
    catch (...) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user(): caught unexpected error");
        markupProcessor.insert("errorType", "Attribute Processing Error");
        markupProcessor.insert("errorText", "Unexpected Exception");
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "rm", markupProcessor);
    }
#endif

    if (status->isError()) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
            "shib_check_user() getAssertions failed: %s", status->getText());

        markupProcessor.insert(*status);
        delete status;
        return shib_error_page(r, application, "rm", markupProcessor);
    }
    delete status;

    // Do we have an access control plugin?
    if (settings.second) {
        Locker acllock(settings.second);
        if (!settings.second->authorized(*sso_statement,assertions)) {
            for (int k = 0; k < assertions.size(); k++)
                delete assertions[k];
            delete sso_statement;
            ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_check_user(): access control provider denied access");
            return shib_error_page(r, application, "access", markupProcessor);
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
                    ap_table_unset(r->headers_in,header);
            }
        }
        catch(...) {
            aap->unlock();
            for (int k = 0; k < assertions.size(); k++)
                delete assertions[k];
            delete sso_statement;
            ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
                "shib_check_user(): caught unexpected error while clearing headers");
            markupProcessor.insert("errorType", "Attribute Processing Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return shib_error_page(r, application, "rm", markupProcessor);
        }
        aap->unlock();
    }
    provs.reset();
    
    // Maybe export the first assertion.
    ap_table_unset(r->headers_in,"Shib-Attributes");
    pair<bool,bool> exp=settings.first->getBool("exportAssertion");
    if (!exp.first || !exp.second)
        if (dc->bExportAssertion==1)
            exp.second=true;
    if (exp.second && assertions.size()) {
        string assertion;
        RM::serialize(*(assertions[0]), assertion);
        ap_table_set(r->headers_in,"Shib-Attributes", assertion.c_str());
    }

    // Export the SAML AuthnMethod and the origin site name, and possibly the NameIdentifier.
    ap_table_unset(r->headers_in,"Shib-Origin-Site");
    ap_table_unset(r->headers_in,"Shib-Authentication-Method");
    ap_table_unset(r->headers_in,"Shib-NameIdentifier-Format");
    auto_ptr_char os(sso_statement->getSubject()->getNameIdentifier()->getNameQualifier());
    auto_ptr_char am(sso_statement->getAuthMethod());
    ap_table_set(r->headers_in,"Shib-Origin-Site", os.get());
    ap_table_set(r->headers_in,"Shib-Authentication-Method", am.get());
    
    // Export NameID?
    AAP wrapper(provs,sso_statement->getSubject()->getNameIdentifier()->getFormat(),Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
    if (!wrapper.fail() && wrapper->getHeader()) {
        auto_ptr_char form(sso_statement->getSubject()->getNameIdentifier()->getFormat());
        auto_ptr_char nameid(sso_statement->getSubject()->getNameIdentifier()->getName());
        ap_table_set(r->headers_in,"Shib-NameIdentifier-Format",form.get());
        if (!strcmp(wrapper->getHeader(),"REMOTE_USER"))
            SH_AP_USER(r)=ap_pstrdup(r->pool,nameid.get());
        else
            ap_table_set(r->headers_in,wrapper->getHeader(),nameid.get());
    }
    
    ap_table_unset(r->headers_in,"Shib-Application-ID");
    ap_table_set(r->headers_in,"Shib-Application-ID",application_id.second);

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
                if (!strcmp(wrapper->getHeader(),"REMOTE_USER") && vals.hasNext())
                    SH_AP_USER(r)=ap_pstrdup(r->pool,vals.next().c_str());
                else {
                    int it=0;
                    char* header = (char*)ap_table_get(r->headers_in, wrapper->getHeader());
                    if (header) {
                        header=ap_pstrdup(r->pool, header);
                        it++;
                    }
                    else
                        header = ap_pstrdup(r->pool, "");
                    for (; vals.hasNext(); it++) {
                        string value = vals.next();
                        for (string::size_type pos = value.find_first_of(";", string::size_type(0));
                                pos != string::npos;
                                pos = value.find_first_of(";", pos)) {
                            value.insert(pos, "\\");
                            pos += 2;
                        }
                        header=ap_pstrcat(r->pool, header, (it ? ";" : ""), value.c_str(), NULL);
                    }
                    ap_table_setn(r->headers_in, wrapper->getHeader(), header);
               }
            }
        }
    }

    // clean up memory
    for (int k = 0; k < assertions.size(); k++)
        delete assertions[k];
    delete sso_statement;

    return OK;
}

extern "C" int shib_post_handler(request_rec* r)
{
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
		"shib_post_handler(%d): ENTER", (int)getpid());
    shib_server_config* sc=(shib_server_config*)ap_get_module_config(r->server->module_config,&mod_shib);

#ifndef SHIB_APACHE_13
    // With 2.x, this handler always runs, though last.
    // We check if shib_check_user ran, because it will detect a SHIRE request
    // and dispatch it directly.
    void* data;
    apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
    if (data==(const void*)42) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_post_handler skipped since check_user ran");
        return DECLINED;
    }
#endif
    
    ostringstream threadid;
    threadid << "[" << getpid() << "] shib_post_handler" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    // We lock the configuration system for the duration.
    IConfig* conf=g_Config->getINI();
    Locker locker(conf);
    
    // Map request to application and content settings.
    IRequestMapper* mapper=conf->getRequestMapper();
    Locker locker2(mapper);
    IRequestMapper::Settings settings=mapper->getSettingsFromParsedURL(
        (sc->szScheme ? sc->szScheme : ap_http_method(r)), ap_get_server_name(r), ap_get_server_port(r), r->unparsed_uri
        );
    pair<bool,const char*> application_id=settings.first->getString("applicationId");
    const IApplication* application=conf->getApplication(application_id.second);
    if (!application) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_post_handler: unable to map request to application settings, check configuration");
        return SERVER_ERROR;
    }
    
    // Declare SHIRE object for this request.
    SHIRE shire(application);
    
    return shib_handler(r, application, shire);
}

int shib_handler(request_rec* r, const IApplication* application, SHIRE& shire)
{
    shib_server_config* sc=(shib_server_config*)ap_get_module_config(r->server->module_config,&mod_shib);

    const char* targeturl=shib_get_targeturl(r,sc->szScheme);

    const char* shireURL=shire.getShireURL(targeturl);
    if (!shireURL) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_post_handler: unable to map request to proper shireURL setting, check configuration");
        return SERVER_ERROR;
    }

    // Make sure we only process the SHIRE requests.
    if (!strstr(targeturl,shireURL))
        return DECLINED;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler() running");

    const IPropertySet* sessionProps=application->getPropertySet("Sessions");
    if (!sessionProps) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_post_handler: unable to map request to application session settings, check configuration");
        return SERVER_ERROR;
    }

    pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();   // always returns something

    ShibMLP markupProcessor;
    markupProcessor.insert("requestURL", targeturl);

    // Process SHIRE request
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_handler() Beginning SHIRE processing");
      
    try {
        pair<bool,bool> shireSSL=sessionProps->getBool("shireSSL");
      
        // Make sure this is SSL, if it should be
        if ((!shireSSL.first || shireSSL.second) && strcmp(ap_http_method(r),"https"))
            throw ShibTargetException(SHIBRPC_OK, "blocked non-SSL access to session creation service");

        // If this is a GET, we manufacture an AuthnRequest.
        if (!strcasecmp(r->method,"GET")) {
            const char* areq=r->args ? shire.getLazyAuthnRequest(r->args) : NULL;
            if (!areq)
                throw ShibTargetException(SHIBRPC_OK, "malformed arguments to request a new session");
            ap_table_setn(r->headers_out, "Location", ap_pstrdup(r->pool,areq));
            return REDIRECT;
        }
        else if (strcasecmp(r->method,"POST")) {
            throw ShibTargetException(SHIBRPC_OK, "blocked non-POST to SHIRE POST processor");
        }

        // Sure sure this POST is an appropriate content type
        const char *ct = ap_table_get(r->headers_in, "Content-type");
        if (!ct || strcasecmp(ct, "application/x-www-form-urlencoded"))
            throw ShibTargetException(SHIBRPC_OK,
				      ap_psprintf(r->pool, "blocked bad content-type to SHIRE POST processor: %s", (ct ? ct : "")));

        // Read the posted data
        if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))
            throw ShibTargetException(SHIBRPC_OK, "CGI setup_client_block failed");
        if (!ap_should_client_block(r))
            throw ShibTargetException(SHIBRPC_OK, "CGI should_client_block failed");
        if (r->remaining > 1024*1024)
            throw ShibTargetException (SHIBRPC_OK, "CGI length too long...");

        string cgistr;
        char buff[HUGE_STRING_LEN];
        ap_hard_timeout("[mod_shib] CGI Parser", r);
        memset(buff, 0, sizeof(buff));
        while (ap_get_client_block(r, buff, sizeof(buff)-1) > 0) {
            ap_reset_timeout(r);
            cgistr += buff;
            memset(buff, 0, sizeof(buff));
        }
        ap_kill_timeout(r);

        // Parse the submission.
        pair<const char*,const char*> elements=shire.getFormSubmission(cgistr.c_str(),cgistr.length());
    
        // Make sure the SAML Response parameter exists
        if (!elements.first || !*elements.first)
            throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find SAMLResponse form element");
    
        // Make sure the target parameter exists
        if (!elements.second || !*elements.second)
            throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find TARGET form element");
    
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
            "shib_handler() Processing POST for target: %s", elements.second);

        // process the post
        string cookie;
        RPCError* status = shire.sessionCreate(elements.first, r->connection->remote_ip, cookie);

        if (status->isError()) {
            ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
    		    "shib_handler() POST process failed (%d): %s", status->getCode(), status->getText());

            if (status->isRetryable()) {
                delete status;
                ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,SH_AP_R(r),
        	        "shib_handler() retryable error, generating new AuthnRequest");
                ap_table_setn(r->headers_out,"Location",ap_pstrdup(r->pool,shire.getAuthnRequest(elements.second)));
                return REDIRECT;
            }

            // return this error to the user.
            markupProcessor.insert(*status);
            delete status;
            return shib_error_page(r, application, "shire", markupProcessor);
        }
        delete status;

        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
    		  "shib_handler() POST process succeeded.  New session: %s", cookie.c_str());

        // We've got a good session, set the cookie...
        char* val = ap_psprintf(r->pool,"%s=%s%s",shib_cookie.first,cookie.c_str(),shib_cookie.second);
        ap_table_setn(r->err_headers_out, "Set-Cookie", val);
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_handler() setting cookie: %s", val);

        // ... and redirect to the target
        ap_table_setn(r->headers_out, "Location", ap_pstrdup(r->pool,elements.second));
        return REDIRECT;
    }
    catch (ShibTargetException &e) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r), "shib_handler() caught exception: %s", e.what());
        markupProcessor.insert("errorType", "Session Creation Service Error");
        markupProcessor.insert("errorText", e.what());
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "shire", markupProcessor);
    }
#ifndef _DEBUG
    catch (...) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_handler(): unexpected exception");
        markupProcessor.insert("errorType", "Session Creation Service Error");
        markupProcessor.insert("errorText", "Unknown Exception");
        markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
        return shib_error_page(r, application, "shire", markupProcessor);
    }
#endif

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),"shib_handler() server error");
    return SERVER_ERROR;
}

static int shib_error_page(request_rec* r, const IApplication* app, const char* page, ShibMLP& mlp)
{
    const IPropertySet* props=app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res) {
                    r->content_type = ap_psprintf(r->pool, "text/html");
                    ap_send_http_header(r);
                    ap_rprintf(r, res);
                    return DONE;
                }
            }
        }
    }

    ap_log_rerror(APLOG_MARK,APLOG_ERR,SH_AP_R(r),
        "shib_error_page() could not process shire error template for application %s",app->getId());
    return SERVER_ERROR;
}

/*
 * shib_auth_checker() -- a simple resource manager to
 * process the .htaccess settings and copy attributes
 * into the HTTP headers.
 */
extern "C" int shib_auth_checker(request_rec* r)
{
    shib_dir_config* dc=
        (shib_dir_config*)ap_get_module_config(r->per_dir_config,&mod_shib);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() executing");

    // Regular access to arbitrary resource...check AuthType
    const char* auth_type=ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type,"shibboleth"))
        return DECLINED;

    ostringstream threadid;
    threadid << "[" << getpid() << "] shibrm" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    // We lock the configuration system for the duration.
    IConfig* conf=g_Config->getINI();
    Locker locker(conf);
    
    const char* application_id=ap_table_get(r->headers_in,"Shib-Application-ID");
    const IApplication* application=NULL;
    if (application_id)
        application = conf->getApplication(application_id);

    // mod_auth clone

    int m=r->method_number;
    bool method_restricted=false;
    const char *t, *w;
    
    const array_header* reqs_arr=ap_requires(r);
    if (!reqs_arr)
        return OK;

    require_line* reqs=(require_line*)reqs_arr->elts;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"REQUIRE nelts: %d", reqs_arr->nelts);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"REQUIRE all: %d", dc->bRequireAll);

    vector<bool> auth_OK(reqs_arr->nelts,false);

#define SHIB_AP_CHECK_IS_OK {       \
     if (dc->bRequireAll < 1)    \
         return OK;      \
     auth_OK[x] = true;      \
     continue;           \
}

    for (int x=0; x<reqs_arr->nelts; x++) {
        auth_OK[x] = false;
        if (!(reqs[x].method_mask & (1 << m)))
            continue;
        method_restricted=true;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

        if (!strcasecmp(w,"Shibboleth")) {
            // This is a dummy rule needed because Apache conflates authn and authz.
            // Without some require rule, AuthType is ignored and no check_user hooks run.
            SHIB_AP_CHECK_IS_OK;
        }
        else if (!strcmp(w,"valid-user") && application_id) {
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() accepting valid-user");
            SHIB_AP_CHECK_IS_OK;
        }
        else if (!strcmp(w,"user") && SH_AP_USER(r)) {
            bool regexp=false;
            while (*t) {
                w=ap_getword_conf(r->pool,&t);
                if (*w=='~') {
                    regexp=true;
                    continue;
                }
                
                if (regexp) {
                    try {
                        // To do regex matching, we have to convert from UTF-8.
                        auto_ptr<XMLCh> trans(fromUTF8(w));
                        RegularExpression re(trans.get());
                        auto_ptr<XMLCh> trans2(fromUTF8(SH_AP_USER(r)));
                        if (re.matches(trans2.get())) {
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() accepting user: %s",w);
                            SHIB_AP_CHECK_IS_OK;
                        }
                    }
                    catch (XMLException& ex) {
                        auto_ptr_char tmp(ex.getMessage());
                        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
                                        "shib_auth_checker caught exception while parsing regular expression (%s): %s",w,tmp.get());
                    }
                }
                else if (!strcmp(SH_AP_USER(r),w)) {
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() accepting user: %s",w);
                    SHIB_AP_CHECK_IS_OK;
                }
            }
        }
        else if (!strcmp(w,"group")) {
            SH_AP_TABLE* grpstatus=NULL;
            if (dc->szAuthGrpFile && SH_AP_USER(r)) {
                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() using groups file: %s\n",dc->szAuthGrpFile);
                grpstatus=groups_for_user(r,SH_AP_USER(r),dc->szAuthGrpFile);
            }
            if (!grpstatus)
                return DECLINED;
    
            while (*t) {
                w=ap_getword_conf(r->pool,&t);
                if (ap_table_get(grpstatus,w)) {
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),"shib_auth_checker() accepting group: %s",w);
                    SHIB_AP_CHECK_IS_OK;
                }
            }
        }
        else {
            Iterator<IAAP*> provs=application ? application->getAAPProviders() : EMPTY(IAAP*);
            AAP wrapper(provs,w);
            if (wrapper.fail()) {
                ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,SH_AP_R(r),
                    "shib_auth_checker() didn't recognize require rule: %s\n",w);
                continue;
            }

            bool regexp=false;
            const char* vals=ap_table_get(r->headers_in,wrapper->getHeader());
            while (*t && vals) {
                w=ap_getword_conf(r->pool,&t);
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
                    for (int i = 0;  i < vals_str.length();  i++) {
                        if (vals_str.at(i) == ';') {
                            if (i == 0) {
                                ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,SH_AP_R(r),
                                                "shib_auth_checker() invalid header encoding %s: starts with semicolon", vals);
                                return SERVER_ERROR;
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
                                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                                    "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                                    SHIB_AP_CHECK_IS_OK;
                                }
                            }
                            else if ((wrapper->getCaseSensitive() && val==w) || (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                                "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                                SHIB_AP_CHECK_IS_OK;
                            }
                            else {
                                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                                "shib_auth_checker() expecting %s, got %s: authorization not granted", w, val.c_str());
                            }
                        }
                    }
    
                    string val = vals_str.substr(j, vals_str.length()-j);
                    if (regexp) {
                        auto_ptr<XMLCh> trans(fromUTF8(val.c_str()));
                        if (re->matches(trans.get())) {
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                            "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                            SHIB_AP_CHECK_IS_OK;
                        }
                    }
                    else if ((wrapper->getCaseSensitive() && val==w) || (!wrapper->getCaseSensitive() && !strcasecmp(val.c_str(),w))) {
                        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                        "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                        SHIB_AP_CHECK_IS_OK;
                    }
                    else {
                        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(r),
                                        "shib_auth_checker() expecting %s, got %s: authorization not granted", w, val.c_str());
                    }
                }
                catch (XMLException& ex) {
                    auto_ptr_char tmp(ex.getMessage());
                    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
                                    "shib_auth_checker caught exception while parsing regular expression (%s): %s",w,tmp.get());
                }
            }
        }
    }

    // check if all require directives are true
    bool auth_all_OK = true;
    for (int i= 0; i<reqs_arr->nelts; i++) {
        auth_all_OK &= auth_OK[i];
    }
    if (auth_all_OK)
        return OK;

    if (!method_restricted)
        return OK;

    if (!application_id) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_auth_checker: Shib-Application-ID header not found in request");
        return HTTP_FORBIDDEN;
    }
    else if (!application) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,SH_AP_R(r),
           "shib_auth_checker: unable to map request to application settings, check configuration");
        return HTTP_FORBIDDEN;
    }

    ShibMLP markupProcessor;
    markupProcessor.insert("requestURL", ap_construct_url(r->pool,r->unparsed_uri,r));
    return shib_error_page(r, application, "access", markupProcessor);
}
#endif /* 0 */

#ifndef SHIB_APACHE_13
/*
 * shib_exit()
 *  Empty cleanup hook, Apache 2.x doesn't check NULL very well...
 */
extern "C" apr_status_t shib_exit(void* data)
{
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
            ShibTargetConfig::SHIREExtensions |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(g_szSchemaDir,g_szSHIBConfig)) {
            ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to initialize SHIB Target");
            exit(1);
        }
    }
    catch (...) {
        ap_log_error(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,SH_AP_R(s),"shib_child_init() failed to initialize SHIB Target");
        exit (1);
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
   
  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibRequireSession", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireSession),
   OR_AUTHCFG, FLAG, "Initiates a new session if one does not exist."},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML assertion to Shibboleth-defined header?"},
  {"AuthGroupFile", (config_fn_t)ap_set_file_slot,
   (void *) XtOffsetOf (shib_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibRequireAll", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireAll),
   OR_AUTHCFG, FLAG, "All require directives must match!"},

  {NULL}
};

extern "C"{
handler_rec shib_handlers[] = {
  { "shib-shire-post", shib_post_handler },
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
  ap_hook_handler(shib_post_handler, NULL, NULL, APR_HOOK_LAST);
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

  AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bBasicHijack),
	       OR_AUTHCFG, "Respond to AuthType Basic and convert to shib?"),
  AP_INIT_FLAG("ShibRequireSession", (config_fn_t)ap_set_flag_slot,
         (void *) offsetof (shib_dir_config, bRequireSession),
        OR_AUTHCFG, "Initiates a new session if one does not exist."),
  AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
         (void *) offsetof (shib_dir_config, bExportAssertion),
        OR_AUTHCFG, "Export SAML assertion to Shibboleth-defined header?"),
  AP_INIT_TAKE1("AuthGroupFile", (config_fn_t)ap_set_file_slot,
		(void *) offsetof (shib_dir_config, szAuthGrpFile),
		OR_AUTHCFG, "text file containing group names and member user IDs"),
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
