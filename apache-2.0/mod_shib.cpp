/*
 * mod_shib.cpp -- Shibboleth module for Apache-2.0
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#include <util_script.h>
#include <apr_strings.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

// For POST processing from Apache
//-- do we still need this? #undef _XOPEN_SOURCE		// bombs on solaris
#include <apreq_params.h>

#include <unistd.h>		// for getpid()

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern "C" AP_MODULE_DECLARE_DATA module mod_shib;

namespace {
    char* g_szSHIREURL = NULL;
    char* g_szSHIBConfig = NULL;
    ThreadKey* rpc_handle_key = NULL;
    ShibTargetConfig* g_Config = NULL;
}

// per-dir module configuration structure
struct shib_dir_config
{
    int bBasicHijack;		// activate for AuthType Basic?
    int bSSLOnly;		// only over SSL?
    SHIREConfig config;		// SHIB Configuration
    RMConfig rm_config;		// RM Configuration
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (apr_pool_t* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)apr_pcalloc(p,sizeof(shib_dir_config));
    dc->bBasicHijack = -1;
    dc->bSSLOnly = -1;
    dc->config.lifetime = -1;
    dc->config.timeout = -1;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shib_dir_config (apr_pool_t* p, void* base, void* sub)
{
    shib_dir_config* dc=(shib_dir_config*)apr_pcalloc(p,sizeof(shib_dir_config));
    shib_dir_config* parent=(shib_dir_config*)base;
    shib_dir_config* child=(shib_dir_config*)sub;

    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    dc->config.lifetime=((child->config.lifetime==-1) ? parent->config.lifetime : child->config.lifetime);
    dc->config.timeout=((child->config.timeout==-1) ? parent->config.timeout : child->config.timeout);
    return dc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=apr_pstrdup(parms->pool,arg);
    return NULL;
}

// some shortcuts for directory config slots
extern "C" const char* set_lifetime(cmd_parms* parms, shib_dir_config* dc, const char* arg)
{
    dc->config.lifetime=atoi(arg);
    return NULL;
}

extern "C" const char* set_timeout(cmd_parms* parms, shib_dir_config* dc, const char* arg)
{
    dc->config.timeout=atoi(arg);
    return NULL;
}

typedef const char* (*config_fn_t)(void);

// SHIB Module commands

static command_rec shib_cmds[] = {
  {"SHIBConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
   RSRC_CONF, TAKE1, "Path to SHIB ini file."},
  {"SHIREURL", (config_fn_t)ap_set_global_string_slot, &g_szSHIREURL,
   RSRC_CONF, TAKE1, "SHIRE POST processor URL."},

  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) offsetof (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibSSLOnly", (config_fn_t)ap_set_flag_slot,
   (void *) offsetof (shib_dir_config, bSSLOnly),
   OR_AUTHCFG, FLAG, "Require SSL when accessing a secured directory?"},
  {"ShibAuthLifetime", (config_fn_t)set_lifetime, NULL,
   OR_AUTHCFG, TAKE1, "Lifetime of session in seconds."},
  {"ShibAuthTimeout", (config_fn_t)set_timeout, NULL,
   OR_AUTHCFG, TAKE1, "Timeout for session in seconds."},

  {NULL}
};

namespace {
    void destroy_handle(void* data)
    {
        delete (RPCHandle*)data;
    }
}

/* 
 * shib_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shib_child_init(server_rec* s, apr_pool_t* p)
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,
		 "shib_child_init() starting");

    if (g_Config) {
      ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,s,
		   "shib_child_init(): already initialized!");
      exit (1);
    }

    try {
      g_Config = &(ShibTargetConfig::init(SHIBTARGET_SHIRE, g_szSHIBConfig));
    } catch (...) {
      ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,
		   "shib_child_init() failed to initialize SHIB Target");
      exit (1);
    }

    // Create the RPC Handle TLS key.
    rpc_handle_key=ThreadKey::create(destroy_handle);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,"shib_child_init() done");
}


/*
 * shib_child_exit()
 *  Cleanup.
 */
extern "C" void shib_child_exit(server_rec* s, apr_pool_t* p)
{
    delete rpc_handle_key;
    g_Config->shutdown();
    g_Config = NULL;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,"shib_child_exit() done");
}

inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

static char* url_encode(request_rec* r, const char* s)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";
    char* ret=(char*)apr_palloc(r->pool,sizeof(char)*3*strlen(s)+1);

    unsigned long count=0;
    for (; *s; s++)
    {
        if (strchr(badchars,*s)!=NULL || *s<=0x1F || *s>=0x7F)
        {
	    ret[count++]='%';
	    ret[count++]=hexchar(*s >> 4);
	    ret[count++]=hexchar(*s & 0x0F);
	}
	else
	    ret[count++]=*s;
    }
    ret[count++]=*s;
    return ret;
}

static const char* get_shire_location(request_rec* r, const char* target, bool encode)
{
  ShibINI& ini = g_Config->getINI();
  string shire_location;

  if (g_szSHIREURL)
    shire_location = g_szSHIREURL;
  else if (! ini.get_tag (ap_get_server_name(r), "shireURL", true, &shire_location)) {
    ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
		  "shire_get_location() no shireURL configuration for %s",
		  ap_get_server_name(r));
    return NULL;
  }

  const char* shire = shire_location.c_str();

  if (*shire != '/') {
    if (encode)
      return url_encode(r,shire);
    else
      return apr_pstrdup(r->pool,shire);
    }    
    const char* colon=strchr(target,':');
    const char* slash=strchr(colon+3,'/');
    if (encode)
      return url_encode(r,apr_pstrcat(r->pool,
				     apr_pstrndup(r->pool,target,slash-target),
				     shire,NULL));
    else
      return apr_pstrcat(r->pool, apr_pstrndup(r->pool,target,slash-target),
			shire, NULL);
}

static bool is_shire_location(request_rec* r, const char* target)
{
  const char* shire = get_shire_location(r, target, false);

  if (!shire) return false;

  if (!strstr(target, shire))
    return false;

  return (!strcmp(target,shire));
}

static int shib_error_page(request_rec* r, const char* filename, ShibMLP& mlp)
{
  ifstream infile (filename);
  if (!infile) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
		    "shib_error_page() cannot open %s", filename);
      return HTTP_INTERNAL_SERVER_ERROR;
  }

  string res = mlp.run(infile);
  r->content_type = apr_psprintf(r->pool, "text/html");
  ap_rprintf(r, res.c_str());
  return DONE;
}

extern "C" int shib_check_user(request_rec* r)
{
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_check_user: ENTER");
    shib_dir_config* dc=(shib_dir_config*)ap_get_module_config(r->per_dir_config,&mod_shib);

    // This will always be normalized, because Apache uses ap_get_server_name in this API call.
    char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

    if (is_shire_location (r, targeturl)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
           "shib_check_user: REQUEST FOR SHIRE!  Maybe you did not configure the SHIRE Handler?");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
      // Regular access to arbitrary resource...check AuthType
      const char *auth_type=ap_auth_type (r);
      if (!auth_type)
        return DECLINED;

      if (strcasecmp(auth_type,"shibboleth"))
      {
        if (!strcasecmp(auth_type,"basic") && dc->bBasicHijack==1)
        {
            core_dir_config* conf=
                (core_dir_config*)ap_get_module_config(r->per_dir_config,
                    ap_find_linked_module("http_core.c"));
            conf->ap_auth_type="shibboleth";
        }
        else
            return DECLINED;
      }

      // set the connection authtype
      r->ap_auth_type = "shibboleth";

      // SSL check.
      if (dc->bSSLOnly==1 && strcmp(ap_http_method(r),"https"))
      {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
           "shib_check_user() blocked non-SSL access");
        return HTTP_INTERNAL_SERVER_ERROR;
      }
    }

    ostringstream threadid;
    threadid << "[" << getpid() << "] shib" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    ShibINI& ini = g_Config->getINI();

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                    "shib_check_user() Shib check for %s", targeturl);


    const char * shire_location = get_shire_location(r,targeturl,true);
    if (!shire_location)
        return HTTP_INTERNAL_SERVER_ERROR;
    string shire_url = get_shire_location(r,targeturl,false);

    const char* serverName = ap_get_server_name(r);
    string tag;
    bool has_tag = ini.get_tag (serverName, "checkIPAddress", true, &tag);
    dc->config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);

    string shib_cookie;
    if (! ini.get_tag(serverName, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no cookieName configuration for %s",
		    serverName);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    string wayfLocation;
    if (! ini.get_tag(serverName, "wayfURL", true, &wayfLocation)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no wayfURL configuration for %s",
		    serverName);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    string shireError;
    if (! ini.get_tag(serverName, "shireError", true, &shireError)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no shireError configuration for %s",
		    serverName);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    // Get an RPC handle and build the SHIRE object.
    RPCHandle* rpc_handle = (RPCHandle*)rpc_handle_key->getData();
    if (!rpc_handle)
    {
        rpc_handle = new RPCHandle(shib_target_sockname(), SHIBRPC_PROG, SHIBRPC_VERS_1);
        rpc_handle_key->setData(rpc_handle);
    }
    SHIRE shire(rpc_handle, dc->config, shire_url);

    // We're in charge, so check for cookie.
    const char* session_id=NULL;
    const char* cookies=apr_table_get(r->headers_in,"Cookie");

    if (cookies)
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                    "shib_check_user() cookies found: %s",cookies);		      

    if (!cookies || !(session_id=strstr(cookies,shib_cookie.c_str())))
    {
        // No cookie.  Redirect to WAYF.
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		      "shib_check_user() no cookie found -- redirecting to WAYF");
        char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,targeturl),NULL);
        apr_table_setn(r->headers_out,"Location",wayf);
        return HTTP_MOVED_TEMPORARILY;
    }

    // Yep, we found a cookie -- pull it out (our session_id)
    session_id+=strlen(shib_cookie.c_str()) + 1;	/* Skip over the '=' */
    char* cookiebuf = apr_pstrdup(r->pool,session_id);
    char* cookieend = strchr(cookiebuf,';');
    if (cookieend)
        *cookieend = '\0';	/* Ignore anyting after a ; */
    session_id=cookiebuf;

    // Make sure this session is still valid
    RPCError* status = NULL;
    ShibMLP markupProcessor;
    has_tag = ini.get_tag(serverName, "supportContact", true, &tag);
    markupProcessor.insert("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag(serverName, "logoLocation", true, &tag);
    markupProcessor.insert("logoLocation", has_tag ? tag : "");
    markupProcessor.insert("requestURL", targeturl);

    try {
        status = shire.sessionIsValid(session_id, r->connection->remote_ip,targeturl);
    }
    catch (ShibTargetException &e) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_check_user(): %s", e.what());
        markupProcessor.insert ("errorType", "SHIRE Processing Error");
        markupProcessor.insert ("errorText", e.what());
        markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
        return shib_error_page (r, shireError.c_str(), markupProcessor);
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_check_user(): caught unexpected error");
        markupProcessor.insert ("errorType", "SHIRE Processing Error");
        markupProcessor.insert ("errorText", "Unexpected Exception");
        markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
        return shib_error_page (r, shireError.c_str(), markupProcessor);
    }

    // Check the status
    if (status->isError()) {
        ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,0,r,
		      "shib_check_user() session invalid: %s",
		      status->getText());

        if (status->isRetryable()) {
            // Oops, session is invalid.  Redirect to WAYF.
            char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
				"?shire=",shire_location,
				"&target=",url_encode(r,targeturl),NULL);
            apr_table_setn(r->headers_out,"Location",wayf);

            delete status;
            return HTTP_MOVED_TEMPORARILY;
        }
        else {
            // return the error page to the user
            markupProcessor.insert (*status);
            delete status;
            return shib_error_page (r, shireError.c_str(), markupProcessor);
        }
    }
    else {
        delete status;
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		      "shib_check_user() success");
        return OK;
    }

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,"shib_check_user() server error");
    return HTTP_INTERNAL_SERVER_ERROR;
}

extern "C" int shire_post_handler (request_rec* r)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shire" << '\0';
  saml::NDC ndc(threadid.str().c_str());

  ShibINI& ini = g_Config->getINI();
  ShibMLP markupProcessor;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shire_post_handler() ENTER");

  const char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);
 
  const char * shire_location = get_shire_location(r,targeturl,true);
  if (!shire_location)
      return HTTP_INTERNAL_SERVER_ERROR;
  string shire_url = get_shire_location(r,targeturl,false);

  const char* serverName = ap_get_server_name(r);
  string tag;
  bool has_tag = ini.get_tag(serverName, "checkIPAddress", true, &tag);
  SHIREConfig config;
  config.checkIPAddress = (has_tag ? ShibINI::boolean(tag) : false);

  string shib_cookie;
  if (! ini.get_tag(serverName, "cookieName", true, &shib_cookie)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no cookieName configuration for %s",
		  serverName);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  string wayfLocation;
  if (! ini.get_tag(serverName, "wayfURL", true, &wayfLocation)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no wayfURL configuration for %s",
		  serverName);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  string shireError;
  if (! ini.get_tag(serverName, "shireError", true, &shireError)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no shireError configuration for %s",
		  serverName);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  has_tag = ini.get_tag(serverName, "supportContact", true, &tag);
  markupProcessor.insert("supportContact", has_tag ? tag : "");
  has_tag = ini.get_tag(serverName, "logoLocation", true, &tag);
  markupProcessor.insert("logoLocation", has_tag ? tag : "");
  markupProcessor.insert("requestURL", targeturl);
  
    // Get an RPC handle and build the SHIRE object.
    RPCHandle* rpc_handle = (RPCHandle*)rpc_handle_key->getData();
    if (!rpc_handle)
    {
        rpc_handle = new RPCHandle(shib_target_sockname(), SHIBRPC_PROG, SHIBRPC_VERS_1);
        rpc_handle_key->setData(rpc_handle);
    }
    SHIRE shire(rpc_handle, config, shire_url);

  // Process SHIRE POST

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		"shire_post_handler() Beginning SHIRE POST processing");
      
  try {
    string sslonly;
    if (!ini.get_tag(serverName, "shireSSLOnly", true, &sslonly))
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shire_post_handler: no shireSSLOnly configuration");
    
    // Make sure this is SSL, if it should be
    if (ShibINI::boolean(sslonly) && strcmp(ap_http_method(r),"https"))
      throw ShibTargetException (SHIBRPC_OK,
				 "blocked non-SSL access to SHIRE POST processor");

    // Make sure this is a POST
    if (strcasecmp (r->method, "POST"))
      throw ShibTargetException (SHIBRPC_OK,
				 "blocked non-POST to SHIRE POST processor");

    // Sure sure this POST is an appropriate content type
    const char *ct = apr_table_get (r->headers_in, "Content-type");
    if (!ct || strcasecmp (ct, "application/x-www-form-urlencoded"))
      throw ShibTargetException (SHIBRPC_OK,
				 apr_psprintf(r->pool,
			     "blocked bad content-type to SHIRE POST processor: %s",
					     (ct ? ct : "")));
	
    // Make sure the "bytes sent" is a reasonable number
    if (r->bytes_sent > 1024*1024) // 1MB?
      throw ShibTargetException (SHIBRPC_OK,
				 "blocked too-large a post to SHIRE POST processor");

    // Read the posted data
    apreq_request_t *ap_req = apreq_request(r, NULL);
    if (!ap_req)
      throw ShibTargetException (SHIBRPC_OK,
				 apr_psprintf(r->pool, "apreq_request() failed"));
    
    // Make sure the target parameter exists
    apreq_param_t *param = apreq_param(ap_req, "TARGET");
    const char *target = param ? apreq_param_value(param) : NULL;
    if (!target || *target == '\0')
      // invalid post
      throw ShibTargetException (SHIBRPC_OK,
				 "SHIRE POST failed to find TARGET");

    // Make sure the SAML Response parameter exists
    param = apreq_param(ap_req, "SAMLResponse");
    const char *post = param ? apreq_param_value(param) : NULL;
    if (!post || *post == '\0')
      // invalid post
      throw ShibTargetException (SHIBRPC_OK,
				 "SHIRE POST failed to find SAMLResponse");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() Processing POST for target: %s", target);

    // process the post
    string cookie;
    RPCError* status = shire.sessionCreate(post, r->connection->remote_ip, cookie);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shire_post_handler() POST process failed (%d): %s",
		    status->getCode(), status->getText());

      if (status->isRetryable()) {
	ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,0,r,
		      "shire_post_handler() Retrying POST by redirecting to WAYF");
	
	char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,target),NULL);
	apr_table_setn(r->headers_out,"Location",wayf);
	delete status;
	return HTTP_MOVED_TEMPORARILY;
      }

      // return this error to the user.
      markupProcessor.insert (*status);
      delete status;
      return shib_error_page (r, shireError.c_str(), markupProcessor);
    }
    delete status;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() POST process succeeded.  New cookie: %s",
		  cookie.c_str());

    // We've got a good session, set the cookie...
    char * domain = NULL;
    char * new_cookie = apr_psprintf(r->pool, "%s=%s; path=/%s%s",
				    shib_cookie.c_str(),
				    cookie.c_str(),
				    (domain ? "; domain=" : ""),
				    (domain ? domain : ""));
    
    apr_table_setn(r->err_headers_out, "Set-Cookie", new_cookie);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() Set cookie: %s", new_cookie);
		    
    // ... and redirect to the target
    char* redir=apr_pstrcat(r->pool,url_encode(r,target),NULL);
    apr_table_setn(r->headers_out, "Location", target);
    return HTTP_MOVED_TEMPORARILY;

  } catch (ShibTargetException &e) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler(): %s", e.what());
	
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", e.what());
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    return shib_error_page (r, shireError.c_str(), markupProcessor);
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shire_post_handler(): unexpected exception");
  
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", "Unexpected Exception");
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    return shib_error_page (r, shireError.c_str(), markupProcessor);
  }

  ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,"shire_post_handler() server error");
  return HTTP_INTERNAL_SERVER_ERROR;
}

#if 0
extern "C"{
handler_rec shib_handlers[] = {
  { "shib-shire-post", shire_post_handler },
  { NULL }
};
#endif

extern "C" void mod_shib_init (server_rec*r, apr_pool_t* p)
{
  ShibTargetConfig::preinit();
}

extern "C" {
command_rec shib_commands[] = {

};

void shib_register_hooks (apr_pool_t *p)
{
}

module AP_MODULE_DECLARE_DATA mod_shib = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,	/* create dir config */
    merge_shib_dir_config,	/* merge dir config --- default is to override */
    NULL,	                /* create server config */
    NULL,	                /* merge server config */
    shib_commands,		/* command table */
    shib_register_hooks		/* register hooks */
};
} /* extern "C" */

#if 0
    shib_handlers,
    mod_shib_init,		/* initializer */
    NULL,			/* filename translation */
    shib_check_user,		/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shib_child_init,		/* child_init */
    shib_child_exit,		/* child_exit */
    NULL			/* post read-request */
#endif
