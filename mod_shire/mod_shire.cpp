/*
 * mod_shire.cpp -- the SHIRE Apache Module
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
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "util_script.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_log.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

// For POST processing from Apache
#undef _XOPEN_SOURCE		// bombs on solaris
#include <libapreq/apache_request.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern "C" module MODULE_VAR_EXPORT shire_module;

namespace {
    char* g_szSHIREURL = NULL;
    char* g_szSHIREConfig = NULL;
    ThreadKey* rpc_handle_key = NULL;
    ShibTargetConfig* g_Config = NULL;
}

// per-dir module configuration structure
struct shire_dir_config
{
    int bBasicHijack;		// activate for AuthType Basic?
    int bSSLOnly;		// only over SSL?
    SHIREConfig config;		// SHIRE Configuration
};

// creates per-directory config structure
extern "C" void* create_shire_dir_config (pool* p, char* d)
{
    shire_dir_config* dc=(shire_dir_config*)ap_pcalloc(p,sizeof(shire_dir_config));
    dc->bBasicHijack = -1;
    dc->bSSLOnly = -1;
    dc->config.lifetime = -1;
    dc->config.timeout = -1;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shire_dir_config (pool* p, void* base, void* sub)
{
    shire_dir_config* dc=(shire_dir_config*)ap_pcalloc(p,sizeof(shire_dir_config));
    shire_dir_config* parent=(shire_dir_config*)base;
    shire_dir_config* child=(shire_dir_config*)sub;

    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    dc->config.lifetime=((child->config.lifetime==-1) ? parent->config.lifetime : child->config.lifetime);
    dc->config.timeout=((child->config.timeout==-1) ? parent->config.timeout : child->config.timeout);
    return dc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

// some shortcuts for directory config slots
extern "C" const char* set_lifetime(cmd_parms* parms, shire_dir_config* dc, const char* arg)
{
    dc->config.lifetime=atoi(arg);
    return NULL;
}

extern "C" const char* set_timeout(cmd_parms* parms, shire_dir_config* dc, const char* arg)
{
    dc->config.timeout=atoi(arg);
    return NULL;
}

typedef const char* (*config_fn_t)(void);

// SHIRE Module commands

static command_rec shire_cmds[] = {
  {"SHIREConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIREConfig,
   RSRC_CONF, TAKE1, "Path to SHIRE ini file."},
  {"SHIREURL", (config_fn_t)ap_set_global_string_slot, &g_szSHIREURL,
   RSRC_CONF, TAKE1, "SHIRE POST processor URL."},

  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibSSLOnly", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_dir_config, bSSLOnly),
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
 * shire_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shire_child_init(server_rec* s, pool* p)
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
		 "shire_child_init() starting");

    if (g_Config) {
      ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,s,
		   "shire_child_init(): already initialized!");
      exit (1);
    }

    try {
      g_Config = &(ShibTargetConfig::init(SHIBTARGET_SHIRE, g_szSHIREConfig));
    } catch (...) {
      ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
		   "shire_child_init() failed to initialize SHIB Target");
      exit (1);
    }

    // Create the RPC Handle TLS key.
    rpc_handle_key=ThreadKey::create(destroy_handle);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shire_child_init() done");
}


/*
 * shire_child_exit()
 *  Cleanup.
 */
extern "C" void shire_child_exit(server_rec* s, pool* p)
{
    delete rpc_handle_key;
    g_Config->shutdown();
    g_Config = NULL;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shire_child_exit() done");
}

inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

static char* url_encode(request_rec* r, const char* s)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";
    char* ret=(char*)ap_palloc(r->pool,sizeof(char)*3*strlen(s)+1);

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
    ap_log_rerror(APLOG_MARK,APLOG_ERR,r,
		  "shire_get_location() no shireURL configuration for %s",
		  ap_get_server_name(r));
    return NULL;
  }

  const char* shire = shire_location.c_str();

  if (*shire != '/') {
    if (encode)
      return url_encode(r,shire);
    else
      return ap_pstrdup(r->pool,shire);
    }    
    const char* colon=strchr(target,':');
    const char* slash=strchr(colon+3,'/');
    if (encode)
      return url_encode(r,ap_pstrcat(r->pool,
				     ap_pstrndup(r->pool,target,slash-target),
				     shire,NULL));
    else
      return ap_pstrcat(r->pool, ap_pstrndup(r->pool,target,slash-target),
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

static int shire_error_page(request_rec* r, const char* filename, ShibMLP& mlp)
{
  ifstream infile (filename);
  if (!infile) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR,r,
		    "shire_error_page() cannot open %s", filename);
      return SERVER_ERROR;
  }

  string res = mlp.run(infile);
  r->content_type = ap_psprintf(r->pool, "text/html");
  ap_send_http_header(r);
  ap_rprintf(r, res.c_str());
  return DONE;
}

extern "C" int shire_check_user(request_rec* r)
{
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shire_check_user: ENTER");
    shire_dir_config* dc=(shire_dir_config*)ap_get_module_config(r->per_dir_config,&shire_module);

    // This will always be normalized, because Apache uses ap_get_server_name in this API call.
    char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

    if (is_shire_location (r, targeturl)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
           "shire_check_user: REQUEST FOR SHIRE!  Maybe you did not configure the SHIRE Handler?");
      return SERVER_ERROR;
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
      if (r->connection)
        r->connection->ap_auth_type = "shibboleth";

      // SSL check.
      if (dc->bSSLOnly==1 && strcmp(ap_http_method(r),"https"))
      {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
           "shire_check_user() blocked non-SSL access");
        return SERVER_ERROR;
      }
    }

    ostringstream threadid;
    threadid << "[" << getpid() << "] shire" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    ShibINI& ini = g_Config->getINI();

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                    "shire_check_user() Shib check for %s", targeturl);


    const char * shire_location = get_shire_location(r,targeturl,true);
    if (!shire_location)
        return SERVER_ERROR;
    string shire_url = get_shire_location(r,targeturl,false);

    const char* serverName = ap_get_server_name(r);
    string tag;
    bool has_tag = ini.get_tag (serverName, "checkIPAddress", true, &tag);
    dc->config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);

    string shib_cookie;
    if (! ini.get_tag(serverName, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		    "shire_check_user: no cookieName configuration for %s",
		    serverName);
      return SERVER_ERROR;
    }

    string wayfLocation;
    if (! ini.get_tag(serverName, "wayfURL", true, &wayfLocation)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		    "shire_check_user: no wayfURL configuration for %s",
		    serverName);
      return SERVER_ERROR;
    }

    string shireError;
    if (! ini.get_tag(serverName, "shireError", true, &shireError)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		    "shire_check_user: no shireError configuration for %s",
		    serverName);
      return SERVER_ERROR;
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
    const char* cookies=ap_table_get(r->headers_in,"Cookie");

    if (cookies)
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                        "shire_check_user() cookies found: %s",cookies);
        if (session_id=strstr(cookies,shib_cookie.c_str()))
        {
            // Yep, we found a cookie -- pull it out (our session_id)
            session_id+=strlen(shib_cookie.c_str()) + 1; /* Skip over the '=' */
            char* cookiebuf = ap_pstrdup(r->pool,session_id);
            char* cookieend = strchr(cookiebuf,';');
            if (cookieend)
                *cookieend = '\0';    /* Ignore anyting after a ; */
            session_id=cookiebuf;
        }
    }

    if (!session_id || !*session_id)
    {
        // No acceptable cookie.  Redirect to WAYF.
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() no cookie found -- redirecting to WAYF");
        char* wayf=ap_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,targeturl),NULL);
        ap_table_setn(r->headers_out,"Location",wayf);
        return REDIRECT;
    }

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
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shire_check_user(): %s", e.what());
        markupProcessor.insert ("errorType", "SHIRE Processing Error");
        markupProcessor.insert ("errorText", e.what());
        markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
        return shire_error_page (r, shireError.c_str(), markupProcessor);
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shire_check_user(): caught unexpected error");
        markupProcessor.insert ("errorType", "SHIRE Processing Error");
        markupProcessor.insert ("errorText", "Unexpected Exception");
        markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
        return shire_error_page (r, shireError.c_str(), markupProcessor);
    }

    // Check the status
    if (status->isError()) {
        ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
		      "shire_check_user() session invalid: %s",
		      status->getText());

        if (status->isRetryable()) {
            // Oops, session is invalid.  Redirect to WAYF.
            char* wayf=ap_pstrcat(r->pool,wayfLocation.c_str(),
				"?shire=",shire_location,
				"&target=",url_encode(r,targeturl),NULL);
            ap_table_setn(r->headers_out,"Location",wayf);

            delete status;
            return REDIRECT;
        }
        else {
            // return the error page to the user
            markupProcessor.insert (*status);
            delete status;
            return shire_error_page (r, shireError.c_str(), markupProcessor);
        }
    }
    else {
        delete status;
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() success");
        return OK;
    }

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,"shire_check_user() server error");
    return SERVER_ERROR;
}

extern "C" int shire_post_handler (request_rec* r)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shire" << '\0';
  saml::NDC ndc(threadid.str().c_str());

  ShibINI& ini = g_Config->getINI();
  ShibMLP markupProcessor;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shire_post_handler() ENTER");

  const char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);
 
  const char * shire_location = get_shire_location(r,targeturl,true);
  if (!shire_location)
      return SERVER_ERROR;
  string shire_url = get_shire_location(r,targeturl,false);

  const char* serverName = ap_get_server_name(r);
  string tag;
  bool has_tag = ini.get_tag(serverName, "checkIPAddress", true, &tag);
  SHIREConfig config;
  config.checkIPAddress = (has_tag ? ShibINI::boolean(tag) : false);

  string shib_cookie;
  if (! ini.get_tag(serverName, "cookieName", true, &shib_cookie)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		  "shire_check_user: no cookieName configuration for %s",
		  serverName);
    return SERVER_ERROR;
  }

  string wayfLocation;
  if (! ini.get_tag(serverName, "wayfURL", true, &wayfLocation)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		  "shire_check_user: no wayfURL configuration for %s",
		  serverName);
    return SERVER_ERROR;
  }

  string shireError;
  if (! ini.get_tag(serverName, "shireError", true, &shireError)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		  "shire_check_user: no shireError configuration for %s",
		  serverName);
    return SERVER_ERROR;
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

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		"shire_post_handler() Beginning SHIRE POST processing");
      
  try {
    string sslonly;
    if (!ini.get_tag(serverName, "shireSSLOnly", true, &sslonly))
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
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
    const char *ct = ap_table_get (r->headers_in, "Content-type");
    if (!ct || strcasecmp (ct, "application/x-www-form-urlencoded"))
      throw ShibTargetException (SHIBRPC_OK,
				 ap_psprintf(r->pool,
			     "blocked bad content-type to SHIRE POST processor: %s",
					     (ct ? ct : "")));
	
    // Make sure the "bytes sent" is a reasonable number
    if (r->bytes_sent > 1024*1024) // 1MB?
      throw ShibTargetException (SHIBRPC_OK,
				 "blocked too-large a post to SHIRE POST processor");

    // Read the posted data
    ApacheRequest *ap_req = ApacheRequest_new(r);
    int err = ApacheRequest_parse(ap_req);
    if (err != OK)
      throw ShibTargetException (SHIBRPC_OK,
				 ap_psprintf(r->pool,
			     "ApacheRequest_parse() failed with %d.", err));

    
    // Make sure the target parameter exists
    const char *target = ApacheRequest_param(ap_req, "TARGET");
    if (!target || *target == '\0')
      // invalid post
      throw ShibTargetException (SHIBRPC_OK,
				 "SHIRE POST failed to find TARGET");

    // Make sure the SAML Response parameter exists
    const char *post = ApacheRequest_param(ap_req, "SAMLResponse");
    if (!post || *post == '\0')
      // invalid post
      throw ShibTargetException (SHIBRPC_OK,
				 "SHIRE POST failed to find SAMLResponse");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shire_post_handler() Processing POST for target: %s", target);

    // process the post
    string cookie;
    RPCError* status = shire.sessionCreate(post, r->connection->remote_ip, cookie);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		    "shire_post_handler() POST process failed (%d): %s",
		    status->getCode(), status->getText());

      if (status->isRetryable()) {
	ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
		      "shire_post_handler() Retrying POST by redirecting to WAYF");
	
	char* wayf=ap_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,target),NULL);
	ap_table_setn(r->headers_out,"Location",wayf);
	delete status;
	return REDIRECT;
      }

      // return this error to the user.
      markupProcessor.insert (*status);
      delete status;
      return shire_error_page (r, shireError.c_str(), markupProcessor);
    }
    delete status;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shire_post_handler() POST process succeeded.  New cookie: %s",
		  cookie.c_str());

    // We've got a good session, set the cookie...
    char * domain = NULL;
    char * new_cookie = ap_psprintf(r->pool, "%s=%s; path=/%s%s",
				    shib_cookie.c_str(),
				    cookie.c_str(),
				    (domain ? "; domain=" : ""),
				    (domain ? domain : ""));
    
    ap_table_setn(r->err_headers_out, "Set-Cookie", new_cookie);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shire_post_handler() Set cookie: %s", new_cookie);
		    
    // ... and redirect to the target
    char* redir=ap_pstrcat(r->pool,url_encode(r,target),NULL);
    ap_table_setn(r->headers_out, "Location", target);
    return REDIRECT;

  } catch (ShibTargetException &e) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shire_post_handler(): %s", e.what());
	
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", e.what());
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    return shire_error_page (r, shireError.c_str(), markupProcessor);
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shire_post_handler(): unexpected exception");
  
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", "Unexpected Exception");
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    return shire_error_page (r, shireError.c_str(), markupProcessor);
  }

  ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,"shire_post_handler() server error");
  return SERVER_ERROR;
}

extern "C"{
handler_rec shire_handlers[] = {
  { "shib-shire-post", shire_post_handler },
  { NULL }
};

extern "C" void mod_shire_init (server_rec*r, pool* p)
{
  ShibTargetConfig::preinit();
}

module MODULE_VAR_EXPORT shire_module = {
    STANDARD_MODULE_STUFF,
    mod_shire_init,		/* initializer */
    create_shire_dir_config,	/* dir config creater */
    merge_shire_dir_config,	/* dir merger --- default is to override */
    NULL,	                /* server config */
    NULL,	                /* merge server config */
    shire_cmds,			/* command table */
    shire_handlers,		/* handlers */
    NULL,			/* filename translation */
    shire_check_user,		/* check_user_id */
    NULL,			/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shire_child_init,		/* child_init */
    shire_child_exit,		/* child_exit */
    NULL			/* post read-request */
};
}
