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
#include <http_request.h>
#include <util_script.h>
#include <apr_strings.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>
#include <apr_pools.h>

#include <xercesc/util/regx/RegularExpression.hpp>

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
    char* g_szSHIBConfig = NULL;
    ThreadKey* rpc_handle_key = NULL;
    ShibTargetConfig* g_Config = NULL;
}

// per-dir module configuration structure
struct shib_dir_config
{
    // RM Configuration
    char* szAuthGrpFile;	// Auth GroupFile name
    int bExportAssertion;       // export SAML assertion to the environment?
    int bDisableRM;		// disable the RM functionality?

    // SHIRE Configuration
    int bBasicHijack;		// activate for AuthType Basic?
    int bSSLOnly;		// only over SSL?
    SHIREConfig config;		// SHIB Configuration
    RMConfig rm_config;		// RM Configuration
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (apr_pool_t* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)apr_pcalloc(p,sizeof(shib_dir_config));
    dc->szAuthGrpFile = NULL;
    dc->bExportAssertion = -1;
    dc->bDisableRM = -1;

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

    if (child->szAuthGrpFile)
        dc->szAuthGrpFile=apr_pstrdup(p,child->szAuthGrpFile);
    else if (parent->szAuthGrpFile)
        dc->szAuthGrpFile=apr_pstrdup(p,parent->szAuthGrpFile);
    else
        dc->szAuthGrpFile=NULL;

    dc->bExportAssertion=((child->bExportAssertion==-1) ?
			  parent->bExportAssertion : child->bExportAssertion);
    dc->bDisableRM=((child->bDisableRM==-1) ?
		    parent->bDisableRM : child->bDisableRM);

    dc->bBasicHijack=((child->bBasicHijack==-1) ?
		      parent->bBasicHijack : child->bBasicHijack);
    dc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    dc->config.lifetime=((child->config.lifetime==-1) ?
			 parent->config.lifetime : child->config.lifetime);
    dc->config.timeout=((child->config.timeout==-1) ?
			parent->config.timeout : child->config.timeout);
    return dc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*,
						 const char* arg)
{
    *((char**)(parms->info))=apr_pstrdup(parms->pool,arg);
    return NULL;
}

// some shortcuts for directory config slots
extern "C" const char* set_lifetime(cmd_parms* parms, shib_dir_config* dc,
				    const char* arg)
{
    dc->config.lifetime=atoi(arg);
    return NULL;
}

extern "C" const char* set_timeout(cmd_parms* parms, shib_dir_config* dc,
				   const char* arg)
{
    dc->config.timeout=atoi(arg);
    return NULL;
}

typedef const char* (*config_fn_t)(void);

static char* url_encode(request_rec* r, const char* s)
{
    int len=strlen(s);
    char* ret=(char*)apr_palloc(r->pool,sizeof(char)*3*len+1);

    // apreq_decode takes a string and url-encodes it.  Don't ask why
    // the name is backwards.
    apreq_decode(ret, s, len);
    return ret;
}

static const char* get_shire_location(request_rec* r, const char* target,
				      bool encode)
{
  ShibINI& ini = g_Config->getINI();
  string shire_location;

  if (! ini.get_tag (ap_get_server_name(r), "shireURL", true, &shire_location)) {
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

// return the "normalized" target URL
static const char* get_target(request_rec* r, const char* target)
{
  string tag;
  if ((g_Config->getINI()).get_tag (ap_get_server_name(r), "normalizeRequest", true, &tag))
  {
    if (ShibINI::boolean (tag))
    {
        const char* colon=strchr(target,':');
        const char* slash=strchr(colon+3,'/');
        const char* second_colon=strchr(colon+3,':');
        return apr_pstrcat(r->pool,apr_pstrndup(r->pool,target,colon+3-target),
			  ap_get_server_name(r),
			  (second_colon && second_colon < slash) ?
			  second_colon : slash,
			  NULL);
    }
  }
  return target;
}

static apr_table_t* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    ap_configfile_t* f;
    apr_table_t* grps=apr_table_make(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if (ap_pcfg_openfile(&f,r->pool,grpfile) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
		      "groups_for_user() could not open group file: %s\n", grpfile);
	return NULL;
    }

    apr_pool_t* sp;
    if (apr_pool_create(&sp,r->pool) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
		      "groups_for_user() could not create a subpool");
	return NULL;
    }

    while (!(ap_cfg_getline(l,MAX_STRING_LEN,f)))
    {
        if ((*l=='#') || (!*l))
	    continue;
	ll = l;
	apr_pool_clear(sp);

	group_name=ap_getword(sp,&ll,':');

	while (*ll)
	{
	    w=ap_getword_conf(sp,&ll);
	    if (!strcmp(w,user))
	    {
	        apr_table_setn(grps,apr_pstrdup(r->pool,group_name),"in");
		break;
	    }
	}
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);
    return grps;
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
    RPCHandle* rpc_handle =
      RPCHandle::get_handle(rpc_handle_key, shib_target_sockname(),
			    SHIBRPC_PROG, SHIBRPC_VERS_1);

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

extern "C" int shib_shire_handler (request_rec* r)
{
  ostringstream threadid;
  threadid << "[" << getpid() << "] shire" << '\0';
  saml::NDC ndc(threadid.str().c_str());

  // This will always be normalized, because Apache uses
  // ap_get_server_name in this API call.
  char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

  // Make sure we only process the SHIRE posts.
  // Is the really the best way to determine if this is a POST request?
  if (!is_shire_location (r, targeturl))
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		"shire_post_handler() ENTER");

  ShibINI& ini = g_Config->getINI();
  ShibMLP markupProcessor;
 
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
  RPCHandle* rpc_handle =
    RPCHandle::get_handle(rpc_handle_key, shib_target_sockname(),
			  SHIBRPC_PROG, SHIBRPC_VERS_1);
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

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() POST contents: %s", post);

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

/*
 * shib_auth_checker() -- a simple resource manager to
 * process the .htaccess settings and copy attributes
 * into the HTTP headers.
 */
extern "C" int shib_auth_checker(request_rec *r)
{
    shib_dir_config* dc=
        (shib_dir_config*)ap_get_module_config(r->per_dir_config,&mod_shib);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shib_auth_checker() executing");

    // Regular access to arbitrary resource...check AuthType
    const char* auth_type=ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type,"shibboleth"))
        return DECLINED;

    ostringstream threadid;
    threadid << "[" << getpid() << "] shib" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    ShibINI& ini = g_Config->getINI();
    const char* serverName = ap_get_server_name(r);

    // Ok, this is a SHIB target; grab the cookie

    string shib_cookie;
    if (!ini.get_tag(serverName, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no cookieName configuration for %s",
		    serverName);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    const char* targeturl=get_target(r,ap_construct_url(r->pool,r->unparsed_uri,r));

    const char* session_id=NULL;
    const char* cookies=apr_table_get(r->headers_in,"Cookie");
    if (!cookies || !(session_id=strstr(cookies,shib_cookie.c_str())))
    {
      // No cookie???  Must be a server error!
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shib_auth_checker() no cookie found");

      return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Yep, we found a cookie -- pull it out (our session_id)
    session_id+=strlen(shib_cookie.c_str()) + 1;	/* Skip over the '=' */
    char* cookiebuf = apr_pstrdup(r->pool,session_id);
    char* cookieend = strchr(cookiebuf,';');
    if (cookieend)
      *cookieend = '\0';	/* Ignore anyting after a ; */
    session_id=cookiebuf;

    ShibMLP markupProcessor;
    string tag;
    bool has_tag = ini.get_tag(serverName, "supportContact", true, &tag);
    markupProcessor.insert("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag(serverName, "logoLocation", true, &tag);
    markupProcessor.insert("logoLocation", has_tag ? tag : "");
    markupProcessor.insert("requestURL", targeturl);

    // Now grab the attributes...
    has_tag = ini.get_tag (serverName, "checkIPAddress", true, &tag);
    dc->rm_config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);

    // Get an RPC handle and build the RM object.
    RPCHandle* rpc_handle =
      RPCHandle::get_handle(rpc_handle_key, shib_target_sockname(),
			    SHIBRPC_PROG, SHIBRPC_VERS_1);
    RM rm(rpc_handle, dc->rm_config);

    vector<SAMLAssertion*> assertions;
    SAMLAuthenticationStatement* sso_statement=NULL;
    RPCError* status = rm.getAssertions(session_id, r->connection->remote_ip, targeturl, assertions, &sso_statement);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shib_auth_checker() getAssertions failed: %s",
		    status->getText());

      string rmError;
      if (!ini.get_tag(serverName, "rmError", true, &rmError)) {
        ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		      "shib_auth_checker: no rmError configuration for %s",
		      serverName);
        delete status;
        return HTTP_INTERNAL_SERVER_ERROR;	
      }
      markupProcessor.insert(*status);
      delete status;
      return shib_error_page (r, rmError.c_str(), markupProcessor);
    }
    delete status;

    string rmError;
    if (!ini.get_tag(serverName, "accessError", true, &rmError)) {
        ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
           "shib_auth_checker: no accessError configuration for %s",
            serverName);

        delete status;
        for (int k = 0; k < assertions.size(); k++)
          delete assertions[k];
        delete sso_statement;
        return HTTP_INTERNAL_SERVER_ERROR;  
    }

    // Only allow a single assertion...
    if (assertions.size() > 1) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shib_auth_checker() found %d assertions (only handle 1 currently)",
		    assertions.size());
        for (int k = 0; k < assertions.size(); k++)
          delete assertions[k];
        delete sso_statement;
        return shib_error_page (r, rmError.c_str(), markupProcessor);
    }

    // Get the AAP providers, which contain the attribute policy info.
    Iterator<IAAP*> provs=ShibConfig::getConfig().getAAPProviders();

    // Clear out the list of mapped attributes
    while (provs.hasNext())
    {
        IAAP* aap=provs.next();
        aap->lock();
        try
        {
            Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
            while (rules.hasNext())
            {
                const char* header=rules.next()->getHeader();
                if (header)
                    apr_table_unset(r->headers_in,header);
            }
        }
        catch(...)
        {
            aap->unlock();
            for (int k = 0; k < assertions.size(); k++)
              delete assertions[k];
            delete sso_statement;
            throw;
        }
        aap->unlock();
    }
    provs.reset();
    
    // Maybe export the assertion.
    apr_table_unset(r->headers_in,"Shib-Attributes");
    if (dc->bExportAssertion==1 && assertions.size()==1) {
        string assertion;
        RM::serialize(*(assertions[0]), assertion);
        apr_table_set(r->headers_in,"Shib-Attributes", assertion.c_str());
    }

    // Export the SAML AuthnMethod and the origin site name.
    apr_table_unset(r->headers_in,"Shib-Origin-Site");
    apr_table_unset(r->headers_in,"Shib-Authentication-Method");
    if (sso_statement)
    {
        auto_ptr<char> os(XMLString::transcode(sso_statement->getSubject()->getNameQualifier()));
        auto_ptr<char> am(XMLString::transcode(sso_statement->getAuthMethod()));
        apr_table_set(r->headers_in,"Shib-Origin-Site", os.get());
        apr_table_set(r->headers_in,"Shib-Authentication-Method", am.get());
    }

    // Export the attributes. Only supports a single statement.
    Iterator<SAMLAttribute*> j = assertions.size()==1 ? RM::getAttributes(*(assertions[0])) : EMPTY(SAMLAttribute*);
    while (j.hasNext())
    {
        SAMLAttribute* attr=j.next();

        // Are we supposed to export it?
        const char* hname=NULL;
        AAP wrapper(attr->getName(),attr->getNamespace());
        if (!wrapper.fail())
            hname=wrapper->getHeader();
        if (hname)
        {
            Iterator<string> vals=attr->getSingleByteValues();
            if (!strcmp(hname,"REMOTE_USER") && vals.hasNext())
                r->user=apr_pstrdup(r->connection->pool,vals.next().c_str());
            else
            {
                char* header = apr_pstrdup(r->pool, "");
                for (int it = 0; vals.hasNext(); it++) {
                    string value = vals.next();
                    for (string::size_type pos = value.find_first_of(";", string::size_type(0)); pos != string::npos; pos = value.find_first_of(";", pos)) {
                    	value.insert(pos, "\\");
                    	pos += 2;
                    }
                    if (it == 0) {
                        header=apr_pstrcat(r->pool, value.c_str(), NULL);
                    }
                    else {
                        header=apr_pstrcat(r->pool, header, ";", value.c_str(), NULL);
                    }
                }
                apr_table_setn(r->headers_in, hname, header);
    	    }
        }
    }

    // clean up memory
    for (int k = 0; k < assertions.size(); k++)
      delete assertions[k];
    delete sso_statement;

    // mod_auth clone

    int m=r->method_number;
    bool method_restricted=false;
    const char *t, *w;
    
    const apr_array_header_t* reqs_arr=ap_requires(r);
    if (!reqs_arr)
        return OK;

    require_line* reqs=(require_line*)reqs_arr->elts;

    for (int x=0; x<reqs_arr->nelts; x++)
    {
        if (!(reqs[x].method_mask & (1 << m)))
            continue;
        method_restricted=true;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

    	if (!strcmp(w,"valid-user"))
    	{
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_auth_checker() accepting valid-user");
            return OK;
    	}
    	else if (!strcmp(w,"user") && r->user)
    	{
            bool regexp=false;
    	    while (*t)
    	    {
    	        w=ap_getword_conf(r->pool,&t);
                if (*w=='~')
                {
                    regexp=true;
                    continue;
                }
                
                if (regexp)
                {
                    try
                    {
                        // To do regex matching, we have to convert from UTF-8.
                        auto_ptr<XMLCh> trans(fromUTF8(w));
                        RegularExpression re(trans.get());
                        auto_ptr<XMLCh> trans2(fromUTF8(r->user));
                        if (re.matches(trans2.get())) {
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_auth_checker() accepting user: %s",w);
                            return OK;
                        }
                    }
                    catch (XMLException& ex)
                    {
                        auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
                                        "shib_auth_checker caught exception while parsing regular expression (%s): %s",w,tmp.get());
                    }
                }
                else if (!strcmp(r->user,w))
                {
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_auth_checker() accepting user: %s",w);
                    return OK;
                }
    	    }
    	}
    	else if (!strcmp(w,"group"))
    	{
    	    apr_table_t* grpstatus=NULL;
    	    if (dc->szAuthGrpFile && r->user)
    	    {
                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_auth_checker() using groups file: %s\n",
                                dc->szAuthGrpFile);
                grpstatus=groups_for_user(r,r->user,dc->szAuthGrpFile);
            }
    	    if (!grpstatus)
    	        return DECLINED;
    
    	    while (*t)
    	    {
    	        w=ap_getword_conf(r->pool,&t);
                if (apr_table_get(grpstatus,w))
                {
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shib_auth_checker() accepting group: %s",w);
                    return OK;
                }
            }
        }
        else
        {
            const char* hname=NULL;
            AAP wrapper(w);
            if (!wrapper.fail())
                hname=wrapper->getHeader();

            if (!hname) {
                ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,0,r,
                                "shib_auth_checker() didn't recognize require rule: %s\n",w);
            }
            else
            {
                bool regexp=false;
                const char* vals=apr_table_get(r->headers_in,hname);
                while (*t && vals)
                {
                    w=ap_getword_conf(r->pool,&t);
                    if (*w=='~')
                    {
                        regexp=true;
                        continue;
                    }

                    try
                    {
                        auto_ptr<RegularExpression> re;
                        if (regexp)
                        {
                            delete re.release();
                            auto_ptr<XMLCh> trans(fromUTF8(w));
                            auto_ptr<RegularExpression> temp(new RegularExpression(trans.get()));
                            re=temp;
                        }
                        
                        string vals_str(vals);
                        int j = 0;
                        for (int i = 0;  i < vals_str.length();  i++)
                        {
                            if (vals_str.at(i) == ';') 
                            {
                                if (i == 0) {
                                    ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,0,r,
                                                    "shib_auth_checker() invalid header encoding %s: starts with semicolon", vals);
                                    return HTTP_INTERNAL_SERVER_ERROR;
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
                                        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                                        "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                                        return OK;
                                    }
                                }
                                else if (val==w) {
                                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                                    "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                                    return OK;
                                }
                                else {
                                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                                    "shib_auth_checker() expecting %s, got %s: authorization not granted", w, val.c_str());
                                }
                            }
                        }
        
                        string val = vals_str.substr(j, vals_str.length()-j);
                        if (regexp) {
                            auto_ptr<XMLCh> trans(fromUTF8(val.c_str()));
                            if (re->matches(trans.get())) {
                                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                                "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                                return OK;
                            }
                        }
                        else if (val==w) {
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                            "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
                            return OK;
                        }
                        else {
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                                            "shib_auth_checker() expecting %s, got %s: authorization not granted", w, val.c_str());
                        }
                    }
                    catch (XMLException& ex)
                    {
                        auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
                                        "shib_auth_checker caught exception while parsing regular expression (%s): %s",w,tmp.get());
                    }
                }
    	    }
    	}
    }

    if (!method_restricted)
        return OK;

    return shib_error_page(r, rmError.c_str(), markupProcessor);
}

namespace {
    void destroy_handle(void* data)
    {
        delete (RPCHandle*)data;
    }
}

/*
 * shib_exit()
 *  Cleanup the (per-process) pool info.
 */
extern "C" apr_status_t shib_exit(void* data)
{
    delete rpc_handle_key;
    g_Config->shutdown();
    g_Config = NULL;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,NULL,"shib_exit() done");
    return OK;
}

/*
 * shib_post_config()
 *  Things to do at process startup after the configs are read
 */
extern "C" int shib_post_config(apr_pool_t* pconf, apr_pool_t* plog,
				apr_pool_t* ptemp, server_rec* s)
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,
		 "shib_post_config() starting");

    ShibTargetConfig::preinit();

    if (g_Config) {
      ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,s,
		   "shib_post_config(): already initialized!");
      exit (1);
    }

    try {
      g_Config = &(ShibTargetConfig::init(SHIBTARGET_SHIRE, g_szSHIBConfig));
    } catch (...) {
      ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,
		   "shib_post_config() failed to initialize SHIB Target");
      exit (1);
    }

    // Create the RPC Handle TLS key.
    rpc_handle_key=ThreadKey::create(destroy_handle);

    // Set the cleanup handler
    apr_pool_cleanup_register(pconf, NULL, shib_exit, NULL);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,"shib_post_config() done");

    return 0;
}

extern "C" void shib_register_hooks (apr_pool_t *p)
{
  ap_hook_post_config(shib_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(shib_check_user, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(shib_auth_checker, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_handler(shib_shire_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

// SHIB Module commands

extern "C" {
static command_rec shib_cmds[] = {
  AP_INIT_TAKE1("SHIBConfig",
		(config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
		RSRC_CONF, "Path to SHIB ini file."),

  AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bBasicHijack),
	       OR_AUTHCFG, "Respond to AuthType Basic and convert to shib?"),
  AP_INIT_FLAG("ShibSSLOnly", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bSSLOnly),
	       OR_AUTHCFG, "Require SSL when accessing a secured directory?"),
  AP_INIT_TAKE1("ShibAuthLifetime", (config_fn_t)set_lifetime, NULL,
		OR_AUTHCFG, "Lifetime of session in seconds."),
  AP_INIT_TAKE1("ShibAuthTimeout", (config_fn_t)set_timeout, NULL,
		OR_AUTHCFG, "Timeout for session in seconds."),

  AP_INIT_TAKE1("AuthGroupFile", (config_fn_t)ap_set_file_slot,
		(void *) offsetof (shib_dir_config, szAuthGrpFile),
		OR_AUTHCFG, "text file containing group names and member user IDs"),
  AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bExportAssertion),
	       OR_AUTHCFG, "Export SAML assertion to Shibboleth-defined header?"),
  AP_INIT_FLAG("DisableRM", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bDisableRM),
	       OR_AUTHCFG, "Disable the Shibboleth Resource Manager?"),

  {NULL}
};

module AP_MODULE_DECLARE_DATA mod_shib = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,	/* create dir config */
    merge_shib_dir_config,	/* merge dir config --- default is to override */
    NULL,	                /* create server config */
    NULL,	                /* merge server config */
    shib_cmds,			/* command table */
    shib_register_hooks		/* register hooks */
};
} // extern "C"
