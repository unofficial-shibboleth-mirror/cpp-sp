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

#include "cgiparse.h"

#include <unistd.h>		// for getpid()

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern "C" AP_MODULE_DECLARE_DATA module mod_shib;

namespace {
    char* g_szSHIBConfig = NULL;
    ShibTargetConfig* g_Config = NULL;
}

// per-dir module configuration structure
struct shib_dir_config
{
    // RM Configuration
    char* szAuthGrpFile;	// Auth GroupFile name
    int bExportAssertion;       // export SAML assertion to the environment?
    int bRequireAll;		// all require directives must match, otherwise OR logic
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
    dc->bRequireAll = -1;
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
    dc->bRequireAll=((child->bRequireAll==-1) ?
			  parent->bRequireAll : child->bRequireAll);
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
				      const char* application_id)
{
  ShibINI& ini = g_Config->getINI();
  string shire_location;
  bool shire_ssl_only = false;

  // Determine if this is supposed to be ssl-only (default == false)
  if (ini.get_tag (application_id, "shireSSLOnly", true, &shire_location))
    shire_ssl_only = ShibINI::boolean(shire_location);

  // Grab the specified shire-location from the config file
  if (! ini.get_tag (application_id, "shireURL", true, &shire_location)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT,0,r,
		  "shire_get_location() no shireURL configuration for %s",
		  application_id);
    return NULL;
  }

  //
  // The "shireURL" can be one of three formats:
  //
  // 1) a full URI:		http://host/foo/bar
  // 2) a partial URI:		http:///foo/bar
  // 3) a relative path:	/foo/bar
  //
  // #  Protocol  Host	  Path
  // 1  shire     shire   shire
  // 2  shire     target  shire
  // 3  target    target  shire
  //
  // note: if shire_ssl_only is true, make sure the protocol is https
  //

  const char* shire = shire_location.c_str();
  const char* path = NULL;

  // Decide whether to use the shire or the target for the "protocol"
  const char* prot;
  if (*shire != '/') {
    prot = shire;
  } else {
    prot = target;
    path = shire;
  }

  //  ap_log_rerror(APLOG_MARK,APLOG_DEBUG,0,r,
  //		"get_shire_location: prot=%s, path=%s", prot,
  //		path ? path : "(null)");

  // break apart the "protocol" string into protocol, host, and "the rest"
  const char* colon=strchr(prot,':');
  colon += 3;
  const char* slash=strchr(colon,'/');
  if (!path)
    path = slash;

  // Compute the actual protocol
  const char* proto;
  if (shire_ssl_only)
    proto = "https://";
  else
    proto = apr_pstrndup(r->pool, prot, colon-prot);

  // create the "host" from either the colon/slash or from the target string
  // If prot == shire then we're in either #1 or #2, else #3.
  // If slash == colon then we're in #2
  if (prot != shire || slash == colon) {
    colon = strchr(target, ':');
    colon += 3;		// Get past the ://
    slash = strchr(colon, '/');
  }
  const char *host = apr_pstrndup(r->pool, colon, slash-colon);

  // Build the shire URL
  return apr_pstrcat(r->pool, proto, host, path, NULL);
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

static const char* get_application_id(request_rec* r)
{
  ApplicationMapper mapper;
  return apr_pstrdup(r->pool,
		    mapper->getApplicationFromParsedURL(
			ap_http_method(r), ap_get_server_name(r),
			ap_get_server_port(r), r->unparsed_uri
			)
		    );
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
    const char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

    // Map request to application ID, which is the key for config lookup.
    const char* application_id=get_application_id(r);
    
    // Get unescaped location of this application's assertion consumer service.
    const char* unescaped_shire = get_shire_location(r, targeturl, application_id);
    
    if (strstr(targeturl,unescaped_shire)) {
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

    string tag;
    bool has_tag = ini.get_tag (application_id, "checkIPAddress", true, &tag);
    dc->config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);

    string shib_cookie;
    if (! ini.get_tag(application_id, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no cookieName configuration for %s",
		    application_id);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    string wayfLocation;
    if (! ini.get_tag(application_id, "wayfURL", true, &wayfLocation)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no wayfURL configuration for %s",
		    application_id);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    string shireError;
    if (! ini.get_tag(application_id, "shireError", true, &shireError)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no shireError configuration for %s",
		    application_id);
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    SHIRE shire(dc->config, unescaped_shire);

    // We're in charge, so check for cookie.
    const char* session_id=NULL;
    const char* cookies=apr_table_get(r->headers_in,"Cookie");

    if (cookies)
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
                        "shire_check_user() cookies found: %s",cookies);
        if (session_id=strstr(cookies,shib_cookie.c_str()))
        {
            // Yep, we found a cookie -- pull it out (our session_id)
            session_id+=strlen(shib_cookie.c_str()) + 1; /* Skip over the '=' */
            char* cookiebuf = apr_pstrdup(r->pool,session_id);
            char* cookieend = strchr(cookiebuf,';');
            if (cookieend)
                *cookieend = '\0';    /* Ignore anyting after a ; */
            session_id=cookiebuf;
        }
    }

    if (!session_id || !*session_id)
    {
        // No cookie.  Redirect to WAYF.
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		      "shib_check_user() no cookie found -- redirecting to WAYF");
	char timebuf[16];
	sprintf(timebuf,"%u",time(NULL));
        char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",url_encode(r,unescaped_shire),
			      "&target=",url_encode(r,targeturl),
			       "&time=",timebuf,
			       "&providerId=",application_id,
			       NULL);
        apr_table_setn(r->headers_out,"Location",wayf);
        return HTTP_MOVED_TEMPORARILY;
    }

    // Make sure this session is still valid
    RPCError* status = NULL;
    ShibMLP markupProcessor;
    has_tag = ini.get_tag(application_id, "supportContact", true, &tag);
    markupProcessor.insert("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag(application_id, "logoLocation", true, &tag);
    markupProcessor.insert("logoLocation", has_tag ? tag : "");
    markupProcessor.insert("requestURL", targeturl);

    try {
        status = shire.sessionIsValid(session_id, r->connection->remote_ip,application_id);
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
	    char timebuf[16];
	    sprintf(timebuf,"%u",time(NULL));
            char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
				   "?shire=",url_encode(r,unescaped_shire),
				   "&target=",url_encode(r,targeturl),
				   "&time=",timebuf,
				   "&providerId=",application_id,
				   NULL);
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
  const char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

  // Map request to application ID, which is the key for config lookup.
  const char* application_id = get_application_id(r);
    
  // Find out what SHOULD be the SHIRE URL...
  const char* unescaped_shire = get_shire_location(r, targeturl, application_id);

  // Make sure we only process the SHIRE posts.
  if (!strstr(targeturl,unescaped_shire))
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		"shire_post_handler() ENTER");

  ShibINI& ini = g_Config->getINI();
  ShibMLP markupProcessor;
 
  string tag;
  bool has_tag = ini.get_tag(application_id, "checkIPAddress", true, &tag);
  SHIREConfig config;
  config.checkIPAddress = (has_tag ? ShibINI::boolean(tag) : false);

  string shib_cookie;
  if (! ini.get_tag(application_id, "cookieName", true, &shib_cookie)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no cookieName configuration for %s",
		  application_id);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  string wayfLocation;
  if (! ini.get_tag(application_id, "wayfURL", true, &wayfLocation)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no wayfURL configuration for %s",
		  application_id);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  string shireError;
  if (! ini.get_tag(application_id, "shireError", true, &shireError)) {
    ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		  "shire_post_handler: no shireError configuration for %s",
		  application_id);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  has_tag = ini.get_tag(application_id, "supportContact", true, &tag);
  markupProcessor.insert("supportContact", has_tag ? tag : "");
  has_tag = ini.get_tag(application_id, "logoLocation", true, &tag);
  markupProcessor.insert("logoLocation", has_tag ? tag : "");
  markupProcessor.insert("requestURL", targeturl);
  
  SHIRE shire(config, unescaped_shire);

  // Process SHIRE POST

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		"shire_post_handler() Beginning SHIRE POST processing");
      
  CgiParse* cgi = NULL;

  try {
    string sslonly;
    if (!ini.get_tag(application_id, "shireSSLOnly", true, &sslonly))
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

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() about to run setup_client_block");

    // Read the posted data
    if (ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))
      throw ShibTargetException (SHIBRPC_OK, "CGI setup_client_block failed");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() about to run should_client_block");

    if (!ap_should_client_block(r))
      throw ShibTargetException (SHIBRPC_OK, "CGI should_client_block failed");

    long length = r->remaining;
    if (length > 1024*1024)
      throw ShibTargetException (SHIBRPC_OK, "CGI length too long...");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() about to read using get_client_block");
    string cgistr = "";
    char buff[BUFSIZ];
    //ap_hard_timeout("[mod_shib] CGI Parser", r);

    memset(buff, 0, sizeof(buff));
    while (ap_get_client_block(r, buff, sizeof(buff)-1) > 0) {
      cgistr += buff;
      memset(buff, 0, sizeof(buff));
    }

    //ap_kill_timeout(r);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() about to parse cgi...");

    cgi = CgiParse::ParseCGI(cgistr);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() CGI parsed... (%p)", cgi);

    if (!cgi)
      throw ShibTargetException (SHIBRPC_OK, "CgiParse failed");
    
    // Make sure the target parameter exists
    const char *target = cgi->get_value("TARGET");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() obtained target...");

    if (!target || *target == '\0')
      // invalid post
      throw ShibTargetException (SHIBRPC_OK,
				 "SHIRE POST failed to find TARGET");

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler() obtained target...");

    // Make sure the SAML Response parameter exists
    const char *post = cgi->get_value("SAMLResponse");
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
    RPCError* status = shire.sessionCreate(post, r->connection->remote_ip, application_id, cookie);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shire_post_handler() POST process failed (%d): %s",
		    status->getCode(), status->getText());

      if (status->isRetryable()) {
	ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,0,r,
		      "shire_post_handler() Retrying POST by redirecting to WAYF");
	
	char timebuf[16];
	sprintf(timebuf,"%u",time(NULL));
	char* wayf=apr_pstrcat(r->pool,wayfLocation.c_str(),
			       "?shire=",url_encode(r,unescaped_shire),
			       "&target=",url_encode(r,target),
			       "&time=",timebuf,
			       "&providerId=",application_id,
			       NULL);
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
    delete cgi;
    return HTTP_MOVED_TEMPORARILY;

  } catch (ShibTargetException &e) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		  "shire_post_handler(): %s", e.what());
	
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", e.what());
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    if (cgi) delete cgi;
    return shib_error_page (r, shireError.c_str(), markupProcessor);
  }
  catch (...) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,"shire_post_handler(): unexpected exception");
  
    markupProcessor.insert ("errorType", "SHIRE Processing Error");
    markupProcessor.insert ("errorText", "Unexpected Exception");
    markupProcessor.insert ("errorDesc", "An error occurred while processing your request.");
    if (cgi) delete cgi;
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

    // This will always be normalized, because Apache uses ap_get_server_name
    // in this API call.
    const char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);
    
    // Map request to application ID, which is the key for config lookup.
    const char* application_id=get_application_id(r);

    // Ok, this is a SHIB target; grab the cookie
    string shib_cookie;
    if (!ini.get_tag(application_id, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		    "shib_check_user: no cookieName configuration for %s",
		    application_id);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

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
    bool has_tag = ini.get_tag(application_id, "supportContact", true, &tag);
    markupProcessor.insert("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag(application_id, "logoLocation", true, &tag);
    markupProcessor.insert("logoLocation", has_tag ? tag : "");
    markupProcessor.insert("requestURL", targeturl);

    // Now grab the attributes...
    has_tag = ini.get_tag (application_id, "checkIPAddress", true, &tag);
    dc->rm_config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);

    RM rm(dc->rm_config);

    vector<SAMLAssertion*> assertions;
    SAMLAuthenticationStatement* sso_statement=NULL;
    RPCError* status = rm.getAssertions(session_id, r->connection->remote_ip, application_id, assertions, &sso_statement);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
		    "shib_auth_checker() getAssertions failed: %s",
		    status->getText());

      string rmError;
      if (!ini.get_tag(application_id, "rmError", true, &rmError)) {
        ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
		      "shib_auth_checker: no rmError configuration for %s",
		      application_id);
        delete status;
        return HTTP_INTERNAL_SERVER_ERROR;	
      }
      markupProcessor.insert(*status);
      delete status;
      return shib_error_page (r, rmError.c_str(), markupProcessor);
    }
    delete status;

    string rmError;
    if (!ini.get_tag(application_id, "accessError", true, &rmError)) {
        ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,0,r,
           "shib_auth_checker: no accessError configuration for %s",
            application_id);

        delete status;
        for (int k = 0; k < assertions.size(); k++)
          delete assertions[k];
        delete sso_statement;
        return HTTP_INTERNAL_SERVER_ERROR;  
    }

    // Get the AAP providers, which contain the attribute policy info.
    Iterator<IAAP*> provs=g_Config->getAAPProviders();

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
    
    // Maybe export the first assertion.
    apr_table_unset(r->headers_in,"Shib-Attributes");
    if (dc->bExportAssertion==1 && assertions.size()) {
        string assertion;
        RM::serialize(*(assertions[0]), assertion);
        apr_table_set(r->headers_in,"Shib-Attributes", assertion.c_str());
    }

    // Export the SAML AuthnMethod and the origin site name.
    apr_table_unset(r->headers_in,"Shib-Origin-Site");
    apr_table_unset(r->headers_in,"Shib-Authentication-Method");
    if (sso_statement)
    {
        auto_ptr_char os(sso_statement->getSubject()->getNameQualifier());
        auto_ptr_char am(sso_statement->getAuthMethod());
        apr_table_set(r->headers_in,"Shib-Origin-Site", os.get());
        apr_table_set(r->headers_in,"Shib-Authentication-Method", am.get());
    }

    apr_table_unset(r->headers_in,"Shib-Application-ID");
    apr_table_set(r->headers_in,"Shib-Application-ID",application_id);

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
	  if (wrapper.fail())
	    continue;
	  
	  Iterator<string> vals=attr->getSingleByteValues();
	  if (!strcmp(wrapper->getHeader(),"REMOTE_USER") && vals.hasNext())
	    r->user=apr_pstrdup(r->connection->pool,vals.next().c_str());
	  else {
	    char* header = apr_pstrdup(r->pool, "");
	    for (int it = 0; vals.hasNext(); it++) {
	      string value = vals.next();
	      for (string::size_type pos = value.find_first_of(";", string::size_type(0)); pos != string::npos; pos = value.find_first_of(";", pos)) {
		value.insert(pos, "\\");
		pos += 2;
	      }
	      header=apr_pstrcat(r->pool, header, (it ? ";" : ""), value.c_str(), NULL);
	    }
	    apr_table_setn(r->headers_in, wrapper->getHeader(), header);
	  }
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

    //XXX
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		 "REQUIRE nelts: %d", reqs_arr->nelts);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
		 "REQUIRE all: %d", dc->bRequireAll);

    bool auth_OK[reqs_arr->nelts];

#define SHIB_AP_CHECK_IS_OK { 		\
	    if (dc->bRequireAll < 1) 	\
	        return OK;		\
	    auth_OK[x] = true;		\
	    continue;			\
}

    for (int x=0; x<reqs_arr->nelts; x++)
    {
    	auth_OK[x] = false;

        if (!(reqs[x].method_mask & (1 << m)))
            continue;
        method_restricted=true;

        t = reqs[x].requirement;
        w = ap_getword_white(r->pool, &t);

    	if (!strcmp(w,"valid-user"))
    	{
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
			  "shib_auth_checker() accepting valid-user");
	    SHIB_AP_CHECK_IS_OK;
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
                            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
					  "shib_auth_checker() accepting user: %s",w);
			    SHIB_AP_CHECK_IS_OK;
                        }
                    }
                    catch (XMLException& ex)
                    {
                        auto_ptr_char tmp(ex.getMessage());
                        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,0,r,
        "shib_auth_checker caught exception while parsing regular expression (%s): %s",w,tmp.get());
                    }
                }
                else if (!strcmp(r->user,w))
                {
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
				  "shib_auth_checker() accepting user: %s",w);
		    SHIB_AP_CHECK_IS_OK;
                }
    	    }
    	}
    	else if (!strcmp(w,"group"))
    	{
    	    apr_table_t* grpstatus=NULL;
    	    if (dc->szAuthGrpFile && r->user)
    	    {
                ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
			      "shib_auth_checker() using groups file: %s\n",
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
                    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
				  "shib_auth_checker() accepting group: %s",w);
		    SHIB_AP_CHECK_IS_OK;
                }
            }
        }
        else
        {
            AAP wrapper(provs,w);
            if (wrapper.fail()) {
                ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,0,r,
                                "shib_auth_checker() didn't recognize require rule: %s\n",w);
		continue;
            }

	    bool regexp=false;
	    const char* vals=apr_table_get(r->headers_in,wrapper->getHeader());
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
			SHIB_AP_CHECK_IS_OK;
		      }
		    }
		    else if (val==w) {
		      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
				    "shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
		      SHIB_AP_CHECK_IS_OK;
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
		    SHIB_AP_CHECK_IS_OK;
		  }
		}
		else if (val==w) {
		  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,r,
				"shib_auth_checker() expecting %s, got %s: authorization granted", w, val.c_str());
		  SHIB_AP_CHECK_IS_OK;
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

    // check if all require directives are true
    bool auth_all_OK = true;
    for (int i= 0; i<reqs_arr->nelts; i++) {
        auth_all_OK &= auth_OK[i];
    } 
    if (auth_all_OK)
        return OK;

    if (!method_restricted)
        return OK;

    return shib_error_page(r, rmError.c_str(), markupProcessor);
}

/*
 * shib_exit()
 *  Cleanup the (per-process) pool info.
 */
extern "C" apr_status_t shib_exit(void* data)
{
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

    // Set the cleanup handler
    apr_pool_cleanup_register(pconf, NULL, shib_exit, NULL);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0,s,"shib_post_config() done");

    return OK;
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
  AP_INIT_FLAG("ShibRequireAll", (config_fn_t)ap_set_flag_slot,
	       (void *) offsetof (shib_dir_config, bRequireAll),
	       OR_AUTHCFG, "All require directives must match!"),
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
