/*
 * mod_shire.cpp -- the SHIRE Apache Module
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

// Apache specific header files
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "util_script.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_log.h"

// For POST processing from Apache
#include <libapreq/apache_request.h>

#include <unistd.h>

// SAML Runtime
#include <saml.h>
#include <shib.h>
#include <shib-target.h>

#include <fstream>
#include <strstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern "C" module MODULE_VAR_EXPORT shire_module;

static char* g_szSHIREConfig = NULL;
static RPCHandle *rpc_handle = NULL;
static ShibTargetConfig * g_szConfig = NULL;

// per-server configuration structure
struct shire_server_config
{
    char* szCookieName;		// name of session token
    char* szWAYFLocation;	// URL of WAYF service
    char* szSHIRELocation;	// URL of SHIRE acceptance point
    int bSSLOnly;		// SSL only for this SHIRE?
    int bNormalizeRequest;      // normalize requested URL based on server name?
};

// creates the per-server configuration
extern "C" void* create_shire_server_config (pool * p, server_rec * s)
{
    shire_server_config* sc=(shire_server_config*)ap_pcalloc(p,sizeof(shire_server_config));
    sc->bSSLOnly = -1;
    sc->bNormalizeRequest = -1;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shire_server_config (pool* p, void* base, void* sub)
{
    shire_server_config* sc=(shire_server_config*)ap_pcalloc(p,sizeof(shire_server_config));
    shire_server_config* parent=(shire_server_config*)base;
    shire_server_config* child=(shire_server_config*)sub;

    if (child->szCookieName)
        sc->szCookieName=ap_pstrdup(p,child->szCookieName);
    else if (parent->szCookieName)
        sc->szCookieName=ap_pstrdup(p,parent->szCookieName);
    else
        sc->szCookieName=NULL;

    if (child->szWAYFLocation)
        sc->szWAYFLocation=ap_pstrdup(p,child->szWAYFLocation);
    else if (parent->szWAYFLocation)
        sc->szWAYFLocation=ap_pstrdup(p,parent->szWAYFLocation);
    else
        sc->szWAYFLocation=NULL;

    if (child->szSHIRELocation)
        sc->szSHIRELocation=ap_pstrdup(p,child->szSHIRELocation);
    else if (parent->szSHIRELocation)
        sc->szSHIRELocation=ap_pstrdup(p,parent->szSHIRELocation);
    else
        sc->szSHIRELocation=NULL;

    sc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    sc->bNormalizeRequest=((child->bNormalizeRequest==-1) ? parent->bNormalizeRequest : child->bNormalizeRequest);
    return sc;
}

// per-dir module configuration structure
struct shire_dir_config
{
    int bBasicHijack;		// activate for AuthType Basic?
    int bSSLOnly;		// only over SSL?
    int checkIPAddress;		// placeholder for check
    SHIREConfig config;		// SHIRE Configuration
};

// creates per-directory config structure
extern "C" void* create_shire_dir_config (pool* p, char* d)
{
    shire_dir_config* dc=(shire_dir_config*)ap_pcalloc(p,sizeof(shire_dir_config));
    dc->bBasicHijack = -1;
    dc->bSSLOnly = -1;
    dc->checkIPAddress = -1;
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

    dc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->checkIPAddress=((child->checkIPAddress==-1) ? parent->checkIPAddress : child->checkIPAddress);
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

// generic per-server slot handlers
extern "C" const char* ap_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&shire_module);
    int offset=(int)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* set_normalize(cmd_parms* parms, shire_server_config* sc, const char* arg)
{
    sc->bNormalizeRequest=atoi(arg);
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

#ifdef SOLARIS
extern "C"
#endif
typedef const char* (*config_fn_t)(void);

// SHIRE Module commands

static command_rec shire_cmds[] = {
  {"SHIREConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIREConfig,
   RSRC_CONF, TAKE1, "Path to SHIRE ini file."},

#if 0
  {"SHIRELocation", (config_fn_t)ap_set_server_string_slot,
   (void *) XtOffsetOf (shire_server_config, szSHIRELocation),
   RSRC_CONF, TAKE1, "URL of SHIRE handle acceptance point."},
  {"SHIRESSLOnly", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_server_config, bSSLOnly),
   RSRC_CONF, FLAG, "Require SSL when POSTING to the SHIRE?"},
  {"WAYFLocation", (config_fn_t)ap_set_server_string_slot,
   (void *) XtOffsetOf (shire_server_config, szWAYFLocation),
   RSRC_CONF, TAKE1, "URL of WAYF service."},
  {"ShibCookieName", (config_fn_t)ap_set_server_string_slot,
   (void *) XtOffsetOf (shire_server_config, szCookieName),
   RSRC_CONF, TAKE1, "Name of cookie to use as session token."},
  {"ShibNormalizeRequest", (config_fn_t)set_normalize, NULL,
   RSRC_CONF, TAKE1, "Normalize/convert browser requests using server name when redirecting."},
#endif

  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibSSLOnly", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_dir_config, bSSLOnly),
   OR_AUTHCFG, FLAG, "Require SSL when accessing a secured directory?"},
  {"ShibCheckAddress", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shire_dir_config, checkIPAddress),
   OR_AUTHCFG, FLAG, "Verify IP address of requester matches token?"},
  {"ShibAuthLifetime", (config_fn_t)set_lifetime, NULL,
   OR_AUTHCFG, TAKE1, "Lifetime of session in seconds."},
  {"ShibAuthTimeout", (config_fn_t)set_timeout, NULL,
   OR_AUTHCFG, TAKE1, "Timeout for session in seconds."},

  {NULL}
};



/* 
 * shire_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shire_child_init(server_rec* s, pool* p)
{
    // Initialize runtime components.

    if (g_szConfig) {
      ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,s,
		   "shire_child_init(): already initialized!");
      exit (1);
    }

    try {
      g_szConfig = &(ShibTargetConfig::init(SHIBTARGET_SHIRE, g_szSHIREConfig));
    } catch (runtime_error& e) {
      ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
		   "shire_child_init() failed to initialize SHIB Target");
      exit (1);
    }

    // Create the RPC Handle..  Note: this should be per _thread_
    // if there is some way to do that reasonably..
    rpc_handle = new RPCHandle(SHIB_SHAR_SOCKET, SHIBRPC_PROG, SHIBRPC_VERS_1);

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shire_child_init() done");
}


/*
 * shire_child_exit()
 *  Cleanup.
 */
extern "C" void shire_child_exit(server_rec* s, pool* p)
{
    delete rpc_handle;
    g_szConfig->shutdown();
    g_szConfig = NULL;
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

static const char* get_target(request_rec* r, const char* target)
{
    shire_server_config* sc=
        (shire_server_config*)ap_get_module_config(r->server->module_config,&shire_module);
    if (sc->bNormalizeRequest)
    {
        const char* colon=strchr(target,':');
        const char* slash=strchr(colon+3,'/');
        const char* second_colon=strchr(colon+3,':');
        return ap_pstrcat(r->pool,ap_pstrndup(r->pool,target,colon+3-target),ap_get_server_name(r),
			  (second_colon && second_colon < slash) ? second_colon : slash,NULL);
    }
    return target;
}

static const char* get_shire_location(request_rec* r, const char* target, bool encode)
{
  ShibINI& ini = g_szConfig->getINI();
  const string& shire_location = ini.get (SHIBTARGET_HTTP, "shire");

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
    ostrstream threadid;
    threadid << "[" << getpid() << "] shire" << '\0';
    saml::NDC ndc(threadid.str());

    ShibINI& ini = g_szConfig->getINI();
    ShibMLP markupProcessor;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shire_check_user: ENTER");

    shire_server_config* sc=
        (shire_server_config*)ap_get_module_config(r->server->module_config,&shire_module);
    shire_dir_config* dc=
        (shire_dir_config*)ap_get_module_config(r->per_dir_config,&shire_module);

    const char* targeturl=get_target(r,ap_construct_url(r->pool,r->unparsed_uri,r));
 
    const char * shire_location = get_shire_location(r,targeturl,true);
    string shire_url = get_shire_location(r,targeturl,false);
    dc->config.checkIPAddress = (dc->checkIPAddress == 1 ? true : false);
    SHIRE shire(rpc_handle, dc->config, shire_url);

    const string& shib_cookie = ini.get (SHIBTARGET_HTTP, "cookie");
    const string& wayfLocation = ini.get (SHIBTARGET_HTTP, "wayfLocation");
    const string& wayfError = ini.get (SHIBTARGET_HTTP, "wayfError");

    string tag;
    bool has_tag = ini.get_tag (SHIBTARGET_HTTP, "supportContact", true, &tag);
    markupProcessor.insert ("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag (SHIBTARGET_HTTP, "logoLocation", true, &tag);
    markupProcessor.insert ("logoLocation", has_tag ? tag : "");
    markupProcessor.insert ("requestURL", targeturl);

    if (is_shire_location (r, targeturl)) {
      // Process SHIRE POST

      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		    "shire_check_user() Beginning SHIRE POST processing");
      

      try {

	const string& sslonly = ini.get (SHIBTARGET_HTTP, "shireSSLOnly");
	const char* sslonlyc = sslonly.c_str();
	
	// Make sure this is SSL, if it should be
	if ((*sslonlyc == 't' || *sslonlyc == 'T') &&
	    strcmp(ap_http_method(r),"https"))
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
	      "shire_check_user() Processing POST for target: %s", target);

#if 0 // 2002-09-19
	post = 
	  "PFJlc3BvbnNlIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6cHJvdG9jb2wi"
	  "IHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6cHJvdG9jb2wiIElz"
	  "c3VlSW5zdGFudD0iMjAwMi0wOS0xOVQwNTozMDowMFoiIE1ham9yVmVyc2lvbj0iMSIgTWlu"
	  "b3JWZXJzaW9uPSIwIiBSZWNpcGllbnQ9Imh0dHA6Ly9sb2NhbGhvc3Qvc2hpYmJvbGV0aC9T"
	  "SElSRSIgUmVzcG9uc2VJRD0iYmI3ZjZmYjQtMmU0YS00YzY1LTgzY2QtYjIyMjQ0OWQwYmY4"
	  "Ij48U3RhdHVzPjxTdGF0dXNDb2RlIFZhbHVlPSJzYW1scDpTdWNjZXNzIj48L1N0YXR1c0Nv"
	  "ZGU+PC9TdGF0dXM+PEFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6"
	  "MS4wOmFzc2VydGlvbiIgQXNzZXJ0aW9uSUQ9IjZhYzUxYTg2LTJhNTgtNDM2My1hZjlkLTQy"
	  "YjQzYTRhMGNiZSIgSXNzdWVJbnN0YW50PSIyMDAyLTA5LTE5VDA1OjMwOjAwWiIgSXNzdWVy"
	  "PSJzaGlicHJvZDAuaW50ZXJuZXQyLmVkdSIgTWFqb3JWZXJzaW9uPSIxIiBNaW5vclZlcnNp"
	  "b249IjAiPjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAwMi0wOS0xN1QwMjo1MDowMFoiIE5v"
	  "dE9uT3JBZnRlcj0iMjAxMC0wOS0xOVQwNjozMDowMFoiPjxBdWRpZW5jZVJlc3RyaWN0aW9u"
	  "Q29uZGl0aW9uPjxBdWRpZW5jZT5odHRwOi8vbWlkZGxld2FyZS5pbnRlcm5ldDIuZWR1L3No"
	  "aWJib2xldGgvY2x1YnMvY2x1YnNoaWIvMjAwMi8wNS88L0F1ZGllbmNlPjwvQXVkaWVuY2VS"
	  "ZXN0cmljdGlvbkNvbmRpdGlvbj48L0NvbmRpdGlvbnM+PEF1dGhlbnRpY2F0aW9uU3RhdGVt"
	  "ZW50IEF1dGhlbnRpY2F0aW9uSW5zdGFudD0iMjAwMi0wOS0xOVQwNTozMDowMFoiIEF1dGhl"
	  "bnRpY2F0aW9uTWV0aG9kPSJCYXNpYyI+PFN1YmplY3Q+PE5hbWVJZGVudGlmaWVyIE5hbWVR"
	  "dWFsaWZpZXI9ImV4YW1wbGUuZWR1Ij40YzBmYjg2Yi01NjQwLTQ1ZTUtOTM3Ny1mNTJkNjhh"
	  "ZDNiNjQ8L05hbWVJZGVudGlmaWVyPjxTdWJqZWN0Q29uZmlybWF0aW9uPjxDb25maXJtYXRp"
	  "b25NZXRob2Q+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmNtOkJlYXJlcjwvQ29uZmly"
	  "bWF0aW9uTWV0aG9kPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PFN1YmplY3RM"
	  "b2NhbGl0eSBJUEFkZHJlc3M9IjE4LjEwMS4xLjEyIj48L1N1YmplY3RMb2NhbGl0eT48QXV0"
	  "aG9yaXR5QmluZGluZyBBdXRob3JpdHlLaW5kPSJzYW1scDpBdHRyaWJ1dGVRdWVyeSIgQmlu"
	  "ZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmJpbmRpbmdzOlNPQVAtYmluZGlu"
	  "ZyIgTG9jYXRpb249Imh0dHBzOi8vc2hpYnByb2QwLmludGVybmV0Mi5lZHUvc2hpYmJvbGV0"
	  "aC9BQSI+PC9BdXRob3JpdHlCaW5kaW5nPjwvQXV0aGVudGljYXRpb25TdGF0ZW1lbnQ+PC9B"
	  "c3NlcnRpb24+PC9SZXNwb25zZT4K";
#endif
#if 0 // 2002-09-20
	post = 
	  "PFJlc3BvbnNlIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6cHJvdG9jb2wi"
	  "IHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6cHJvdG9jb2wiIElz"
	  "c3VlSW5zdGFudD0iMjAwMi0wOS0yMFQyMzowMDowMFoiIE1ham9yVmVyc2lvbj0iMSIgTWlu"
	  "b3JWZXJzaW9uPSIwIiBSZWNpcGllbnQ9Imh0dHA6Ly9sb2NhbGhvc3Qvc2hpYmJvbGV0aC9T"
	  "SElSRSIgUmVzcG9uc2VJRD0iYmI3ZjZmYjQtMmU0YS00YzY1LTgzY2QtYjIyMjQ0OWQwYmY4"
	  "Ij48U3RhdHVzPjxTdGF0dXNDb2RlIFZhbHVlPSJzYW1scDpTdWNjZXNzIj48L1N0YXR1c0Nv"
	  "ZGU+PC9TdGF0dXM+PEFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6"
	  "MS4wOmFzc2VydGlvbiIgQXNzZXJ0aW9uSUQ9IjZhYzUxYTg2LTJhNTgtNDM2My1hZjlkLTQy"
	  "YjQzYTRhMGNiZSIgSXNzdWVJbnN0YW50PSIyMDAyLTA5LTIwVDIzOjAwOjAwWiIgSXNzdWVy"
	  "PSJzaGlicHJvZDAuaW50ZXJuZXQyLmVkdSIgTWFqb3JWZXJzaW9uPSIxIiBNaW5vclZlcnNp"
	  "b249IjAiPjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAwMi0wOS0xN1QwMjo1MDowMFoiIE5v"
	  "dE9uT3JBZnRlcj0iMjAxMC0wOS0xOVQwNjozMDowMFoiPjxBdWRpZW5jZVJlc3RyaWN0aW9u"
	  "Q29uZGl0aW9uPjxBdWRpZW5jZT5odHRwOi8vbWlkZGxld2FyZS5pbnRlcm5ldDIuZWR1L3No"
	  "aWJib2xldGgvY2x1YnMvY2x1YnNoaWIvMjAwMi8wNS88L0F1ZGllbmNlPjwvQXVkaWVuY2VS"
	  "ZXN0cmljdGlvbkNvbmRpdGlvbj48L0NvbmRpdGlvbnM+PEF1dGhlbnRpY2F0aW9uU3RhdGVt"
	  "ZW50IEF1dGhlbnRpY2F0aW9uSW5zdGFudD0iMjAwMi0wOS0yMFQyMzowMDowMFoiIEF1dGhl"
	  "bnRpY2F0aW9uTWV0aG9kPSJCYXNpYyI+PFN1YmplY3Q+PE5hbWVJZGVudGlmaWVyIE5hbWVR"
	  "dWFsaWZpZXI9ImV4YW1wbGUuZWR1Ij40YzBmYjg2Yi01NjQwLTQ1ZTUtOTM3Ny1mNTJkNjhh"
	  "ZDNiNjQ8L05hbWVJZGVudGlmaWVyPjxTdWJqZWN0Q29uZmlybWF0aW9uPjxDb25maXJtYXRp"
	  "b25NZXRob2Q+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmNtOkJlYXJlcjwvQ29uZmly"
	  "bWF0aW9uTWV0aG9kPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PFN1YmplY3RM"
	  "b2NhbGl0eSBJUEFkZHJlc3M9IjE4LjEwMS4xLjEyIj48L1N1YmplY3RMb2NhbGl0eT48QXV0"
	  "aG9yaXR5QmluZGluZyBBdXRob3JpdHlLaW5kPSJzYW1scDpBdHRyaWJ1dGVRdWVyeSIgQmlu"
	  "ZGluZz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6MS4wOmJpbmRpbmdzOlNPQVAtYmluZGlu"
	  "ZyIgTG9jYXRpb249Imh0dHBzOi8vc2hpYnByb2QwLmludGVybmV0Mi5lZHUvc2hpYmJvbGV0"
	  "aC9BQSI+PC9BdXRob3JpdHlCaW5kaW5nPjwvQXV0aGVudGljYXRpb25TdGF0ZW1lbnQ+PC9B"
	  "c3NlcnRpb24+PC9SZXNwb25zZT4K";
#endif
	
	// process the post
	string cookie;
	RPCError* status = shire.sessionCreate(post, r->connection->remote_ip, cookie);

	if (status->isError()) {
	  ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
			"shire_check_user() POST process failed (%d): %s",
			status->status, status->error_msg.c_str());

	  if (status->isRetryable()) {
	    ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
			  "shire_check_user() Retrying POST by redirecting to WAYF");

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
	  return shire_error_page (r, wayfError.c_str(), markupProcessor);
	}
	delete status;

	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() POST process succeeded.  New cookie: %s",
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
		      "shire_check_user() Set cookie: %s", new_cookie);
		    
	// ... and redirect to the target
	char* redir=ap_pstrcat(r->pool,url_encode(r,target),NULL);
	ap_table_setn(r->headers_out, "Location", target);
	return REDIRECT;

      } catch (ShibTargetException &e) {
	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user(): %s", e.what());
	
	markupProcessor.insert ("errorType", "SHIRE Processing Error");
	markupProcessor.insert ("errorText", e.what());
	return shire_error_page (r, wayfError.c_str(), markupProcessor);
      }

      /**************************************************************************/

    } else {
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

      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		    "shire_check_user() Shib check for %s", targeturl);

      // SSL check.
      if (dc->bSSLOnly==1 && strcmp(ap_http_method(r),"https"))
      {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		      "shire_check_user() blocked non-SSL access");
        return SERVER_ERROR;
      }

      // We're in charge, so check for cookie.
      const char* session_id=NULL;
      const char* cookies=ap_table_get(r->headers_in,"Cookie");

      if (cookies)
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() cookies found: %s",
		      cookies);		      

      if (!cookies || !(session_id=strstr(cookies,shib_cookie.c_str())))
      {
        // No cookie.  Redirect to WAYF.
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() no cookie found -- redirecting to WAYF");
        char* wayf=ap_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,targeturl),NULL);
	ap_table_setn(r->headers_out,"Location",wayf);
	return REDIRECT;
      }

      // Yep, we found a cookie -- pull it out (our session_id)
      session_id+=strlen(shib_cookie.c_str()) + 1;	/* Skip over the '=' */
      char* cookiebuf = ap_pstrdup(r->pool,session_id);
      char* cookieend = strchr(cookiebuf,';');
      if (cookieend)
	*cookieend = '\0';	/* Ignore anyting after a ; */
      session_id=cookiebuf;

      // Make sure this session is still valid
      RPCError* status = shire.sessionIsValid(session_id, r->connection->remote_ip);

      // Check the status
      if (status->isError()) {

	ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
		      "shire_check_user() session invalid: %s",
		      status->error_msg.c_str());

        // Oops, session is invalid.  Redirect to WAYF.
        char* wayf=ap_pstrcat(r->pool,wayfLocation.c_str(),
			      "?shire=",shire_location,
			      "&target=",url_encode(r,targeturl),NULL);
	ap_table_setn(r->headers_out,"Location",wayf);

	delete status;
	return REDIRECT;

      } else {
	delete status;
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		      "shire_check_user() success");
	return OK;
      }
    }

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		  "shire_check_user() server error");
    return SERVER_ERROR;
}

extern "C"{
module MODULE_VAR_EXPORT shire_module = {
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_shire_dir_config,	/* dir config creater */
    merge_shire_dir_config,	/* dir merger --- default is to override */
    create_shire_server_config,	/* server config */
    merge_shire_server_config,	/* merge server config */
    shire_cmds,			/* command table */
    NULL,			/* handlers */
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
