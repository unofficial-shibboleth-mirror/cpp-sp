/*
 * mod_shibrm.cpp -- the SHIB Resource Manager Apache Module
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

// Apache specific header files
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_log.h"

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib-target/shib-target.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace {
    RPCHandle *rpc_handle = NULL;
    ShibTargetConfig* g_szConfig = NULL;

    map<string,string> g_mapAttribNameToHeader;
    map<string,string> g_mapAttribRuleToHeader;
    map<xstring,string> g_mapAttribNames;
}

extern "C" const char*
ap_set_attribute_mapping(cmd_parms* parms, void*, const char* attrName,
			 const char* headerName, const char* ruleName)
{
    g_mapAttribNameToHeader[attrName]=headerName;
    if (ruleName)
	g_mapAttribRuleToHeader[ruleName]=headerName;
    return NULL;
}

extern "C" module MODULE_VAR_EXPORT shibrm_module;

// per-server configuration structure
struct shibrm_server_config
{
    char* serverName;		// Name of this server
};

// creates the per-server configuration
extern "C" void* create_shibrm_server_config (pool * p, server_rec * s)
{
    shibrm_server_config* sc=(shibrm_server_config*)ap_pcalloc(p,sizeof(shibrm_server_config));
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shibrm_server_config (pool* p, void* base, void* sub)
{
    shibrm_server_config* sc=(shibrm_server_config*)ap_pcalloc(p,sizeof(shibrm_server_config));
    shibrm_server_config* parent=(shibrm_server_config*)base;
    shibrm_server_config* child=(shibrm_server_config*)sub;

    if (child->serverName)
        sc->serverName=ap_pstrdup(p,child->serverName);
    else if (parent->serverName)
        sc->serverName=ap_pstrdup(p,parent->serverName);
    else
        sc->serverName=NULL;

    return sc;
}

// per-dir module configuration structure
struct shibrm_dir_config
{
    char* szAuthGrpFile;	// Auth GroupFile name
    int bExportAssertion;       // export SAML assertion to the environment?
    RMConfig config;		// Resource Manager Configuration
};

// creates per-directory config structure
extern "C" void* create_shibrm_dir_config (pool* p, char* d)
{
    shibrm_dir_config* dc=(shibrm_dir_config*)ap_pcalloc(p,sizeof(shibrm_dir_config));
    dc->szAuthGrpFile = NULL;
    dc->bExportAssertion = -1;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shibrm_dir_config (pool* p, void* base, void* sub)
{
    shibrm_dir_config* dc=(shibrm_dir_config*)ap_pcalloc(p,sizeof(shibrm_dir_config));
    shibrm_dir_config* parent=(shibrm_dir_config*)base;
    shibrm_dir_config* child=(shibrm_dir_config*)sub;

    if (child->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,child->szAuthGrpFile);
    else if (parent->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,parent->szAuthGrpFile);
    else
        dc->szAuthGrpFile=NULL;

    dc->bExportAssertion=((child->bExportAssertion==-1) ? parent->bExportAssertion : child->bExportAssertion);
    return dc;
}

// generic per-server slot handlers
extern "C" const char* ap_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&shibrm_module);
    int offset=(int)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

#ifdef SOLARIS
extern "C"
#endif
typedef const char* (*config_fn_t)(void);

// SHIBRM Module commands

static command_rec shibrm_cmds[] = {
  {"ShibMapAttribute", (config_fn_t)ap_set_attribute_mapping, NULL,
   RSRC_CONF, TAKE23, "Define request header name and 'require' alias for an attribute."},

  {"AuthGroupFile", (config_fn_t)ap_set_file_slot,
   (void *) XtOffsetOf (shibrm_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shibrm_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML assertion to Shibboleth-defined header?"},

  {NULL}
};



/* 
 * shibrm_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shibrm_child_init(server_rec* s, pool* p)
{
    if (g_szConfig) {
      ap_log_error(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,s,
		   "shibrm_child_init(): already initialized!");
      exit (1);
    }

    try {
      // Assume that we've been initialized from the SHIRE module!
      g_szConfig = &(ShibTargetConfig::init(SHIBTARGET_RM, "NOOP"));
    } catch (runtime_error& e) {
      ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
		   "shibrm_child_init() failed to initialize SHIB Target");
      exit (1);
    }
  
    saml::NDC ndc("shibrm_child_init");

    // Create the RPC Handle..  Note: this should be per _thread_
    // if there is some way to do that reasonably..
    rpc_handle = new RPCHandle(SHIB_SHAR_SOCKET, SHIBRPC_PROG, SHIBRPC_VERS_1);

    // Transcode the attribute names we know about for quick handling map access.
    for (map<string,string>::const_iterator i=g_mapAttribNameToHeader.begin();
	 i!=g_mapAttribNameToHeader.end(); i++)
    {
        auto_ptr<XMLCh> temp(XMLString::transcode(i->first.c_str()));
	g_mapAttribNames[temp.get()]=i->first;
    }

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shibrm_child_init() done");
}


/*
 * shibrm_child_exit()
 *  Cleanup.
 */
extern "C" void shibrm_child_exit(server_rec* s, pool* p)
{
    delete rpc_handle;
    g_szConfig->shutdown();
    g_szConfig = NULL;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shibrm_child_exit() done");
}

static table* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    configfile_t* f;
    table* grps=ap_make_table(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if (!(f=ap_pcfg_openfile(r->pool,grpfile)))
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"groups_for_user() could not open group file: %s\n",
		      grpfile);
	return NULL;
    }

    pool* sp=ap_make_sub_pool(r->pool);

    while (!(ap_cfg_getline(l,MAX_STRING_LEN,f)))
    {
        if ((*l=='#') || (!*l))
	    continue;
	ll = l;
	ap_clear_pool(sp);

	group_name=ap_getword(sp,&ll,':');

	while (*ll)
	{
	    w=ap_getword_conf(sp,&ll);
	    if (!strcmp(w,user))
	    {
	        ap_table_setn(grps,ap_pstrdup(r->pool,group_name),"in");
		break;
	    }
	}
    }
    ap_cfg_closefile(f);
    ap_destroy_pool(sp);
    return grps;
}

static int shibrm_error_page(request_rec* r, const char* filename, ShibMLP& mlp)
{
  ifstream infile (filename);
  if (!infile) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR,r,
		    "shibrm_error_page() cannot open %s", filename);
      return SERVER_ERROR;
  }

  string res = mlp.run(infile);
  r->content_type = ap_psprintf(r->pool, "text/html");
  ap_send_http_header(r);
  ap_rprintf(r, res.c_str());
  return DONE;
}

// Return the "name" of this server to look up configuration options
static const char* get_service_name(request_rec* r)
{
  shibrm_server_config* sc =
    (shibrm_server_config*) ap_get_module_config(r->server->module_config,
						 &shibrm_module);

  if (sc->serverName)
    return sc->serverName;

  return ap_get_server_name(r);
}

// return the "normalized" target URL
static const char* get_target(request_rec* r, const char* target)
{
  const char* serverName = get_service_name(r);
  string tag;
  if ((g_szConfig->getINI()).get_tag (serverName, "normalizeRequest", true, &tag))
  {
    if (ShibINI::boolean (tag))
    {
        const char* colon=strchr(target,':');
        const char* slash=strchr(colon+3,'/');
        const char* second_colon=strchr(colon+3,':');
        return ap_pstrcat(r->pool,ap_pstrndup(r->pool,target,colon+3-target),
			  ap_get_server_name(r),
			  (second_colon && second_colon < slash) ?
			  second_colon : slash,
			  NULL);
    }
  }
  return target;
}

extern "C" int shibrm_check_auth(request_rec* r)
{
    ostringstream threadid;
    threadid << "[" << getpid() << "] shibrm" << '\0';
    saml::NDC ndc(threadid.str().c_str());

    ShibINI& ini = g_szConfig->getINI();
    const char* serverName = get_service_name (r);

    shibrm_dir_config* dc=
        (shibrm_dir_config*)ap_get_module_config(r->per_dir_config,&shibrm_module);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
		  "shibrm_check_auth() executing");

    const char* targeturl=get_target(r,ap_construct_url(r->pool,r->unparsed_uri,r));

    // Regular access to arbitrary resource...check AuthType
    const char* auth_type=ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type,"shibboleth"))
        return DECLINED;

    // Ok, this is a SHIB target; grab the cookie

    string shib_cookie;
    if (! ini.get_tag (serverName, "cookieName", true, &shib_cookie)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		    "shibrm_check_user: no cookieName configuration for %s",
		    serverName);
      return SERVER_ERROR;
    }

    ShibMLP markupProcessor;
    string tag;
    bool has_tag = ini.get_tag (serverName, "supportContact", true, &tag);
    markupProcessor.insert ("supportContact", has_tag ? tag : "");
    has_tag = ini.get_tag (serverName, "logoLocation", true, &tag);
    markupProcessor.insert ("logoLocation", has_tag ? tag : "");
    markupProcessor.insert ("requestURL", targeturl);

    const char* session_id=NULL;
    const char* cookies=ap_table_get(r->headers_in,"Cookie");
    if (!cookies || !(session_id=strstr(cookies,shib_cookie.c_str())))
    {
      // No cookie???  Must be a server error!
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		    "shibrm_check_auth() no cookie found");

      return SERVER_ERROR;
    }

    // Yep, we found a cookie -- pull it out (our session_id)
    session_id+=strlen(shib_cookie.c_str()) + 1;	/* Skip over the '=' */
    char* cookiebuf = ap_pstrdup(r->pool,session_id);
    char* cookieend = strchr(cookiebuf,';');
    if (cookieend)
      *cookieend = '\0';	/* Ignore anyting after a ; */
    session_id=cookiebuf;

    // Now grab the attributes...
    has_tag = ini.get_tag (serverName, "checkIPAddress", true, &tag);
    dc->config.checkIPAddress = (has_tag ? ShibINI::boolean (tag) : false);
    RM rm(rpc_handle, dc->config);

    vector<SAMLAssertion*> assertions;

    RPCError* status = rm.getAssertions(session_id, r->connection->remote_ip,
					targeturl, assertions);

    if (status->isError()) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		    "shibrm_check_auth() getAssertions failed: %s",
		    status->error_msg.c_str());

      string rmError;
      if (! ini.get_tag (serverName, "rmError", true, &rmError)) {
	ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		      "shibrm_check_auth: no rmError configuration for %s",
		      serverName);
	delete status;
	return SERVER_ERROR;	
      }
      markupProcessor.insert (*status);
      delete status;
      return shibrm_error_page (r, rmError.c_str(), markupProcessor);
    }
    delete status;

    string rmError;
    if (! ini.get_tag (serverName, "accessError", true, &rmError)) {
      ap_log_rerror(APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO,r,
		    "shibrm_check_auth: no accessError configuration for %s",
		    serverName);
      delete status;
      return SERVER_ERROR;	
    }

    // Only allow a single assertion...
    if (assertions.size() != 1) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
		    "shibrm_check_auth() found %d assertions (should be 1)",
		    assertions.size());
    }

    if (assertions.size() < 1)
      return shibrm_error_page (r, rmError.c_str(), markupProcessor);


    // Clear out the list of mapped attributes
    for (map<string,string>::const_iterator i=g_mapAttribNameToHeader.begin();
	 i!=g_mapAttribNameToHeader.end(); i++)
      ap_table_unset(r->headers_in, i->second.c_str());

    // Maybe export the assertion
    ap_table_unset(r->headers_in,"Shib-Attributes");
    if (dc->bExportAssertion==1) {
      string assertion;
      RM::serialize(*(assertions[0]), assertion);
      ap_table_set(r->headers_in,"Shib-Attributes", assertion.c_str());
    }

    // Export the attributes -- XXX: Assumes one statement!
    Iterator<SAMLAttribute*> i = RM::getAttributes(*(assertions[0]));
    while (i.hasNext())
    {
      SAMLAttribute* attr=i.next();

      // Are we supposed to export it?
      map<xstring,string>::const_iterator iname=g_mapAttribNames.find(attr->getName());
      if (iname!=g_mapAttribNames.end())
      {
	string hname=g_mapAttribNameToHeader[iname->second];
	Iterator<string> vals=attr->getSingleByteValues();
	if (hname=="REMOTE_USER" && vals.hasNext())
	  r->connection->user=ap_pstrdup(r->connection->pool,vals.next().c_str());
	else
	{
	 char* header = ap_pstrdup(r->pool, "");
	 for (int it = 0; vals.hasNext(); it++) {
		string value = vals.next();
		for (string::size_type pos = value.find_first_of(";", string::size_type(0)); pos != string::npos; pos = value.find_first_of(";", pos)) {
			value.insert(pos, "\\");
			pos += 2;
		}
		if (it == 0) {
			header=ap_pstrcat(r->pool, value.c_str(), NULL);
		} else {
			header=ap_pstrcat(r->pool, header, ";", value.c_str(), NULL);
		}
	 }
	 ap_table_setn(r->headers_in, hname.c_str(), header);
	}
      }
    }

    // clean up memory
    for (int i = 0; i < assertions.size(); i++)
      delete assertions[i];

    // mod_auth clone

    int m=r->method_number;
    bool method_restricted=false;
    const char *t, *w;
    
    const array_header* reqs_arr=ap_requires(r);
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
	    ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() accepting valid-user");
	    return OK;
	}
	else if (!strcmp(w,"user") && r->connection->user)
	{
	    while (*t)
	    {
	        w=ap_getword_conf(r->pool,&t);
		if (!strcmp(r->connection->user,w))
		{
		    ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() accepting user: %s",w);
		    return OK;
		}
	    }
	}
	else if (!strcmp(w,"group"))
	{
	    table* grpstatus=NULL;
	    if (dc->szAuthGrpFile && r->connection->user)
	    {
		ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() using groups file: %s\n",
			      dc->szAuthGrpFile);
		grpstatus=groups_for_user(r,r->connection->user,dc->szAuthGrpFile);
	    }
	    if (!grpstatus)
	        return DECLINED;

	    while (*t)
	    {
	        w=ap_getword_conf(r->pool,&t);
		if (ap_table_get(grpstatus,w))
		{
		    ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() accepting group: %s",w);
		    return OK;
		}
	    }
	}
	else
	{
	    map<string,string>::const_iterator i=g_mapAttribRuleToHeader.find(w);
	    if (i==g_mapAttribRuleToHeader.end())
		ap_log_rerror(APLOG_MARK,APLOG_WARNING,r,"shibrm_check_auth() didn't recognize require rule: %s\n",w);
	    else
	    {		
		const char* vals=ap_table_get(r->headers_in,i->second.c_str());
		while (*t && vals)
		{
		    string ruleval(ap_getword_conf(r->pool,&t));

                    string vals_str(vals);
                    int j = 0;
                    for (int i = 0;  i < vals_str.length();  i++)
		    {
			if (vals_str.at(i) == ';') 
			{
                            if (i == 0)
			    {
			        ap_log_rerror(APLOG_MARK,APLOG_WARNING,r,"shibrm_check_auth() invalid header encoding %s: starts with semicolon", vals);
                                return SERVER_ERROR;
			    }

                            if (vals_str.at(i-1) == '\\')
                            {
                                vals_str.erase(i-1, 1);
                                i--;
                                continue;
                            }

                            string val = vals_str.substr(j, i-j);
                            j = i+1;

                            if (val == ruleval)
                            {
		                ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() expecting %s, got %s: authorization granted", ruleval.c_str(), val.c_str());
                                return OK;
                            }
                            else
			    {
		                ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() expecting %s, got %s: authorization not granted", ruleval.c_str(), val.c_str());
			    }
                        }
		    }

		    string val = vals_str.substr(j, vals_str.length()-j);
                    if (val == ruleval)
                    {
	                ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() expecting %s, got %s: authorization granted", ruleval.c_str(), val.c_str());
                        return OK;
                    }
                    else
		    {
	                ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() expecting %s, got %s: authorization not granted", ruleval.c_str(), val.c_str());
		    }
		}
	    }
	}
    }

    if (!method_restricted)
        return OK;

    return shibrm_error_page (r, rmError.c_str(), markupProcessor);
}

extern "C"{
module MODULE_VAR_EXPORT shibrm_module = {
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_shibrm_dir_config,	/* dir config creater */
    merge_shibrm_dir_config,	/* dir merger --- default is to override */
    create_shibrm_server_config,	/* server config */
    merge_shibrm_server_config,	/* merge server config */
    shibrm_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    NULL,			/* check_user_id */
    shibrm_check_auth,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shibrm_child_init,		/* child_init */
    shibrm_child_exit,		/* child_exit */
    NULL			/* post read-request */
};
}
