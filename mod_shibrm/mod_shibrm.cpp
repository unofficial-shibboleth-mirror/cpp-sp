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
#include "http_protocol.h"
#include "http_main.h"
#include "util_script.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_log.h"

#include <unistd.h>

// SAML Runtime
#include <saml.h>
#include <shib.h>
#include <shib-target.h>

#include <strstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

static RPCHandle *rpc_handle = NULL;

map<string,string> g_mapAttribNameToHeader;
map<string,string> g_mapAttribRuleToHeader;
map<xstring,string> g_mapAttribNames;

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
    char* szCookieName;		// name of session token
    int bNormalizeRequest;      // normalize requested URL based on server name?
};

// creates the per-server configuration
extern "C" void* create_shibrm_server_config (pool * p, server_rec * s)
{
    shibrm_server_config* sc=(shibrm_server_config*)ap_pcalloc(p,sizeof(shibrm_server_config));
    sc->szCookieName = NULL;
    sc->bNormalizeRequest = -1;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shibrm_server_config (pool* p, void* base, void* sub)
{
    shibrm_server_config* sc=(shibrm_server_config*)ap_pcalloc(p,sizeof(shibrm_server_config));
    shibrm_server_config* parent=(shibrm_server_config*)base;
    shibrm_server_config* child=(shibrm_server_config*)sub;

    if (child->szCookieName)
        sc->szCookieName=ap_pstrdup(p,child->szCookieName);
    else if (parent->szCookieName)
        sc->szCookieName=ap_pstrdup(p,parent->szCookieName);
    else
        sc->szCookieName=NULL;

    sc->bNormalizeRequest=((child->bNormalizeRequest==-1) ? parent->bNormalizeRequest : child->bNormalizeRequest);
    return sc;
}

// per-dir module configuration structure
struct shibrm_dir_config
{
    char* szAuthGrpFile;	// Auth GroupFile name
    int bExportAssertion;       // export SAML assertion to the environment?
    int checkIPAddress;		// placeholder for check
    RMConfig config;		// Resource Manager Configuration
};

// creates per-directory config structure
extern "C" void* create_shibrm_dir_config (pool* p, char* d)
{
    shibrm_dir_config* dc=(shibrm_dir_config*)ap_pcalloc(p,sizeof(shibrm_dir_config));
    dc->szAuthGrpFile = NULL;
    dc->bExportAssertion = -1;
    dc->checkIPAddress = -1;
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
    dc->checkIPAddress=((child->checkIPAddress==-1) ? parent->checkIPAddress : child->checkIPAddress);
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

extern "C" const char* set_normalize(cmd_parms* parms, shibrm_server_config* sc, const char* arg)
{
    sc->bNormalizeRequest=atoi(arg);
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
  {"ShibCookieName", (config_fn_t)ap_set_server_string_slot,
   (void *) XtOffsetOf (shibrm_server_config, szCookieName),
   RSRC_CONF, TAKE1, "Name of cookie to use as session token."},
  {"ShibNormalizeRequest", (config_fn_t)set_normalize, NULL,
   RSRC_CONF, TAKE1, "Normalize/convert browser requests using server name when redirecting."},

  {"AuthGroupFile", (config_fn_t)ap_set_file_slot,
   (void *) XtOffsetOf (shibrm_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shibrm_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML assertion to Shibboleth-defined header?"},
  {"ShibCheckAddress", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shibrm_dir_config, checkIPAddress),
   OR_AUTHCFG, FLAG, "Verify IP address of requester matches token?"},

  {NULL}
};



/* 
 * shibrm_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shibrm_child_init(server_rec* s, pool* p)
{
    // XXX: Runtime components are initialized in SHIRE module...

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

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shibrm_child_exit() done");
}


/*
 * shibrm_child_exit()
 *  Cleanup.
 */
extern "C" void shibrm_child_exit(server_rec* s, pool* p)
{
    delete rpc_handle;
    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shibrm_child_exit() done");
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
    shibrm_server_config* sc=
        (shibrm_server_config*)ap_get_module_config(r->server->module_config,&shibrm_module);
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

extern "C" int shibrm_check_auth(request_rec* r)
{
    shibrm_server_config* sc=
        (shibrm_server_config*)ap_get_module_config(r->server->module_config,&shibrm_module);
    shibrm_dir_config* dc=
        (shibrm_dir_config*)ap_get_module_config(r->per_dir_config,&shibrm_module);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() executing");

    char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);

    // Regular access to arbitrary resource...check AuthType
    const char* auth_type=ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type,"shibboleth"))
        return DECLINED;

    // Ok, this is a SHIB target; grab the cookie

    const char* session_id=NULL;
    const char* cookies=ap_table_get(r->headers_in,"Cookie");
    if (!cookies || !(session_id=strstr(cookies,sc->szCookieName)))
    {
      // No cookie???  Must be a server error!
      ap_log_rerror(APLOG_MARK,APLOG_ERR,r,"shibrm_check_auth() no cookie found");

      return SERVER_ERROR;
    }

    // Yep, we found a cookie -- pull it out (our session_id)
    session_id+=strlen(sc->szCookieName) + 1;	/* Skip over the '=' */
    char* cookiebuf = ap_pstrdup(r->pool,session_id);
    char* cookieend = strchr(cookiebuf,';');
    if (cookieend)
      *cookieend = '\0';	/* Ignore anyting after a ; */
    session_id=cookiebuf;

    // Now grab the attributes...
    dc->config.checkIPAddress = (dc->checkIPAddress == 1 ? true : false);
    RM rm(rpc_handle, dc->config);
    Resource resource(targeturl);

    vector<saml::QName*> request;
    vector<SAMLAttribute*> response;
    string assertion;

    RPCError status = rm.getAttributes(session_id, r->connection->remote_ip,
				       &resource, request, response, assertion);


    if (status.isError()) {
      // XXX: return an error page

      ap_log_rerror(APLOG_MARK,APLOG_ERR,r,
		    "shibrm_check_auth() getAttributed failed: %s",
		    status.error_msg.c_str());

      return SERVER_ERROR;
    }

    // Clear out the list of mapped attributes
    for (map<string,string>::const_iterator i=g_mapAttribNameToHeader.begin();
	 i!=g_mapAttribNameToHeader.end(); i++)
      ap_table_unset(r->headers_in, i->second.c_str());


    // Maybe export the assertion
    ap_table_unset(r->headers_in,"Shib-Attributes");
    if (dc->bExportAssertion==1)
      ap_table_setn(r->headers_in,"Shib-Attributes", assertion.c_str());


    // Export the attributes
    Iterator<SAMLAttribute*> i=Iterator<SAMLAttribute*>(response);
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
	  char* header=ap_pstrdup(r->pool," ");
	  while (vals.hasNext())
	    header=ap_pstrcat(r->pool,header,vals.next().c_str()," ",NULL);
	  ap_table_setn(r->headers_in,hname.c_str(),header);
	}
      }
    }

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
		    string ruleval(" ");
		    ruleval+=ap_getword_conf(r->pool,&t);
		    ruleval+=" ";
		    if (strstr(vals,ruleval.c_str()))
		    {
		        ap_log_rerror(APLOG_MARK,APLOG_DEBUG,r,"shibrm_check_auth() accepting rule %s, value%s",
				      w,ruleval.c_str());
			return OK;
		    }
		}
	    }
	}
    }

    if (!method_restricted)
        return OK;

    r->content_type = ap_psprintf(r->pool, "text/html");
    ap_send_http_header(r);
    ap_rprintf(r, "<html>\n");
    ap_rprintf(r, "<head>\n");
    ap_rprintf(r, "<title>Authorization Failed</title>\n");
    ap_rprintf(r, "<h1>Authorization Failed</h1>\n");
    ap_rprintf(r, "Based on the information provided to this server about you, you are not authorized to access '%s'<br>", targeturl);
    ap_rprintf(r, "Please contact the administrator of this service or application if you believe this to be an error.<br>");
    ap_rprintf(r, "</head>\n");
    ap_rprintf(r, "</html>\n");
    ap_rflush(r);

    return DONE;
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
