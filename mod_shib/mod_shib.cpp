/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/*
 *  mod_shib.cpp
 *      Apache module to implement SHIRE and SHAR functionality.
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

#ifdef WIN32
# undef strtoul
#else
# include <unistd.h>
#endif

// SAML Runtime
#include <saml.h>
#include <shib.h>
#include <eduPerson.h>

#include <xercesc/util/Base64.hpp>

#include <strstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;

class CCacheEntry
{
public:
    CCacheEntry(request_rec* r, const char* sessionFile);
    ~CCacheEntry();

    SAMLAuthorityBinding* getBinding() { return m_binding; }
    Iterator<SAMLAttribute*> getAttributes(const char* resource_url);
    const XMLByte* getSerializedAssertion(const char* resource_url);
    bool isSessionValid(time_t lifetime, time_t timeout);
    const XMLCh* getHandle() { return m_handle.c_str(); }
    const XMLCh* getOriginSite() { return m_originSite.c_str(); }
    const char* getClientAddress() { return m_clientAddress.c_str(); }

private:
    void populate(const char* resource_url);

    xstring m_originSite;
    xstring m_handle;
    SAMLAuthorityBinding* m_binding;
    string m_clientAddress;
    SAMLResponse* m_response;
    SAMLAssertion* m_assertion;
    time_t m_sessionCreated;
    time_t m_lastAccess;
    XMLByte* m_serialized;

    static saml::QName g_authorityKind;
    static saml::QName g_respondWith;
    static vector<SAMLAttribute*> g_emptyVector;
};

class CCache
{
public:
    CCache();
    ~CCache();

    SAMLBinding* getBinding(const XMLCh* bindingProt);
    CCacheEntry* find(const char* key);
    void insert(const char* key, CCacheEntry* entry);
    void remove(const char* key);

    static CCache* g_Cache;

private:
    SAMLBinding* m_SAMLBinding;
    map<string,CCacheEntry*> m_hashtable;
};

// static members
CCache* CCache::g_Cache=NULL;
saml::QName CCacheEntry::g_authorityKind(saml::XML::SAMLP_NS,L(AttributeQuery));
saml::QName CCacheEntry::g_respondWith(saml::XML::SAML_NS,L(AttributeStatement));
vector<SAMLAttribute*> CCacheEntry::g_emptyVector;

CCache::CCache()
{
    m_SAMLBinding=SAMLBindingFactory::getInstance();
}

CCache::~CCache()
{
    delete m_SAMLBinding;
    for (map<string,CCacheEntry*>::iterator i=m_hashtable.begin(); i!=m_hashtable.end(); i++)
        delete i->second;
}

SAMLBinding* CCache::getBinding(const XMLCh* bindingProt)
{
    if (!XMLString::compareString(bindingProt,SAMLBinding::SAML_SOAP_HTTPS))
        return m_SAMLBinding;
    return NULL;
}

CCacheEntry* CCache::find(const char* key)
{
    map<string,CCacheEntry*>::const_iterator i=m_hashtable.find(key);
    if (i==m_hashtable.end())
        return NULL;
    return i->second;
}

void CCache::insert(const char* key, CCacheEntry* entry)
{
    m_hashtable[key]=entry;
}

void CCache::remove(const char* key)
{
    m_hashtable.erase(key);
}

CCacheEntry::CCacheEntry(request_rec* r, const char* sessionFile)
  : m_binding(NULL), m_assertion(NULL), m_response(NULL), m_lastAccess(0), m_sessionCreated(0), m_serialized(NULL)
{
    configfile_t* f;
    char line[MAX_STRING_LEN];
    const char* token = NULL;
    const char* w = NULL;
    auto_ptr<XMLCh> binding,location;

    if (!(f=ap_pcfg_openfile(r->pool,sessionFile)))
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,r,
                      "CCacheEntry() could not open session file: %s",sessionFile);
        throw runtime_error("CCacheEntry() could not open session file");
    }

    while (!(ap_cfg_getline(line,MAX_STRING_LEN,f)))
    {
        if ((*line=='#') || (!*line))
            continue;
        token = line;
        w=ap_getword(r->pool,&token,'=');

	if (!strcmp("Domain",w))
	{
	    auto_ptr<XMLCh> origin(XMLString::transcode(ap_getword(r->pool,&token,'=')));
	    m_originSite=origin.get();
	}
	else if (!strcmp("Handle",w))
	{
	    auto_ptr<XMLCh> handle(XMLString::transcode(ap_getword(r->pool,&token,'=')));
	    m_handle=handle.get();
	}
	else if (!strcmp("PBinding0",w))
	    binding=auto_ptr<XMLCh>(XMLString::transcode(ap_getword(r->pool,&token,'=')));
	else if (!strcmp("LBinding0",w))
	    location=auto_ptr<XMLCh>(XMLString::transcode(ap_getword(r->pool,&token,'=')));
        else if (!strcmp("Time",w))
	    m_sessionCreated=atoi(ap_getword(r->pool,&token,'='));
	else if (!strcmp("ClientAddress",w))
	    m_clientAddress=ap_getword(r->pool,&token,'=');
	else if (!strcmp("EOF",w))
	    break;
    }
    ap_cfg_closefile(f);
    
    if (binding.get()!=NULL || location.get()!=NULL)
        m_binding=new SAMLAuthorityBinding(g_authorityKind,binding.get(),location.get());

    m_lastAccess=time(NULL);
    if (!m_sessionCreated)
        m_sessionCreated=m_lastAccess;
}

CCacheEntry::~CCacheEntry()
{
    delete m_binding;
    delete m_response;
    delete[] m_serialized;
}

bool CCacheEntry::isSessionValid(time_t lifetime, time_t timeout)
{
    time_t now=time(NULL);
    if (lifetime > 0 && now > m_sessionCreated+lifetime)
        return false;
    if (timeout > 0 && now-m_lastAccess >= timeout)
        return false;
    m_lastAccess=now;
    return true;
}

Iterator<SAMLAttribute*> CCacheEntry::getAttributes(const char* resource_url)
{
    populate(resource_url);
    if (m_assertion)
    {
        Iterator<SAMLStatement*> i=m_assertion->getStatements();
        if (i.hasNext())
	{
	    SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(i.next());
	    if (s)
	        return s->getAttributes();
	}
    }
    return Iterator<SAMLAttribute*>(g_emptyVector);
}

const XMLByte* CCacheEntry::getSerializedAssertion(const char* resource_url)
{
    populate(resource_url);
    if (m_serialized)
        return m_serialized;
    if (!m_assertion)
        return NULL;
    ostrstream os;
    os << *m_assertion;
    unsigned int outlen;
    return m_serialized=Base64::encode(reinterpret_cast<XMLByte*>(os.str()),os.pcount(),&outlen);
}

void CCacheEntry::populate(const char* resource_url)
{
    // Can we use what we have?
    if (m_assertion && m_assertion->getNotOnOrAfter())
    {
        // This is awful, but the XMLDateTime class is truly horrible.
        time_t now=time(NULL);
#ifdef WIN32
        struct tm* ptime=gmtime(&now);
#else
	struct tm res;
	struct tm* ptime=gmtime_r(&now,&res);
#endif
	char timebuf[32];
	strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
	auto_ptr<XMLCh> timeptr(XMLString::transcode(timebuf));
	XMLDateTime curDateTime(timeptr.get());
	int result=XMLDateTime::compareOrder(&curDateTime,m_assertion->getNotOnOrAfter());
	if (XMLDateTime::LESS_THAN)
	    return;

	delete m_response;
	delete[] m_serialized;
	m_assertion=NULL;
        m_response=NULL;
	m_serialized=NULL;
    }

    if (!m_binding)
        return;

    auto_ptr<XMLCh> resource(XMLString::transcode(resource_url));    
    static const XMLCh* policies[] = { shibboleth::Constants::POLICY_CLUBSHIB };
    // static const saml::QName* respondWiths[] = { &g_respondWith };

    // Build a SAML Request and send it to the AA.
    SAMLSubject* subject=new SAMLSubject(m_handle.c_str(),m_originSite.c_str());
    SAMLAttributeQuery* q=new SAMLAttributeQuery(subject,resource.get());
    SAMLRequest* req=new SAMLRequest(q,ArrayIterator<saml::QName>(&g_respondWith));
    SAMLBinding* pBinding=CCache::g_Cache->getBinding(m_binding->getBinding());
    m_response=pBinding->send(*m_binding,*req);
    delete req;

    // Store off the assertion for quick access. Memory mgmt is based on the response pointer.
    Iterator<SAMLAssertion*> i=m_response->getAssertions();
    if (i.hasNext())
        m_assertion=i.next();

    auto_ptr<char> h(XMLString::transcode(m_handle.c_str()));
    auto_ptr<char> d(XMLString::transcode(m_originSite.c_str()));
    fprintf(stderr,"CCacheEntry::populate() fetched and stored SAML response for %s@%s\n",h.get(),d.get());
}


// per-process configuration
extern "C" module MODULE_VAR_EXPORT shib_module;
char* g_szSchemaPath = "/usr/local/shib/schemas/";
char* g_szSSLCertFile="";
char* g_szSSLKeyFile="";
char* g_szSSLKeyPass="";
char* g_szSSLCAList="";

map<string,string> g_mapAttribNameToHeader;
map<string,string> g_mapAttribRuleToHeader;
map<xstring,string> g_mapAttribNames;

extern "C" const char* ap_set_attribute_mapping(cmd_parms* parms, void*,
				     const char* attrName, const char* headerName, const char* ruleName)
{
    g_mapAttribNameToHeader[attrName]=headerName;
    if (ruleName)
	g_mapAttribRuleToHeader[ruleName]=headerName;
    return NULL;
}

// per-server configuration structure
struct shib_server_config
{
    char* szCookieName;		// name of session token
    char* szWAYFLocation;	// URL of WAYF service
    char* szSHIRELocation;	// URL of SHIRE acceptance point
    char* szSHIRESessionPath;	// path to storage for sessions
    int bNormalizeRequest;      // normalize requested URL based on server name?
};

// creates the per-server configuration
extern "C" void* create_shib_server_config (pool * p, server_rec * s)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    sc->szCookieName = NULL;
    sc->szWAYFLocation = NULL;
    sc->szSHIRELocation = NULL;
    sc->szSHIRESessionPath = NULL;
    sc->bNormalizeRequest = -1;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shib_server_config (pool* p, void* base, void* sub)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    shib_server_config* parent=(shib_server_config*)base;
    shib_server_config* child=(shib_server_config*)sub;
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

    if (child->szSHIRESessionPath)
        sc->szSHIRESessionPath=ap_pstrdup(p,child->szSHIRESessionPath);
    else if (parent->szSHIRESessionPath)
        sc->szSHIRESessionPath=ap_pstrdup(p,parent->szSHIRESessionPath);
    else
        sc->szSHIRESessionPath=NULL;

    sc->bNormalizeRequest=((child->bNormalizeRequest==-1) ? parent->bNormalizeRequest : child->bNormalizeRequest);
    return sc;
}

// per-dir module configuration structure
struct shib_dir_config
{
    char* szAuthGrpFile;	// Auth GroupFile name
    int bBasicHijack;		// activate for AuthType Basic?
    int bCheckAddress;		// validate IP address?
    int bSSLOnly;		// only over SSL?
    int bExportAssertion;       // export SAML assertion to the environment?
    time_t secLifetime;		// maximum token lifetime
    time_t secTimeout;		// maximum time between uses
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (pool* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    dc->secLifetime = -1;
    dc->secTimeout = -1;
    dc->bCheckAddress = -1;
    dc->bBasicHijack = -1;
    dc->bSSLOnly = -1;
    dc->bExportAssertion = -1;
    dc->szAuthGrpFile = NULL;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shib_dir_config (pool* p, void* base, void* sub)
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

    dc->bSSLOnly=((child->bSSLOnly==-1) ? parent->bSSLOnly : child->bSSLOnly);
    dc->bBasicHijack=((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bCheckAddress=((child->bCheckAddress==-1) ? parent->bCheckAddress : child->bCheckAddress);
    dc->bExportAssertion=((child->bExportAssertion==-1) ? parent->bExportAssertion : child->bExportAssertion);
    dc->secLifetime=((child->secLifetime==-1) ? parent->secLifetime : child->secLifetime);
    dc->secTimeout=((child->secTimeout==-1) ? parent->secTimeout : child->secTimeout);
    return dc;
}

// generic global slot handlers
extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* ap_set_global_flag_slot(cmd_parms* parms, void*, int arg)
{
    *((int*)(parms->info))=arg;
    return NULL;
}

// generic per-server slot handlers
extern "C" const char* shib_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&shib_module);
    int offset=(int)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return NULL;
}

extern "C" const char* set_normalize(cmd_parms* parms, shib_server_config* sc, const char* arg)
{
    sc->bNormalizeRequest=atoi(arg);
    return NULL;
}

// some shortcuts for directory config slots
extern "C" const char* set_lifetime(cmd_parms* parms, shib_dir_config* dc, const char* arg)
{
    dc->secLifetime=atoi(arg);
    return NULL;
}

extern "C" const char* set_timeout(cmd_parms* parms, shib_dir_config* dc, const char* arg)
{
    dc->secTimeout=atoi(arg);
    return NULL;
}

#ifdef SOLARIS
extern "C"
#endif
typedef const char* (*config_fn_t)(void);

// Shibboleth module commands

command_rec shib_cmds[] = {
  {"ShibSchemaPath", (config_fn_t)ap_set_global_string_slot, &g_szSchemaPath,
   RSRC_CONF, TAKE1, "Path to XML schema files."},
  {"ShibSSLCertFile", (config_fn_t)ap_set_global_string_slot, &g_szSSLCertFile,
   RSRC_CONF, TAKE1, "File containing SHAR's client certificate for contacting AA."},
  {"ShibSSLKeyFile", (config_fn_t)ap_set_global_string_slot, &g_szSSLKeyFile,
   RSRC_CONF, TAKE1, "File containing SHAR's private key for contacting AA."},
  {"ShibSSLKeyPass", (config_fn_t)ap_set_global_string_slot, &g_szSSLKeyPass,
   RSRC_CONF, TAKE1, "File containing passphrase for SHAR's private key."},
  {"ShibSSLCAList", (config_fn_t)ap_set_global_string_slot, &g_szSSLCAList,
   RSRC_CONF, TAKE1, "File containing list of CAs to trust when validating AA credentials."},
  {"ShibMapAttribute", (config_fn_t)ap_set_attribute_mapping, NULL,
   RSRC_CONF, TAKE23, "Define request header name and 'require' alias for an attribute."},

  {"ShibCookieName", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szCookieName),
   RSRC_CONF, TAKE1, "Name of cookie to use as session token."},
  {"SHIRELocation", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szSHIRELocation),
   RSRC_CONF, TAKE1, "URL of SHIRE handle acceptance point."},
  {"SHIRESessionPath", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szSHIRESessionPath),
   RSRC_CONF, TAKE1, "Path to SHIRE session cache files."},
  {"WAYFLocation", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szWAYFLocation),
   RSRC_CONF, TAKE1, "URL of WAYF service."},
  {"ShibNormalizeRequest", (config_fn_t)set_normalize, NULL,
   RSRC_CONF, TAKE1, "Normalize/convert browser requests using server name when redirecting."},

  {"AuthGroupFile", (config_fn_t)ap_set_file_slot,
   (void *) XtOffsetOf (shib_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibSSLOnly", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bSSLOnly),
   OR_AUTHCFG, FLAG, "Require SSL when accessing a secured directory?"},
  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "Respond to AuthType Basic and convert to shib?"},
  {"ShibCheckAddress", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bCheckAddress),
   OR_AUTHCFG, FLAG, "Verify IP address of requester matches token?"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML assertion to Shibboleth-defined header?"},
  {"ShibAuthLifetime", (config_fn_t)set_lifetime, NULL,
   OR_AUTHCFG, TAKE1, "Lifetime of session in seconds."},
  {"ShibAuthTimeout", (config_fn_t)set_timeout, NULL,
   OR_AUTHCFG, TAKE1, "Timeout for session in seconds."},

  {NULL}
};

class DummyMapper : public IOriginSiteMapper
{
public:
    DummyMapper() {}
    ~DummyMapper();
    virtual Iterator<xstring> getHandleServiceNames(const XMLCh* originSite) { return Iterator<xstring>(); }
    virtual Key* getHandleServiceKey(const XMLCh* handleService) { return NULL; }
    virtual Iterator<xstring> getSecurityDomains(const XMLCh* originSite);
    virtual Iterator<X509Certificate*> getTrustedRoots() { return Iterator<X509Certificate*>(); }

private:
    typedef map<xstring,vector<xstring>*> domains_t;
    domains_t m_domains;
};

Iterator<xstring> DummyMapper::getSecurityDomains(const XMLCh* originSite)
{
    domains_t::iterator i=m_domains.find(originSite);
    if (i==m_domains.end())
    {
        vector<xstring>* pv=new vector<xstring>();
        pv->push_back(originSite);
        pair<domains_t::iterator,bool> p=m_domains.insert(domains_t::value_type(originSite,pv));
	i=p.first;
    }
    return Iterator<xstring>(*(i->second));
}

DummyMapper::~DummyMapper()
{
    for (domains_t::iterator i=m_domains.begin(); i!=m_domains.end(); i++)
        delete i->second;
}

/* 
 * shib_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void shib_child_init(server_rec* s, pool* p)
{
    // Initialize runtime components.

    static SAMLConfig SAMLconf;
    static ShibConfig Shibconf;
    static DummyMapper mapper;

    SAMLconf.schema_dir=g_szSchemaPath;
    SAMLconf.ssl_certfile=g_szSSLCertFile;
    SAMLconf.ssl_keyfile=g_szSSLKeyFile;
    SAMLconf.ssl_keypass=g_szSSLKeyPass;
    SAMLconf.ssl_calist=g_szSSLCAList;
    SAMLconf.bVerbose=(s->loglevel==APLOG_DEBUG);

    if (!SAMLConfig::init(&SAMLconf))
    {
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
                     "shib_child_init() failed to initialize OpenSAML");
        exit(1);
    }

    Shibconf.origin_mapper=&mapper;
    if (!ShibConfig::init(&Shibconf))
    {
        ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,
                     "shib_child_init() failed to initialize Shibboleth runtime");
        exit(1);
    }

    // Transcode the attribute names we know about for quick handling map access.
    for (map<string,string>::const_iterator i=g_mapAttribNameToHeader.begin();
         i!=g_mapAttribNameToHeader.end(); i++)
    {
        auto_ptr<XMLCh> temp(XMLString::transcode(i->first.c_str()));
        g_mapAttribNames[temp.get()]=i->first;
    }

    CCache::g_Cache=new CCache();

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shib_child_init() done");
}


/*
 * shib_child_exit()
 *  Cleanup.
 */
extern "C" void shib_child_exit(server_rec* s, pool* p)
{
    delete CCache::g_Cache;
    ShibConfig::term();
    SAMLConfig::term();

    ap_log_error(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,s,"shib_child_exit() done");
}

inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

char* url_encode(request_rec* r, const char* s)
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

const char* get_target(request_rec* r, const char* target)
{
    shib_server_config* sc=
        (shib_server_config*)ap_get_module_config(r->server->module_config,&shib_module);
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

const char* get_shire_location(request_rec* r, const char* target)
{
    shib_server_config* sc=
        (shib_server_config*)ap_get_module_config(r->server->module_config,&shib_module);
    if (*(sc->szSHIRELocation)!='/')
        return url_encode(r,sc->szSHIRELocation);
    const char* colon=strchr(target,':');
    const char* slash=strchr(colon+3,'/');
    return url_encode(r,ap_pstrcat(r->pool,ap_pstrndup(r->pool,target,slash-target),
				   sc->szSHIRELocation,NULL));
}

int shib_shar_error(request_rec* r, SAMLException& e)
{
    r->content_type = ap_psprintf(r->pool, "text/html");
    ap_send_http_header(r);
    ap_rprintf(r, "<html>\n");
    ap_rprintf(r, "<head>\n");
    ap_rprintf(r, "<title>Shibboleth Attribute Exchange Failed</title>\n");
    ap_rprintf(r, "</HEAD><BODY><H3>Shibboleth Attribute Exchange Failed</H3>\n");
    ap_rprintf(r, "While attempting to securely contact your origin site to obtain information about you, an error occurred:<BR>");
    ap_rprintf(r, "<BLOCKQUOTE>%s</BLOCKQUOTE>", e.what());

    bool origin=true;
    Iterator<saml::QName> i=e.getCodes();
    if (i.hasNext() && XMLString::compareString(L(Responder),i.next().getLocalName()))
        origin=false;

    ap_rprintf(r, "<P>The error appears to be located at %s.<BR>", origin ? "your origin site" : "the resource provider's site");
    ap_rprintf(r, "<P>Try restarting your browser and accessing the site again to make sure the problem isn't temporary. Please contact the administrator of that site if this problem recurs. If possible, provide him/her with the error message shown above.");
    ap_rprintf(r, "</BODY>\n");
    ap_rprintf(r, "</HTML>\n");
    ap_rflush(r);

    return DONE;
}

extern "C" int shib_check_user(request_rec* r)
{
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shib_check_user executing");

    shib_server_config* sc=
        (shib_server_config*)ap_get_module_config(r->server->module_config,&shib_module);
    shib_dir_config* dc=
        (shib_dir_config*)ap_get_module_config(r->per_dir_config,&shib_module);

    const char* targeturl=get_target(r,ap_construct_url(r->pool,r->unparsed_uri,r));
 
    // If the user is accessing the SHIRE acceptance point, pass on.
    if (strstr(targeturl,sc->szSHIRELocation))
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shib_check_user ignoring SHIRE request");
        return OK;
    }

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

    // SSL check.
    if (dc->bSSLOnly==1 && strcmp(ap_http_method(r),"https"))
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
                      "shib_check_user() blocked non-SSL access");
        return SERVER_ERROR;
    }

    // We're in charge, so check for cookie.
    const char* session_id=NULL;
    const char* cookies=ap_table_get(r->headers_in,"Cookie");
    if (!cookies || !(session_id=strstr(cookies,sc->szCookieName)))
    {
        // Redirect to WAYF.
        char* wayf=ap_pstrcat(r->pool,sc->szWAYFLocation,
			      "?shire=",get_shire_location(r,targeturl),
			      "&target=",url_encode(r,targeturl),NULL);
        ap_table_setn(r->headers_out,"Location",wayf);
        return REDIRECT;
    }

    session_id+=strlen(sc->szCookieName) + 1;	/* Skip over the '=' */
    char* cookiebuf = ap_pstrdup(r->pool,session_id);
    char* cookieend = strchr(cookiebuf,';');
    if (cookieend)
        *cookieend = '\0';	/* Ignore anyting after a ; */
    session_id=cookiebuf;
	
    // The caching logic is the heart of the "SHAR".
    CCacheEntry* entry=NULL;
    try
    {
        entry=CCache::g_Cache->find(session_id);
        if (!entry)
        {
            // Construct the path to the session file
            char* sessionFile=ap_pstrcat(r->pool,sc->szSHIRESessionPath,"/",session_id,NULL);
            try
            {
                entry=new CCacheEntry(r,sessionFile);
                CCache::g_Cache->insert(session_id,entry);
            }
            catch (runtime_error e)
            {
                char* wayf=ap_pstrcat(r->pool,sc->szWAYFLocation,
				      "?shire=",get_shire_location(r,targeturl),
				      "&target=",url_encode(r,targeturl),NULL);
                ap_table_setn(r->headers_out,"Location",wayf);
                return REDIRECT;
            }
            auto_ptr<char> h(XMLString::transcode(entry->getHandle()));
            auto_ptr<char> d(XMLString::transcode(entry->getOriginSite()));
            ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
                          "shib_check_user() started session for %s@%s",h.get(),d.get());
        }
        
        if (!entry->isSessionValid(dc->secLifetime,dc->secTimeout))
        {
            ap_log_rerror(APLOG_MARK,APLOG_INFO,r,"shib_check_user() expired session");
            CCache::g_Cache->remove(session_id);
            delete entry;
            char* wayf=ap_pstrcat(r->pool,sc->szWAYFLocation,
				  "?shire=",get_shire_location(r,targeturl),
				  "&target=",url_encode(r,targeturl),NULL);
            ap_table_setn(r->headers_out,"Location",wayf);
            return REDIRECT;
        }

        if (dc->bCheckAddress==1 && entry->getClientAddress() &&
                 strcmp(entry->getClientAddress(),r->connection->remote_ip))
        {
            ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
                          "shib_check_user() detected bad address, expected %s",
                          entry->getClientAddress());
            CCache::g_Cache->remove(session_id);
            delete entry;
            return SERVER_ERROR;
        }

        // Clear existing headers.
        ap_table_unset(r->headers_in,"Shib-Attributes");
        for (map<string,string>::const_iterator h_iter=g_mapAttribNameToHeader.begin(); h_iter!=g_mapAttribNameToHeader.end(); h_iter++)
            if (h_iter->second!="REMOTE_USER")
                ap_table_unset(r->headers_in,h_iter->second.c_str());

        if (dc->bExportAssertion==1)
            ap_table_setn(r->headers_in,"Shib-Attributes",
                          reinterpret_cast<const char*>(entry->getSerializedAssertion(targeturl)));
        Iterator<SAMLAttribute*> i=entry->getAttributes(targeturl);
	
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
        return OK;
    }
    catch (SAMLException& e)
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
                      "shib_check_user() SAML exception: %s",e.what());
        Iterator<saml::QName> i=e.getCodes();
        int c=0;
        while (i.hasNext())
        {
	        c++;
	        saml::QName q=i.next();
	        if (c==1 && !XMLString::compareString(q.getNamespaceURI(),saml::XML::SAMLP_NS) &&
                !XMLString::compareString(q.getLocalName(),L(Requester)))
                continue;
            else if (c==2 && !XMLString::compareString(q.getNamespaceURI(),shibboleth::XML::SHIB_NS) &&
                     !XMLString::compareString(q.getLocalName(),shibboleth::XML::Literals::InvalidHandle))
            {
	            ap_log_rerror(APLOG_MARK,APLOG_INFO|APLOG_NOERRNO,r,
                              "shib_check_user() told by AA to discard handle");
                CCache::g_Cache->remove(session_id);
                delete entry;
                char* wayf=ap_pstrcat(r->pool,sc->szWAYFLocation,
			                  "?shire=",get_shire_location(r,targeturl),
			                  "&target=",url_encode(r,targeturl),NULL);
                ap_table_setn(r->headers_out,"Location",wayf);
                return REDIRECT;
            }
            break;
        }
	    return shib_shar_error(r,e);
    }
    catch (XMLException& e)
    {
        auto_ptr<char> msg(XMLString::transcode(e.getMessage()));
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
                      "shib_check_user() Xerxes XML exception: %s",msg.get());
        SAMLException ex(SAMLException::RESPONDER,msg.get());
        return shib_shar_error(r,ex);
    }
    catch (...)
    {
        ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO,r,
                      "shib_check_user() unknown exception");
    }

    return SERVER_ERROR;
}

table* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    configfile_t* f;
    table* grps=ap_make_table(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

    if (!(f=ap_pcfg_openfile(r->pool,grpfile)))
    {
        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                      "groups_for_user() could not open group file: %s\n",grpfile);
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


extern "C" int shib_check_auth(request_rec* r)
{
    shib_server_config* sc=
        (shib_server_config*)ap_get_module_config(r->server->module_config,&shib_module);
    shib_dir_config* dc=
        (shib_dir_config*)ap_get_module_config(r->per_dir_config,&shib_module);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,"shib_check_auth() executing");

    char* targeturl=ap_construct_url(r->pool,r->unparsed_uri,r);
    if (strstr(targeturl,sc->szSHIRELocation))
        return OK;

    // Regular access to arbitrary resource...check AuthType
    const char* auth_type=ap_auth_type(r);
    if (!auth_type || strcasecmp(auth_type,"shibboleth"))
        return DECLINED;

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
	    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                      "shib_check_auth() accepting valid-user");
	    return OK;
	}
	else if (!strcmp(w,"user") && r->connection->user)
	{
	    while (*t)
	    {
	        w=ap_getword_conf(r->pool,&t);
		if (!strcmp(r->connection->user,w))
		{
		    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                          "shib_check_auth() accepting user: %s",w);
		    return OK;
		}
	    }
	}
	else if (!strcmp(w,"group"))
	{
	    table* grpstatus=NULL;
	    if (dc->szAuthGrpFile && r->connection->user)
	    {
		ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                      "shib_check_auth() using groups file: %s\n",
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
		    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                          "shib_check_auth() accepting group: %s",w);
		    return OK;
		}
	    }
	}
	else
	{
	    map<string,string>::const_iterator i=g_mapAttribRuleToHeader.find(w);
	    if (i==g_mapAttribRuleToHeader.end())
		ap_log_rerror(APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO,r,
                      "shib_check_auth() didn't recognize require rule: %s\n",w);
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
		        ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,r,
                              "shib_check_auth() accepting rule %s, value%s",
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
module MODULE_VAR_EXPORT shib_module = {
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    create_shib_dir_config,	/* dir config creater */
    merge_shib_dir_config,	/* dir merger --- default is to override */
    create_shib_server_config,	/* server config */
    merge_shib_server_config,	/* merge server config */
    shib_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    shib_check_user,		/* check_user_id */
    shib_check_auth,		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    shib_child_init,		/* child_init */
    shib_child_exit,		/* child_exit */
    NULL			/* post read-request */
};
}
