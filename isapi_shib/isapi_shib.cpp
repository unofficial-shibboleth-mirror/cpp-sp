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

/* isapi_shib.cpp - Shibboleth ISAPI filter

   Scott Cantor
   8/23/02
*/

#include <windows.h>
#include <httpfilt.h>

// SAML Runtime
#include <saml.h>
#include <shib.h>
#include <eduPerson.h>

#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <xercesc/util/Base64.hpp>

#include <ctime>
#include <strstream>
#include <stdexcept>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;

class CCacheEntry;
class CCache
{
public:
    CCache();
    ~CCache();

    SAMLBinding* getBinding(const XMLCh* bindingProt);
    CCacheEntry* find(const char* key);
    void insert(const char* key, CCacheEntry* entry);
    void remove(const char* key);
    void sweep(time_t lifetime);

    bool lock() { EnterCriticalSection(&m_lock); return true; }
    void unlock() { LeaveCriticalSection(&m_lock); }

private:
    SAMLBinding* m_SAMLBinding;
    map<string,CCacheEntry*> m_hashtable;
    CRITICAL_SECTION m_lock;
};

// Per-website global structure
struct settings_t
{
    settings_t();
    string g_CookieName;                    // name of authentication token
    string g_WAYFLocation;                  // URL of WAYF service
    string g_GarbageCollector;              // URL of cache garbage collection service
    string g_SHIRELocation;                 // URL of SHIRE acceptance point
    string g_SHIRESessionPath;              // path to storage for sessions
    vector<string> g_MustContain;           // simple URL matching string array
    bool g_bSSLOnly;                        // only over SSL?
    time_t g_Lifetime;                      // maximum token lifetime
    time_t g_Timeout;                       // maximum time between uses
    bool g_bCheckAddress;                   // validate IP addresses?
    bool g_bExportAssertion;                // export SAML assertion to header?
    CCache g_AuthCache;                     // local auth cache
};

settings_t::settings_t()
{
    g_bSSLOnly=true;
    g_Lifetime=7200;
    g_Timeout=3600;
    g_bCheckAddress=true;
    g_bExportAssertion=false;
}

class CCacheEntry
{
public:
    CCacheEntry(const char* sessionFile);
    ~CCacheEntry();

    SAMLAuthorityBinding* getBinding() { return m_binding; }
    Iterator<SAMLAttribute*> getAttributes(const char* resource_url, settings_t* pSite);
    const XMLByte* getSerializedAssertion(const char* resource_url, settings_t* pSite);
    bool isSessionValid(time_t lifetime, time_t timeout);
    const XMLCh* getHandle() { return m_handle.c_str(); }
    const XMLCh* getOriginSite() { return m_originSite.c_str(); }
    const char* getClientAddress() { return m_clientAddress.c_str(); }

private:
    void populate(const char* resource_url, settings_t* pSite);

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
    friend class CCache;
};

// static members
saml::QName CCacheEntry::g_authorityKind(saml::XML::SAMLP_NS,L(AttributeQuery));
saml::QName CCacheEntry::g_respondWith(saml::XML::SAML_NS,L(AttributeStatement));

CCache::CCache()
{
    m_SAMLBinding=SAMLBindingFactory::getInstance();
    InitializeCriticalSection(&m_lock);
}

CCache::~CCache()
{
    DeleteCriticalSection(&m_lock);
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

void CCache::sweep(time_t lifetime)
{
    time_t now=time(NULL);
    for (map<string,CCacheEntry*>::iterator i=m_hashtable.begin(); i!=m_hashtable.end();)
    {
        if (lifetime > 0 && now > i->second->m_sessionCreated+lifetime)
        {
            delete i->second;
            i=m_hashtable.erase(i);
        }
        else
            i++;
    }
}

CCacheEntry::CCacheEntry(const char* sessionFile)
  : m_binding(NULL), m_assertion(NULL), m_response(NULL), m_lastAccess(0), m_sessionCreated(0), m_serialized(NULL)
{
    FILE* f;
    char line[1024];
    const char* token = NULL;
    char* w = NULL;
    auto_ptr<XMLCh> binding,location;

    if (!(f=fopen(sessionFile,"r")))
    {
        fprintf(stderr,"CCacheEntry() could not open session file: %s",sessionFile);
        throw runtime_error("CCacheEntry() could not open session file");
    }

    while (fgets(line,1024,f))
    {
        if ((*line=='#') || (!*line))
            continue;
        token = line;
        w=strchr(token,'=');
        if (!w)
            continue;
        *w++=0;
        if (w[strlen(w)-1]=='\n')
            w[strlen(w)-1]=0;

        if (!strcmp("Domain",token))
        {
	        auto_ptr<XMLCh> origin(XMLString::transcode(w));
	        m_originSite=origin.get();
        }
        else if (!strcmp("Handle",token))
        {
	        auto_ptr<XMLCh> handle(XMLString::transcode(w));
	        m_handle=handle.get();
        }
        else if (!strcmp("PBinding0",token))
	        binding=auto_ptr<XMLCh>(XMLString::transcode(w));
        else if (!strcmp("LBinding0",token))
	        location=auto_ptr<XMLCh>(XMLString::transcode(w));
        else if (!strcmp("Time",token))
	        m_sessionCreated=atoi(w);
        else if (!strcmp("ClientAddress",token))
	        m_clientAddress=w;
        else if (!strcmp("EOF",token))
	        break;
    }
    fclose(f);
    
    if (binding.get()!=NULL && location.get()!=NULL)
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

Iterator<SAMLAttribute*> CCacheEntry::getAttributes(const char* resource_url, settings_t* pSite)
{
    populate(resource_url,pSite);
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
    return Iterator<SAMLAttribute*>();
}

const XMLByte* CCacheEntry::getSerializedAssertion(const char* resource_url, settings_t* pSite)
{
    populate(resource_url,pSite);
    if (m_serialized)
        return m_serialized;
    if (!m_assertion)
        return NULL;
    ostrstream os;
    os << *m_assertion;
    unsigned int outlen;
    return m_serialized=Base64::encode(reinterpret_cast<XMLByte*>(os.str()),os.pcount(),&outlen);
}

void CCacheEntry::populate(const char* resource_url, settings_t* pSite)
{
#undef FUNC
#define FUNC populate
    Category& log=Category::getInstance("isapi_shib.CCacheEntry");

    // Can we use what we have?
    if (m_assertion && m_assertion->getNotOnOrAfter())
    {
        // This is awful, but the XMLDateTime class is truly horrible.
        time_t now=time(NULL);
        struct tm* ptime=gmtime(&now);
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

        log.info("%s: cached attributes have expired",FUNC);
    }

    if (!m_binding)
        return;

    auto_ptr<XMLCh> resource(XMLString::transcode(resource_url));

    // Build a SAML Request and send it to the AA.
    SAMLSubject* subject=new SAMLSubject(m_handle.c_str(),m_originSite.c_str());
    SAMLAttributeQuery* q=new SAMLAttributeQuery(subject,resource.get());
    SAMLRequest* req=new SAMLRequest(q,ArrayIterator<saml::QName>(&g_respondWith));
    SAMLBinding* pBinding=pSite->g_AuthCache.getBinding(m_binding->getBinding());
    m_response=pBinding->send(*m_binding,*req);
    delete req;

    // Store off the assertion for quick access. Memory mgmt is based on the response pointer.
    Iterator<SAMLAssertion*> i=m_response->getAssertions();
    if (i.hasNext())
        m_assertion=i.next();

    auto_ptr<char> h(XMLString::transcode(m_handle.c_str()));
    auto_ptr<char> d(XMLString::transcode(m_originSite.c_str()));
    log.info("%s: fetched and stored SAML response for %s@%s",FUNC,h.get(),d.get());
}

class DummyMapper : public IOriginSiteMapper
{
public:
    DummyMapper() { InitializeCriticalSection(&m_lock); }
    ~DummyMapper();
    virtual Iterator<xstring> getHandleServiceNames(const XMLCh* originSite) { return Iterator<xstring>(); }
    virtual Key* getHandleServiceKey(const XMLCh* handleService) { return NULL; }
    virtual Iterator<xstring> getSecurityDomains(const XMLCh* originSite);
    virtual Iterator<X509Certificate*> getTrustedRoots() { return Iterator<X509Certificate*>(); }

private:
    typedef map<xstring,vector<xstring>*> domains_t;
    domains_t m_domains;
    CRITICAL_SECTION m_lock;
};

Iterator<xstring> DummyMapper::getSecurityDomains(const XMLCh* originSite)
{
    EnterCriticalSection(&m_lock);
    vector<xstring>* pv=NULL;
    domains_t::iterator i=m_domains.find(originSite);
    if (i==m_domains.end())
    {
        pv=new vector<xstring>();
        pv->push_back(originSite);
        pair<domains_t::iterator,bool> p=m_domains.insert(domains_t::value_type(originSite,pv));
	    i=p.first;
    }
    else
        pv=i->second;
    LeaveCriticalSection(&m_lock);
    return Iterator<xstring>(*pv);
}

DummyMapper::~DummyMapper()
{
    for (domains_t::iterator i=m_domains.begin(); i!=m_domains.end(); i++)
        delete i->second;
    DeleteCriticalSection(&m_lock);
}

// globals
HINSTANCE g_hinstDLL;
ULONG g_ulMaxSite=1;                        // max IIS site instance to handle
settings_t* g_Sites=NULL;                   // array of site settings
map<string,string> g_mapAttribNameToHeader; // attribute mapping
map<xstring,string> g_mapAttribNames;


extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason==DLL_PROCESS_ATTACH)
        g_hinstDLL=hinstDLL;
    return TRUE;
}

extern "C" BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
    if (!pVer)
        return FALSE;

    // Get module pathname and replace file name with ini file name.
    char inifile[MAX_PATH+1];
    if (GetModuleFileName(g_hinstDLL,inifile,MAX_PATH+1)==0)
        return FALSE;
    char* pch=strrchr(inifile,'\\');
    if (pch==NULL)
        return FALSE;
    pch++;
    *pch=0;
    strcat(inifile,"isapi_shib.ini");

    // Read system-wide parameters from isapi_shib.ini.
    char buf[1024];
    char buf3[48];

    try
    {
        SAMLConfig& SAMLconf=SAMLConfig::getConfig();
        
        GetPrivateProfileString("shibboleth","ShibLogConfig","",buf,sizeof(buf),inifile);
        if (*buf)
            PropertyConfigurator::configure(buf);
        Category& log=Category::getInstance("isapi_shib.GetFilterVersion");
        log.info("using INI file: %s",inifile);

        GetPrivateProfileString("shibboleth","ShibSchemaPath","",buf,sizeof(buf),inifile);
        if (!*buf)
        {
            log.fatal("ShibSchemaPath missing");
            return FALSE;
        }
        SAMLconf.schema_dir=buf;
        if (*SAMLconf.schema_dir.end()!='\\')
            SAMLconf.schema_dir+='\\';

        GetPrivateProfileString("shibboleth","ShibSSLCertFile","",buf,sizeof(buf),inifile);
        if (!*buf)
        {
            log.fatal("ShibSSLCertFile missing");
            return FALSE;
        }
        SAMLconf.ssl_certfile=buf;

        GetPrivateProfileString("shibboleth","ShibSSLKeyFile","",buf,sizeof(buf),inifile);
        if (!*buf)
        {
            log.fatal("ShibSSLKeyFile missing");
            return FALSE;
        }
        SAMLconf.ssl_keyfile=buf;

        GetPrivateProfileString("shibboleth","ShibSSLKeyPass","",buf,sizeof(buf),inifile);
        SAMLconf.ssl_keypass=buf;

        GetPrivateProfileString("shibboleth","ShibSSLCAList","",buf,sizeof(buf),inifile);
        SAMLconf.ssl_calist=buf;

        // Read site count and allocate site array.
        g_ulMaxSite=GetPrivateProfileInt("shibboleth","max-site",0,inifile);
        if (g_ulMaxSite==0)
        {
            log.fatal("max-site was 0 or invalid");
            return FALSE;
        }
        log.debug("max-site is %d",g_ulMaxSite);
        g_Sites=new settings_t[g_ulMaxSite];

        // Read site-specific settings for each site.
        for (ULONG i=0; i<g_ulMaxSite; i++)
        {
            ultoa(i+1,buf3,10);
            GetPrivateProfileString(buf3,"ShibSiteName","X",buf,sizeof(buf),inifile);
            if (!strcmp(buf,"X"))
            {
                log.info("skipping site %d (no ShibSiteName)",i);
                continue;
            }

            GetPrivateProfileString(buf3,"ShibCookieName","",buf,sizeof(buf),inifile);
            if (!*buf)
            {
                delete[] g_Sites;
                log.fatal("ShibCookieName missing in site %d",i);
                return FALSE;
            }
            g_Sites[i].g_CookieName=buf;

            GetPrivateProfileString(buf3,"WAYFLocation","",buf,sizeof(buf),inifile);
            if (!*buf)
            {
                delete[] g_Sites;
                log.fatal("WAYFLocation missing in site %d",i);
                return FALSE;
            }
            g_Sites[i].g_WAYFLocation=buf;

            GetPrivateProfileString(buf3,"GarbageCollector","",buf,sizeof(buf),inifile);
            if (!*buf)
            {
                delete[] g_Sites;
                log.fatal("GarbageCollector missing in site %d",i);
                return FALSE;
            }
            g_Sites[i].g_GarbageCollector=buf;

            GetPrivateProfileString(buf3,"SHIRELocation","",buf,sizeof(buf),inifile);
            if (!*buf)
            {
                delete[] g_Sites;
                log.fatal("SHIRELocation missing in site %d",i);
                return FALSE;
            }
            g_Sites[i].g_SHIRELocation=buf;

            GetPrivateProfileString(buf3,"SHIRESessionPath","",buf,sizeof(buf),inifile);
            if (!*buf)
            {
                delete[] g_Sites;
                log.fatal("SHIRESessionPath missing in site %d",i);
                return FALSE;
            }
            g_Sites[i].g_SHIRESessionPath=buf;
            if (g_Sites[i].g_SHIRESessionPath[g_Sites[i].g_SHIRESessionPath.length()]!='\\')
                g_Sites[i].g_SHIRESessionPath+='\\';

            // Old-style matching string.
            GetPrivateProfileString(buf3,"ShibMustContain","",buf,sizeof(buf),inifile);
            _strupr(buf);
            char* start=buf;
            while (char* sep=strchr(start,';'))
            {
                *sep='\0';
                if (*start)
                {
                    g_Sites[i].g_MustContain.push_back(start);
                    log.info("site %d told to match against %s",i,start);
                }
                start=sep+1;
            }
            if (*start)
            {
                g_Sites[i].g_MustContain.push_back(start);
                log.info("site %d told to match against %s",i,start);
            }
            
            if (GetPrivateProfileInt(buf3,"ShibSSLOnly",1,inifile)==0)
                g_Sites[i].g_bSSLOnly=false;
            if (GetPrivateProfileInt(buf3,"ShibCheckAddress",1,inifile)==0)
                g_Sites[i].g_bCheckAddress=false;
            if (GetPrivateProfileInt(buf3,"ShibExportAssertion",0,inifile)==1)
                g_Sites[i].g_bExportAssertion=true;
            g_Sites[i].g_Lifetime=GetPrivateProfileInt(buf3,"ShibAuthLifetime",7200,inifile);
            if (g_Sites[i].g_Lifetime<=0)
                g_Sites[i].g_Lifetime=7200;
            g_Sites[i].g_Timeout=GetPrivateProfileInt(buf3,"ShibAuthTimeout",3600,inifile);
            if (g_Sites[i].g_Timeout<=0)
                g_Sites[i].g_Timeout=3600;
            log.info("configuration of site %d complete",i);
        }

        ShibConfig& Shibconf=ShibConfig::getConfig();
        static DummyMapper mapper;

        if (!SAMLconf.init())
        {
            delete[] g_Sites;
            log.fatal("SAML initialization failed");
            return FALSE;
        }

        Shibconf.origin_mapper=&mapper;
        if (!Shibconf.init())
        {
            delete[] g_Sites;
            log.fatal("Shibboleth initialization failed");
            return FALSE;
        }

        char buf2[32767];
        DWORD res=GetPrivateProfileSection("ShibMapAttributes",buf2,sizeof(buf2),inifile);
        if (res==sizeof(buf2)-2)
        {
            delete[] g_Sites;
            log.fatal("ShibMapAttributes INI section was larger than 32k");
            return FALSE;
        }

        for (char* attr=buf2; *attr; attr++)
        {
            char* delim=strchr(attr,'=');
            if (!delim)
            {
                delete[] g_Sites;
                log.fatal("unrecognizable ShibMapAttributes directive: %s",attr);
                return FALSE;
            }
            *delim++=0;
            g_mapAttribNameToHeader[attr]=(string(delim) + ':');
            log.info("mapping attribute %s to request header %s",attr,delim);
            attr=delim + strlen(delim);
        }

        log.info("configuration of attributes complete");

        // Transcode the attribute names we know about for quick handling map access.
        for (map<string,string>::const_iterator j=g_mapAttribNameToHeader.begin();
             j!=g_mapAttribNameToHeader.end(); j++)
        {
            auto_ptr<XMLCh> temp(XMLString::transcode(j->first.c_str()));
            g_mapAttribNames[temp.get()]=j->first;
        }

        res=GetPrivateProfileSection("ShibExtensions",buf2,sizeof(buf2),inifile);
        if (res==sizeof(buf2)-2)
        {
            delete[] g_Sites;
            log.fatal("ShibExtensions INI section was larger than 32k");
            return FALSE;
        }

        for (char* libpath=buf2; *libpath; libpath+=strlen(libpath)+1)
            SAMLconf.saml_register_extension(libpath);

        log.info("completed loading of extension libraries");
    }
    catch (bad_alloc)
    {
        delete[] g_Sites;
        Category::getInstance("isapi_shib.GetFilterVersion").fatal("out of memory");
        return FALSE;
    }
    catch (log4cpp::ConfigureFailure& ex)
    {
        delete[] g_Sites;
        WritePrivateProfileString("startlog","bailed-at","log4cpp exception caught",inifile);
        WritePrivateProfileString("startlog","log4cpp",ex.what(),inifile);
        return FALSE;
    }
    catch (SAMLException& ex)
    {
        delete[] g_Sites;
        Category::getInstance("isapi_shib.GetFilterVersion").fatal("caught SAML exception: %s",ex.what());
        return FALSE;
    }

    pVer->dwFilterVersion=HTTP_FILTER_REVISION;
    strncpy(pVer->lpszFilterDesc,"Shibboleth ISAPI Filter",SF_MAX_FILTER_DESC_LEN);
    pVer->dwFlags=(SF_NOTIFY_ORDER_HIGH |
                   SF_NOTIFY_SECURE_PORT |
                   SF_NOTIFY_NONSECURE_PORT |
                   SF_NOTIFY_PREPROC_HEADERS |
                   SF_NOTIFY_LOG);
    return TRUE;
}

extern "C" BOOL WINAPI TerminateFilter(DWORD dwFlags)
{
    Category::getInstance("isapi_shib.TerminateFilter").info("shutting down...");
    delete[] g_Sites;
    g_Sites=NULL;
    ShibConfig::getConfig().term();
    SAMLConfig::getConfig().term();
    Category::getInstance("isapi_shib.TerminateFilter").info("shut down complete");
    return TRUE;
}

/* Next up, some suck-free versions of various APIs.

   You DON'T require people to guess the buffer size and THEN tell them the right size.
   Returning an LPCSTR is apparently way beyond their ken. Not to mention the fact that
   constant strings aren't typed as such, making it just that much harder. These versions
   are now updated to use a special growable buffer object, modeled after the standard
   string class. The standard string won't work because they left out the option to
   pre-allocate a non-constant buffer.
*/

class dynabuf
{
public:
    dynabuf() { bufptr=NULL; buflen=0; }
    dynabuf(size_t s) { bufptr=new char[buflen=s]; *bufptr=0; }
    ~dynabuf() { delete[] bufptr; }
    size_t length() const { return bufptr ? strlen(bufptr) : 0; }
    size_t size() const { return buflen; }
    bool empty() const { return length()==0; }
    void reserve(size_t s, bool keep=false);
    void erase() { if (bufptr) *bufptr=0; }
    operator char*() { return bufptr; }
    bool operator ==(const char* s) const;
    bool operator !=(const char* s) const { return !(*this==s); }
private:
    char* bufptr;
    size_t buflen;
};

void dynabuf::reserve(size_t s, bool keep)
{
    if (s<=buflen)
        return;
    char* p=new char[s];
    if (keep)
        while (buflen--)
            p[buflen]=bufptr[buflen];
    buflen=s;
    delete[] bufptr;
    bufptr=p;
}

bool dynabuf::operator==(const char* s) const
{
    if (buflen==NULL || s==NULL)
        return (buflen==NULL && s==NULL);
    else
        return strcmp(bufptr,s)==0;
}

void GetServerVariable(PHTTP_FILTER_CONTEXT pfc,
                       LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
    throw (bad_alloc, DWORD)
{
    s.erase();
    s.reserve(size);
    size=s.size();

    while (!pfc->GetServerVariable(pfc,lpszVariable,s,&size))
    {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        throw ERROR_NO_DATA;
}

void GetHeader(PHTTP_FILTER_PREPROC_HEADERS pn, PHTTP_FILTER_CONTEXT pfc,
               LPSTR lpszName, dynabuf& s, DWORD size=80, bool bRequired=true)
    throw (bad_alloc, DWORD)
{
    s.erase();
    s.reserve(size);
    size=s.size();

    while (!pn->GetHeader(pfc,lpszName,s,&size))
    {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        throw ERROR_NO_DATA;
}

inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

string url_encode(const char* url) throw (bad_alloc)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";
    string s;
    for (const char* pch=url; *pch; pch++)
    {
        if (strchr(badchars,*pch)!=NULL || *pch<=0x1F || *pch>=0x7F)
            s=s + '%' + hexchar(*pch >> 4) + hexchar(*pch & 0x0F);
        else
            s+=*pch;
    }
    return s;
}

string get_target(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pn, settings_t* pSite)
{
    // Reconstructing the requested URL is not fun. Apparently, the PREPROC_HEADERS
    // event means way pre. As in, none of the usual CGI headers are in place yet.
    // It's actually almost easier, in a way, because all the path-info and query
    // stuff is in one place, the requested URL, which we can get. But we have to
    // reconstruct the protocol/host pair using tweezers.
    string s;
    if (pfc->fIsSecurePort)
        s="https://";
    else
        s="http://";

    dynabuf buf(256);
    GetServerVariable(pfc,"SERVER_NAME",buf);
    s+=buf;

    GetServerVariable(pfc,"SERVER_PORT",buf,10);
    if (buf!=(pfc->fIsSecurePort ? "443" : "80"))
        s=s + ':' + static_cast<char*>(buf);

    GetHeader(pn,pfc,"url",buf,256,false);
    s+=buf;

    return s;
}

string get_shire_location(PHTTP_FILTER_CONTEXT pfc, settings_t* pSite, const char* target)
{
    if (pSite->g_SHIRELocation[0]!='/')
        return url_encode(pSite->g_SHIRELocation.c_str());
    const char* colon=strchr(target,':');
    const char* slash=strchr(colon+3,'/');
    string s(target,slash-target);
    s+=pSite->g_SHIRELocation;
    return url_encode(s.c_str());
}

DWORD WriteClientError(PHTTP_FILTER_CONTEXT pfc, const char* msg)
{
    Category::getInstance("isapi_shib.WriteClientError").error("sending error page to browser: %s",msg);

    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",0,0);
    static const char* xmsg="<HTML><HEAD><TITLE>Shibboleth Filter Error</TITLE></HEAD><BODY>"
                            "<H1>Shibboleth Filter Error</H1>";
    DWORD resplen=strlen(xmsg);
    pfc->WriteClient(pfc,(LPVOID)xmsg,&resplen,0);
    resplen=strlen(msg);
    pfc->WriteClient(pfc,(LPVOID)msg,&resplen,0);
    static const char* xmsg2="</BODY></HTML>";
    resplen=strlen(xmsg2);
    pfc->WriteClient(pfc,(LPVOID)xmsg2,&resplen,0);
    return SF_STATUS_REQ_FINISHED;
}

DWORD shib_shar_error(PHTTP_FILTER_CONTEXT pfc, SAMLException& e)
{
    Category::getInstance("isapi_shib.shib_shar_error").errorStream()
        << "exception during SHAR request: " << e;

    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",0,0);
    
    static const char* msg="<HTML><HEAD><TITLE>Shibboleth Attribute Exchange Failed</TITLE></HEAD>\n"
                           "<BODY><H3>Shibboleth Attribute Exchange Failed</H3>\n"
                           "While attempting to securely contact your origin site to obtain "
                           "information about you, an error occurred:<BR><BLOCKQUOTE>";
    DWORD resplen=strlen(msg);
    pfc->WriteClient(pfc,(LPVOID)msg,&resplen,0);

    const char* msg2=e.what();
    resplen=strlen(msg2);
    pfc->WriteClient(pfc,(LPVOID)msg2,&resplen,0);

    bool origin=true;
    Iterator<saml::QName> i=e.getCodes();
    if (i.hasNext() && XMLString::compareString(L(Responder),i.next().getLocalName()))
        origin=false;

    const char* msg4=(origin ? "</BLOCKQUOTE><P>The error appears to be located at your origin site.<BR>" :
                               "</BLOCKQUOTE><P>The error appears to be located at the resource provider's site.<BR>");
    resplen=strlen(msg4);
    pfc->WriteClient(pfc,(LPVOID)msg4,&resplen,0);
    
    static const char* msg5="<P>Try restarting your browser and accessing the site again to make "
                            "sure the problem isn't temporary. Please contact the administrator "
                            "of that site if this problem recurs. If possible, provide him/her "
                            "with the error message shown above.</BODY></HTML>";
    resplen=strlen(msg5);
    pfc->WriteClient(pfc,(LPVOID)msg5,&resplen,0);
    return SF_STATUS_REQ_FINISHED;
}

extern "C" DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD notificationType, LPVOID pvNotification)
{
    // Is this a log notification?
    if (notificationType==SF_NOTIFY_LOG)
    {
        if (pfc->pFilterContext)
            ((PHTTP_FILTER_LOG)pvNotification)->pszClientUserName=static_cast<LPCSTR>(pfc->pFilterContext);
        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    char* xmsg=NULL;
    settings_t* pSite=NULL;
    bool bLocked=false;
    PHTTP_FILTER_PREPROC_HEADERS pn=(PHTTP_FILTER_PREPROC_HEADERS)pvNotification;
    Category& log=Category::getInstance("isapi_shib.HttpFilterProc");
    try
    {
        // Determine web site number.
        dynabuf buf(128);
        ULONG site_id=0;
        GetServerVariable(pfc,"INSTANCE_ID",buf,10);
        if ((site_id=strtoul(buf,NULL,10))==0)
            return WriteClientError(pfc,"IIS site instance appears to be invalid.");

        // Match site instance to site settings pointer.
        if (site_id>g_ulMaxSite || g_Sites[site_id-1].g_CookieName.empty())
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
        pSite=&g_Sites[site_id-1];

        string targeturl=get_target(pfc,pn,pSite);

        // If the user is accessing the SHIRE acceptance point, pass on.
        if (targeturl.find(pSite->g_SHIRELocation)!=string::npos)
        {
            log.debug("passing on SHIRE acceptance request");
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
        }

        // If this is the garbage collection service, do a cache sweep.
        if (targeturl==pSite->g_GarbageCollector)
        {
            log.notice("garbage collector triggered");
            pSite->g_AuthCache.lock();
            bLocked=true;
            pSite->g_AuthCache.sweep(pSite->g_Lifetime);
            pSite->g_AuthCache.unlock();
            bLocked=false;
            return WriteClientError(pfc,"The cache was swept for expired sessions.");
        }

        // Get the url request and scan for the must-contain string.
        if (!pSite->g_MustContain.empty())
        {
            char* upcased=new char[targeturl.length()+1];
            strcpy(upcased,targeturl.c_str());
            _strupr(upcased);
            for (vector<string>::const_iterator index=pSite->g_MustContain.begin(); index!=pSite->g_MustContain.end(); index++)
                if (strstr(upcased,index->c_str()))
                    break;
            delete[] upcased;
            if (index==pSite->g_MustContain.end())
                return SF_STATUS_REQ_NEXT_NOTIFICATION;
        }

        // SSL check.
        if (pSite->g_bSSLOnly && !pfc->fIsSecurePort)
        {
            log.warn("blocking non-SSL request");
            xmsg="<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>"
                 "<H1>Access Denied</H1>"
                 "This server is configured to deny non-SSL requests for secure resources. "
                 "Try your request again using https instead of http."
                 "</BODY></HTML>";
            DWORD resplen=strlen(xmsg);
            pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",0,0);
            pfc->WriteClient(pfc,xmsg,&resplen,0);
            return SF_STATUS_REQ_FINISHED;
        }

        // Check for authentication cookie.
        const char* session_id=NULL;
        GetHeader(pn,pfc,"Cookie:",buf,128,false);
        if (buf.empty() || !(session_id=strstr(buf,pSite->g_CookieName.c_str())) ||
            *(session_id+pSite->g_CookieName.length())!='=')
        {
            log.info("session cookie not found, redirecting to WAYF");

            // Redirect to WAYF.
            string wayf("Location: ");
            wayf+=pSite->g_WAYFLocation + "?shire=" + get_shire_location(pfc,pSite,targeturl.c_str()) +
                                          "&target=" + url_encode(targeturl.c_str()) + "\r\n";
            // Insert the headers.
            pfc->AddResponseHeaders(pfc,const_cast<char*>(wayf.c_str()),0);
            pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",0,0);
            return SF_STATUS_REQ_FINISHED;
        }

        session_id+=pSite->g_CookieName.length() + 1;	/* Skip over the '=' */
        char* cookieend=strchr(session_id,';');
        if (cookieend)
            *cookieend = '\0';	/* Ignore anyting after a ; */
  
        pSite->g_AuthCache.lock();    // ---> Get cache lock
        bLocked=true;

        // The caching logic is the heart of the "SHAR".
        CCacheEntry* entry=pSite->g_AuthCache.find(session_id);
        try
        {
            if (!entry)
            {
                pSite->g_AuthCache.unlock();    // ---> Release cache lock
                bLocked=false;

                // Construct the path to the session file
                string sessionFile=pSite->g_SHIRESessionPath + session_id;
                try
                {
                    entry=new CCacheEntry(sessionFile.c_str());
                }
                catch (runtime_error e)
                {
                    log.info("unable to load session from file '%s', redirecting to WAYF",sessionFile.c_str());

                    // Redirect to WAYF.
                    string wayf("Location: ");
                    wayf+=pSite->g_WAYFLocation + "?shire=" + get_shire_location(pfc,pSite,targeturl.c_str()) +
                                                  "&target=" + url_encode(targeturl.c_str()) + "\r\n";
                    wayf+="Set-Cookie: " + pSite->g_CookieName + "=; path=/; expires=19-Mar-1971 08:23:00 GMT\r\n";

                    // Insert the headers.
                    pfc->AddResponseHeaders(pfc,const_cast<char*>(wayf.c_str()),0);
                    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",0,0);
                    return SF_STATUS_REQ_FINISHED;
                }
                pSite->g_AuthCache.lock();    // ---> Get cache lock
                bLocked=true;
                pSite->g_AuthCache.insert(session_id,entry);
                log.info("new session established: %s",session_id);
            }
            
            if (!entry->isSessionValid(pSite->g_Lifetime,pSite->g_Timeout))
            {
                pSite->g_AuthCache.remove(session_id);
                pSite->g_AuthCache.unlock();    // ---> Release cache lock
                bLocked=false;
                delete entry;

                log.warn("invalidating session because of timeout, redirecting to WAYF");

                // Redirect to WAYF.
                string wayf("Location: ");
                wayf+=pSite->g_WAYFLocation + "?shire=" + get_shire_location(pfc,pSite,targeturl.c_str()) +
                                              "&target=" + url_encode(targeturl.c_str()) + "\r\n";
                wayf+="Set-Cookie: " + pSite->g_CookieName + "=; path=/; expires=19-Mar-1971 08:23:00 GMT\r\n";

                // Insert the headers.
                pfc->AddResponseHeaders(pfc,const_cast<char*>(wayf.c_str()),0);
                pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",0,0);
                return SF_STATUS_REQ_FINISHED;
            }

            if (pSite->g_bCheckAddress && entry->getClientAddress())
            {
                GetServerVariable(pfc,"REMOTE_ADDR",buf,16);
                if (strcmp(entry->getClientAddress(),buf))
                {
                    pSite->g_AuthCache.remove(session_id);
                    delete entry;
                    pSite->g_AuthCache.unlock();  // ---> Release cache lock
                    bLocked=false;

                    log.warn("IP address mismatch detected, clearing session");

                    string clearcookie("Set-Cookie: ");
                    clearcookie+=pSite->g_CookieName + "=; path=/; expires=19-Mar-1971 08:23:00 GMT\r\n";
                    pfc->AddResponseHeaders(pfc,const_cast<char*>(clearcookie.c_str()),0);
                    return WriteClientError(pfc,
                        "Your session was terminated because the network address associated "
                        "with it does not match your current address. This is usually caused "
                        "by a firewall or proxy of some sort.");
                }
            }

            // Clear relevant headers.
            pn->SetHeader(pfc,"Shib-Attributes:","");
            pn->SetHeader(pfc,"remote-user:","");
            for (map<string,string>::const_iterator h_iter=g_mapAttribNameToHeader.begin(); h_iter!=g_mapAttribNameToHeader.end(); h_iter++)
                if (h_iter->second!="REMOTE_USER:")
                    pn->SetHeader(pfc,const_cast<char*>(h_iter->second.c_str()),"");

            if (pSite->g_bExportAssertion)
            {
                string exp((char*)entry->getSerializedAssertion(targeturl.c_str(),pSite));
                string::size_type lfeed;
                while ((lfeed=exp.find('\n'))!=string::npos)
                    exp.erase(lfeed,1);
                pn->SetHeader(pfc,"Shib-Attributes:",const_cast<char*>(exp.c_str()));
            }
            Iterator<SAMLAttribute*> i=entry->getAttributes(targeturl.c_str(),pSite);
	    
            while (i.hasNext())
            {
                SAMLAttribute* attr=i.next();

                // Are we supposed to export it?
                map<xstring,string>::const_iterator iname=g_mapAttribNames.find(attr->getName());
                if (iname!=g_mapAttribNames.end())
                {
                    string hname=g_mapAttribNameToHeader[iname->second];
                    Iterator<string> vals=attr->getSingleByteValues();
                    if (hname=="REMOTE_USER:" && vals.hasNext())
                    {
                        char* principal=const_cast<char*>(vals.next().c_str());
                        pn->SetHeader(pfc,"remote-user:",principal);
                        pfc->pFilterContext=pfc->AllocMem(pfc,strlen(principal)+1,0);
                        if (pfc->pFilterContext)
                            strcpy(static_cast<char*>(pfc->pFilterContext),principal);
                    }   
                    else
                    {
                        string header(" ");
                        while (vals.hasNext())
                            header+=vals.next() + " ";
                        pn->SetHeader(pfc,const_cast<char*>(hname.c_str()),const_cast<char*>(header.c_str()));
                    }
                }
            }

            pSite->g_AuthCache.unlock();  // ---> Release cache lock
            bLocked=false;
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
        }
        catch (SAMLException& e)
        {
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
                    if (!bLocked)
                        pSite->g_AuthCache.lock();  // ---> Grab cache lock
                    pSite->g_AuthCache.remove(session_id);
                    pSite->g_AuthCache.unlock();  // ---> Release cache lock
                    delete entry;

                    log.info("invaliding session due to shib:InvalidHandle code from AA");

                    // Redirect to WAYF.
                    string wayf("Location: ");
                    wayf+=pSite->g_WAYFLocation + "?shire=" + get_shire_location(pfc,pSite,targeturl.c_str()) +
                                                  "&target=" + url_encode(targeturl.c_str()) + "\r\n";
                    wayf+="Set-Cookie: " + pSite->g_CookieName + "=; path=/; expires=19-Mar-1971 08:23:00 GMT\r\n";

                    // Insert the headers.
                    pfc->AddResponseHeaders(pfc,const_cast<char*>(wayf.c_str()),0);
                    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",0,0);
                    return SF_STATUS_REQ_FINISHED;
                }
                break;
            }
            if (bLocked)
                pSite->g_AuthCache.unlock();
	        return shib_shar_error(pfc,e);
        }
        catch (XMLException& e)
        {
            if (bLocked)
                pSite->g_AuthCache.unlock();
            auto_ptr<char> msg(XMLString::transcode(e.getMessage()));
            SAMLException ex(SAMLException::RESPONDER,msg.get());
            return shib_shar_error(pfc,ex);
        }
    }
    catch(bad_alloc)
    {
        xmsg="Out of memory.";
        log.error("out of memory");
    }
    catch(DWORD e)
    {
        if (e==ERROR_NO_DATA)
            xmsg="A required variable or header was empty.";
        else
            xmsg="Server detected unexpected IIS error.";
    }
    catch(...)
    {
        xmsg="Server caught an unknown exception.";
    }

    // If we drop here, the exception handler set the proper message.
    if (bLocked)
        pSite->g_AuthCache.unlock();
    return WriteClientError(pfc,xmsg);
}
