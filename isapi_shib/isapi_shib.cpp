/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* isapi_shib.cpp - Shibboleth ISAPI filter

   Scott Cantor
   8/23/02
*/

#include "config_win32.h"

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_DEPRECATE 1

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib-target/shib-target.h>

#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <process.h>

#include <httpfilt.h>
#include <httpext.h>

using namespace shibtarget;
using namespace saml;
using namespace xmltooling;
using namespace std;

// globals
namespace {
    static const XMLCh name[] = { chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
    static const XMLCh port[] = { chLatin_p, chLatin_o, chLatin_r, chLatin_t, chNull };
    static const XMLCh sslport[] = { chLatin_s, chLatin_s, chLatin_l, chLatin_p, chLatin_o, chLatin_r, chLatin_t, chNull };
    static const XMLCh scheme[] = { chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_e, chNull };
    static const XMLCh id[] = { chLatin_i, chLatin_d, chNull };
    static const XMLCh Implementation[] =
    { chLatin_I, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };
    static const XMLCh ISAPI[] = { chLatin_I, chLatin_S, chLatin_A, chLatin_P, chLatin_I, chNull };
    static const XMLCh Alias[] = { chLatin_A, chLatin_l, chLatin_i, chLatin_a, chLatin_s, chNull };
    static const XMLCh normalizeRequest[] =
    { chLatin_n, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_l, chLatin_i, chLatin_z, chLatin_e,
      chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chNull
    };
    static const XMLCh Site[] = { chLatin_S, chLatin_i, chLatin_t, chLatin_e, chNull };

    struct site_t {
        site_t(const DOMElement* e)
        {
            auto_ptr_char n(e->getAttributeNS(NULL,name));
            auto_ptr_char s(e->getAttributeNS(NULL,scheme));
            auto_ptr_char p(e->getAttributeNS(NULL,port));
            auto_ptr_char p2(e->getAttributeNS(NULL,sslport));
            if (n.get()) m_name=n.get();
            if (s.get()) m_scheme=s.get();
            if (p.get()) m_port=p.get();
            if (p2.get()) m_sslport=p2.get();
            DOMNodeList* nlist=e->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,Alias);
            for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
                if (nlist->item(i)->hasChildNodes()) {
                    auto_ptr_char alias(nlist->item(i)->getFirstChild()->getNodeValue());
                    m_aliases.insert(alias.get());
                }
            }
        }
        string m_scheme,m_port,m_sslport,m_name;
        set<string> m_aliases;
    };
    
    HINSTANCE g_hinstDLL;
    ShibTargetConfig* g_Config = NULL;
    map<string,site_t> g_Sites;
    bool g_bNormalizeRequest = true;
}

BOOL LogEvent(
    LPCSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCSTR  message)
{
    LPCSTR  messages[] = {message, NULL};
    
    HANDLE hElog = RegisterEventSource(lpUNCServerName, "Shibboleth ISAPI Filter");
    BOOL res = ReportEvent(hElog, wType, 0, dwEventID, lpUserSid, 1, 0, messages, NULL);
    return (DeregisterEventSource(hElog) && res);
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason==DLL_PROCESS_ATTACH)
        g_hinstDLL=hinstDLL;
    return TRUE;
}

extern "C" BOOL WINAPI GetExtensionVersion(HSE_VERSION_INFO* pVer)
{
    if (!pVer)
        return FALSE;
        
    if (!g_Config)
    {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Extension mode startup not possible, is the DLL loaded as a filter?");
        return FALSE;
    }

    pVer->dwExtensionVersion=HSE_VERSION;
    strncpy(pVer->lpszExtensionDesc,"Shibboleth ISAPI Extension",HSE_MAX_EXT_DLL_NAME_LEN-1);
    return TRUE;
}

extern "C" BOOL WINAPI TerminateExtension(DWORD)
{
    return TRUE;    // cleanup should happen when filter unloads
}

extern "C" BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
    if (!pVer)
        return FALSE;
    else if (g_Config) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                "Reentrant filter initialization, ignoring...");
        return TRUE;
    }

#ifndef _DEBUG
    try
    {
#endif
        LPCSTR schemadir=getenv("SHIBSCHEMAS");
        if (!schemadir)
            schemadir=SHIB_SCHEMAS;
        LPCSTR config=getenv("SHIBCONFIG");
        if (!config)
            config=SHIB_CONFIG;
        g_Config=&ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Caching |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::InProcess |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(schemadir)) {
            g_Config=NULL;
            LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                    "Filter startup failed during library initialization, check native log for help.");
            return FALSE;
        }
        else if (!g_Config->load(config)) {
            g_Config=NULL;
            LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                    "Filter startup failed to load configuration, check native log for help.");
            return FALSE;
        }
        
        // Access the implementation-specifics for site mappings.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        const IPropertySet* props=conf->getPropertySet("Local");
        if (props) {
            const DOMElement* impl=saml::XML::getFirstChildElement(
                props->getElement(),shibtarget::XML::SHIBTARGET_NS,Implementation
                );
            if (impl && (impl=saml::XML::getFirstChildElement(impl,shibtarget::XML::SHIBTARGET_NS,ISAPI))) {
                const XMLCh* flag=impl->getAttributeNS(NULL,normalizeRequest);
                g_bNormalizeRequest=(!flag || !*flag || *flag==chDigit_1 || *flag==chLatin_t);
                impl=saml::XML::getFirstChildElement(impl,shibtarget::XML::SHIBTARGET_NS,Site);
                while (impl) {
                    auto_ptr_char id(impl->getAttributeNS(NULL,id));
                    if (id.get())
                        g_Sites.insert(pair<string,site_t>(id.get(),site_t(impl)));
                    impl=saml::XML::getNextSiblingElement(impl,shibtarget::XML::SHIBTARGET_NS,Site);
                }
            }
        }
#ifndef _DEBUG
    }
    catch (...)
    {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Filter startup failed with an exception.");
        return FALSE;
    }
#endif

    pVer->dwFilterVersion=HTTP_FILTER_REVISION;
    strncpy(pVer->lpszFilterDesc,"Shibboleth ISAPI Filter",SF_MAX_FILTER_DESC_LEN);
    pVer->dwFlags=(SF_NOTIFY_ORDER_HIGH |
                   SF_NOTIFY_SECURE_PORT |
                   SF_NOTIFY_NONSECURE_PORT |
                   SF_NOTIFY_PREPROC_HEADERS |
                   SF_NOTIFY_LOG);
    LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7701, NULL, "Filter initialized...");
    return TRUE;
}

extern "C" BOOL WINAPI TerminateFilter(DWORD)
{
    if (g_Config)
        g_Config->shutdown();
    g_Config = NULL;
    LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7701, NULL, "Filter shut down...");
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
    void erase() { if (bufptr) memset(bufptr,0,buflen); }
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

void GetServerVariable(PHTTP_FILTER_CONTEXT pfc, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
    throw (bad_alloc, DWORD)
{
    s.reserve(size);
    s.erase();
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

void GetServerVariable(LPEXTENSION_CONTROL_BLOCK lpECB, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
    throw (bad_alloc, DWORD)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!lpECB->GetServerVariable(lpECB->ConnID,lpszVariable,s,&size))
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
    s.reserve(size);
    s.erase();
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

/****************************************************************************/
// ISAPI Filter

class ShibTargetIsapiF : public ShibTarget
{
  PHTTP_FILTER_CONTEXT m_pfc;
  PHTTP_FILTER_PREPROC_HEADERS m_pn;
  string m_cookie;
public:
  ShibTargetIsapiF(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pn, const site_t& site) {

    // URL path always come from IIS.
    dynabuf url(256);
    GetHeader(pn,pfc,"url",url,256,false);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (!g_bNormalizeRequest || (pfc->fIsSecurePort && site.m_sslport.empty()) || (!pfc->fIsSecurePort && site.m_port.empty()))
        GetServerVariable(pfc,"SERVER_PORT",port,10);
    else if (pfc->fIsSecurePort) {
        strncpy(port,site.m_sslport.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    
    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest)
        scheme=pfc->fIsSecurePort ? "https" : "http";

    // Get the rest of the server variables.
    dynabuf remote_addr(16),method(5),content_type(32),hostname(32);
    GetServerVariable(pfc,"SERVER_NAME",hostname,32);
    GetServerVariable(pfc,"REMOTE_ADDR",remote_addr,16);
    GetServerVariable(pfc,"REQUEST_METHOD",method,5,false);
    GetServerVariable(pfc,"CONTENT_TYPE",content_type,32,false);

    // Make sure SERVER_NAME is "authorized" for use on this site. If not, set to canonical name.
    const char* host=hostname;
    if (site.m_name!=host && site.m_aliases.find(host)==site.m_aliases.end())
        host=site.m_name.c_str();

    init(scheme, host, atoi(port), url, content_type, remote_addr, method); 

    m_pfc = pfc;
    m_pn = pn;
  }
  ~ShibTargetIsapiF() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    ShibTarget::log(level,msg);
    if (level == LogLevelError)
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg.c_str());
  }
  virtual string getCookies() const {
    dynabuf buf(128);
    GetHeader(m_pn, m_pfc, "Cookie:", buf, 128, false);
    return buf.empty() ? "" : buf;
  }
  
  virtual void clearHeader(const string &name) {
    string hdr = (name=="REMOTE_USER" ? "remote-user" : name) + ":";
    m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), "");
  }
  virtual void setHeader(const string &name, const string &value) {
    string hdr = name + ":";
    m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()),
		    const_cast<char*>(value.c_str()));
  }
  virtual string getHeader(const string &name) {
    string hdr = name + ":";
    dynabuf buf(1024);
    GetHeader(m_pn, m_pfc, const_cast<char*>(hdr.c_str()), buf, 1024, false);
    return string(buf);
  }
  virtual void setRemoteUser(const string &user) {
    setHeader(string("remote-user"), user);
  }
  virtual string getRemoteUser(void) {
    return getHeader(string("remote-user"));
  }
  virtual void* sendPage(
    const string& msg,
    int code=200,
    const string& content_type="text/html",
    const Iterator<header_t>& headers=EMPTY(header_t)) {
    string hdr = string ("Connection: close\r\nContent-type: ") + content_type + "\r\n";
    while (headers.hasNext()) {
        const header_t& h=headers.next();
        hdr += h.first + ": " + h.second + "\r\n";
    }
    hdr += "\r\n";
    const char* codestr="200 OK";
    switch (code) {
        case 403:   codestr="403 Forbidden"; break;
        case 404:   codestr="404 Not Found"; break;
        case 500:   codestr="500 Server Error"; break;
    }
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, (void*)codestr, (DWORD)hdr.c_str(), 0);
    DWORD resplen = msg.size();
    m_pfc->WriteClient(m_pfc, (LPVOID)msg.c_str(), &resplen, 0);
    return (void*)SF_STATUS_REQ_FINISHED;
  }
  virtual void* sendRedirect(const string& url) {
    // XXX: Don't support the httpRedirect option, yet.
    string hdrs=m_cookie + string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache\r\n\r\n";
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER,
				 "302 Please Wait", (DWORD)hdrs.c_str(), 0);
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_pfc->WriteClient(m_pfc, (LPVOID)redmsg, &resplen, 0);
    return reinterpret_cast<void*>(SF_STATUS_REQ_FINISHED);
  }
  // XXX: We might not ever hit the 'decline' status in this filter.
  //virtual void* returnDecline(void) { }
  virtual void* returnOK(void) { return (void*) SF_STATUS_REQ_NEXT_NOTIFICATION; }

  // The filter never processes the POST, so stub these methods.
  virtual void setCookie(const string &name, const string &value) {
    // Set the cookie for later.  Use it during the redirect.
    m_cookie += "Set-Cookie: " + name + "=" + value + "\r\n";
  }
  virtual const char* getQueryString() const { throw runtime_error("getQueryString not implemented"); }
  virtual const char* getRequestBody() const { throw runtime_error("getRequestBody not implemented"); }
};

DWORD WriteClientError(PHTTP_FILTER_CONTEXT pfc, const char* msg)
{
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg);
    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",(DWORD)ctype,0);
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

extern "C" DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD notificationType, LPVOID pvNotification)
{
    // Is this a log notification?
    if (notificationType==SF_NOTIFY_LOG)
    {
        if (pfc->pFilterContext)
            ((PHTTP_FILTER_LOG)pvNotification)->pszClientUserName=static_cast<LPCSTR>(pfc->pFilterContext);
        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    PHTTP_FILTER_PREPROC_HEADERS pn=(PHTTP_FILTER_PREPROC_HEADERS)pvNotification;
    try
    {
        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(pfc,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return SF_STATUS_REQ_NEXT_NOTIFICATION;
            
        ostringstream threadid;
        threadid << "[" << getpid() << "] isapi_shib" << '\0';
        saml::NDC ndc(threadid.str().c_str());

        ShibTargetIsapiF stf(pfc, pn, map_i->second);

        // "false" because we don't override the Shib settings
        pair<bool,void*> res = stf.doCheckAuthN();
        if (res.first) return (DWORD)res.second;

        // "false" because we don't override the Shib settings
        res = stf.doExportAssertions();
        if (res.first) return (DWORD)res.second;

        res = stf.doCheckAuthZ();
        if (res.first) return (DWORD)res.second;

        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }
    catch(bad_alloc) {
        return WriteClientError(pfc,"Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(pfc,"A required variable or header was empty.");
        else
            return WriteClientError(pfc,"Shibboleth Filter detected unexpected IIS error.");
    }
    catch (SAMLException& e) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, e.what());
        return WriteClientError(pfc,"Shibboleth Filter caught an exception, check Event Log for details.");
    }
#ifndef _DEBUG
    catch(...) {
        return WriteClientError(pfc,"Shibboleth Filter caught an unknown exception.");
    }
#endif

    return WriteClientError(pfc,"Shibboleth Filter reached unreachable code, save my walrus!");
}
        

/****************************************************************************/
// ISAPI Extension

DWORD WriteClientError(LPEXTENSION_CONTROL_BLOCK lpECB, const char* msg)
{
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg);
    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
    lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"200 OK",0,(LPDWORD)ctype);
    static const char* xmsg="<HTML><HEAD><TITLE>Shibboleth Error</TITLE></HEAD><BODY><H1>Shibboleth Error</H1>";
    DWORD resplen=strlen(xmsg);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)xmsg,&resplen,HSE_IO_SYNC);
    resplen=strlen(msg);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)msg,&resplen,HSE_IO_SYNC);
    static const char* xmsg2="</BODY></HTML>";
    resplen=strlen(xmsg2);
    lpECB->WriteClient(lpECB->ConnID,(LPVOID)xmsg2,&resplen,HSE_IO_SYNC);
    return HSE_STATUS_SUCCESS;
}


class ShibTargetIsapiE : public ShibTarget
{
  LPEXTENSION_CONTROL_BLOCK m_lpECB;
  string m_cookie;
  mutable string m_body;
  mutable bool m_gotBody;
  
public:
  ShibTargetIsapiE(LPEXTENSION_CONTROL_BLOCK lpECB, const site_t& site) : m_gotBody(false) {
    dynabuf ssl(5);
    GetServerVariable(lpECB,"HTTPS",ssl,5);
    bool SSL=(ssl=="on" || ssl=="ON");

    // URL path always come from IIS.
    dynabuf url(256);
    GetServerVariable(lpECB,"URL",url,255);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (!g_bNormalizeRequest || (SSL && site.m_sslport.empty()) || (!SSL && site.m_port.empty()))
        GetServerVariable(lpECB,"SERVER_PORT",port,10);
    else if (SSL) {
        strncpy(port,site.m_sslport.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }

    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest) {
        scheme = SSL ? "https" : "http";
    }

    // Get the other server variables.
    dynabuf remote_addr(16),hostname(32);
    GetServerVariable(lpECB, "REMOTE_ADDR", remote_addr, 16);
    GetServerVariable(lpECB, "SERVER_NAME", hostname, 32);

    // Make sure SERVER_NAME is "authorized" for use on this site. If not, set to canonical name.
    const char* host=hostname;
    if (site.m_name!=host && site.m_aliases.find(host)==site.m_aliases.end())
        host=site.m_name.c_str();

    /*
     * IIS screws us over on PATH_INFO (the hits keep on coming). We need to figure out if
     * the server is set up for proper PATH_INFO handling, or "IIS sucks rabid weasels mode",
     * which is the default. No perfect way to tell, but we can take a good guess by checking
     * whether the URL is a substring of the PATH_INFO:
     * 
     * e.g. for /Shibboleth.sso/SAML/POST
     * 
     *  Bad mode (default):
     *      URL:        /Shibboleth.sso
     *      PathInfo:   /Shibboleth.sso/SAML/POST
     * 
     *  Good mode:
     *      URL:        /Shibboleth.sso
     *      PathInfo:   /SAML/POST
     */
    
    string fullurl;
    
    // Clearly we're only in bad mode if path info exists at all.
    if (lpECB->lpszPathInfo && *(lpECB->lpszPathInfo)) {
        if (strstr(lpECB->lpszPathInfo,url))
            // Pretty good chance we're in bad mode, unless the PathInfo repeats the path itself.
            fullurl=lpECB->lpszPathInfo;
        else {
            fullurl+=url;
            fullurl+=lpECB->lpszPathInfo;
        }
    }
    
    // For consistency with Apache, let's add the query string.
    if (lpECB->lpszQueryString && *(lpECB->lpszQueryString)) {
        fullurl+='?';
        fullurl+=lpECB->lpszQueryString;
    }
    init(scheme, host, atoi(port), fullurl.c_str(), lpECB->lpszContentType, remote_addr, lpECB->lpszMethod);

    m_lpECB = lpECB;
  }
  ~ShibTargetIsapiE() { }

  virtual void log(ShibLogLevel level, const string &msg) {
      ShibTarget::log(level,msg);
      if (level == LogLevelError)
          LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, msg.c_str());
  }
  virtual string getCookies() const {
    dynabuf buf(128);
    GetServerVariable(m_lpECB, "HTTP_COOKIE", buf, 128, false);
    return buf.empty() ? "" : buf;
  }
  virtual void setCookie(const string &name, const string &value) {
    // Set the cookie for later.  Use it during the redirect.
    m_cookie += "Set-Cookie: " + name + "=" + value + "\r\n";
  }
  virtual const char* getQueryString() const {
    return m_lpECB->lpszQueryString;
  }
  virtual const char* getRequestBody() const {
    if (m_gotBody)
        return m_body.c_str();
    if (m_lpECB->cbTotalBytes > 1024*1024) // 1MB?
      throw SAMLException("Size of POST request body exceeded limit.");
    else if (m_lpECB->cbTotalBytes != m_lpECB->cbAvailable) {
      m_gotBody=true;
      char buf[8192];
      DWORD datalen=m_lpECB->cbTotalBytes;
      while (datalen) {
        DWORD buflen=8192;
        BOOL ret = m_lpECB->ReadClient(m_lpECB->ConnID, buf, &buflen);
        if (!ret || !buflen)
          throw SAMLException("Error reading POST request body from browser.");
        m_body.append(buf, buflen);
        datalen-=buflen;
      }
    }
    else {
        m_gotBody=true;
        m_body.assign(reinterpret_cast<char*>(m_lpECB->lpbData),m_lpECB->cbAvailable);
    }
    return m_body.c_str();
  }
  virtual void* sendPage(
    const string &msg,
    int code=200,
    const string& content_type="text/html",
    const Iterator<header_t>& headers=EMPTY(header_t)) {
    string hdr = string ("Connection: close\r\nContent-type: ") + content_type + "\r\n";
    for (unsigned int k = 0; k < headers.size(); k++) {
      hdr += headers[k].first + ": " + headers[k].second + "\r\n";
    }
    hdr += "\r\n";
    const char* codestr="200 OK";
    switch (code) {
        case 403:   codestr="403 Forbidden"; break;
        case 404:   codestr="404 Not Found"; break;
        case 500:   codestr="500 Server Error"; break;
    }
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER, (void*)codestr, 0, (LPDWORD)hdr.c_str());
    DWORD resplen = msg.size();
    m_lpECB->WriteClient(m_lpECB->ConnID, (LPVOID)msg.c_str(), &resplen, HSE_IO_SYNC);
    return (void*)HSE_STATUS_SUCCESS;
  }
  virtual void* sendRedirect(const string& url) {
    // XXX: Don't support the httpRedirect option, yet.
    string hdrs = m_cookie + "Location: " + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache\r\n\r\n";
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER,
				 "302 Moved", 0, (LPDWORD)hdrs.c_str());
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_lpECB->WriteClient(m_lpECB->ConnID, (LPVOID)redmsg, &resplen, HSE_IO_SYNC);
    return (void*)HSE_STATUS_SUCCESS;
  }
  // Decline happens in the POST processor if this isn't the shire url
  // Note that it can also happen with HTAccess, but we don't support that, yet.
  virtual void* returnDecline(void) {
    return (void*)
      WriteClientError(m_lpECB, "ISAPI extension can only be invoked to process Shibboleth protocol requests."
		       "Make sure the mapped file extension doesn't match actual content.");
  }
  virtual void* returnOK(void) { return (void*) HSE_STATUS_SUCCESS; }

  // Not used in the extension.
  virtual void clearHeader(const string &name) { throw runtime_error("clearHeader not implemented"); }
  virtual void setHeader(const string &name, const string &value) { throw runtime_error("setHeader not implemented"); }
  virtual string getHeader(const string &name) { throw runtime_error("getHeader not implemented"); }
  virtual void setRemoteUser(const string &user) { throw runtime_error("setRemoteUser not implemented"); }
  virtual string getRemoteUser(void) { throw runtime_error("getRemoteUser not implemented"); }
};

extern "C" DWORD WINAPI HttpExtensionProc(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    string targeturl;
    const IApplication* application=NULL;
    try {
        ostringstream threadid;
        threadid << "[" << getpid() << "] isapi_shib_extension" << '\0';
        saml::NDC ndc(threadid.str().c_str());

        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(lpECB,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return WriteClientError(lpECB, "Shibboleth Extension not configured for this web site.");

        ShibTargetIsapiE ste(lpECB, map_i->second);
        pair<bool,void*> res = ste.doHandler();
        if (res.first) return (DWORD)res.second;
        
        return WriteClientError(lpECB, "Shibboleth Extension failed to process request");

    }
    catch(bad_alloc) {
        return WriteClientError(lpECB,"Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(lpECB,"A required variable or header was empty.");
        else
            return WriteClientError(lpECB,"Server detected unexpected IIS error.");
    }
    catch (SAMLException& e) {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, e.what());
        return WriteClientError(lpECB,"Shibboleth Extension caught an exception, check Event Log for details.");
    }
#ifndef _DEBUG
    catch(...) {
        return WriteClientError(lpECB,"Shibboleth Extension caught an unknown exception.");
    }
#endif

    // If we get here we've got an error.
    return HSE_STATUS_ERROR;
}
