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

#include "config_win32.h"

// SAML Runtime
#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>

#include <log4cpp/Category.hh>

#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <httpfilt.h>
#include <httpext.h>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

// globals
namespace {
    static const XMLCh name[] = { chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
    static const XMLCh port[] = { chLatin_p, chLatin_o, chLatin_r, chLatin_t, chNull };
    static const XMLCh scheme[] = { chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_e, chNull };
    static const XMLCh id[] = { chLatin_i, chLatin_d, chNull };
    static const XMLCh Implementation[] =
    { chLatin_I, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };
    static const XMLCh ISAPI[] = { chLatin_I, chLatin_S, chLatin_A, chLatin_P, chLatin_I, chNull };
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
            if (n.get()) m_name=n.get();
            if (s.get()) m_scheme=s.get();
            if (p.get()) m_port=p.get();
        }
        string m_scheme,m_name,m_port;
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

    try
    {
        LPCSTR schemadir=getenv("SHIBSCHEMAS");
        if (!schemadir)
            schemadir=SHIB_SCHEMAS;
        LPCSTR config=getenv("SHIBCONFIG");
        if (!config)
            config=SHIB_CONFIG;
        g_Config=&ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::SHIREExtensions |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(schemadir,config)) {
            g_Config=NULL;
            LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL,
                    "Filter startup failed during initialization, check shire log for help.");
            return FALSE;
        }
        
        // Access the implementation-specifics for site mappings.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        const IPropertySet* props=conf->getPropertySet("SHIRE");
        if (props) {
            const DOMElement* impl=saml::XML::getFirstChildElement(
                props->getElement(),ShibTargetConfig::SHIBTARGET_NS,Implementation
                );
            if (impl && (impl=saml::XML::getFirstChildElement(impl,ShibTargetConfig::SHIBTARGET_NS,ISAPI))) {
                const XMLCh* flag=impl->getAttributeNS(NULL,normalizeRequest);
                g_bNormalizeRequest=(!flag || !*flag || *flag==chDigit_1 || *flag==chLatin_t);
                impl=saml::XML::getFirstChildElement(impl,ShibTargetConfig::SHIBTARGET_NS,Site);
                while (impl) {
                    auto_ptr_char id(impl->getAttributeNS(NULL,id));
                    if (id.get())
                        g_Sites.insert(pair<string,site_t>(id.get(),site_t(impl)));
                    impl=saml::XML::getNextSiblingElement(impl,ShibTargetConfig::SHIBTARGET_NS,Site);
                }
            }
        }
    }
    catch (...)
    {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Filter startup failed with an exception.");
#ifdef _DEBUG
        throw;
#endif
        return FALSE;
    }

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

    while (lpECB->GetServerVariable(lpECB->ConnID,lpszVariable,s,&size))
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
public:
  ShibTargetIsapiF(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPRC_HEADERS pn,
		   const site_t& site) {

    // URL path always come from IIS.
    dynabuf url(256);
    GetHeader(pn,pfc,"url",url,256,false);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (site.m_port.empty() || !g_bNormalizeRequest)
        GetServerVariable(pfc,"SERVER_PORT",port,10);
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    
    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest)
        scheme=pfc->fIsSecurePort ? "https" : "http";

    // Get the remote address
    dynabuf remote_addr(16);
    GetServerVariable(pfc,"REMOTE_ADDR",remote_addr,16);

    // XXX: How do I get the content type and HTTP Method from this context?

    init(g_Config, string(scheme), site.m_name, atoi(port),
	 string(url), string(""), // XXX: content type
	 string(remote_addr), string("") // XXX: http method
	 ); 

    m_pfc = pfc;
    m_pn = pn;
  }
  ~ShibTargetIsapiF() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    LogEvent(NULL, (level == LogLevelDebug : EVENTLOG_DEBUG_TYPE ?
		    (level == LogLevelInfo : EVENTLOG_INFORMATION_TYPE ?
		     (level == LogLevelWarn : EVENTLOG_WARNING_TYPE ?
		      EVENTLOG_ERROR_TYPE))),
	     2100, NULL, msg.c_str());
  }
  virtual string getCookies(void) {
    dynabuf buf(128);
    GetHeader(m_pn, m_pfc, "Cookie:", buf, 128, false);
  }
  // XXX: the filter never processes the POST.
  //virtual void setCookie(const string &name, const string &value) {  }
  //virtual string getArgs(void) {  }
  //virtual string getPostData(void) {  }
  virtual void clearHeader(const string &name) {
    string hdr = name + ":";
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
    GetHeader(m_pn, m_pfc, hdr.c_str(), buf, 1024, false);
    return string(buf);
  }
  virtual void setRemoteUser(const string &user) {
    setHeader(string("remote-user"), user);
  }
  virtual string getRemoteUser(void) {
    return getHeader(string("remote-user"));
  }
  virtual void* sendPage(const string &msg, const string content_type,
			 const pair<string, string> headers[], int code) {
    string hdr = string ("Connection: close\r\nContent-type: ") + content_type + "\r\n";
    for (int k = 0; k < headers.size(); k++) {
      hdr += headers[k].first + ": " + headers[k].second + "\r\n";
    }
    hdr += "\r\n";
    // XXX Need to handle "code"
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, "200 OK",
				 (dword)hdr.c_str(), 0);
    DWORD resplen = msg.size();
    m_pfc->WriteClient(m_pfc, (LPVOID)msg.c_str(), &resplen, 0);
    return (void*)SF_STATUS_REQ_FINISHED;
  }
  virtual void* sendRedirect(const string url) {
    // XXX: Don't support the httpRedirect option, yet.
    string hdrs=string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache\r\n\r\n";
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER,
				 "302 Please Wait", (DWORD)hdrs.c_str(), 0);
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_pfc->WriteClient(m_pfc, (LPVOID)redmsg, &resplen, 0);
    return SF_STATUS_REQ_FINISHED;
  }
  // XXX: We might not ever hit the 'decline' status in this filter.
  //virtual void* returnDecline(void) { }
  virtual void* returnOK(void) { return (void*) SF_STATUS_REQ_NEXT_NOTIFICATION; }

  PHTTP_FILTER_CONTEXT m_pfc;
  PHTTP_FILTER_PREPRC_HEADERS m_pn
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
	pair<bool,void*> res = ste.doCheckAuthN(false);
	if (res.first) return (DWORD)res.second;

	// "false" because we don't override the Shib settings
	res = ste.doExportAssertions(false);
	if (res.first) return (DWORD)res.second;

	res = ste.doCheckAuthZ();
	if (res.first) return (DWORD)res.second;

        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }
    catch(bad_alloc) {
        return WriteClientError(pfc,"Out of Memory");
    }
    catch(DWORD e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(pfc,"A required variable or header was empty.");
        else
            return WriteClientError(pfc,"Server detected unexpected IIS error.");
    }
#ifndef _DEBUG
    catch(...) {
        return WriteClientError(pfc,"Server caught an unknown exception.");
    }
#endif

    return WriteClientError(pfc,"Server reached unreachable code, save my walrus!");
}
        

#if 0
IRequestMapper::Settings map_request(
    PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pn, IRequestMapper* mapper, const site_t& site, string& target
    )
{
    // URL path always come from IIS.
    dynabuf url(256);
    GetHeader(pn,pfc,"url",url,256,false);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (site.m_port.empty() || !g_bNormalizeRequest)
        GetServerVariable(pfc,"SERVER_PORT",port,10);
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }
    
    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest)
        scheme=pfc->fIsSecurePort ? "https" : "http";

    // Start with scheme and hostname.
    if (g_bNormalizeRequest) {
        target = string(scheme) + "://" + site.m_name;
    }
    else {
        dynabuf name(64);
        GetServerVariable(pfc,"SERVER_NAME",name,64);
        target = string(scheme) + "://" + static_cast<char*>(name);
    }
    
    // If port is non-default, append it.
    if ((!strcmp(scheme,"http") && port!="80") || (!strcmp(scheme,"https") && port!="443"))
        target = target + ':' + static_cast<char*>(port);

    // Append path.
    if (!url.empty())
        target+=static_cast<char*>(url);
    
    return mapper->getSettingsFromParsedURL(scheme,site.m_name.c_str(),strtoul(port,NULL,10),url);
}

DWORD WriteClientError(PHTTP_FILTER_CONTEXT pfc, const IApplication* app, const char* page, ShibMLP& mlp)
{
    const IPropertySet* props=app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res) {
                    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
                    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",(DWORD)ctype,0);
                    DWORD resplen=strlen(res);
                    pfc->WriteClient(pfc,(LPVOID)res,&resplen,0);
                    return SF_STATUS_REQ_FINISHED;
                }
            }
        }
    }

    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Filter unable to open error template.");
    return WriteClientError(pfc,"Unable to open error template, check settings.");
}

DWORD WriteRedirectPage(PHTTP_FILTER_CONTEXT pfc, const IApplication* app, const char* file, ShibMLP& mlp, const char* headers=NULL)
{
    ifstream infile(file);
    if (!infile.fail()) {
        const char* res = mlp.run(infile,app->getPropertySet("Errors"));
        if (res) {
            char buf[255];
            sprintf(buf,"Content-Length: %u\r\nContent-Type: text/html\r\n\r\n",strlen(res));
            if (headers) {
                string h(headers);
                h+=buf;
                pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",(DWORD)h.c_str(),0);
            }
            else
                pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"200 OK",(DWORD)buf,0);
            DWORD resplen=strlen(res);
            pfc->WriteClient(pfc,(LPVOID)res,&resplen,0);
            return SF_STATUS_REQ_FINISHED;
        }
    }
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Extension unable to open redirect template.");
    return WriteClientError(pfc,"Unable to open redirect template, check settings.");
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
        
        // We lock the configuration system for the duration.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        
        // Map request to application and content settings.
        string targeturl;
        IRequestMapper* mapper=conf->getRequestMapper();
        Locker locker2(mapper);
        IRequestMapper::Settings settings=map_request(pfc,pn,mapper,map_i->second,targeturl);
        pair<bool,const char*> application_id=settings.first->getString("applicationId");
        const IApplication* application=conf->getApplication(application_id.second);
        if (!application)
            return WriteClientError(pfc,"Unable to map request to application settings, check configuration.");
        
        // Declare SHIRE object for this request.
        SHIRE shire(application);
        
        const char* shireURL=shire.getShireURL(targeturl.c_str());
        if (!shireURL)
            return WriteClientError(pfc,"Unable to map request to proper shireURL setting, check configuration.");

        // If the user is accessing the SHIRE acceptance point, pass it on.
        if (targeturl.find(shireURL)!=string::npos)
            return SF_STATUS_REQ_NEXT_NOTIFICATION;

        // Now check the policy for this request.
        pair<bool,bool> requireSession=settings.first->getBool("requireSession");
        pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();
        pair<bool,bool> httpRedirects=application->getPropertySet("Sessions")->getBool("httpRedirects");
        pair<bool,const char*> redirectPage=application->getPropertySet("Sessions")->getString("redirectPage");
        if (httpRedirects.first && !httpRedirects.second && !redirectPage.first)
            return WriteClientError(pfc,"HTML-based redirection requires a redirectPage property.");

        // Check for session cookie.
        const char* session_id=NULL;
        GetHeader(pn,pfc,"Cookie:",buf,128,false);
        Category::getInstance("isapi_shib.HttpFilterProc").debug("cookie header is {%s}",(const char*)buf);
        if (!buf.empty() && (session_id=strstr(buf,shib_cookie.first))) {
            session_id+=strlen(shib_cookie.first) + 1;   /* Skip over the '=' */
            char* cookieend=strchr(session_id,';');
            if (cookieend)
                *cookieend = '\0';    /* Ignore anyting after a ; */
        }
        
        if (!session_id || !*session_id) {
            // If no session required, bail now.
            if (!requireSession.second)
                return SF_STATUS_REQ_NEXT_NOTIFICATION;
    
            // No acceptable cookie, and we require a session.  Generate an AuthnRequest.
            const char* areq = shire.getAuthnRequest(targeturl.c_str());
            if (!httpRedirects.first || httpRedirects.second) {
                string hdrs=string("Location: ") + areq + "\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: 40\r\n"
                    "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
                    "Cache-Control: private,no-store,no-cache\r\n\r\n";
                pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",(DWORD)hdrs.c_str(),0);
                static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
                DWORD resplen=40;
                pfc->WriteClient(pfc,(LPVOID)redmsg,&resplen,0);
                return SF_STATUS_REQ_FINISHED;
            }
            else {
                ShibMLP markupProcessor;
                markupProcessor.insert("requestURL",areq);
                return WriteRedirectPage(pfc, application, redirectPage.second, markupProcessor);
            }
        }

        // Make sure this session is still valid.
        RPCError* status = NULL;
        ShibMLP markupProcessor;
        markupProcessor.insert("requestURL", targeturl);
    
        dynabuf abuf(16);
        GetServerVariable(pfc,"REMOTE_ADDR",abuf,16);
        try {
            status = shire.sessionIsValid(session_id, abuf);
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Session Processing Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(pfc, application, "shire", markupProcessor);
        }
#ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Session Processing Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(pfc, application, "shire", markupProcessor);
        }
#endif

        // Check the status
        if (status->isError()) {
            if (!requireSession.second)
                return SF_STATUS_REQ_NEXT_NOTIFICATION;
            else if (status->isRetryable()) {
                // Oops, session is invalid. Generate AuthnRequest.
                delete status;
                const char* areq = shire.getAuthnRequest(targeturl.c_str());
                if (!httpRedirects.first || httpRedirects.second) {
                    string hdrs=string("Location: ") + areq + "\r\n"
                        "Content-Type: text/html\r\n"
                        "Content-Length: 40\r\n"
                        "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
                        "Cache-Control: private,no-store,no-cache\r\n\r\n";
                    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,"302 Please Wait",(DWORD)hdrs.c_str(),0);
                    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
                    DWORD resplen=40;
                    pfc->WriteClient(pfc,(LPVOID)redmsg,&resplen,0);
                    return SF_STATUS_REQ_FINISHED;
                }
                else {
                    markupProcessor.insert("requestURL",areq);
                    return WriteRedirectPage(pfc, application, redirectPage.second, markupProcessor);
                }
            }
            else {
                // return the error page to the user
                markupProcessor.insert(*status);
                delete status;
                return WriteClientError(pfc, application, "shire", markupProcessor);
            }
        }
        delete status;
    
        // Move to RM phase.
        RM rm(application);
        vector<SAMLAssertion*> assertions;
        SAMLAuthenticationStatement* sso_statement=NULL;

        try {
            status = rm.getAssertions(session_id, abuf, assertions, &sso_statement);
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Attribute Processing Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(pfc, application, "rm", markupProcessor);
        }
    #ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Attribute Processing Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(pfc, application, "rm", markupProcessor);
        }
    #endif
    
        if (status->isError()) {
            markupProcessor.insert(*status);
            delete status;
            return WriteClientError(pfc, application, "rm", markupProcessor);
        }
        delete status;

        // Do we have an access control plugin?
        if (settings.second) {
            Locker acllock(settings.second);
            if (!settings.second->authorized(*sso_statement,assertions)) {
                for (int k = 0; k < assertions.size(); k++)
                    delete assertions[k];
                delete sso_statement;
                return WriteClientError(pfc, application, "access", markupProcessor);
            }
        }

        // Get the AAP providers, which contain the attribute policy info.
        Iterator<IAAP*> provs=application->getAAPProviders();
    
        // Clear out the list of mapped attributes
        while (provs.hasNext()) {
            IAAP* aap=provs.next();
            aap->lock();
            try {
                Iterator<const IAttributeRule*> rules=aap->getAttributeRules();
                while (rules.hasNext()) {
                    const char* header=rules.next()->getHeader();
                    if (header) {
                        string hname=string(header) + ':';
                        pn->SetHeader(pfc,const_cast<char*>(hname.c_str()),"");
                    }
                }
            }
            catch(...) {
                aap->unlock();
                for (int k = 0; k < assertions.size(); k++)
                  delete assertions[k];
                delete sso_statement;
                markupProcessor.insert("errorType", "Attribute Processing Error");
                markupProcessor.insert("errorText", "Unexpected Exception");
                markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
                return WriteClientError(pfc, application, "rm", markupProcessor);
            }
            aap->unlock();
        }
        provs.reset();

        // Maybe export the first assertion.
        pn->SetHeader(pfc,"remote-user:","");
        pn->SetHeader(pfc,"Shib-Attributes:","");
        pair<bool,bool> exp=settings.first->getBool("exportAssertion");
        if (exp.first && exp.second && assertions.size()) {
            string assertion;
            RM::serialize(*(assertions[0]), assertion);
            string::size_type lfeed;
            while ((lfeed=assertion.find('\n'))!=string::npos)
                assertion.erase(lfeed,1);
            pn->SetHeader(pfc,"Shib-Attributes:",const_cast<char*>(assertion.c_str()));
        }
        
        pn->SetHeader(pfc,"Shib-Origin-Site:","");
        pn->SetHeader(pfc,"Shib-Authentication-Method:","");
        pn->SetHeader(pfc,"Shib-NameIdentifier-Format:","");

        // Export the SAML AuthnMethod and the origin site name.
        auto_ptr_char os(sso_statement->getSubject()->getNameIdentifier()->getNameQualifier());
        auto_ptr_char am(sso_statement->getAuthMethod());
        pn->SetHeader(pfc,"Shib-Origin-Site:", const_cast<char*>(os.get()));
        pn->SetHeader(pfc,"Shib-Authentication-Method:", const_cast<char*>(am.get()));

        // Export NameID?
        AAP wrapper(provs,sso_statement->getSubject()->getNameIdentifier()->getFormat(),Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        if (!wrapper.fail() && wrapper->getHeader()) {
            auto_ptr_char form(sso_statement->getSubject()->getNameIdentifier()->getFormat());
            auto_ptr_char nameid(sso_statement->getSubject()->getNameIdentifier()->getName());
            pn->SetHeader(pfc,"Shib-NameIdentifier-Format:",const_cast<char*>(form.get()));
            if (!strcmp(wrapper->getHeader(),"REMOTE_USER")) {
                char* principal=const_cast<char*>(nameid.get());
                pn->SetHeader(pfc,"remote-user:",principal);
                pfc->pFilterContext=pfc->AllocMem(pfc,strlen(principal)+1,0);
                if (pfc->pFilterContext)
                    strcpy(static_cast<char*>(pfc->pFilterContext),principal);
            }
            else {
                string hname=string(wrapper->getHeader()) + ':';
                pn->SetHeader(pfc,const_cast<char*>(wrapper->getHeader()),const_cast<char*>(nameid.get()));
            }
        }

        pn->SetHeader(pfc,"Shib-Application-ID:","");
        pn->SetHeader(pfc,"Shib-Application-ID:",const_cast<char*>(application_id.second));

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
                    if (wrapper.fail() || !wrapper->getHeader())
                        continue;
                
                    Iterator<string> vals=attr->getSingleByteValues();
                    if (!strcmp(wrapper->getHeader(),"REMOTE_USER") && vals.hasNext()) {
                        char* principal=const_cast<char*>(vals.next().c_str());
                        pn->SetHeader(pfc,"remote-user:",principal);
                        pfc->pFilterContext=pfc->AllocMem(pfc,strlen(principal)+1,0);
                        if (pfc->pFilterContext)
                            strcpy(static_cast<char*>(pfc->pFilterContext),principal);
                    }
                    else {
                        int it=0;
                        string header;
                        string hname=string(wrapper->getHeader()) + ':';
                        GetHeader(pn,pfc,const_cast<char*>(hname.c_str()),buf,256,false);
                        if (!buf.empty()) {
                            header=buf;
                            it++;
                        }
                        for (; vals.hasNext(); it++) {
                            string value = vals.next();
                            for (string::size_type pos = value.find_first_of(";", string::size_type(0));
                                    pos != string::npos;
                                    pos = value.find_first_of(";", pos)) {
                                value.insert(pos, "\\");
                                pos += 2;
                            }
                            if (it == 0)
                                header=value;
                            else
                                header=header + ';' + value;
                        }
                        pn->SetHeader(pfc,const_cast<char*>(hname.c_str()),const_cast<char*>(header.c_str()));
        	        }
                }
            }
        }
    
        // clean up memory
        for (int k = 0; k < assertions.size(); k++)
          delete assertions[k];
        delete sso_statement;

        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }
    catch(bad_alloc) {
        return WriteClientError(pfc,"Out of Memory");
    }
    catch(DWORD e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(pfc,"A required variable or header was empty.");
        else
            return WriteClientError(pfc,"Server detected unexpected IIS error.");
    }
#ifndef _DEBUG
    catch(...) {
        return WriteClientError(pfc,"Server caught an unknown exception.");
    }
#endif

    return WriteClientError(pfc,"Server reached unreachable code, save my walrus!");
}
#endif // 0

/****************************************************************************/
// ISAPI Extension

class ShibTargetIsapiE : public ShibTarget
{
public:
  ShibTargetIsapiE(LPEXTENSION_CONTROL_BLOCK lpECB, const site_t& site) :
    m_cookie(NULL)
  {
    dynabuf ssl(5);
    GetServerVariable(lpECB,"HTTPS",ssl,5);
    bool SSL=(ssl=="on" || ssl=="ON");

    // URL path always come from IIS.
    dynabuf url(256);
    GetServerVariable(lpECB,"URL",url,255);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (site.m_port.empty() || !g_bNormalizeRequest)
        GetServerVariable(lpECB,"SERVER_PORT",port,10);
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }

    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest) {
        scheme = SSL ? "https" : "http";
    }

    // Get the remote address
    dynabuf remote_addr(16);
    GetServerVariable(lpECB, "REMOTE_ADDR", remote_addr, 16);

    init(g_Config, string(scheme), site.m_name, atoi(port),
	 string(url), string(lpECB->lpszContentType ? lpECB->lpszContentType : ""),
	 string(remote_addr), string(lpECB->lpszMethod)
	 ); 

    m_lpECB = lpECB;
  }
  ~ShibTargetIsapiE() { }

  virtual void log(ShibLogLevel level, const string &msg) {
    LogEvent(NULL, (level == LogLevelDebug : EVENTLOG_DEBUG_TYPE ?
		    (level == LogLevelInfo : EVENTLOG_INFORMATION_TYPE ?
		     (level == LogLevelWarn : EVENTLOG_WARNING_TYPE ?
		      EVENTLOG_ERROR_TYPE))),
	     2100, NULL, msg.c_str());
  }
  // Not used in the extension.
  //virtual string getCookies(void) { }
  virtual void setCookie(const string &name, const string &value) {
    // Set the cookie for later.  Use it during the redirect.
    m_cookie += "Set-Cookie: " + name + "=" + value + "\r\n";
  }
  virtual string getArgs(void) {
    return string(m_lpECB->lpszQueryString ? m_lpECB->lpszQueryString : "");
  }
  virtual string getPostData(void) {
    if (m_lpECB->cbTotalBytes > 1024*1024) // 1MB?
      throw ShibTargetException(SHIBRPC_OK,
				"blocked too-large a post to SHIRE POST processor");
    else if (m_lpECB->cbTotalBytes != lpECB->cbAvailable) {
      string cgistr;
      char buf[8192];
      DWORD datalen=m_lpECB->cbTotalBytes;
      while (datalen) {
	DWORD buflen=8192;
	BOOL ret = m_lpECB->ReadClient(m_lpECB->ConnID, buf, &buflen);
	if (!ret || !buflen)
	  throw ShibTargetException(SHIBRPC_OK,
				    "error reading POST data from browser");
	cgistr.append(buf, buflen);
	datalen-=buflen;
      }
      return cgistr;
    }
    else
      return string(reinterpret_cast<char*>(m_lpECB->lpbData),m_lpECB->cbAvailable);
  }
  // Not used in the Extension
  //virtual void clearHeader(const string &name) {  }
  //virtual void setHeader(const string &name, const string &value) {  }
  //virtual string getHeader(const string &name) {  }
  //virtual void setRemoteUser(const string &user) { }
  //virtual string getRemoteUser(void) { }
  virtual void* sendPage(const string &msg, const string content_type,
			 const pair<string, string> headers[], int code) {
    string hdr = string ("Connection: close\r\nContent-type: ") + content_type + "\r\n";
    for (int k = 0; k < headers.size(); k++) {
      hdr += headers[k].first + ": " + headers[k].second + "\r\n";
    }
    hdr += "\r\n";
    // XXX Need to handle "code"
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER,
				   "200 OK", (LPDWORD)hdr.c_str());
    DWORD resplen = msg.size();
    m_lpECB->WriteClient(m_lpECB->ConnID, (LPVOID)msg.c_str(), &resplen, HSE_IO_SYNC);
    return (void*)HSE_STATUS_SUCCESS;
  }
  virtual void* sendRedirect(const string url) {
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
  // Note that it can also happen with HTAccess, but we don't suppor that, yet.
  virtual void* returnDecline(void) {
    return (void*)
      WriteClientError(m_lpECB, "UISAPA extension can only be unvoked to process incoming sessions."
		       "Make sure the mapped file extension doesn't match actual content.");
  }
  virtual void* returnOK(void) { return (void*) HSE_STATUS_SUCCESS; }

  LPEXTENSION_CONTROL_BLOCK m_lpECB;
  string m_cookie;
};

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

extern "C" DWORD WINAPI HttpExtensionProc(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    string targeturl;
    const IApplication* application=NULL;
    try
    {
        ostringstream threadid;
        threadid << "[" << getpid() << "] shire_handler" << '\0';
        saml::NDC ndc(threadid.str().c_str());

        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(lpECB,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return WriteClientError(lpECB, "Shibboleth Extension not configured for this web site.");

	ShibTargetIsapiE ste(lpECB, map_i->second);
	pair<bool,void*> res = ste.doHandlePOST();
	if (res.first) return (DWORD)res.second;

	return WriteClientError(lpECB, "Shibboleth Extension failed to process POST");

    } catch (...) {
      return WriteClientError(lpECB,
			      "Shibboleth Extension caught an unknown error. "
			      "Memory Failure?");
    }

    // If we get here we've got an error.
    return HSE_STATUS_ERROR;
}

#if 0
IRequestMapper::Settings map_request(
    LPEXTENSION_CONTROL_BLOCK lpECB, IRequestMapper* mapper, const site_t& site, string& target
    )
{
    dynabuf ssl(5);
    GetServerVariable(lpECB,"HTTPS",ssl,5);
    bool SSL=(ssl=="on" || ssl=="ON");

    // URL path always come from IIS.
    dynabuf url(256);
    GetServerVariable(lpECB,"URL",url,255);

    // Port may come from IIS or from site def.
    dynabuf port(11);
    if (site.m_port.empty() || !g_bNormalizeRequest)
        GetServerVariable(lpECB,"SERVER_PORT",port,10);
    else {
        strncpy(port,site.m_port.c_str(),10);
        static_cast<char*>(port)[10]=0;
    }

    // Scheme may come from site def or be derived from IIS.
    const char* scheme=site.m_scheme.c_str();
    if (!scheme || !*scheme || !g_bNormalizeRequest) {
        scheme = SSL ? "https" : "http";
    }

    // Start with scheme and hostname.
    if (g_bNormalizeRequest) {
        target = string(scheme) + "://" + site.m_name;
    }
    else {
        dynabuf name(64);
        GetServerVariable(lpECB,"SERVER_NAME",name,64);
        target = string(scheme) + "://" + static_cast<char*>(name);
    }
    
    // If port is non-default, append it.
    if ((!strcmp(scheme,"http") && port!="80") || (!strcmp(scheme,"https") && port!="443"))
        target = target + ':' + static_cast<char*>(port);

    // Append path.
    if (!url.empty())
        target+=static_cast<char*>(url);
    
    return mapper->getSettingsFromParsedURL(scheme,site.m_name.c_str(),strtoul(port,NULL,10),url);
}

DWORD WriteClientError(LPEXTENSION_CONTROL_BLOCK lpECB, const IApplication* app, const char* page, ShibMLP& mlp)
{
    const IPropertySet* props=app->getPropertySet("Errors");
    if (props) {
        pair<bool,const char*> p=props->getString(page);
        if (p.first) {
            ifstream infile(p.second);
            if (!infile.fail()) {
                const char* res = mlp.run(infile,props);
                if (res) {
                    static const char* ctype="Connection: close\r\nContent-Type: text/html\r\n\r\n";
                    lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"200 OK",0,(LPDWORD)ctype);
                    DWORD resplen=strlen(res);
                    lpECB->WriteClient(lpECB->ConnID,(LPVOID)res,&resplen,0);
                    return HSE_STATUS_SUCCESS;
                }
            }
        }
    }
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Extension unable to open error template.");
    return WriteClientError(lpECB,"Unable to open error template, check settings.");
}

DWORD WriteRedirectPage(LPEXTENSION_CONTROL_BLOCK lpECB, const IApplication* app, const char* file, ShibMLP& mlp, const char* headers=NULL)
{
    ifstream infile(file);
    if (!infile.fail()) {
        const char* res = mlp.run(infile,app->getPropertySet("Errors"));
        if (res) {
            char buf[255];
            sprintf(buf,"Content-Length: %u\r\nContent-Type: text/html\r\n\r\n",strlen(res));
            if (headers) {
                string h(headers);
                h+=buf;
                lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"200 OK",0,(LPDWORD)h.c_str());
            }
            else
                lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"200 OK",0,(LPDWORD)buf);
            DWORD resplen=strlen(res);
            lpECB->WriteClient(lpECB->ConnID,(LPVOID)res,&resplen,0);
            return HSE_STATUS_SUCCESS;
        }
    }
    LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "Extension unable to open redirect template.");
    return WriteClientError(lpECB,"Unable to open redirect template, check settings.");
}

extern "C" DWORD WINAPI HttpExtensionProc(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    string targeturl;
    const IApplication* application=NULL;
    try
    {
        ostringstream threadid;
        threadid << "[" << getpid() << "] shire_handler" << '\0';
        saml::NDC ndc(threadid.str().c_str());

        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(lpECB,"INSTANCE_ID",buf,10);

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i=g_Sites.find(static_cast<char*>(buf));
        if (map_i==g_Sites.end())
            return WriteClientError(lpECB,"Shibboleth filter not configured for this web site.");
            
        // We lock the configuration system for the duration.
        IConfig* conf=g_Config->getINI();
        Locker locker(conf);
        
        // Map request to application and content settings.
        IRequestMapper* mapper=conf->getRequestMapper();
        Locker locker2(mapper);
        IRequestMapper::Settings settings=map_request(lpECB,mapper,map_i->second,targeturl);
        pair<bool,const char*> application_id=settings.first->getString("applicationId");
        application=conf->getApplication(application_id.second);
        const IPropertySet* sessionProps=application ? application->getPropertySet("Sessions") : NULL;
        if (!application || !sessionProps)
            return WriteClientError(lpECB,"Unable to map request to application session settings, check configuration.");

        SHIRE shire(application);
        
        const char* shireURL=shire.getShireURL(targeturl.c_str());
        if (!shireURL)
            return WriteClientError(lpECB,"Unable to map request to proper shireURL setting, check configuration.");

        // Make sure we only process the SHIRE requests.
        if (!strstr(targeturl.c_str(),shireURL))
            return WriteClientError(lpECB,"ISAPI extension can only be invoked to process incoming sessions."
                "Make sure the mapped file extension doesn't match actual content.");

        pair<const char*,const char*> shib_cookie=shire.getCookieNameProps();

        // Make sure this is SSL, if it should be
        pair<bool,bool> shireSSL=sessionProps->getBool("shireSSL");
        if (!shireSSL.first || shireSSL.second) {
            GetServerVariable(lpECB,"HTTPS",buf,10);
            if (buf!="on")
                throw ShibTargetException(SHIBRPC_OK,"blocked non-SSL access to SHIRE POST processor");
        }
        
        pair<bool,bool> httpRedirects=sessionProps->getBool("httpRedirects");
        pair<bool,const char*> redirectPage=sessionProps->getString("redirectPage");
        if (httpRedirects.first && !httpRedirects.second && !redirectPage.first)
            return WriteClientError(lpECB,"HTML-based redirection requires a redirectPage property.");
        
        // Check for Mac web browser
        /*
        bool bSafari=false;
        dynabuf agent(64);
        GetServerVariable(lpECB,"HTTP_USER_AGENT",agent,64);
        if (strstr(agent,"AppleWebKit/"))
            bSafari=true;
        */
        
        // If this is a GET, we manufacture an AuthnRequest.
        if (!stricmp(lpECB->lpszMethod,"GET")) {
            const char* areq=lpECB->lpszQueryString ? shire.getLazyAuthnRequest(lpECB->lpszQueryString) : NULL;
            if (!areq)
                throw ShibTargetException(SHIBRPC_OK, "malformed arguments to request a new session");
            if (!httpRedirects.first || httpRedirects.second) {
                string hdrs=string("Location: ") + areq + "\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: 40\r\n"
                    "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
                    "Cache-Control: private,no-store,no-cache\r\n\r\n";
                lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"302 Moved",0,(LPDWORD)hdrs.c_str());
                static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
                DWORD resplen=40;
                lpECB->WriteClient(lpECB->ConnID,(LPVOID)redmsg,&resplen,HSE_IO_SYNC);
                return HSE_STATUS_SUCCESS;
            }
            else {
                ShibMLP markupProcessor;
                markupProcessor.insert("requestURL",areq);
                return WriteRedirectPage(lpECB, application, redirectPage.second, markupProcessor);
            }
        }
        else if (stricmp(lpECB->lpszMethod,"POST"))
            throw ShibTargetException(SHIBRPC_OK,"blocked non-POST to SHIRE POST processor");

        // Sure sure this POST is an appropriate content type
        if (!lpECB->lpszContentType || stricmp(lpECB->lpszContentType,"application/x-www-form-urlencoded"))
            throw ShibTargetException(SHIBRPC_OK,"blocked bad content-type to SHIRE POST processor");
    
        // Read the data.
        pair<const char*,const char*> elements=pair<const char*,const char*>(NULL,NULL);
        if (lpECB->cbTotalBytes > 1024*1024) // 1MB?
            throw ShibTargetException(SHIBRPC_OK,"blocked too-large a post to SHIRE POST processor");
        else if (lpECB->cbTotalBytes!=lpECB->cbAvailable) {
            string cgistr;
            char buf[8192];
            DWORD datalen=lpECB->cbTotalBytes;
            while (datalen) {
                DWORD buflen=8192;
                BOOL ret=lpECB->ReadClient(lpECB->ConnID,buf,&buflen);
                if (!ret || !buflen)
                    throw ShibTargetException(SHIBRPC_OK,"error reading POST data from browser");
                cgistr.append(buf,buflen);
                datalen-=buflen;
            }
            elements=shire.getFormSubmission(cgistr.c_str(),cgistr.length());
        }
        else
            elements=shire.getFormSubmission(reinterpret_cast<char*>(lpECB->lpbData),lpECB->cbAvailable);
    
        // Make sure the SAML Response parameter exists
        if (!elements.first || !*elements.first)
            throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find SAMLResponse form element");
    
        // Make sure the target parameter exists
        if (!elements.second || !*elements.second)
            throw ShibTargetException(SHIBRPC_OK, "SHIRE POST failed to find TARGET form element");
            
        GetServerVariable(lpECB,"REMOTE_ADDR",buf,16);

        // Process the post.
        string cookie;
        RPCError* status=NULL;
        ShibMLP markupProcessor;
        markupProcessor.insert("requestURL", targeturl.c_str());
        try {
            status = shire.sessionCreate(elements.first,buf,cookie);
        }
        catch (ShibTargetException &e) {
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(lpECB, application, "shire", markupProcessor);
        }
#ifndef _DEBUG
        catch (...) {
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(lpECB, application, "shire", markupProcessor);
        }
#endif

        if (status->isError()) {
            if (status->isRetryable()) {
                delete status;
                const char* loc=shire.getAuthnRequest(elements.second);
                if (!httpRedirects.first || httpRedirects.second) {
                    string hdrs=string("Location: ") + loc + "\r\n"
                        "Content-Type: text/html\r\n"
                        "Content-Length: 40\r\n"
                        "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
                        "Cache-Control: private,no-store,no-cache\r\n\r\n";
                    lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"302 Moved",0,(LPDWORD)hdrs.c_str());
                    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
                    DWORD resplen=40;
                    lpECB->WriteClient(lpECB->ConnID,(LPVOID)redmsg,&resplen,HSE_IO_SYNC);
                    return HSE_STATUS_SUCCESS;
                }
                else {
                    markupProcessor.insert("requestURL",loc);
                    return WriteRedirectPage(lpECB, application, redirectPage.second, markupProcessor);
                }
            }
    
            // Return this error to the user.
            markupProcessor.insert(*status);
            delete status;
            return WriteClientError(lpECB,application,"shire",markupProcessor);
        }
        delete status;
    
        // We've got a good session, set the cookie and redirect to target.
        cookie = string("Set-Cookie: ") + shib_cookie.first + '=' + cookie + shib_cookie.second + "\r\n"
            "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
            "Cache-Control: private,no-store,no-cache\r\n";
        if (!httpRedirects.first || httpRedirects.second) {
            cookie=cookie + "Content-Type: text/html\r\nLocation: " + elements.second + "\r\nContent-Length: 40\r\n\r\n";
            lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,"302 Moved",0,(LPDWORD)cookie.c_str());
            static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
            DWORD resplen=40;
            lpECB->WriteClient(lpECB->ConnID,(LPVOID)redmsg,&resplen,HSE_IO_SYNC);
            return HSE_STATUS_SUCCESS;
        }
        else {
            markupProcessor.insert("requestURL",elements.second);
            return WriteRedirectPage(lpECB, application, redirectPage.second, markupProcessor, cookie.c_str());
        }
    }
    catch (ShibTargetException &e) {
        if (application) {
            ShibMLP markupProcessor;
            markupProcessor.insert("requestURL", targeturl.c_str());
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", e.what());
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(lpECB,application,"shire",markupProcessor);
        }
    }
#ifndef _DEBUG
    catch (...) {
        if (application) {
            ShibMLP markupProcessor;
            markupProcessor.insert("requestURL", targeturl.c_str());
            markupProcessor.insert("errorType", "Session Creation Service Error");
            markupProcessor.insert("errorText", "Unexpected Exception");
            markupProcessor.insert("errorDesc", "An error occurred while processing your request.");
            return WriteClientError(lpECB,application,"shire",markupProcessor);
        }
    }
#endif

    return HSE_STATUS_ERROR;
}
#endif // 0
