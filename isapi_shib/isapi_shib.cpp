/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * isapi_shib.cpp
 *
 * Shibboleth ISAPI filter.
 */

#define SHIBSP_LITE
#include "config_win32.h"

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_RAND_S

#include <shibsp/exceptions.h>
#include <shibsp/AbstractSPRequest.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>

#include <set>
#include <fstream>
#include <stdexcept>
#include <process.h>
#include <boost/lexical_cast.hpp>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/logging.h>

#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

#include <windows.h>
#include <httpfilt.h>
#include <httpext.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

using xmltooling::logging::Category;
using xmltooling::logging::Priority;

// globals
namespace {
    static const XMLCh path[] =             UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh validate[] =         UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
    static const XMLCh name[] =             UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh port[] =             UNICODE_LITERAL_4(p,o,r,t);
    static const XMLCh sslport[] =          UNICODE_LITERAL_7(s,s,l,p,o,r,t);
    static const XMLCh scheme[] =           UNICODE_LITERAL_6(s,c,h,e,m,e);
    static const XMLCh id[] =               UNICODE_LITERAL_2(i,d);
    static const XMLCh useHeaders[] =       UNICODE_LITERAL_10(u, s, e, H, e, a, d, e, r, s);
    static const XMLCh useVariables[] =     UNICODE_LITERAL_12(u, s, e, V, a, r, i, a, b, l, e, s);
    static const XMLCh Alias[] =            UNICODE_LITERAL_5(A,l,i,a,s);
    static const XMLCh Site[] =             UNICODE_LITERAL_4(S,i,t,e);

    struct site_t {
        site_t(const DOMElement* e)
            : m_name(XMLHelper::getAttrString(e, "", name)),
                m_scheme(XMLHelper::getAttrString(e, "", scheme)),
                m_port(XMLHelper::getAttrString(e, "", port)),
                m_sslport(XMLHelper::getAttrString(e, "", sslport))
        {
            e = XMLHelper::getFirstChildElement(e, Alias);
            while (e) {
                if (e->hasChildNodes()) {
                    auto_ptr_char alias(XMLHelper::getTextContent(e));
                    m_aliases.insert(alias.get());
                }
                e = XMLHelper::getNextSiblingElement(e, Alias);
            }
        }
        string m_scheme,m_port,m_sslport,m_name;
        set<string> m_aliases;
    };

    HINSTANCE g_hinstDLL;
    SPConfig* g_Config = nullptr;
    map<string,site_t> g_Sites;
    bool g_bNormalizeRequest = true;
    string g_unsetHeaderValue,g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
    bool g_bSafeHeaderNames = false;
    vector<string> g_NoCerts;
}

void _my_invalid_parameter_handler(
   const wchar_t * expression,
   const wchar_t * function,
   const wchar_t * file,
   unsigned int line,
   uintptr_t pReserved
   )
{
    return;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        g_hinstDLL = hinstDLL;
    return TRUE;
}

extern "C" BOOL WINAPI GetExtensionVersion(HSE_VERSION_INFO* pVer)
{
    if (!pVer)
        return FALSE;

    if (!g_Config) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").fatal("extension mode startup not possible, is the DLL loaded as a filter?");
        return FALSE;
    }

    pVer->dwExtensionVersion = HSE_VERSION;
    strncpy(pVer->lpszExtensionDesc, "Shibboleth ISAPI Extension", HSE_MAX_EXT_DLL_NAME_LEN-1);
    return TRUE;
}

extern "C" BOOL WINAPI TerminateExtension(DWORD)
{
    return TRUE;    // cleanup should happen when filter unloads
}

extern "C" BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".ISAPI");

    if (!pVer)
        return FALSE;
    else if (g_Config) {
        log.warn("reentrant ISAPI filter initialization, ignoring...");
        return TRUE;
    }

    g_Config = &SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
        );
    if (!g_Config->init()) {
        g_Config = nullptr;
        log.fatal("ISAPI filter startup failed during library initialization, check native log for help");
        return FALSE;
    }

    try {
        if (!g_Config->instantiate(nullptr, true))
            throw runtime_error("unknown error");
    }
    catch (const std::exception& ex) {
        log.fatal("ISAPI filter startup failed: %s", ex.what());
        g_Config->term();
        g_Config=nullptr;
        return FALSE;
    }

    // Access implementation-specifics and site mappings.
    ServiceProvider* sp = g_Config->getServiceProvider();
    Locker locker(sp);
    const PropertySet* props = sp->getPropertySet("InProcess");
    if (props) {
        pair<bool,bool> flag = props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        flag = props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;

        pair<bool,const char*> unsetValue = props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        if (g_checkSpoofing) {
            unsetValue = props->getString("spoofKey");
            if (unsetValue.first)
                g_spoofKey = unsetValue.second;
            else {
                _invalid_parameter_handler old = _set_invalid_parameter_handler(_my_invalid_parameter_handler);
                unsigned int randkey=0,randkey2=0,randkey3=0,randkey4=0;
                if (rand_s(&randkey) == 0 && rand_s(&randkey2) == 0 && rand_s(&randkey3) == 0 && rand_s(&randkey4) == 0) {
                    _set_invalid_parameter_handler(old);
                    g_spoofKey = lexical_cast<string>(randkey) + lexical_cast<string>(randkey2) +
                        lexical_cast<string>(randkey3) + lexical_cast<string>(randkey4);
                }
                else {
                    _set_invalid_parameter_handler(old);
                    log.fatal("ISAPI filter failed to generate a random anti-spoofing key");
                    locker.assign();    // pops lock on SP config
                    g_Config->term();
                    g_Config = nullptr;
                    return FALSE;
                }
            }
        }

        props = props->getPropertySet("ISAPI");
        if (props) {
            flag = props->getBool("normalizeRequest");
            g_bNormalizeRequest = !flag.first || flag.second;
            flag = props->getBool("safeHeaderNames");
            g_bSafeHeaderNames = flag.first && flag.second;
            if (props->getString("useHeaders").first)
                log.warn("useHeaders attribute not supported by ISAPI filter, ignored");
            if (props->getString("useVariables").first)
                log.warn("useVariables attribute not supported by ISAPI filter, ignored");

            const DOMElement* child = XMLHelper::getFirstChildElement(props->getElement(), Site);
            while (child) {
                string id(XMLHelper::getAttrString(child, "", id));
                if (!id.empty()) {
                    g_Sites.insert(make_pair(id, site_t(child)));
                    if (!XMLHelper::getAttrString(child, "", useHeaders).empty())
                        log.warn("useHeaders attribute not valid for this filter");
                    if (!XMLHelper::getAttrString(child, "", useVariables).empty())
                        log.warn("useVariables attribute not valid for this filter");
                }
                child = XMLHelper::getNextSiblingElement(child, Site);
            }

            if (nullptr != props->getPropertySet("Roles"))
                log.warn("<Roles> element not valid for this filter");
        }
    }

    pVer->dwFilterVersion = HTTP_FILTER_REVISION;
    strncpy(pVer->lpszFilterDesc, "Shibboleth ISAPI Filter", SF_MAX_FILTER_DESC_LEN);
    pVer->dwFlags=(SF_NOTIFY_ORDER_HIGH |
                   SF_NOTIFY_SECURE_PORT |
                   SF_NOTIFY_NONSECURE_PORT |
                   SF_NOTIFY_PREPROC_HEADERS |
                   SF_NOTIFY_LOG);
    log.info("ISAPI filter initialized");
    return TRUE;
}

extern "C" BOOL WINAPI TerminateFilter(DWORD)
{
    if (g_Config)
        g_Config->term();
    g_Config = nullptr;
    Category::getInstance(SHIBSP_LOGCAT ".ISAPI").info("ISAPI filter shutting down");
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
    dynabuf() { bufptr=nullptr; buflen=0; }
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
    if (buflen==0 || s==nullptr)
        return (buflen==0 && s==nullptr);
    else
        return strcmp(bufptr,s)==0;
}

/****************************************************************************/
// ISAPI Filter

class ShibTargetIsapiF : public AbstractSPRequest
{
  PHTTP_FILTER_CONTEXT m_pfc;
  PHTTP_FILTER_PREPROC_HEADERS m_pn;
  multimap<string,string> m_headers;
  int m_port;
  string m_scheme,m_hostname;
  mutable string m_remote_addr,m_content_type,m_method;
  dynabuf m_allhttp;
  bool m_firsttime;

public:
  ShibTargetIsapiF(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pn, const site_t& site)
      : AbstractSPRequest(SHIBSP_LOGCAT ".ISAPI"), m_pfc(pfc), m_pn(pn), m_allhttp(4096), m_firsttime(true) {

    static char _url[] = "url";
    static char _SERVER_PORT[] = "SERVER_PORT";
    static char _SERVER_NAME[] = "SERVER_NAME";
    static char _ShibSpoofCheck[] = "ShibSpoofCheck:";

    // URL path always come from IIS.
    dynabuf var(256);
    GetHeader(_url,var,256,false);
    setRequestURI(var);

    // Port may come from IIS or from site def.
    if (!g_bNormalizeRequest || (pfc->fIsSecurePort && site.m_sslport.empty()) || (!pfc->fIsSecurePort && site.m_port.empty())) {
        GetServerVariable(_SERVER_PORT,var,10);
        if (var.empty()) {
            m_port = pfc->fIsSecurePort ? 443 : 80;
        }
        else {
            m_port = atoi(var);
        }
    }
    else if (pfc->fIsSecurePort) {
        m_port = atoi(site.m_sslport.c_str());
    }
    else {
        m_port = atoi(site.m_port.c_str());
    }

    // Scheme may come from site def or be derived from IIS.
    m_scheme=site.m_scheme;
    if (m_scheme.empty() || !g_bNormalizeRequest)
        m_scheme=pfc->fIsSecurePort ? "https" : "http";

    GetServerVariable(_SERVER_NAME,var,32);

    // Make sure SERVER_NAME is "authorized" for use on this site. If not, or empty, set to canonical name.
    if (var.empty()) {
        m_hostname = site.m_name;
    }
    else {
        m_hostname = var;
        if (site.m_name != m_hostname && site.m_aliases.find(m_hostname) == site.m_aliases.end())
            m_hostname = site.m_name;
    }

    if (!g_spoofKey.empty()) {
        GetHeader(_ShibSpoofCheck, var, 32, false);
        if (!var.empty() && g_spoofKey == (char*)var)
            m_firsttime = false;
    }

    if (!m_firsttime)
        log(SPDebug, "ISAPI filter running more than once");
  }
  ~ShibTargetIsapiF() { }

  const char* getScheme() const {
    return m_scheme.c_str();
  }
  const char* getHostname() const {
    return m_hostname.c_str();
  }
  int getPort() const {
    return m_port;
  }
  const char* getQueryString() const {
      const char* uri = getRequestURI();
      uri = (uri ? strchr(uri, '?') : nullptr);
      return uri ? (uri + 1) : nullptr;
  }
  const char* getMethod() const {
    static char _HTTP_METHOD[] = "HTTP_METHOD";
    if (m_method.empty()) {
        dynabuf var(5);
        GetServerVariable(_HTTP_METHOD,var,5,false);
        if (!var.empty())
            m_method = var;
    }
    return m_method.c_str();
  }
  string getContentType() const {
    static char _HTTP_CONTENT_TYPE[] = "HTTP_CONTENT_TYPE";
    if (m_content_type.empty()) {
        dynabuf var(32);
        GetServerVariable(_HTTP_CONTENT_TYPE,var,32,false);
        if (!var.empty())
            m_content_type = var;
    }
    return m_content_type;
  }
  string getRemoteAddr() const {
    static char _REMOTE_ADDR[] = "REMOTE_ADDR";
    m_remote_addr = AbstractSPRequest::getRemoteAddr();
    if (m_remote_addr.empty()) {
        dynabuf var(16);
        GetServerVariable(_REMOTE_ADDR,var,16,false);
        if (!var.empty())
            m_remote_addr = var;
    }
    return m_remote_addr;
  }
  string makeSafeHeader(const char* rawname) const {
      string hdr;
      for (; *rawname; ++rawname) {
          if (isalnum(*rawname))
              hdr += *rawname;
      }
      return (hdr + ':');
  }
  void clearHeader(const char* rawname, const char* cginame) {
    static char _ALL_HTTP[] = "ALL_HTTP";
    static char _REMOTE_USER[] = "remote-user:";
    static char _REMOTE_USER2[] = "remote_user:";

    if (g_checkSpoofing && m_firsttime) {
        if (m_allhttp.empty())
	        GetServerVariable(_ALL_HTTP, m_allhttp, 4096, false);
        if (!m_allhttp.empty()) {
            string hdr = g_bSafeHeaderNames ? ("HTTP_" + makeSafeHeader(cginame + 5)) : (string(cginame) + ':');
            if (strstr(m_allhttp, hdr.c_str()))
                throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, hdr.c_str()));
        }
    }
    if (g_bSafeHeaderNames) {
        string hdr = makeSafeHeader(rawname);
        m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), const_cast<char*>(g_unsetHeaderValue.c_str()));
    }
    else if (!strcmp(rawname,"REMOTE_USER")) {
        m_pn->SetHeader(m_pfc, _REMOTE_USER, const_cast<char*>(g_unsetHeaderValue.c_str()));
        m_pn->SetHeader(m_pfc, _REMOTE_USER2, const_cast<char*>(g_unsetHeaderValue.c_str()));
	}
	else {
        string hdr = string(rawname) + ':';
        m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), const_cast<char*>(g_unsetHeaderValue.c_str()));
	}
  }
  void setHeader(const char* name, const char* value) {
    string hdr = g_bSafeHeaderNames ? makeSafeHeader(name) : (string(name) + ':');
    m_pn->SetHeader(m_pfc, const_cast<char*>(hdr.c_str()), const_cast<char*>(value));
  }
  string getSecureHeader(const char* name) const {
    string hdr = g_bSafeHeaderNames ? makeSafeHeader(name) : (string(name) + ':');
    dynabuf buf(256);
    GetHeader(const_cast<char*>(hdr.c_str()), buf, 256, false);
    return string(buf.empty() ? "" : static_cast<char*>(buf));
  }
  string getHeader(const char* name) const {
    string hdr(name);
    hdr += ':';
    dynabuf buf(256);
    GetHeader(const_cast<char*>(hdr.c_str()), buf, 256, false);
    return string(buf.empty() ? "" : static_cast<char*>(buf));
  }
  void setRemoteUser(const char* user) {
    setHeader("remote-user", user);
    if (!user || !*user)
        m_pfc->pFilterContext = nullptr;
    else if (m_pfc->pFilterContext = m_pfc->AllocMem(m_pfc, sizeof(char) * (strlen(user) + 1), 0))
        strcpy(reinterpret_cast<char*>(m_pfc->pFilterContext), user);
  }
  string getRemoteUser() const {
    return getSecureHeader("remote-user");
  }
  void setResponseHeader(const char* name, const char* value, bool replace=false) {
    HTTPResponse::setResponseHeader(name, value, replace);
    if (name && *name) {
        // Set for later.
        if (replace || !value)
            m_headers.erase(name);
        if (value && *value)
            m_headers.insert(make_pair(name,value));
    }
  }
  long sendResponse(istream& in, long status) {
    string hdr = string("Connection: close\r\n");
    for (multimap<string,string>::const_iterator i = m_headers.begin(); i != m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    const char* codestr="200 OK";
    switch (status) {
        case XMLTOOLING_HTTP_STATUS_NOTMODIFIED:    codestr="304 Not Modified"; break;
        case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="401 Authorization Required"; break;
        case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="403 Forbidden"; break;
        case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="404 Not Found"; break;
        case XMLTOOLING_HTTP_STATUS_ERROR:          codestr="500 Server Error"; break;
    }
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, (void*)codestr, (ULONG_PTR)hdr.c_str(), 0);
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        DWORD resplen = in.gcount();
        m_pfc->WriteClient(m_pfc, buf, &resplen, 0);
    }
    return SF_STATUS_REQ_FINISHED;
  }
  long sendRedirect(const char* url) {
    static char _status[] = "302 Please Wait";
    HTTPResponse::sendRedirect(url);
    string hdr=string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: Wed, 01 Jan 1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache,max-age=0\r\n";
    for (multimap<string,string>::const_iterator i = m_headers.begin(); i != m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    m_pfc->ServerSupportFunction(m_pfc, SF_REQ_SEND_RESPONSE_HEADER, _status, (ULONG_PTR)hdr.c_str(), 0);
    static const char* redmsg="<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_pfc->WriteClient(m_pfc, (LPVOID)redmsg, &resplen, 0);
    return SF_STATUS_REQ_FINISHED;
  }
  long returnDecline() {
      return SF_STATUS_REQ_NEXT_NOTIFICATION;
  }
  long returnOK() {
    return SF_STATUS_REQ_NEXT_NOTIFICATION;
  }

  const vector<string>& getClientCertificates() const {
      return g_NoCerts;
  }

  // The filter never processes the POST, so stub these methods.
  long getContentLength() const { throw IOException("The request's Content-Length is not available to an ISAPI filter."); }
  const char* getRequestBody() const { throw IOException("The request body is not available to an ISAPI filter."); }

  void GetServerVariable(LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true) const {
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!m_pfc->GetServerVariable(m_pfc,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e = GetLastError();
        if (e == ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        log(SPRequest::SPError, string("missing required server variable: ") + lpszVariable);
  }

  void GetHeader(LPSTR lpszName, dynabuf& s, DWORD size=80, bool bRequired=true) const {
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!m_pn->GetHeader(m_pfc,lpszName,s,&size)) {
        // Grumble. Check the error.
        DWORD e = GetLastError();
        if (e == ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty())
        log(SPRequest::SPError, string("missing required header: ") + lpszName);
  }
};

DWORD WriteClientError(PHTTP_FILTER_CONTEXT pfc, const char* msg)
{
    static char _status[] = "200 OK";
    static char ctype[] = "Connection: close\r\nContent-Type: text/html\r\n\r\n";
    pfc->ServerSupportFunction(pfc,SF_REQ_SEND_RESPONSE_HEADER,_status,(ULONG_PTR)ctype,0);
    static char xmsg[] = "<HTML><HEAD><TITLE>Shibboleth Filter Error</TITLE></HEAD><BODY>"
                            "<H1>Shibboleth Filter Error</H1>";
    DWORD resplen=strlen(xmsg);
    pfc->WriteClient(pfc,xmsg,&resplen,0);
    resplen=strlen(msg);
    pfc->WriteClient(pfc,const_cast<char*>(msg),&resplen,0);
    static char xmsg2[] = "</BODY></HTML>";
    resplen=strlen(xmsg2);
    pfc->WriteClient(pfc,xmsg2,&resplen,0);
    return SF_STATUS_REQ_FINISHED;
}

void GetServerVariable(PHTTP_FILTER_CONTEXT pfc, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!pfc->GetServerVariable(pfc,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty()) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").error("missing server variable: %s", lpszVariable);
    }
}


extern "C" DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD notificationType, LPVOID pvNotification)
{
    static char _INSTANCE_ID[] = "INSTANCE_ID";
    static char _ShibSpoofCheck[] = "ShibSpoofCheck:";

    // Is this a log notification?
    if (notificationType == SF_NOTIFY_LOG) {
        if (pfc->pFilterContext)
        	((PHTTP_FILTER_LOG)pvNotification)->pszClientUserName = reinterpret_cast<char*>(pfc->pFilterContext);
        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }

    PHTTP_FILTER_PREPROC_HEADERS pn=(PHTTP_FILTER_PREPROC_HEADERS)pvNotification;
    try {
        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(pfc,_INSTANCE_ID,buf,10);
        if (buf.empty())
            return WriteClientError(pfc, "Shibboleth Filter failed to obtain INSTANCE_ID server variable.");

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i = g_Sites.find(static_cast<char*>(buf));
        if (map_i == g_Sites.end())
            return SF_STATUS_REQ_NEXT_NOTIFICATION;

        string threadid("[");
        threadid += lexical_cast<string>(getpid()) + "] isapi_shib";
        xmltooling::NDC ndc(threadid.c_str());

        ShibTargetIsapiF stf(pfc, pn, map_i->second);

        pair<bool,long> res = stf.getServiceProvider().doAuthentication(stf);
        if (!g_spoofKey.empty())
            pn->SetHeader(pfc, _ShibSpoofCheck, const_cast<char*>(g_spoofKey.c_str()));
        if (res.first) return res.second;

        res = stf.getServiceProvider().doExport(stf);
        if (res.first) return res.second;

        res = stf.getServiceProvider().doAuthorization(stf);
        if (res.first) return res.second;

        return SF_STATUS_REQ_NEXT_NOTIFICATION;
    }
    catch(const bad_alloc&) {
        return WriteClientError(pfc, "Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(pfc, "A required variable or header was empty.");
        else
            return WriteClientError(pfc, "Shibboleth Filter detected unexpected IIS error.");
    }
    catch (const std::exception& e) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").error("ISAPI filter caught an exception: %s", e.what());
        return WriteClientError(pfc, "Shibboleth Filter caught an exception, check Event Log for details.");
    }
    catch(...) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").crit("ISAPI extension caught an unknown exception");
        if (g_catchAll)
            return WriteClientError(pfc, "Shibboleth Filter threw an unknown exception.");
        throw;
    }
    return WriteClientError(pfc, "Shibboleth Filter reached unreachable code, save my walrus!");
}


/****************************************************************************/
// ISAPI Extension

DWORD WriteClientError(LPEXTENSION_CONTROL_BLOCK lpECB, const char* msg)
{
    static char _status[] = "200 OK";
    static char ctype[] = "Connection: close\r\nContent-Type: text/html\r\n\r\n";
    lpECB->ServerSupportFunction(lpECB->ConnID,HSE_REQ_SEND_RESPONSE_HEADER,_status,0,(LPDWORD)ctype);
    static char xmsg[] = "<HTML><HEAD><TITLE>Shibboleth Error</TITLE></HEAD><BODY><H1>Shibboleth Error</H1>";
    DWORD resplen=strlen(xmsg);
    lpECB->WriteClient(lpECB->ConnID,xmsg,&resplen,HSE_IO_SYNC);
    resplen=strlen(msg);
    lpECB->WriteClient(lpECB->ConnID,const_cast<char*>(msg),&resplen,HSE_IO_SYNC);
    static char xmsg2[] = "</BODY></HTML>";
    resplen=strlen(xmsg2);
    lpECB->WriteClient(lpECB->ConnID,xmsg2,&resplen,HSE_IO_SYNC);
    return HSE_STATUS_SUCCESS;
}


class ShibTargetIsapiE : public AbstractSPRequest
{
  LPEXTENSION_CONTROL_BLOCK m_lpECB;
  multimap<string,string> m_headers;
  mutable vector<string> m_certs;
  mutable string m_body;
  mutable bool m_gotBody;
  int m_port;
  string m_scheme,m_hostname,m_uri;
  mutable string m_remote_addr,m_remote_user;

public:
  ShibTargetIsapiE(LPEXTENSION_CONTROL_BLOCK lpECB, const site_t& site)
      : AbstractSPRequest(SHIBSP_LOGCAT ".ISAPI"), m_lpECB(lpECB), m_gotBody(false) {
    static char _HTTPS[] = "HTTPS";
    static char _URL[] = "URL";
    static char _SERVER_PORT[] = "SERVER_PORT";
    static char _SERVER_NAME[] = "SERVER_NAME";

    dynabuf ssl(5);
    GetServerVariable(_HTTPS,ssl,5);
    bool SSL=(ssl=="on" || ssl=="ON");

    // Scheme may come from site def or be derived from IIS.
    m_scheme = site.m_scheme;
    if (m_scheme.empty() || !g_bNormalizeRequest)
        m_scheme = SSL ? "https" : "http";

    // URL path always come from IIS.
    dynabuf url(256);
    GetServerVariable(_URL,url,255);

    // Port may come from IIS or from site def.
    if (!g_bNormalizeRequest || (SSL && site.m_sslport.empty()) || (!SSL && site.m_port.empty())) {
        dynabuf port(11);
        GetServerVariable(_SERVER_PORT,port,10);
        if (port.empty()) {
            m_port = SSL ? 443 : 80;
        }
        else {
            m_port = atoi(port);
        }
    }
    else if (SSL) {
        m_port = atoi(site.m_sslport.c_str());
    }
    else {
        m_port = atoi(site.m_port.c_str());
    }

    dynabuf var(32);
    GetServerVariable(_SERVER_NAME, var, 32);
    if (var.empty()) {
        m_hostname = site.m_name;
    }
    else {
        // Make sure SERVER_NAME is "authorized" for use on this site. If not, set to canonical name.
        m_hostname=var;
        if (site.m_name != m_hostname && site.m_aliases.find(m_hostname) == site.m_aliases.end())
            m_hostname = site.m_name;
    }

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

    string uri;

    // Clearly we're only in bad mode if path info exists at all.
    if (lpECB->lpszPathInfo && *(lpECB->lpszPathInfo)) {
        if (strstr(lpECB->lpszPathInfo,url))
            // Pretty good chance we're in bad mode, unless the PathInfo repeats the path itself.
            uri = lpECB->lpszPathInfo;
        else {
            if (!url.empty())
                uri = url;
            uri += lpECB->lpszPathInfo;
        }
    }
    else if (!url.empty()) {
        uri = url;
    }

    // For consistency with Apache, let's add the query string.
    if (lpECB->lpszQueryString && *(lpECB->lpszQueryString)) {
        uri += '?';
        uri += lpECB->lpszQueryString;
    }

    setRequestURI(uri.c_str());
  }
  ~ShibTargetIsapiE() {}

  const char* getScheme() const {
    return m_scheme.c_str();
  }
  const char* getHostname() const {
    return m_hostname.c_str();
  }
  int getPort() const {
    return m_port;
  }
  const char* getMethod() const {
    return m_lpECB->lpszMethod;
  }
  string getContentType() const {
    return m_lpECB->lpszContentType ? m_lpECB->lpszContentType : "";
  }
  long getContentLength() const {
      return m_lpECB->cbTotalBytes;
  }
  string getRemoteUser() const {
    static char _REMOTE_USER[] = "REMOTE_USER";
    if (m_remote_user.empty()) {
        dynabuf var(16);
        GetServerVariable(_REMOTE_USER, var, 32, false);
        if (!var.empty())
            m_remote_user = var;
    }
    return m_remote_user;
  }
  string getRemoteAddr() const {
      static char _REMOTE_ADDR[] = "REMOTE_ADDR";
    m_remote_addr = AbstractSPRequest::getRemoteAddr();
    if (m_remote_addr.empty()) {
        dynabuf var(16);
        GetServerVariable(_REMOTE_ADDR, var, 16, false);
        if (!var.empty())
            m_remote_addr = var;
    }
    return m_remote_addr;
  }
  string getHeader(const char* name) const {
    string hdr("HTTP_");
    for (; *name; ++name) {
        if (*name == '-')
            hdr += '_';
        else
            hdr += toupper(*name);
    }
    dynabuf buf(128);
    GetServerVariable(const_cast<char*>(hdr.c_str()), buf, 128, false);
    return buf.empty() ? "" : static_cast<char*>(buf);
  }
  void setResponseHeader(const char* name, const char* value, bool replace = false) {
      HTTPResponse::setResponseHeader(name, value, replace);
      if (name && *name) {
          // Set for later.
          if (replace || !value)
              m_headers.erase(name);
          if (value && *value)
              m_headers.insert(make_pair(name, value));
      }
  }
  const char* getQueryString() const {
    return m_lpECB->lpszQueryString;
  }
  const char* getRequestBody() const {
    if (m_gotBody)
        return m_body.c_str();
    if (m_lpECB->cbTotalBytes > 1024*1024) // 1MB?
        throw opensaml::SecurityPolicyException("Size of request body exceeded 1M size limit.");
    else if (m_lpECB->cbTotalBytes > m_lpECB->cbAvailable) {
      m_gotBody=true;
      DWORD datalen=m_lpECB->cbTotalBytes;
      if (m_lpECB->cbAvailable > 0) {
        m_body.assign(reinterpret_cast<char*>(m_lpECB->lpbData),m_lpECB->cbAvailable);
        datalen-=m_lpECB->cbAvailable;
      }
      char buf[8192];
      while (datalen) {
        DWORD buflen=8192;
        BOOL ret = m_lpECB->ReadClient(m_lpECB->ConnID, buf, &buflen);
        if (!ret) {
            char message[65];
            _snprintf(message, 64, "Error reading request body from browser (%x).", GetLastError());
            throw IOException(message);
        }
        else if (!buflen)
            throw IOException("Socket closed while reading request body from browser.");
        m_body.append(buf, buflen);
        datalen-=buflen;
      }
    }
    else if (m_lpECB->cbAvailable) {
        m_gotBody=true;
        m_body.assign(reinterpret_cast<char*>(m_lpECB->lpbData),m_lpECB->cbAvailable);
    }
    return m_body.c_str();
  }
  long sendResponse(istream& in, long status) {
    string hdr = string("Connection: close\r\n");
    for (multimap<string,string>::const_iterator i = m_headers.begin(); i != m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";

    static char okstr[] = "200 OK";
    static char notmodstr[] = "304 Not Modified";
    static char authzstr[] = "401 Authorization Required";
    static char forbiddenstr[] = "403 Forbidden";
    static char notfoundstr[] = "404 Not Found";
    static char errorstr[] = "500 Server Error";
    
    char* str = nullptr;

    switch (status) {
        case XMLTOOLING_HTTP_STATUS_NOTMODIFIED:    str = notmodstr; break;
        case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   str = authzstr; break;
        case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      str = forbiddenstr; break;
        case XMLTOOLING_HTTP_STATUS_NOTFOUND:       str = notfoundstr; break;
        case XMLTOOLING_HTTP_STATUS_ERROR:          str = errorstr; break;

        default: str = okstr;
    }
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER, str, 0, (LPDWORD)hdr.c_str());
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        DWORD resplen = in.gcount();
        m_lpECB->WriteClient(m_lpECB->ConnID, buf, &resplen, HSE_IO_SYNC);
    }
    return HSE_STATUS_SUCCESS;
  }
  long sendRedirect(const char* url) {
    static char _status[] = "302 Moved";

    HTTPResponse::sendRedirect(url);
    string hdr=string("Location: ") + url + "\r\n"
      "Content-Type: text/html\r\n"
      "Content-Length: 40\r\n"
      "Expires: Wed, 01 Jan 1997 12:00:00 GMT\r\n"
      "Cache-Control: private,no-store,no-cache,max-age=0\r\n";
    for (multimap<string,string>::const_iterator i = m_headers.begin(); i != m_headers.end(); ++i)
        hdr += i->first + ": " + i->second + "\r\n";
    hdr += "\r\n";
    m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_SEND_RESPONSE_HEADER, _status, 0, (LPDWORD)hdr.c_str());
    static char redmsg[] = "<HTML><BODY>Redirecting...</BODY></HTML>";
    DWORD resplen=40;
    m_lpECB->WriteClient(m_lpECB->ConnID, redmsg, &resplen, HSE_IO_SYNC);
    return HSE_STATUS_SUCCESS;
  }
  // Decline happens in the POST processor if this isn't the handler url
  // Note that it can also happen with HTAccess, but we don't support that, yet.
  long returnDecline() {
    return WriteClientError(
        m_lpECB,
        "ISAPI extension can only be invoked to process Shibboleth protocol requests."
		"Make sure the mapped file extension doesn't match actual content."
        );
  }
  long returnOK() {
      return HSE_STATUS_SUCCESS;
  }

  const vector<string>& getClientCertificates() const {
      if (m_certs.empty()) {
        char CertificateBuf[8192];
        CERT_CONTEXT_EX ccex;
        ccex.cbAllocated = sizeof(CertificateBuf);
        ccex.CertContext.pbCertEncoded = (BYTE*)CertificateBuf;
        DWORD dwSize = sizeof(ccex);

        if (m_lpECB->ServerSupportFunction(m_lpECB->ConnID, HSE_REQ_GET_CERT_INFO_EX, (LPVOID)&ccex, (LPDWORD)dwSize, nullptr)) {
            if (ccex.CertContext.cbCertEncoded) {
                XMLSize_t outlen;
                XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(CertificateBuf), ccex.CertContext.cbCertEncoded, &outlen);
                m_certs.push_back(reinterpret_cast<char*>(serialized));
                XMLString::release((char**)&serialized);
            }
        }
      }
      return m_certs;
  }

  // Not used in the extension.
  void clearHeader(const char* rawname, const char* cginame) { throw runtime_error("clearHeader not implemented"); }
  void setHeader(const char* name, const char* value) { throw runtime_error("setHeader not implemented"); }
  void setRemoteUser(const char* user) { throw runtime_error("setRemoteUser not implemented"); }

  void GetServerVariable(LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true) const {
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!m_lpECB->GetServerVariable(m_lpECB->ConnID,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty()) {
        log(SPRequest::SPError, string("missing required server variable: ") + lpszVariable);
    }
  }
};

void GetServerVariable(LPEXTENSION_CONTROL_BLOCK lpECB, LPSTR lpszVariable, dynabuf& s, DWORD size=80, bool bRequired=true)
{
    s.reserve(size);
    s.erase();
    size=s.size();

    while (!lpECB->GetServerVariable(lpECB->ConnID,lpszVariable,s,&size)) {
        // Grumble. Check the error.
        DWORD e=GetLastError();
        if (e==ERROR_INSUFFICIENT_BUFFER)
            s.reserve(size);
        else
            break;
    }
    if (bRequired && s.empty()) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").error("missing required server variable: %s", lpszVariable);
    }
}

extern "C" DWORD WINAPI HttpExtensionProc(LPEXTENSION_CONTROL_BLOCK lpECB)
{
    static char _INSTANCE_ID[] = "INSTANCE_ID";

    try {
        string threadid("[");
        threadid += lexical_cast<string>(getpid()) + "] isapi_shib_extension";
        xmltooling::NDC ndc(threadid.c_str());

        // Determine web site number. This can't really fail, I don't think.
        dynabuf buf(128);
        GetServerVariable(lpECB,_INSTANCE_ID,buf,10);
        if (buf.empty())
            return WriteClientError(lpECB, "Shibboleth Extension failed to obtain INSTANCE_ID server variable.");

        // Match site instance to host name, skip if no match.
        map<string,site_t>::const_iterator map_i = g_Sites.find(static_cast<char*>(buf));
        if (map_i == g_Sites.end())
            return WriteClientError(lpECB, "Shibboleth Extension not configured for web site (check ISAPI mappings in SP configuration).");

        ShibTargetIsapiE ste(lpECB, map_i->second);
        pair<bool,long> res = ste.getServiceProvider().doHandler(ste);
        if (res.first) return res.second;

        return WriteClientError(lpECB, "Shibboleth Extension failed to process request");

    }
    catch(const bad_alloc&) {
        return WriteClientError(lpECB, "Out of Memory");
    }
    catch(long e) {
        if (e==ERROR_NO_DATA)
            return WriteClientError(lpECB, "A required variable or header was empty.");
        else
            return WriteClientError(lpECB, "Server detected unexpected IIS error.");
    }
    catch (const std::exception& e) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").error("ISAPI extension caught an exception: %s", e.what());
        return WriteClientError(lpECB, "Shibboleth Extension caught an exception, check native log for details.");
    }
    catch(...) {
        Category::getInstance(SHIBSP_LOGCAT ".ISAPI").crit("ISAPI filter caught an unknown exception");
        if (g_catchAll)
            return WriteClientError(lpECB, "Shibboleth Extension threw an unknown exception.");
        throw;
    }

    // If we get here we've got an error.
    return HSE_STATUS_ERROR;
}
