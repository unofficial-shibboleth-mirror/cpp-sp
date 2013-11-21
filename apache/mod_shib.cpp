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
 * mod_shib.cpp
 *
 * Apache module implementation.
 */

#define SHIBSP_LITE

#ifdef SOLARIS2
#undef _XOPEN_SOURCE    // causes gethostname conflict in unistd.h
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/exceptions.h>
#include <shibsp/AbstractSPRequest.h>
#include <shibsp/AccessControl.h>
#include <shibsp/GSSRequest.h>
#include <shibsp/RequestMapper.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/Attribute.h>

#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#undef _XPG4_2

#include <set>
#include <memory>
#include <fstream>
#include <stdexcept>
#include <boost/lexical_cast.hpp>

// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#ifndef SHIB_APACHE_13
#include <apr_buckets.h>
#include <apr_strings.h>
#include <apr_pools.h>
#endif

#ifdef SHIB_APACHE_24
#include <mod_auth.h>
#endif

#include <cstddef>
#ifdef HAVE_UNISTD_H
#include <unistd.h>		// for getpid()
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;
using xercesc::RegularExpression;
using xercesc::XMLException;

#ifdef APLOG_USE_MODULE
    extern "C" module AP_MODULE_DECLARE_DATA mod_shib;
    static int* const aplog_module_index = &(mod_shib.module_index);
#else
    extern "C" module MODULE_VAR_EXPORT mod_shib;
#endif

namespace {
    char* g_szSHIBConfig = nullptr;
    char* g_szSchemaDir = nullptr;
    char* g_szPrefix = nullptr;
    SPConfig* g_Config = nullptr;
    string g_unsetHeaderValue,g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
#ifndef SHIB_APACHE_13
    char* g_szGSSContextKey = "mod_auth_gssapi:gss_ctx";
#endif
    static const char* g_UserDataKey = "urn:mace:shibboleth:Apache:shib_check_user";
}

/* Apache 2.2.x headers must be accumulated and set in the output filter.
   Apache 2.0.49+ supports the filter method.
   Apache 1.3.x and lesser 2.0.x must write the headers directly. */

#if (defined(SHIB_APACHE_20) || defined(SHIB_APACHE_22) || defined(SHIB_APACHE_24)) && AP_MODULE_MAGIC_AT_LEAST(20020903,6)
#define SHIB_DEFERRED_HEADERS
#endif

/********************************************************************************/
// Basic Apache Configuration code.
//

// per-server module configuration structure
struct shib_server_config
{
    char* szScheme;
    int bCompatValidUser;
};

// creates the per-server configuration
extern "C" void* create_shib_server_config(SH_AP_POOL* p, server_rec* s)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    sc->szScheme = nullptr;
    sc->bCompatValidUser = -1;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shib_server_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_server_config* sc=(shib_server_config*)ap_pcalloc(p,sizeof(shib_server_config));
    shib_server_config* parent=(shib_server_config*)base;
    shib_server_config* child=(shib_server_config*)sub;

    if (child->szScheme)
        sc->szScheme=ap_pstrdup(p,child->szScheme);
    else if (parent->szScheme)
        sc->szScheme=ap_pstrdup(p,parent->szScheme);
    else
        sc->szScheme=nullptr;

    sc->bCompatValidUser = ((child->bCompatValidUser==-1) ? parent->bCompatValidUser : child->bCompatValidUser);

    return sc;
}

// per-dir module configuration structure
struct shib_dir_config
{
    SH_AP_TABLE* tSettings; // generic table of extensible settings

    // RM Configuration
#ifdef SHIB_APACHE_24
    int bRequestMapperAuthz;// support RequestMapper AccessControl plugins
#else
    char* szAuthGrpFile;    // Auth GroupFile name
	char* szAccessControl;	// path to "external" AccessControl plugin file
    int bRequireAll;        // all "known" require directives must match, otherwise OR logic
    int bAuthoritative;     // allow htaccess plugin to DECLINE when authz fails
    int bCompatWith24;      // support 2.4-reserved require logic for compatibility
#endif

    // Content Configuration
    char* szApplicationId;  // Shib applicationId value
    char* szRequireWith;    // require a session using a specific initiator?
    char* szRedirectToSSL;  // redirect non-SSL requests to SSL port
    int bOff;               // flat-out disable all Shib processing
    int bBasicHijack;       // activate for AuthType Basic?
    int bRequireSession;    // require a session?
    int bExportAssertion;   // export SAML assertion to the environment?
    int bUseEnvVars;        // use environment?
    int bUseHeaders;        // use headers?
    int bExpireRedirects;   // expire redirects?
};

// creates per-directory config structure
extern "C" void* create_shib_dir_config (SH_AP_POOL* p, char* d)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    dc->tSettings = nullptr;
#ifdef SHIB_APACHE_24
    dc->bRequestMapperAuthz = -1;
#else
    dc->szAuthGrpFile = nullptr;
	dc->szAccessControl = nullptr;
    dc->bRequireAll = -1;
    dc->bAuthoritative = -1;
    dc->bCompatWith24 = -1;
#endif
    dc->szApplicationId = nullptr;
    dc->szRequireWith = nullptr;
    dc->szRedirectToSSL = nullptr;
    dc->bOff = -1;
    dc->bBasicHijack = -1;
    dc->bRequireSession = -1;
    dc->bExportAssertion = -1;
    dc->bUseEnvVars = -1;
    dc->bUseHeaders = -1;
    dc->bExpireRedirects = -1;
    return dc;
}

// overrides server configuration in directories
extern "C" void* merge_shib_dir_config (SH_AP_POOL* p, void* base, void* sub)
{
    shib_dir_config* dc=(shib_dir_config*)ap_pcalloc(p,sizeof(shib_dir_config));
    shib_dir_config* parent=(shib_dir_config*)base;
    shib_dir_config* child=(shib_dir_config*)sub;

    // The child supersedes any matching table settings in the parent.
    dc->tSettings = nullptr;
    if (parent->tSettings)
        dc->tSettings = ap_copy_table(p, parent->tSettings);
    if (child->tSettings) {
        if (dc->tSettings)
            ap_overlap_tables(dc->tSettings, child->tSettings, AP_OVERLAP_TABLES_SET);
        else
            dc->tSettings = ap_copy_table(p, child->tSettings);
    }

#ifdef SHIB_APACHE_24
    dc->bRequestMapperAuthz = ((child->bRequestMapperAuthz==-1) ? parent->bRequestMapperAuthz : child->bRequestMapperAuthz);
#else
    if (child->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,child->szAuthGrpFile);
    else if (parent->szAuthGrpFile)
        dc->szAuthGrpFile=ap_pstrdup(p,parent->szAuthGrpFile);
    else
        dc->szAuthGrpFile=nullptr;

	if (child->szAccessControl)
        dc->szAccessControl=ap_pstrdup(p,child->szAccessControl);
    else if (parent->szAccessControl)
        dc->szAccessControl=ap_pstrdup(p,parent->szAccessControl);
    else
        dc->szAccessControl=nullptr;
#endif

    if (child->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,child->szApplicationId);
    else if (parent->szApplicationId)
        dc->szApplicationId=ap_pstrdup(p,parent->szApplicationId);
    else
        dc->szApplicationId=nullptr;

    if (child->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,child->szRequireWith);
    else if (parent->szRequireWith)
        dc->szRequireWith=ap_pstrdup(p,parent->szRequireWith);
    else
        dc->szRequireWith=nullptr;

    if (child->szRedirectToSSL)
        dc->szRedirectToSSL=ap_pstrdup(p,child->szRedirectToSSL);
    else if (parent->szRedirectToSSL)
        dc->szRedirectToSSL=ap_pstrdup(p,parent->szRedirectToSSL);
    else
        dc->szRedirectToSSL=nullptr;

    dc->bOff = ((child->bOff==-1) ? parent->bOff : child->bOff);
    dc->bBasicHijack = ((child->bBasicHijack==-1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bRequireSession = ((child->bRequireSession==-1) ? parent->bRequireSession : child->bRequireSession);
    dc->bExportAssertion = ((child->bExportAssertion==-1) ? parent->bExportAssertion : child->bExportAssertion);
#ifndef SHIB_APACHE_24
    dc->bRequireAll = ((child->bRequireAll==-1) ? parent->bRequireAll : child->bRequireAll);
    dc->bAuthoritative = ((child->bAuthoritative==-1) ? parent->bAuthoritative : child->bAuthoritative);
    dc->bCompatWith24 = ((child->bCompatWith24==-1) ? parent->bCompatWith24 : child->bCompatWith24);
#endif
    dc->bUseEnvVars = ((child->bUseEnvVars==-1) ? parent->bUseEnvVars : child->bUseEnvVars);
    dc->bUseHeaders = ((child->bUseHeaders==-1) ? parent->bUseHeaders : child->bUseHeaders);
    dc->bExpireRedirects = ((child->bExpireRedirects==-1) ? parent->bExpireRedirects : child->bExpireRedirects);
    return dc;
}

class ShibTargetApache; // forward decl

// per-request module structure
struct shib_request_config
{
    SH_AP_TABLE* env;        // environment vars
#ifdef SHIB_DEFERRED_HEADERS
    SH_AP_TABLE* hdr_out;    // headers to browser
#endif
#ifndef SHIB_APACHE_13
    ShibTargetApache* sta;  // SP per-request structure wrapped around Apache's request
#endif
};

// create or return a request record
static shib_request_config* get_request_config(request_rec *r)
{
    shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
    if (rc) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "get_request_config called redundantly");
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "get_request_config created per-request structure");
        rc = (shib_request_config*)ap_pcalloc(r->pool,sizeof(shib_request_config));
        memset(rc, 0, sizeof(shib_request_config));
        ap_set_module_config(r->request_config, &mod_shib, rc);
    }
    return rc;
}

class ShibTargetApache : public AbstractSPRequest
#if defined(SHIBSP_HAVE_GSSAPI) && !defined(SHIB_APACHE_13)
    , public GSSRequest
#endif
{
  mutable string m_body;
  mutable bool m_gotBody,m_firsttime;
  mutable vector<string> m_certs;
  set<string> m_allhttp;
#if defined(SHIBSP_HAVE_GSSAPI) && !defined(SHIB_APACHE_13)
  mutable gss_name_t m_gssname;
#endif

public:
  bool m_handler;
  request_rec* m_req;
  shib_dir_config* m_dc;
  shib_server_config* m_sc;
  shib_request_config* m_rc;

  ShibTargetApache(request_rec* req) : AbstractSPRequest(SHIBSP_LOGCAT".Apache"),
        m_gotBody(false),m_firsttime(true),
#if defined(SHIBSP_HAVE_GSSAPI) && !defined(SHIB_APACHE_13)
        m_gssname(GSS_C_NO_NAME),
#endif
        m_handler(false), m_req(req), m_dc(nullptr), m_sc(nullptr), m_rc(nullptr) {
  }
  virtual ~ShibTargetApache() {
#if defined(SHIBSP_HAVE_GSSAPI) && !defined(SHIB_APACHE_13)
    if (m_gssname != GSS_C_NO_NAME) {
        OM_uint32 minor;
        gss_release_name(&minor, &m_gssname);
    }
#endif
  }

  bool isInitialized() const {
      return (m_sc != nullptr);
  }

  bool init(bool handler, bool check_user) {
    m_handler = handler;
    if (m_sc)
        return !check_user; // only initialize once
    m_sc = (shib_server_config*)ap_get_module_config(m_req->server->module_config, &mod_shib);
    m_dc = (shib_dir_config*)ap_get_module_config(m_req->per_dir_config, &mod_shib);
    m_rc = (shib_request_config*)ap_get_module_config(m_req->request_config, &mod_shib);

    setRequestURI(m_req->unparsed_uri);

    if (check_user && m_dc->bUseHeaders == 1) {
        // Try and see if this request was already processed, to skip spoof checking.
        if (!ap_is_initial_req(m_req)) {
            m_firsttime = false;
        }
        else if (!g_spoofKey.empty()) {
            const char* hdr = ap_table_get(m_req->headers_in, "Shib-Spoof-Check");
            if (hdr && g_spoofKey == hdr)
                m_firsttime = false;
        }
        if (!m_firsttime)
            log(SPDebug, "shib_check_user running more than once");
    }
    return true;
  }

  const char* getScheme() const {
    return m_sc->szScheme ? m_sc->szScheme : ap_http_method(m_req);
  }
  bool isSecure() const {
      return HTTPRequest::isSecure();
  }
  const char* getHostname() const {
#ifdef SHIB_APACHE_24
      return ap_get_server_name_for_url(m_req);
#else
      return ap_get_server_name(m_req);
#endif
  }
  int getPort() const {
    return ap_get_server_port(m_req);
  }
  const char* getMethod() const {
    return m_req->method;
  }
  string getContentType() const {
    const char* type = ap_table_get(m_req->headers_in, "Content-Type");
    return type ? type : "";
  }
  long getContentLength() const {
      // Apache won't expose content length until the body's read.
      if (!m_gotBody) {
          getRequestBody();
      }
      return m_body.length();
  }
  string getRemoteAddr() const {
    string ret = AbstractSPRequest::getRemoteAddr();
    if (!ret.empty())
        return ret;
#ifdef SHIB_APACHE_24
    return m_req->useragent_ip;
#else
    return m_req->connection->remote_ip;
#endif
  }
  void log(SPLogLevel level, const string& msg) const {
    AbstractSPRequest::log(level,msg);
    ap_log_rerror(
        APLOG_MARK,
        (level == SPDebug ? APLOG_DEBUG :
        (level == SPInfo ? APLOG_INFO :
        (level == SPWarn ? APLOG_WARNING :
        (level == SPError ? APLOG_ERR : APLOG_CRIT))))|APLOG_NOERRNO,
        SH_AP_R(m_req),
        "%s",
        msg.c_str()
        );
  }
  const char* getQueryString() const { return m_req->args; }
  const char* getRequestBody() const {
    if (m_gotBody || m_req->method_number==M_GET)
        return m_body.c_str();
#ifdef SHIB_APACHE_13
    // Read the posted data
    if (ap_setup_client_block(m_req, REQUEST_CHUNKED_DECHUNK) != OK) {
        m_gotBody=true;
        log(SPError, "Apache function (setup_client_block) failed while reading request body.");
        return m_body.c_str();
    }
    if (!ap_should_client_block(m_req)) {
        m_gotBody=true;
        log(SPError, "Apache function (should_client_block) failed while reading request body.");
        return m_body.c_str();
    }
    if (m_req->remaining > 1024*1024)
        throw opensaml::SecurityPolicyException("Blocked request body larger than 1M size limit.");
    m_gotBody=true;
    int len;
    char buff[HUGE_STRING_LEN];
    ap_hard_timeout("[mod_shib] getRequestBody", m_req);
    while ((len=ap_get_client_block(m_req, buff, sizeof(buff))) > 0) {
      ap_reset_timeout(m_req);
      m_body.append(buff, len);
    }
    ap_kill_timeout(m_req);
#else
    const char *data;
    apr_size_t len;
    int seen_eos = 0;
    apr_bucket_brigade* bb = apr_brigade_create(m_req->pool, m_req->connection->bucket_alloc);
    do {
        apr_bucket *bucket;
        apr_status_t rv = ap_get_brigade(m_req->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            log(SPError, "Apache function (ap_get_brigade) failed while reading request body.");
            break;
        }

        for (bucket = APR_BRIGADE_FIRST(bb); bucket != APR_BRIGADE_SENTINEL(bb); bucket = APR_BUCKET_NEXT(bucket)) {
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }

            /* We can't do much with this. */
            if (APR_BUCKET_IS_FLUSH(bucket))
                continue;

            /* read */
            apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (len > 0)
                m_body.append(data, len);
        }
        apr_brigade_cleanup(bb);
    } while (!seen_eos);
    apr_brigade_destroy(bb);
    m_gotBody=true;
#endif
    return m_body.c_str();
  }
  const char* getParameter(const char* name) const {
      return AbstractSPRequest::getParameter(name);
  }
  vector<const char*>::size_type getParameters(const char* name, vector<const char*>& values) const {
      return AbstractSPRequest::getParameters(name, values);
  }
  void clearHeader(const char* rawname, const char* cginame) {
    if (m_dc->bUseHeaders == 1) {
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_clear_header: hdr\n");
        if (g_checkSpoofing && m_firsttime) {
            if (m_allhttp.empty()) {
                // First time, so populate set with "CGI" versions of client-supplied headers.
#ifdef SHIB_APACHE_13
                array_header *hdrs_arr = ap_table_elts(m_req->headers_in);
                table_entry *hdrs = (table_entry *) hdrs_arr->elts;
#else
                const apr_array_header_t *hdrs_arr = apr_table_elts(m_req->headers_in);
                const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
#endif
                for (int i = 0; i < hdrs_arr->nelts; ++i) {
                    if (!hdrs[i].key)
                        continue;
                    string cgiversion("HTTP_");
                    const char* pch = hdrs[i].key;
                    while (*pch) {
                        cgiversion += (isalnum(*pch) ? toupper(*pch) : '_');
                        pch++;
                    }
                    m_allhttp.insert(cgiversion);
                }
            }

            if (m_allhttp.count(cginame) > 0)
                throw opensaml::SecurityPolicyException("Attempt to spoof header ($1) was detected.", params(1, rawname));
        }
        ap_table_unset(m_req->headers_in, rawname);
        ap_table_set(m_req->headers_in, rawname, g_unsetHeaderValue.c_str());
    }
  }
  void setHeader(const char* name, const char* value) {
    if (m_dc->bUseEnvVars != 0) {
       if (!m_rc) {
          // this happens on subrequests
          // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_setheader: no_m_rc\n");
          m_rc = get_request_config(m_req);
       }
       if (!m_rc->env)
           m_rc->env = ap_make_table(m_req->pool, 10);
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,SH_AP_R(m_req), "shib_set_env: %s=%s\n", name, value?value:"Null");
       ap_table_set(m_rc->env, name, value ? value : "");
    }
    if (m_dc->bUseHeaders == 1)
       ap_table_set(m_req->headers_in, name, value);
  }
  string getHeader(const char* name) const {
    const char* hdr = ap_table_get(m_req->headers_in, name);
    return string(hdr ? hdr : "");
  }
  string getSecureHeader(const char* name) const {
    if (m_dc->bUseEnvVars != 0) {
       const char *hdr;
       if (m_rc && m_rc->env)
           hdr = ap_table_get(m_rc->env, name);
       else
           hdr = nullptr;
       return string(hdr ? hdr : "");
    }
    return getHeader(name);
  }
  void setRemoteUser(const char* user) {
      SH_AP_USER(m_req) = user ? ap_pstrdup(m_req->pool, user) : nullptr;
      if (m_dc->bUseHeaders == 1) {
          if (user) {
              ap_table_set(m_req->headers_in, "REMOTE_USER", user);
          }
          else {
              ap_table_unset(m_req->headers_in, "REMOTE_USER");
              ap_table_set(m_req->headers_in, "REMOTE_USER", g_unsetHeaderValue.c_str());
          }
      }
  }
  string getRemoteUser() const {
    return string(SH_AP_USER(m_req) ? SH_AP_USER(m_req) : "");
  }
  void setAuthType(const char* authtype) {
      if (authtype && m_dc->bBasicHijack == 1)
          authtype = "Basic";
      SH_AP_AUTH_TYPE(m_req) = authtype ? ap_pstrdup(m_req->pool, authtype) : nullptr;
  }
  string getAuthType() const {
    return string(SH_AP_AUTH_TYPE(m_req) ? SH_AP_AUTH_TYPE(m_req) : "");
  }
  void setContentType(const char* type) {
      m_req->content_type = ap_psprintf(m_req->pool, "%s", type);
  }
  void setResponseHeader(const char* name, const char* value) {
   HTTPResponse::setResponseHeader(name, value);
#ifdef SHIB_DEFERRED_HEADERS
   if (!m_rc)
      // this happens on subrequests
      m_rc = get_request_config(m_req);
    if (m_handler) {
        if (!m_rc->hdr_out)
            m_rc->hdr_out = ap_make_table(m_req->pool, 5);
        ap_table_add(m_rc->hdr_out, name, value);
    }
    else
#endif
    ap_table_add(m_req->err_headers_out, name, value);
  }
  long sendResponse(istream& in, long status) {
    if (status != XMLTOOLING_HTTP_STATUS_OK)
        m_req->status = status;
    ap_send_http_header(m_req);
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        ap_rwrite(buf,in.gcount(),m_req);
    }
#if (defined(SHIB_APACHE_20) || defined(SHIB_APACHE_22) || defined(SHIB_APACHE_24))
    if (status != XMLTOOLING_HTTP_STATUS_OK && status != XMLTOOLING_HTTP_STATUS_ERROR)
        return status;
#endif
    return DONE;
  }
  long sendRedirect(const char* url) {
    HTTPResponse::sendRedirect(url);
    ap_table_set(m_req->headers_out, "Location", url);
    if (m_dc->bExpireRedirects != 0) {
        ap_table_set(m_req->err_headers_out, "Expires", "Wed, 01 Jan 1997 12:00:00 GMT");
        ap_table_set(m_req->err_headers_out, "Cache-Control", "private,no-store,no-cache,max-age=0");
    }
    return REDIRECT;
  }
  const vector<string>& getClientCertificates() const {
      if (m_certs.empty()) {
          const char* cert = ap_table_get(m_req->subprocess_env, "SSL_CLIENT_CERT");
          if (cert)
              m_certs.push_back(cert);
          int i = 0;
          do {
              cert = ap_table_get(m_req->subprocess_env, ap_psprintf(m_req->pool, "SSL_CLIENT_CERT_CHAIN_%d", i++));
              if (cert)
                  m_certs.push_back(cert);
          } while (cert);
      }
      return m_certs;
  }
  long returnDecline(void) { return DECLINED; }
  long returnOK(void) { return OK; }
#if defined(SHIBSP_HAVE_GSSAPI) && !defined(SHIB_APACHE_13)
  gss_ctx_id_t getGSSContext() const {
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    apr_pool_userdata_get((void**)&ctx, g_szGSSContextKey, m_req->pool);
    return ctx;
  }
  gss_name_t getGSSName() const {
      if (m_gssname == GSS_C_NO_NAME) {
          gss_ctx_id_t ctx = getGSSContext();
          if (ctx != GSS_C_NO_CONTEXT) {
              OM_uint32 minor;
              OM_uint32 major = gss_inquire_context(&minor, ctx, &m_gssname, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
              if (major != GSS_S_COMPLETE)
                  m_gssname = GSS_C_NO_NAME;
          }
      }
      return m_gssname;
  }
  #endif
};

/********************************************************************************/
// Apache hooks

#ifndef SHIB_APACHE_13
extern "C" apr_status_t shib_request_cleanup(void* rc)
{
    if (rc && reinterpret_cast<shib_request_config*>(rc)->sta) {
        delete reinterpret_cast<ShibTargetApache*>(reinterpret_cast<shib_request_config*>(rc)->sta);
        reinterpret_cast<shib_request_config*>(rc)->sta = nullptr;
    }
    return APR_SUCCESS;
}
#endif

// Initial look at a request - create the per-request structure if need be
static int shib_post_read(request_rec *r)
{
    shib_request_config* rc = get_request_config(r);
#ifdef SHIB_APACHE_24
    if (!rc->sta) {
        rc->sta = new ShibTargetApache(r);
        apr_pool_cleanup_register(r->pool, rc, shib_request_cleanup, apr_pool_cleanup_null);
    }
#endif
    return DECLINED;
}

// Performs authentication and enforce session requirements.
// Also does header/env export from session, and will dispatch
// SP handler requests if it detects a handler URL.
extern "C" int shib_check_user(request_rec* r)
{
    // Short-circuit entirely?
    if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff == 1)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user entered in pid (%d)", (int)getpid());

    string threadid("[");
    threadid += lexical_cast<string>(getpid()) + "] shib_check_user";
    xmltooling::NDC ndc(threadid.c_str());

    try {
#ifndef SHIB_APACHE_24
        ShibTargetApache sta(r);
        ShibTargetApache* psta = &sta;
#else
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        }
        ShibTargetApache* psta = rc->sta;
#endif
        if (!psta->init(false, true)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user unable to initialize SP request object");
            return SERVER_ERROR;
        }

        // Check user authentication and export information, then set the handler bypass
        pair<bool,long> res = psta->getServiceProvider().doAuthentication(*psta, true);
        apr_pool_userdata_setn((const void*)42,g_UserDataKey,nullptr,r->pool);
        // If directed, install a spoof key to recognize when we've already cleared headers.
        if (!g_spoofKey.empty() && (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bUseHeaders == 1))
            ap_table_set(r->headers_in, "Shib-Spoof-Check", g_spoofKey.c_str());
        if (res.first) {
#ifdef SHIB_APACHE_24
            // This is insane, but Apache's internal request.c logic insists that an auth module
            // returning OK MUST set r->user to avoid a failure. But they check for NULL and not
            // for an empty string. If this turns out to cause trouble, there's no solution except
            // to set a dummy ID any time it's not set.
            if (res.second == OK && !r->user)
                r->user = "";
#endif
            return res.second;
        }

        // user auth was okay -- export the session data now
        res = psta->getServiceProvider().doExport(*psta);
        if (res.first) {
#ifdef SHIB_APACHE_24
            // See above for explanation of this hack.
            if (res.second == OK && !r->user)
                r->user = "";
#endif
            return res.second;
        }

#ifdef SHIB_APACHE_24
        // See above for explanation of this hack.
        if (!r->user)
            r->user = "";
#endif
        return OK;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an exception: %s", e.what());
        return SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_check_user threw an unknown exception!");
        if (g_catchAll)
            return SERVER_ERROR;
        throw;
    }
}

// Runs SP handler requests when invoked directly.
extern "C" int shib_handler(request_rec* r)
{
    // Short-circuit entirely?
    if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib))->bOff == 1)
        return DECLINED;

    string threadid("[");
    threadid += lexical_cast<string>(getpid()) + "] shib_handler";
    xmltooling::NDC ndc(threadid.c_str());

#ifndef SHIB_APACHE_13
    // With 2.x, this handler always runs, though last.
    // We check if shib_check_user ran, because it will detect a handler request
    // and dispatch it directly.
    void* data;
    apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
    if (data==(const void*)42) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_handler skipped since check_user ran");
        return DECLINED;
    }
#endif

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_handler entered in pid (%d): %s", (int)getpid(), r->handler);

    try {
#ifndef SHIB_APACHE_24
        ShibTargetApache sta(r);
        ShibTargetApache* psta = &sta;
#else
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_handler found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        }
        ShibTargetApache* psta = rc->sta;
#endif
        if (!psta->init(true, false)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler unable to initialize SP request object");
            return SERVER_ERROR;
        }

        pair<bool,long> res = psta->getServiceProvider().doHandler(*psta);
        if (res.first) return res.second;

        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "doHandler() did not handle the request");
        return SERVER_ERROR;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an exception: %s", e.what());
        return SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_handler threw an unknown exception!");
        if (g_catchAll)
          return SERVER_ERROR;
        throw;
    }
}

// This performs authorization functions to limit access.
// On all versions, this runs any RequestMap-attached plugins.
// For pre-2.4 versions, the RequestMap will always find an htAccess plugin
// that runs code to parse and enforce Apache Require rules.
// On 2.4, we have to short-circuit that and let Apache run callbacks
// for each Require rule we handle.
extern "C" int shib_auth_checker(request_rec* r)
{
    // Short-circuit entirely?
    shib_dir_config* dc = (shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib);
    if (dc->bOff == 1
#ifdef SHIB_APACHE_24
        || dc->bRequestMapperAuthz == 0     // this allows for bypass of the full auth_checker hook if only htaccess is used
#endif
        ) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker entered in pid (%d)", (int)getpid());

    string threadid("[");
    threadid += lexical_cast<string>(getpid()) + "] shib_auth_checker";
    xmltooling::NDC ndc(threadid.c_str());

    try {
#ifndef SHIB_APACHE_24
        ShibTargetApache sta(r);
        ShibTargetApache* psta = &sta;
#else
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
        }
        ShibTargetApache* psta = rc->sta;
#endif
        if (!psta->init(false, false)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker unable to initialize SP request object");
            return SERVER_ERROR;
        }

        pair<bool,long> res = psta->getServiceProvider().doAuthorization(*psta);
        if (res.first) return res.second;

        // The SP method should always return true, so if we get this far, something unusual happened.
        // Just let Apache (or some other module) decide what to do.
        return DECLINED;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an exception: %s", e.what());
        return SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(r), "shib_auth_checker threw an unknown exception!");
        if (g_catchAll)
          return SERVER_ERROR;
        throw;
    }
}

// Overlays environment variables on top of subprocess table.
extern "C" int shib_fixups(request_rec* r)
{
    shib_dir_config *dc = (shib_dir_config*)ap_get_module_config(r->per_dir_config, &mod_shib);
    if (dc->bOff==1 || dc->bUseEnvVars==0)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_fixups entered in pid (%d)", (int)getpid());

    shib_request_config *rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
    if (rc==nullptr || rc->env==nullptr || ap_is_empty_table(rc->env))
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_fixups adding %d vars", ap_table_elts(rc->env)->nelts);
    r->subprocess_env = ap_overlay_tables(r->pool, r->subprocess_env, rc->env);

    return OK;
}


// Access control plugin that enforces pre-2.4 htaccess rules.
// Post-2.4, we have to register individual methods to respond
// to each require rule we want to handle, and have those call
// into these methods directly.
class htAccessControl : virtual public AccessControl
{
public:
    htAccessControl() {}
    ~htAccessControl() {}
    Lockable* lock() {return this;}
    void unlock() {}
    aclresult_t authorized(const SPRequest& request, const Session* session) const;

    aclresult_t doAccessControl(const ShibTargetApache& sta, const Session* session, const char* plugin) const;
    aclresult_t doUser(const ShibTargetApache& sta, const char* params) const;
#ifndef SHIB_APACHE_24
    aclresult_t doGroup(const ShibTargetApache& sta, const char* params) const;
#endif
    aclresult_t doAuthnContext(const ShibTargetApache& sta, const char* acRef, const char* params) const;
    aclresult_t doShibAttr(const ShibTargetApache& sta, const Session* session, const char* rule, const char* params) const;

private:
    bool checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, RegularExpression* re) const;
};

AccessControl* htAccessFactory(const xercesc::DOMElement* const & e)
{
    return new htAccessControl();
}

AccessControl::aclresult_t htAccessControl::doAccessControl(const ShibTargetApache& sta, const Session* session, const char* plugin) const
{
	aclresult_t result = shib_acl_false;
	try {
        ifstream aclfile(plugin);
        if (!aclfile)
            throw ConfigurationException("Unable to open access control file ($1).", params(1, plugin));
        xercesc::DOMDocument* acldoc = XMLToolingConfig::getConfig().getParser().parse(aclfile);
		XercesJanitor<xercesc::DOMDocument> docjanitor(acldoc);
		static XMLCh _type[] = UNICODE_LITERAL_4(t,y,p,e);
        string t(XMLHelper::getAttrString(acldoc ? acldoc->getDocumentElement() : nullptr, nullptr, _type));
        if (t.empty())
            throw ConfigurationException("Missing type attribute in AccessControl plugin configuration.");
        scoped_ptr<AccessControl> aclplugin(SPConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), acldoc->getDocumentElement()));
		Locker acllock(aclplugin.get());
		result = aclplugin->authorized(sta, session);
	}
	catch (std::exception& ex) {
		sta.log(SPRequest::SPError, ex.what());
	}
    return result;
}

AccessControl::aclresult_t htAccessControl::doUser(const ShibTargetApache& sta, const char* params) const
{
    bool regexp = false;
    bool negated = false;
    while (*params) {
        const char* w = ap_getword_conf(sta.m_req->pool, &params);
        if (*w == '~') {
            regexp = true;
            continue;
        }
        else if (*w == '!') {
            // A negated rule presumes success unless a match is found.
            negated = true;
            if (*(w+1) == '~')
                regexp = true;
            continue;
        }

        // Figure out if there's a match.
        bool match = false;
        if (regexp) {
            try {
                // To do regex matching, we have to convert from UTF-8.
                auto_arrayptr<XMLCh> trans(fromUTF8(w));
                RegularExpression re(trans.get());
                auto_arrayptr<XMLCh> trans2(fromUTF8(sta.getRemoteUser().c_str()));
                match = re.matches(trans2.get());
            }
            catch (XMLException& ex) {
                auto_ptr_char tmp(ex.getMessage());
                sta.log(SPRequest::SPError,
                    string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
            }
        }
        else if (sta.getRemoteUser() == w) {
            match = true;
        }

        if (match) {
            if (sta.isPriorityEnabled(SPRequest::SPDebug))
                sta.log(SPRequest::SPDebug,
                    string("htaccess: require user ") + (negated ? "rejecting (" : "accepting (") + sta.getRemoteUser() + ")");
            return (negated ? shib_acl_false : shib_acl_true);
        }
    }
    return (negated ? shib_acl_true : shib_acl_false);
}

#ifndef SHIB_APACHE_24
static SH_AP_TABLE* groups_for_user(request_rec* r, const char* user, char* grpfile)
{
    SH_AP_CONFIGFILE* f;
    SH_AP_TABLE* grps=ap_make_table(r->pool,15);
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;

#ifdef SHIB_APACHE_13
    if (!(f=ap_pcfg_openfile(r->pool, grpfile))) {
#else
    if (ap_pcfg_openfile(&f,r->pool,grpfile) != APR_SUCCESS) {
#endif
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, SH_AP_R(r), "groups_for_user: could not open group file: %s\n", grpfile);
        return nullptr;
    }

    SH_AP_POOL* sp;
#ifdef SHIB_APACHE_13
    sp=ap_make_sub_pool(r->pool);
#else
    if (apr_pool_create(&sp,r->pool) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK,APLOG_ERR,0,r,
            "groups_for_user: could not create a subpool");
        return nullptr;
    }
#endif

    while (!(ap_cfg_getline(l,MAX_STRING_LEN,f))) {
        if ((*l=='#') || (!*l))
            continue;
        ll = l;
        ap_clear_pool(sp);
        group_name = ap_getword(sp,&ll,':');
        while (*ll) {
            w=ap_getword_conf(sp,&ll);
            if (!strcmp(w,user)) {
                ap_table_setn(grps,ap_pstrdup(r->pool,group_name),"in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    ap_destroy_pool(sp);
    return grps;
}

AccessControl::aclresult_t htAccessControl::doGroup(const ShibTargetApache& sta, const char* params) const
{
    SH_AP_TABLE* grpstatus = nullptr;
    if (sta.m_dc->szAuthGrpFile) {
        if (sta.isPriorityEnabled(SPRequest::SPDebug))
            sta.log(SPRequest::SPDebug, string("htaccess plugin using groups file: ") + sta.m_dc->szAuthGrpFile);
        grpstatus = groups_for_user(sta.m_req, sta.getRemoteUser().c_str(), sta.m_dc->szAuthGrpFile);
    }

    bool negated = false;
    while (*params) {
        const char* w = ap_getword_conf(sta.m_req->pool, &params);
        if (*w == '!') {
            // A negated rule presumes success unless a match is found.
            negated = true;
            continue;
        }

        if (grpstatus && ap_table_get(grpstatus, w)) {
            // If we matched, then we're done with this rule either way and we flip status to reflect the outcome.
            sta.log(SPRequest::SPDebug, string("htaccess: require group ") + (negated ? "rejecting (" : "accepting (") + w + ")");
            return (negated ? shib_acl_false : shib_acl_true);
        }
    }

    return (negated ? shib_acl_true : shib_acl_false);
}
#endif

AccessControl::aclresult_t htAccessControl::doAuthnContext(const ShibTargetApache& sta, const char* ref, const char* params) const
{
    if (ref && *ref) {
        bool regexp = false;
        bool negated = false;
        while (ref && *params) {
            const char* w = ap_getword_conf(sta.m_req->pool, &params);
            if (*w == '~') {
                regexp = true;
                continue;
            }
            else if (*w == '!') {
                // A negated rule presumes success unless a match is found.
                negated = true;
                if (*(w+1) == '~')
                    regexp = true;
                continue;
            }

            // Figure out if there's a match.
            bool match = false;
            if (regexp) {
                try {
                    RegularExpression re(w);
                    match = re.matches(ref);
                }
                catch (XMLException& ex) {
                    auto_ptr_char tmp(ex.getMessage());
                    sta.log(SPRequest::SPError,
                        string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
                }
            }
            else if (!strcmp(w, ref)) {
                match = true;
            }

            if (match) {
                if (sta.isPriorityEnabled(SPRequest::SPDebug))
                    sta.log(SPRequest::SPDebug,
                        string("htaccess: require authnContext ") + (negated ? "rejecting (" : "accepting (") + ref + ")");
                return (negated ? shib_acl_false : shib_acl_true);
            }
        }
        return (negated ? shib_acl_true : shib_acl_false);
    }

    if (sta.isPriorityEnabled(SPRequest::SPDebug))
        sta.log(SPRequest::SPDebug, "htaccess: require authnContext rejecting session with no context associated");
    return shib_acl_false;
}

bool htAccessControl::checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, RegularExpression* re) const
{
    bool caseSensitive = attr->isCaseSensitive();
    const vector<string>& vals = attr->getSerializedValues();
    for (vector<string>::const_iterator v = vals.begin(); v != vals.end(); ++v) {
        if (re) {
            auto_arrayptr<XMLCh> trans(fromUTF8(v->c_str()));
            if (re->matches(trans.get())) {
                if (request.isPriorityEnabled(SPRequest::SPDebug))
                    request.log(SPRequest::SPDebug, string("htaccess: expecting regexp ") + toMatch + ", got " + *v + ": acccepted");
                return true;
            }
        }
        else if ((caseSensitive && *v == toMatch) || (!caseSensitive && !strcasecmp(v->c_str(), toMatch))) {
            if (request.isPriorityEnabled(SPRequest::SPDebug))
                request.log(SPRequest::SPDebug, string("htaccess: expecting ") + toMatch + ", got " + *v + ": accepted");
            return true;
        }
        else if (request.isPriorityEnabled(SPRequest::SPDebug)) {
            request.log(SPRequest::SPDebug, string("htaccess: expecting ") + toMatch + ", got " + *v + ": rejected");
        }
    }
    return false;
}

AccessControl::aclresult_t htAccessControl::doShibAttr(const ShibTargetApache& sta, const Session* session, const char* rule, const char* params) const
{
#ifndef SHIB_APACHE_24
    // Look for the new shib-attr placeholder and move past it.
    if (sta.m_dc->bCompatWith24 == 1 && rule && !strcmp(rule, "shib-attr")) {
        if (*params)
            rule = ap_getword_conf(sta.m_req->pool, &params);
    }
#endif

    // Find the attribute(s) matching the require rule.
    pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> attrs =
        session->getIndexedAttributes().equal_range(rule ? rule : "");

    bool regexp = false;
    while (attrs.first != attrs.second && *params) {
        const char* w = ap_getword_conf(sta.m_req->pool, &params);
        if (*w == '~') {
            regexp = true;
            continue;
        }

        try {
            scoped_ptr<RegularExpression> re;
            if (regexp) {
                auto_arrayptr<XMLCh> trans(fromUTF8(w));
                re.reset(new xercesc::RegularExpression(trans.get()));
            }
                    
            pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> attrs2(attrs);
            for (; attrs2.first != attrs2.second; ++attrs2.first) {
                if (checkAttribute(sta, attrs2.first->second, w, regexp ? re.get() : nullptr)) {
                    return shib_acl_true;
                }
            }
        }
        catch (XMLException& ex) {
            auto_ptr_char tmp(ex.getMessage());
            sta.log(SPRequest::SPError, string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + tmp.get());
        }
    }
    return shib_acl_false;
}

AccessControl::aclresult_t htAccessControl::authorized(const SPRequest& request, const Session* session) const
{
#ifdef SHIB_APACHE_24
    // We should never be invoked in 2.4 as an SP plugin.
    throw ConfigurationException("Save my walrus!");
#else
    // Make sure the object is our type.
    const ShibTargetApache* sta=dynamic_cast<const ShibTargetApache*>(&request);
    if (!sta)
        throw ConfigurationException("Request wrapper object was not of correct type.");

    int m = sta->m_req->method_number;
    bool method_restricted = false;
    const char *t, *w;

    const array_header* reqs_arr = ap_requires(sta->m_req);
    if (!reqs_arr)
        return shib_acl_indeterminate;  // should never happen

	// Check for an "embedded" AccessControl plugin.
	if (sta->m_dc->szAccessControl) {
        aclresult_t result = doAccessControl(*sta, session, sta->m_dc->szAccessControl);
        if (result == shib_acl_true && sta->m_dc->bRequireAll != 1) {
            // If we're not insisting that all rules be met, then we're done.
            request.log(SPRequest::SPDebug, "htaccess: embedded AccessControl plugin was successful, granting access");
            return shib_acl_true;
        }
        else if (result != shib_acl_true && sta->m_dc->bRequireAll == 1) {
            // If we're insisting that all rules be met, which is not something Apache really handles well,
            // then we either return false or indeterminate based on the authoritative option, which defaults on.
            if (sta->m_dc->bAuthoritative != 0) {
                request.log(SPRequest::SPDebug, "htaccess: embedded AccessControl plugin was unsuccessful, denying access");
                return shib_acl_false;
            }

            request.log(SPRequest::SPDebug, "htaccess: embedded AccessControl plugin was unsuccessful but not authoritative, leaving it up to Apache");
            return shib_acl_indeterminate;
        }
    }

    require_line* reqs = (require_line*)reqs_arr->elts;

    for (int x = 0; x < reqs_arr->nelts; ++x) {
        // This rule should be completely ignored, the method doesn't fit.
        // The rule just doesn't exist for our purposes.
        if (!(reqs[x].method_mask & (1 << m)))
            continue;

        method_restricted = true; // this lets us know at the end that at least one rule was potentially enforcable.

        // Tracks status of this rule's evaluation.
        bool status = false;

        string remote_user = request.getRemoteUser();

        t = reqs[x].requirement;
        w = ap_getword_white(sta->m_req->pool, &t);

        if (!strcasecmp(w,"shibboleth")) {
            // This is a dummy rule needed because Apache conflates authn and authz.
            // Without some require rule, AuthType is ignored and no check_user hooks run.

            // We evaluate to false if ShibAccessControl is used and ShibRequireAll is off.
            // This allows actual rules to dictate the result, since ShibAccessControl returned
            // non-true, and if nothing else is used, access will be denied.
            if (!sta->m_dc->szAccessControl || sta->m_dc->bRequireAll == 1) {
                // We evaluate to true, because ShibRequireAll is enabled (so a true is just a no-op)
                // or because there was no other AccessControl rule in place, so this may be the only
                // rule in effect.
                status = true;
            }
        }
        else if (!strcmp(w,"valid-user") && session) {
            request.log(SPRequest::SPDebug, "htaccess: accepting valid-user based on active session");
            status = true;
        }
        else if (sta->m_dc->bCompatWith24 == 1 && !strcmp(w,"shib-session") && session) {
            request.log(SPRequest::SPDebug, "htaccess: accepting shib-session based on active session");
            status = true;
        }
        else if (!strcmp(w,"user") && !remote_user.empty()) {
            status = (doUser(*sta, t) == shib_acl_true);
        }
        else if (sta->m_dc->bCompatWith24 == 1 && !strcmp(w,"shib-user") && !remote_user.empty()) {
            status = (doUser(*sta, t) == shib_acl_true);
        }
        else if (!strcmp(w,"group")  && !remote_user.empty()) {
            status = (doGroup(*sta, t) == shib_acl_true);
        }
        else if (!strcmp(w,"authnContextClassRef") || !strcmp(w,"authnContextDeclRef")) {
            const char* ref = !strcmp(w, "authnContextClassRef") ? session->getAuthnContextClassRef() : session->getAuthnContextDeclRef();
            status = (doAuthnContext(*sta, ref, t) == shib_acl_true);
        }
        else if (!session) {
            request.log(SPRequest::SPError, string("htaccess: require ") + w + " not given a valid session, are you using lazy sessions?");
        }
        else if (sta->m_dc->bCompatWith24 == 1 && !strcmp(w,"shib-plugin")) {
            w = ap_getword_conf(sta->m_req->pool, &t);
            if (w) {
                status = (doAccessControl(*sta, session, w) == shib_acl_true);
            }
        }
        else {
            status = (doShibAttr(*sta, session, w, t) == shib_acl_true);
        }

        // If status is false, we found a rule we couldn't satisfy.
        // Could be an unknown rule to us, or it just didn't match.

        if (status && sta->m_dc->bRequireAll != 1) {
            // If we're not insisting that all rules be met, then we're done.
            request.log(SPRequest::SPDebug, "htaccess: a rule was successful, granting access");
            return shib_acl_true;
        }
        else if (!status && sta->m_dc->bRequireAll == 1) {
            // If we're insisting that all rules be met, which is not something Apache really handles well,
            // then we either return false or indeterminate based on the authoritative option, which defaults on.
            if (sta->m_dc->bAuthoritative != 0) {
                request.log(SPRequest::SPDebug, "htaccess: a rule was unsuccessful, denying access");
                return shib_acl_false;
            }

            request.log(SPRequest::SPDebug, "htaccess: a rule was unsuccessful but not authoritative, leaving it up to Apache");
            return shib_acl_indeterminate;
        }

        // Otherwise, we keep going. If we're requring all, then we have to check every rule.
        // If not we just didn't find a successful rule yet, so we keep going anyway.
    }

    // If we get here, we either "failed" or we're in require all mode (but not both).
    // If no rules possibly apply or we insisted that all rules check out, then we're good.
    if (!method_restricted) {
        request.log(SPRequest::SPDebug, "htaccess: no rules applied to this request method, granting access");
        return shib_acl_true;
    }
    else if (sta->m_dc->bRequireAll == 1) {
        request.log(SPRequest::SPDebug, "htaccess: all rules successful, granting access");
        return shib_acl_true;
    }
    else if (sta->m_dc->bAuthoritative != 0) {
        request.log(SPRequest::SPDebug, "htaccess: no rules were successful, denying access");
        return shib_acl_false;
    }

    request.log(SPRequest::SPDebug, "htaccess: no rules were successful but not authoritative, leaving it up to Apache");
    return shib_acl_indeterminate;
#endif
}

class ApacheRequestMapper : public virtual RequestMapper, public virtual PropertySet
{
public:
    ApacheRequestMapper(const xercesc::DOMElement* e);
    ~ApacheRequestMapper() {}
    Lockable* lock() { return m_mapper->lock(); }
    void unlock() { m_staKey->setData(nullptr); m_propsKey->setData(nullptr); m_mapper->unlock(); }
    Settings getSettings(const HTTPRequest& request) const;

    const PropertySet* getParent() const { return nullptr; }
    void setParent(const PropertySet*) {}
    pair<bool,bool> getBool(const char* name, const char* ns=nullptr) const;
    pair<bool,const char*> getString(const char* name, const char* ns=nullptr) const;
    pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=nullptr) const;
    pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=nullptr) const;
    pair<bool,int> getInt(const char* name, const char* ns=nullptr) const;
    void getAll(map<string,const char*>& properties) const;
    const PropertySet* getPropertySet(const char* name, const char* ns=shibspconstants::ASCII_SHIB2SPCONFIG_NS) const;
    const xercesc::DOMElement* getElement() const;

    const htAccessControl& getHTAccessControl() const { return m_htaccess; }

private:
    scoped_ptr<RequestMapper> m_mapper;
    scoped_ptr<ThreadKey> m_staKey,m_propsKey;
    mutable htAccessControl m_htaccess;
};

RequestMapper* ApacheRequestMapFactory(const xercesc::DOMElement* const & e)
{
    return new ApacheRequestMapper(e);
}

ApacheRequestMapper::ApacheRequestMapper(const xercesc::DOMElement* e)
    : m_mapper(SPConfig::getConfig().RequestMapperManager.newPlugin(XML_REQUEST_MAPPER,e)),
        m_staKey(ThreadKey::create(nullptr)), m_propsKey(ThreadKey::create(nullptr))
{
}

RequestMapper::Settings ApacheRequestMapper::getSettings(const HTTPRequest& request) const
{
    Settings s = m_mapper->getSettings(request);
    m_staKey->setData((void*)dynamic_cast<const ShibTargetApache*>(&request));
    m_propsKey->setData((void*)s.first);
    // Only return the htAccess plugin for pre-2.4 servers.
#ifdef SHIB_APACHE_24
    return pair<const PropertySet*,AccessControl*>(this, s.second);
#else
    return pair<const PropertySet*,AccessControl*>(this, s.second ? s.second : &m_htaccess);
#endif
}

pair<bool,bool> ApacheRequestMapper::getBool(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable boolean properties.
        if (name && !strcmp(name,"requireSession") && sta->m_dc->bRequireSession != -1)
            return make_pair(true, sta->m_dc->bRequireSession==1);
        else if (name && !strcmp(name,"exportAssertion") && sta->m_dc->bExportAssertion != -1)
            return make_pair(true, sta->m_dc->bExportAssertion==1);
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, !strcmp(prop, "true") || !strcmp(prop, "1") || !strcmp(prop, "On"));
        }
    }
    return s ? s->getBool(name,ns) : make_pair(false,false);
}

pair<bool,const char*> ApacheRequestMapper::getString(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable string properties.
        if (name && !strcmp(name,"authType")) {
            const char* auth_type = ap_auth_type(sta->m_req);
            if (auth_type) {
                // Check for Basic Hijack
                if (!strcasecmp(auth_type, "basic") && sta->m_dc->bBasicHijack == 1)
                    auth_type = "shibboleth";
                return make_pair(true, auth_type);
            }
        }
        else if (name && !strcmp(name,"applicationId") && sta->m_dc->szApplicationId)
            return pair<bool,const char*>(true,sta->m_dc->szApplicationId);
        else if (name && !strcmp(name,"requireSessionWith") && sta->m_dc->szRequireWith)
            return pair<bool,const char*>(true,sta->m_dc->szRequireWith);
        else if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,const char*>(true,sta->m_dc->szRedirectToSSL);
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, prop);
        }
    }
    return s ? s->getString(name,ns) : pair<bool,const char*>(false,nullptr);
}

pair<bool,const XMLCh*> ApacheRequestMapper::getXMLString(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getXMLString(name,ns) : pair<bool,const XMLCh*>(false,nullptr);
}

pair<bool,unsigned int> ApacheRequestMapper::getUnsignedInt(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,unsigned int>(true, strtol(sta->m_dc->szRedirectToSSL, nullptr, 10));
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return pair<bool,unsigned int>(true, atoi(prop));
        }
    }
    return s ? s->getUnsignedInt(name,ns) : pair<bool,unsigned int>(false,0);
}

pair<bool,int> ApacheRequestMapper::getInt(const char* name, const char* ns) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    if (sta && !ns) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && sta->m_dc->szRedirectToSSL)
            return pair<bool,int>(true,atoi(sta->m_dc->szRedirectToSSL));
        else if (sta->m_dc->tSettings) {
            const char* prop = ap_table_get(sta->m_dc->tSettings, name);
            if (prop)
                return make_pair(true, atoi(prop));
        }
    }
    return s ? s->getInt(name,ns) : pair<bool,int>(false,0);
}

static int _rm_get_all_table_walk(void *v, const char *key, const char *value)
{
    reinterpret_cast<map<string,const char*>*>(v)->insert(pair<string,const char*>(key, value));
    return 1;
}

void ApacheRequestMapper::getAll(map<string,const char*>& properties) const
{
    const ShibTargetApache* sta=reinterpret_cast<const ShibTargetApache*>(m_staKey->getData());
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());

    if (s)
        s->getAll(properties);
    if (!sta)
        return;

    const char* auth_type=ap_auth_type(sta->m_req);
    if (auth_type) {
        // Check for Basic Hijack
        if (!strcasecmp(auth_type, "basic") && sta->m_dc->bBasicHijack == 1)
            auth_type = "shibboleth";
        properties["authType"] = auth_type;
    }

    if (sta->m_dc->szApplicationId)
        properties["applicationId"] = sta->m_dc->szApplicationId;
    if (sta->m_dc->szRequireWith)
        properties["requireSessionWith"] = sta->m_dc->szRequireWith;
    if (sta->m_dc->szRedirectToSSL)
        properties["redirectToSSL"] = sta->m_dc->szRedirectToSSL;
    if (sta->m_dc->bRequireSession != 0)
        properties["requireSession"] = (sta->m_dc->bRequireSession==1) ? "true" : "false";
    if (sta->m_dc->bExportAssertion != 0)
        properties["exportAssertion"] = (sta->m_dc->bExportAssertion==1) ? "true" : "false";

    if (sta->m_dc->tSettings)
        ap_table_do(_rm_get_all_table_walk, &properties, sta->m_dc->tSettings, NULL);
}

const PropertySet* ApacheRequestMapper::getPropertySet(const char* name, const char* ns) const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getPropertySet(name,ns) : nullptr;
}

const xercesc::DOMElement* ApacheRequestMapper::getElement() const
{
    const PropertySet* s=reinterpret_cast<const PropertySet*>(m_propsKey->getData());
    return s ? s->getElement() : nullptr;
}

// Authz callbacks for Apache 2.4
// For some reason, these get run twice for each request, once before hooks like check_user, etc.
// and once after. The first time through, the request object exists, but isn't initialized.
// The other case is subrequests of some kinds: then post_read doesn't run, and the objects
// themselves don't exist. We do deferred creation of the objects in check_user to fix that case.
// In each screwed up case, we return "denied" so that nothing bad happens.
#ifdef SHIB_APACHE_24
pair<ShibTargetApache*,authz_status> shib_base_check_authz(request_rec* r)
{
    shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &mod_shib);
    if (!rc || !rc->sta) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_base_check_authz found no per-request structure");
        return make_pair((ShibTargetApache*)nullptr, AUTHZ_DENIED_NO_USER);
    }
    else if (!rc->sta->isInitialized()) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "shib_base_check_authz found uninitialized request object");
        return make_pair((ShibTargetApache*)nullptr, AUTHZ_DENIED_NO_USER);
    }
    return make_pair(rc->sta, AUTHZ_GRANTED);
}

extern "C" authz_status shib_shibboleth_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;
    return AUTHZ_GRANTED;
}

extern "C" authz_status shib_session_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    try {
        Session* session = sta.first->getSession(false, true, false);
        Locker slocker(session, false);
        if (session) {
            sta.first->log(SPRequest::SPDebug, "htaccess: accepting shib-session/valid-user based on active session");
            return AUTHZ_GRANTED;
        }
    }
    catch (std::exception& e) {
        sta.first->log(SPRequest::SPWarn, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    sta.first->log(SPRequest::SPDebug, "htaccess: denying shib-access/valid-user rule, no active session");
    return AUTHZ_DENIED_NO_USER;
}

extern "C" authz_status shib_validuser_check_authz(request_rec* r, const char* require_line, const void*)
{
    // Shouldn't have actually ever hooked this, and now we're in conflict with mod_authz_user over the meaning.
    // For now, added a command to restore "normal" semantics for valid-user so that combined deployments can
    // use valid-user for non-Shibboleth cases and shib-session for the Shibboleth semantic.

    // In future, we may want to expose the AuthType set to honor down at this level so we can differentiate
    // based on AuthType. Unfortunately we allow overriding the AuthType to honor and we don't have access to
    // that setting from the ServiceProvider class..

    shib_server_config* sc = (shib_server_config*)ap_get_module_config(r->server->module_config, &mod_shib);
    if (sc->bCompatValidUser != 1) {
        return shib_session_check_authz(r, require_line, nullptr);
    }

    // Reproduce mod_authz_user version...

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }

    return AUTHZ_GRANTED;
}

extern "C" authz_status shib_ext_user_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    const htAccessControl& hta = dynamic_cast<const ApacheRequestMapper*>(sta.first->getRequestSettings().first)->getHTAccessControl();
    if (hta.doUser(*sta.first, require_line) == AccessControl::shib_acl_true)
        return AUTHZ_GRANTED;
    return AUTHZ_DENIED;
}

extern "C" authz_status shib_user_check_authz(request_rec* r, const char* require_line, const void*)
{
    // Shouldn't have actually ever hooked this, and now we're in conflict with mod_authz_user over the meaning.
    // For now, added a command to restore "normal" semantics for user rules so that combined deployments can
    // use user for non-Shibboleth cases and shib-user for the Shibboleth semantic.

    // In future, we may want to expose the AuthType set to honor down at this level so we can differentiate
    // based on AuthType. Unfortunately we allow overriding the AuthType to honor and we don't have access to
    // that setting from the ServiceProvider class..

    shib_server_config* sc = (shib_server_config*)ap_get_module_config(r->server->module_config, &mod_shib);
    if (sc->bCompatValidUser != 1) {
        return shib_ext_user_check_authz(r, require_line, nullptr);
    }

    // Reproduce mod_authz_user version...

    if (!r->user) {
        return AUTHZ_DENIED_NO_USER;
    }
 	
    const char* t = require_line;
    const char *w;
    while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {
        if (!strcmp(r->user, w)) {
            return AUTHZ_GRANTED;
        }
    }
 	
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01663)
        "access to %s failed, reason: user '%s' does not meet "
        "'require'ments for user to be allowed access",
        r->uri, r->user);
 	
    return AUTHZ_DENIED;
}

extern "C" authz_status shib_acclass_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    const htAccessControl& hta = dynamic_cast<const ApacheRequestMapper*>(sta.first->getRequestSettings().first)->getHTAccessControl();

    try {
        Session* session = sta.first->getSession(false, true, false);
        Locker slocker(session, false);
        if (session && hta.doAuthnContext(*sta.first, session->getAuthnContextClassRef(), require_line) == AccessControl::shib_acl_true)
            return AUTHZ_GRANTED;
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(SPRequest::SPWarn, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    return AUTHZ_GENERAL_ERROR;
}

extern "C" authz_status shib_acdecl_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    const htAccessControl& hta = dynamic_cast<const ApacheRequestMapper*>(sta.first->getRequestSettings().first)->getHTAccessControl();

    try {
        Session* session = sta.first->getSession(false, true, false);
        Locker slocker(session, false);
        if (session && hta.doAuthnContext(*sta.first, session->getAuthnContextDeclRef(), require_line) == AccessControl::shib_acl_true)
            return AUTHZ_GRANTED;
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(SPRequest::SPWarn, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    return AUTHZ_GENERAL_ERROR;
}

extern "C" authz_status shib_attr_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    const htAccessControl& hta = dynamic_cast<const ApacheRequestMapper*>(sta.first->getRequestSettings().first)->getHTAccessControl();

    try {
        Session* session = sta.first->getSession(false, true, false);
        Locker slocker(session, false);
        if (session) {
            const char* rule = ap_getword_conf(r->pool, &require_line);
            if (rule && hta.doShibAttr(*sta.first, session, rule, require_line) == AccessControl::shib_acl_true)
                return AUTHZ_GRANTED;
        }
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(SPRequest::SPWarn, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    return AUTHZ_GENERAL_ERROR;
}

extern "C" authz_status shib_plugin_check_authz(request_rec* r, const char* require_line, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    const htAccessControl& hta = dynamic_cast<const ApacheRequestMapper*>(sta.first->getRequestSettings().first)->getHTAccessControl();

    try {
        Session* session = sta.first->getSession(false, true, false);
        Locker slocker(session, false);
        if (session) {
            const char* config = ap_getword_conf(r->pool, &require_line);
            if (config && hta.doAccessControl(*sta.first, session, config) == AccessControl::shib_acl_true)
                return AUTHZ_GRANTED;
        }
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(SPRequest::SPWarn, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    return AUTHZ_GENERAL_ERROR;
}
#endif

// Command manipulation functions

extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=ap_pstrdup(parms->pool,arg);
    return nullptr;
}

extern "C" const char* shib_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&mod_shib);
    size_t offset=(size_t)parms->info;
    *((char**)(base + offset))=ap_pstrdup(parms->pool,arg);
    return nullptr;
}

extern "C" const char* shib_set_server_flag_slot(cmd_parms* parms, void*, int arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&mod_shib);
    size_t offset=(size_t)parms->info;
    *((int*)(base + offset)) = arg;
    return nullptr;
}

extern "C" const char* shib_ap_set_file_slot(cmd_parms* parms,
#ifdef SHIB_APACHE_13
					     char* arg1, char* arg2
#else
					     void* arg1, const char* arg2
#endif
					     )
{
  ap_set_file_slot(parms, arg1, arg2);
  return DECLINE_CMD;
}

extern "C" const char* shib_table_set(cmd_parms* parms, shib_dir_config* dc, const char* arg1, const char* arg2)
{
    if (!dc->tSettings)
        dc->tSettings = ap_make_table(parms->pool, 4);
    ap_table_set(dc->tSettings, arg1, arg2);
    return nullptr;
}

#ifndef SHIB_APACHE_24
extern "C" const char* shib_set_acl_slot(cmd_parms* params, shib_dir_config* dc, char* arg)
{
    bool absolute;
    switch (*arg) {
        case 0:
            absolute = false;
            break;
        case '/':
        case '\\':
            absolute = true;
            break;
        case '.':
            absolute = (*(arg+1) == '.' || *(arg+1) == '/' || *(arg+1) == '\\');
            break;
        default:
            absolute = *(arg+1) == ':';
    }

    if (absolute || !params->path)
        dc->szAccessControl = ap_pstrdup(params->pool, arg);
    else
        dc->szAccessControl = ap_pstrcat(params->pool, params->path, arg, NULL);
    return nullptr;
}
#endif


#ifdef SHIB_APACHE_13
/*
 * shib_child_exit()
 *  Cleanup the (per-process) pool info.
 */
extern "C" void shib_child_exit(server_rec* s, SH_AP_POOL* p)
{
    if (g_Config) {
        g_Config->term();
        g_Config = nullptr;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(s), "child_exit: mod_shib shutdown in pid (%d)", (int)getpid());
}
#else
/*
 * shib_exit()
 *  Apache 2.x doesn't allow for per-child cleanup, causes CGI forks to hang.
 */
extern "C" apr_status_t shib_exit(void* data)
{
    if (g_Config) {
        g_Config->term();
        g_Config = nullptr;
    }
    server_rec* s = reinterpret_cast<server_rec*>(data);
    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(s), "shib_exit: mod_shib shutdown in pid (%d)", (int)getpid());
    return OK;
}

/*
 * shib_post_config()
 *  We do the library init/term work here for 2.x to reduce overhead and
 *  get default logging established before the fork happens.
 */
apr_status_t shib_post_config(apr_pool_t* p, apr_pool_t*, apr_pool_t*, server_rec* s)
{
    // Initialize runtime components.
    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(s),"post_config: mod_shib initializing in pid (%d)", (int)getpid());

    if (g_Config) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(s), "post_config: mod_shib already initialized");
        return !OK;
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
    if (!g_Config->init(g_szSchemaDir, g_szPrefix)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, SH_AP_R(s), "post_config: mod_shib failed to initialize libraries");
        return !OK;
    }
#ifndef SHIB_APACHE_24
    g_Config->AccessControlManager.registerFactory(HT_ACCESS_CONTROL, &htAccessFactory);
#endif
    g_Config->RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, &ApacheRequestMapFactory);

    // Set the cleanup handler, passing in the server_rec for logging.
    apr_pool_cleanup_register(p, s, &shib_exit, apr_pool_cleanup_null);

    return OK;
}

#endif

/*
 * shib_child_init()
 *  Things to do when the child process is initialized.
 *  We can't use post-config for all of it on 2.x because only the forking thread shows
 *  up in the child, losing the internal threads spun up by plugins in the SP.
 */
#ifdef SHIB_APACHE_13
extern "C" void shib_child_init(server_rec* s, SH_AP_POOL* p)
#else
extern "C" void shib_child_init(apr_pool_t* p, server_rec* s)
#endif
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, SH_AP_R(s),"child_init: mod_shib initializing in pid (%d)", (int)getpid());

    // 2.x versions have already initialized the libraries.
#ifdef SHIB_APACHE_13
    if (g_Config) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, SH_AP_R(s), "child_init: mod_shib already initialized, exiting");
        exit(1);
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
    if (!g_Config->init(g_szSchemaDir, g_szPrefix)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, SH_AP_R(s), "child_init: mod_shib failed to initialize libraries");
        exit(1);
    }
    g_Config->AccessControlManager.registerFactory(HT_ACCESS_CONTROL, &htAccessFactory);
    g_Config->RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, &ApacheRequestMapFactory);
#endif

    // The config gets installed for all versions here due to the background thread/fork issues.
    try {
        if (!g_Config->instantiate(g_szSHIBConfig, true))
            throw runtime_error("unknown error");
    }
    catch (std::exception& ex) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, SH_AP_R(s), "child_init: mod_shib failed to load configuration: %s", ex.what());
        g_Config->term();
        exit(1);
    }

    ServiceProvider* sp = g_Config->getServiceProvider();
    xmltooling::Locker locker(sp);
    const PropertySet* props = sp->getPropertySet("InProcess");
    if (props) {
        pair<bool,const char*> unsetValue = props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        pair<bool,bool> flag=props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        if (g_checkSpoofing) {
            unsetValue=props->getString("spoofKey");
            if (unsetValue.first)
                g_spoofKey = unsetValue.second;
        }
        flag=props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;
    }

    // Set the cleanup handler, passing in the server_rec for logging.
    apr_pool_cleanup_register(p, s, &shib_exit, apr_pool_cleanup_null);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(s), "child_init: mod_shib config initialized");
}

// Output filters
#ifdef SHIB_DEFERRED_HEADERS
static void set_output_filter(request_rec *r)
{
   ap_add_output_filter("SHIB_HEADERS_OUT", nullptr, r, r->connection);
}

static void set_error_filter(request_rec *r)
{
   ap_add_output_filter("SHIB_HEADERS_ERR", nullptr, r, r->connection);
}

static int _table_add(void *v, const char *key, const char *value)
{
    apr_table_addn((apr_table_t*)v, key, value);
    return 1;
}

static apr_status_t do_output_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &mod_shib);

    if (rc && rc->hdr_out) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "output_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
        // can't use overlap call because it will collapse Set-Cookie headers
        //apr_table_overlap(r->headers_out, rc->hdr_out, APR_OVERLAP_TABLES_MERGE);
        apr_table_do(_table_add,r->headers_out, rc->hdr_out,NULL);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

static apr_status_t do_error_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &mod_shib);

    if (rc && rc->hdr_out) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, SH_AP_R(r), "error_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
        // can't use overlap call because it will collapse Set-Cookie headers
        //apr_table_overlap(r->err_headers_out, rc->hdr_out, APR_OVERLAP_TABLES_MERGE);
        apr_table_do(_table_add,r->err_headers_out, rc->hdr_out,NULL);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}
#endif // SHIB_DEFERRED_HEADERS

typedef const char* (*config_fn_t)(void);

#ifdef SHIB_APACHE_13

// SHIB Module commands

static command_rec shire_cmds[] = {
  {"ShibPrefix", (config_fn_t)ap_set_global_string_slot, &g_szPrefix,
   RSRC_CONF, TAKE1, "Shibboleth installation directory"},
  {"ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
   RSRC_CONF, TAKE1, "Path to shibboleth2.xml config file"},
  {"ShibCatalogs", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
   RSRC_CONF, TAKE1, "Paths of XML schema catalogs"},

  {"ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
   (void *) XtOffsetOf (shib_server_config, szScheme),
   RSRC_CONF, TAKE1, "URL scheme to force into generated URLs for a vhost"},

  {"ShibRequestSetting", (config_fn_t)shib_table_set, nullptr,
   OR_AUTHCFG, TAKE2, "Set arbitrary Shibboleth request property for content"},

  {"ShibAccessControl", (config_fn_t)shib_set_acl_slot, nullptr,
   OR_AUTHCFG, TAKE1, "Set arbitrary Shibboleth access control plugin for content"},

  {"ShibDisable", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bOff),
   OR_AUTHCFG, FLAG, "Disable all Shib module activity here to save processing effort"},
  {"ShibApplicationId", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szApplicationId),
   OR_AUTHCFG, TAKE1, "Set Shibboleth applicationId property for content"},
  {"ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bBasicHijack),
   OR_AUTHCFG, FLAG, "(DEPRECATED) Respond to AuthType Basic and convert to shibboleth"},
  {"ShibRequireSession", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireSession),
   OR_AUTHCFG, FLAG, "Initiates a new session if one does not exist"},
  {"ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szRequireWith),
   OR_AUTHCFG, TAKE1, "Initiates a new session if one does not exist using a specific SessionInitiator"},
  {"ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExportAssertion),
   OR_AUTHCFG, FLAG, "Export SAML attribute assertion(s) to Shib-Attributes header"},
  {"ShibRedirectToSSL", (config_fn_t)ap_set_string_slot,
   (void *) XtOffsetOf (shib_dir_config, szRedirectToSSL),
   OR_AUTHCFG, TAKE1, "Redirect non-SSL requests to designated port" },
  {"AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
   (void *) XtOffsetOf (shib_dir_config, szAuthGrpFile),
   OR_AUTHCFG, TAKE1, "text file containing group names and member user IDs"},
  {"ShibRequireAll", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bRequireAll),
   OR_AUTHCFG, FLAG, "All require directives must match"},
  {"AuthzShibAuthoritative", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bAuthoritative),
   OR_AUTHCFG, FLAG, "Allow failed mod_shib htaccess authorization to fall through to other modules"},
  {"ShibCompatWith24", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bCompatWith24),
   OR_AUTHCFG, FLAG, "Support Apache 2.4-style require rules"},
  {"ShibUseEnvironment", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bUseEnvVars),
   OR_AUTHCFG, FLAG, "Export attributes using environment variables (default)"},
  {"ShibUseHeaders", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bUseHeaders),
   OR_AUTHCFG, FLAG, "Export attributes using custom HTTP headers"},
  {"ShibExpireRedirects", (config_fn_t)ap_set_flag_slot,
   (void *) XtOffsetOf (shib_dir_config, bExpireRedirects),
   OR_AUTHCFG, FLAG, "Expire SP-generated redirects"},

  {nullptr}
};

extern "C"{
handler_rec shib_handlers[] = {
  { "shib-handler", shib_handler },
  { nullptr }
};

module MODULE_VAR_EXPORT mod_shib = {
    STANDARD_MODULE_STUFF,
    nullptr,                        /* initializer */
    create_shib_dir_config,	/* dir config creater */
    merge_shib_dir_config,	/* dir merger --- default is to override */
    create_shib_server_config, /* server config */
    merge_shib_server_config,   /* merge server config */
    shire_cmds,			/* command table */
    shib_handlers,		/* handlers */
    nullptr,			/* filename translation */
    shib_check_user,		/* check_user_id */
    shib_auth_checker,		/* check auth */
    nullptr,			/* check access */
    nullptr,			/* type_checker */
    shib_fixups,		/* fixups */
    nullptr,			/* logger */
    nullptr,			/* header parser */
    shib_child_init,		/* child_init */
    shib_child_exit,		/* child_exit */
    shib_post_read		/* post read-request */
};

#else

#ifdef SHIB_APACHE_24
extern "C" const authz_provider shib_authz_shibboleth_provider = { &shib_shibboleth_check_authz, nullptr };
extern "C" const authz_provider shib_authz_validuser_provider = { &shib_validuser_check_authz, nullptr };
extern "C" const authz_provider shib_authz_session_provider = { &shib_session_check_authz, nullptr };
extern "C" const authz_provider shib_authz_user_provider = { &shib_user_check_authz, nullptr };
extern "C" const authz_provider shib_authz_ext_user_provider = { &shib_ext_user_check_authz, nullptr };
extern "C" const authz_provider shib_authz_acclass_provider = { &shib_acclass_check_authz, nullptr };
extern "C" const authz_provider shib_authz_acdecl_provider = { &shib_acdecl_check_authz, nullptr };
extern "C" const authz_provider shib_authz_attr_provider = { &shib_attr_check_authz, nullptr };
extern "C" const authz_provider shib_authz_plugin_provider = { &shib_plugin_check_authz, nullptr };
#endif

extern "C" void shib_register_hooks (apr_pool_t *p)
{
#ifdef SHIB_DEFERRED_HEADERS
    ap_register_output_filter("SHIB_HEADERS_OUT", do_output_filter, nullptr, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_filter(set_output_filter, nullptr, nullptr, APR_HOOK_LAST);
    ap_register_output_filter("SHIB_HEADERS_ERR", do_error_filter, nullptr, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_error_filter(set_error_filter, nullptr, nullptr, APR_HOOK_LAST);
    ap_hook_post_read_request(shib_post_read, nullptr, nullptr, APR_HOOK_MIDDLE);
#endif
    ap_hook_post_config(shib_post_config, nullptr, nullptr, APR_HOOK_MIDDLE);
    ap_hook_child_init(shib_child_init, nullptr, nullptr, APR_HOOK_MIDDLE);
    const char* prereq = getenv("SHIBSP_APACHE_PREREQ");
#ifdef SHIB_APACHE_24
    if (prereq && *prereq) {
        const char* const authnPre[] = { prereq, nullptr };
        ap_hook_check_authn(shib_check_user, authnPre, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
    }
    else {
        ap_hook_check_authn(shib_check_user, nullptr, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
    }
    ap_hook_check_authz(shib_auth_checker, nullptr, nullptr, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
#else
    if (prereq && *prereq) {
        const char* const authnPre[] = { prereq, nullptr };
        ap_hook_check_user_id(shib_check_user, authnPre, nullptr, APR_HOOK_MIDDLE);
    }
    else {
        ap_hook_check_user_id(shib_check_user, nullptr, nullptr, APR_HOOK_MIDDLE);
    }
    ap_hook_auth_checker(shib_auth_checker, nullptr, nullptr, APR_HOOK_FIRST);
#endif
    ap_hook_handler(shib_handler, nullptr, nullptr, APR_HOOK_LAST);
    ap_hook_fixups(shib_fixups, nullptr, nullptr, APR_HOOK_MIDDLE);

#ifdef SHIB_APACHE_24
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shibboleth", AUTHZ_PROVIDER_VERSION, &shib_authz_shibboleth_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-user", AUTHZ_PROVIDER_VERSION, &shib_authz_validuser_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-session", AUTHZ_PROVIDER_VERSION, &shib_authz_session_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user", AUTHZ_PROVIDER_VERSION, &shib_authz_user_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-user", AUTHZ_PROVIDER_VERSION, &shib_authz_ext_user_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "authnContextClassRef", AUTHZ_PROVIDER_VERSION, &shib_authz_acclass_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "authnContextDeclRef", AUTHZ_PROVIDER_VERSION, &shib_authz_acdecl_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-attr", AUTHZ_PROVIDER_VERSION, &shib_authz_attr_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-plugin", AUTHZ_PROVIDER_VERSION, &shib_authz_plugin_provider, AP_AUTH_INTERNAL_PER_CONF);
#endif
}

// SHIB Module commands

extern "C" {
static command_rec shib_cmds[] = {
    AP_INIT_TAKE1("ShibPrefix", (config_fn_t)ap_set_global_string_slot, &g_szPrefix,
        RSRC_CONF, "Shibboleth installation directory"),
    AP_INIT_TAKE1("ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
        RSRC_CONF, "Path to shibboleth2.xml config file"),
    AP_INIT_TAKE1("ShibCatalogs", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
        RSRC_CONF, "Paths of XML schema catalogs"),
    AP_INIT_TAKE1("ShibGSSKey", (config_fn_t)ap_set_global_string_slot, &g_szGSSContextKey,
        RSRC_CONF, "Name of user data key containing GSS context established by GSS module"),

    AP_INIT_TAKE1("ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
        (void *) offsetof (shib_server_config, szScheme),
        RSRC_CONF, "URL scheme to force into generated URLs for a vhost"),

    AP_INIT_TAKE2("ShibRequestSetting", (config_fn_t)shib_table_set, nullptr,
        OR_AUTHCFG, "Set arbitrary Shibboleth request property for content"),

    AP_INIT_FLAG("ShibDisable", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bOff),
        OR_AUTHCFG, "Disable all Shib module activity here to save processing effort"),
    AP_INIT_TAKE1("ShibApplicationId", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szApplicationId),
        OR_AUTHCFG, "Set Shibboleth applicationId property for content"),
    AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bBasicHijack),
        OR_AUTHCFG, "(DEPRECATED) Respond to AuthType Basic and convert to shibboleth"),
    AP_INIT_FLAG("ShibRequireSession", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequireSession),
        OR_AUTHCFG, "Initiates a new session if one does not exist"),
    AP_INIT_TAKE1("ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRequireWith),
        OR_AUTHCFG, "Initiates a new session if one does not exist using a specific SessionInitiator"),
    AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bExportAssertion),
        OR_AUTHCFG, "Export SAML attribute assertion(s) to Shib-Attributes header"),
    AP_INIT_TAKE1("ShibRedirectToSSL", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRedirectToSSL),
        OR_AUTHCFG, "Redirect non-SSL requests to designated port"),
#ifdef SHIB_APACHE_24
    AP_INIT_FLAG("ShibRequestMapperAuthz", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequestMapperAuthz),
        OR_AUTHCFG, "Support access control via shibboleth2.xml / RequestMapper"),
    AP_INIT_FLAG("ShibCompatValidUser", (config_fn_t)shib_set_server_flag_slot,
        (void *) offsetof (shib_server_config, bCompatValidUser),
        RSRC_CONF, "Handle 'require valid-user' in mod_authz_user-compatible fashion (requiring username)"),
#else
    AP_INIT_TAKE1("AuthGroupFile", (config_fn_t)shib_ap_set_file_slot,
        (void *) offsetof (shib_dir_config, szAuthGrpFile),
        OR_AUTHCFG, "Text file containing group names and member user IDs"),
    AP_INIT_TAKE1("ShibAccessControl", (config_fn_t)shib_set_acl_slot, nullptr,
        OR_AUTHCFG, "Set arbitrary Shibboleth access control plugin for content"),
    AP_INIT_FLAG("ShibRequireAll", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequireAll),
        OR_AUTHCFG, "All require directives must match"),
    AP_INIT_FLAG("AuthzShibAuthoritative", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bAuthoritative),
        OR_AUTHCFG, "Allow failed mod_shib htaccess authorization to fall through to other modules"),
    AP_INIT_FLAG("ShibCompatWith24", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bCompatWith24),
        OR_AUTHCFG, "Support Apache 2.4-style require rules"),
#endif
    AP_INIT_FLAG("ShibUseEnvironment", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bUseEnvVars),
        OR_AUTHCFG, "Export attributes using environment variables (default)"),
    AP_INIT_FLAG("ShibUseHeaders", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bUseHeaders),
        OR_AUTHCFG, "Export attributes using custom HTTP headers"),
    AP_INIT_FLAG("ShibExpireRedirects", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bExpireRedirects),
        OR_AUTHCFG, "Expire SP-generated redirects"),

    {nullptr}
};

module AP_MODULE_DECLARE_DATA mod_shib = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,     /* create dir config */
    merge_shib_dir_config,      /* merge dir config --- default is to override */
    create_shib_server_config,  /* create server config */
    merge_shib_server_config,   /* merge server config */
    shib_cmds,                  /* command table */
    shib_register_hooks         /* register hooks */
};

#endif

}
