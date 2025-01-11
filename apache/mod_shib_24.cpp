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
 * shib_module.cpp
 *
 * Apache module implementation.
 */

#define SHIBSP_LITE

#ifdef SOLARIS2
# undef _XOPEN_SOURCE    // causes gethostname conflict in unistd.h
#endif

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/exceptions.h>
#include <shibsp/AbstractSPRequest.h>
#include <shibsp/AccessControl.h>
#include <shibsp/Agent.h>
#include <shibsp/AgentConfig.h>
#include <shibsp/RequestMapper.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/session/SessionCache.h>
#include <shibsp/util/Lockable.h>

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#undef _XPG4_2

#include <set>
#include <memory>
#include <fstream>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif
#include <stdexcept>
#include <boost/property_tree/xml_parser.hpp>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex.hpp>
namespace regexp = boost;
#else
# include <regex>
namespace regexp = std;
#endif
// Apache specific header files
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_main.h>
#define CORE_PRIVATE
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>

#include <apr_buckets.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <mod_auth.h>

#include <cstddef>
#ifdef HAVE_UNISTD_H
#include <unistd.h>        // for getpid()
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

extern "C" module AP_MODULE_DECLARE_DATA shib_module;
static int* const aplog_module_index = &(shib_module.module_index);

namespace {
    char* g_szSHIBConfig = nullptr;
    char* g_szSchemaDir = nullptr;
    char* g_szPrefix = nullptr;
    AgentConfig* g_Config = nullptr;
    string g_unsetHeaderValue,g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
    static const char* g_UserDataKey = "urn:mace:shibboleth:Apache:shib_check_user";
}

/* Apache 2.4 headers must be accumulated and set in the output filter. */
#define SHIB_DEFERRED_HEADERS

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
extern "C" void* create_shib_server_config(apr_pool_t* p, server_rec*)
{
    shib_server_config* sc=(shib_server_config*)apr_pcalloc(p,sizeof(shib_server_config));
    sc->szScheme = nullptr;
    sc->bCompatValidUser = -1;
    return sc;
}

// overrides server configuration in virtual servers
extern "C" void* merge_shib_server_config (apr_pool_t* p, void* base, void* sub)
{
    shib_server_config* sc=(shib_server_config*)apr_pcalloc(p,sizeof(shib_server_config));
    shib_server_config* parent=(shib_server_config*)base;
    shib_server_config* child=(shib_server_config*)sub;

    if (child->szScheme)
        sc->szScheme=apr_pstrdup(p,child->szScheme);
    else if (parent->szScheme)
        sc->szScheme=apr_pstrdup(p,parent->szScheme);
    else
        sc->szScheme=nullptr;

    sc->bCompatValidUser = ((child->bCompatValidUser==-1) ? parent->bCompatValidUser : child->bCompatValidUser);

    return sc;
}

// per-dir module configuration structure
struct shib_dir_config
{
    apr_table_t* tSettings; // generic table of extensible settings
    apr_table_t* tUnsettings; // generic table of settings to "unset", i.e. default and block inheritance

    // RM Configuration
    int bRequestMapperAuthz;// support RequestMapper AccessControl plugins

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
extern "C" void* create_shib_dir_config (apr_pool_t* p, char*)
{
    shib_dir_config* dc=(shib_dir_config*)apr_pcalloc(p,sizeof(shib_dir_config));
    dc->tSettings = nullptr;
    dc->tUnsettings = nullptr;
    dc->bRequestMapperAuthz = -1;
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
extern "C" void* merge_shib_dir_config (apr_pool_t* p, void* base, void* sub)
{
    shib_dir_config* dc=(shib_dir_config*)apr_pcalloc(p,sizeof(shib_dir_config));
    shib_dir_config* parent=(shib_dir_config*)base;
    shib_dir_config* child=(shib_dir_config*)sub;

    // The child supersedes any matching table settings in the parent,
    // and only parent settings not "unset" by the child are copied in.
    dc->tSettings = nullptr;
    if (parent->tSettings) {
        if (child->tUnsettings) {
            const apr_array_header_t* thdr = apr_table_elts(parent->tSettings);
            const apr_table_entry_t* tent = (const apr_table_entry_t*)thdr->elts;
            for (int i = 0; i < thdr->nelts; ++i) {
                if (!apr_table_get(child->tUnsettings, tent[i].key)) {
                    if (!dc->tSettings)
                        dc->tSettings = apr_table_make(p, thdr->nelts);
                    apr_table_set(dc->tSettings, tent[i].key, tent[i].val);
                }
            }
        }
        else {
            dc->tSettings = apr_table_copy(p, parent->tSettings);
        }
    }
    if (child->tSettings) {
        if (dc->tSettings)
            apr_table_overlap(dc->tSettings, child->tSettings, APR_OVERLAP_TABLES_SET);
        else
            dc->tSettings = apr_table_copy(p, child->tSettings);
    }

    // Unsetting is weird. We don't need to carry forward either the parent's
    // or child's table for our own use because its only relevance is to block
    // inheritance of the parent's settings during this specific merge. If another
    // child is merged in, then *its* unset table will be applied to that merge, and
    // so forth. So the merged result contains no explicit unsetters. Weird.
    // EXCEPT: we need to merge and track all the unsets done as a group in order
    // to block inheritance from the RequestMap, which is the "parent" for all
    // settings.
    dc->tUnsettings = nullptr;
    if (parent->tUnsettings)
        dc->tUnsettings = apr_table_copy(p, parent->tUnsettings);
    if (child->tUnsettings) {
        if (dc->tUnsettings)
            apr_table_overlap(dc->tUnsettings, child->tUnsettings, APR_OVERLAP_TABLES_SET);
        else
            dc->tUnsettings = apr_table_copy(p, child->tUnsettings);
    }

    dc->bRequestMapperAuthz = ((child->bRequestMapperAuthz==-1) ? parent->bRequestMapperAuthz : child->bRequestMapperAuthz);

    if (child->szApplicationId)
        dc->szApplicationId=apr_pstrdup(p,child->szApplicationId);
    else if (parent->szApplicationId && (!child->tUnsettings || !apr_table_get(child->tUnsettings, "applicationId")))
        dc->szApplicationId=apr_pstrdup(p,parent->szApplicationId);
    else
        dc->szApplicationId=nullptr;

    if (child->szRequireWith)
        dc->szRequireWith=apr_pstrdup(p,child->szRequireWith);
    else if (parent->szRequireWith && (!child->tUnsettings || !apr_table_get(child->tUnsettings, "requireSessionWith")))
        dc->szRequireWith=apr_pstrdup(p,parent->szRequireWith);
    else
        dc->szRequireWith=nullptr;

    if (child->szRedirectToSSL)
        dc->szRedirectToSSL=apr_pstrdup(p,child->szRedirectToSSL);
    else if (parent->szRedirectToSSL && (!child->tUnsettings || !apr_table_get(child->tUnsettings, "redirectToSSL")))
        dc->szRedirectToSSL=apr_pstrdup(p,parent->szRedirectToSSL);
    else
        dc->szRedirectToSSL=nullptr;

    if (child->bRequireSession != -1)
        dc->bRequireSession = child->bRequireSession;
    else if (parent->bRequireSession != -1 && (!child->tUnsettings || !apr_table_get(child->tUnsettings, "requireSession")))
        dc->bRequireSession = parent->bRequireSession;
    else
        dc->bRequireSession = -1;

    if (child->bExportAssertion != -1)
        dc->bExportAssertion = child->bExportAssertion;
    else if (parent->bExportAssertion != -1 && (!child->tUnsettings || !apr_table_get(child->tUnsettings, "exportAssertion")))
        dc->bExportAssertion = parent->bExportAssertion;
    else
        dc->bExportAssertion = -1;

    dc->bOff = ((child->bOff == -1) ? parent->bOff : child->bOff);
    dc->bBasicHijack = ((child->bBasicHijack == -1) ? parent->bBasicHijack : child->bBasicHijack);
    dc->bUseEnvVars = ((child->bUseEnvVars==-1) ? parent->bUseEnvVars : child->bUseEnvVars);
    dc->bUseHeaders = ((child->bUseHeaders==-1) ? parent->bUseHeaders : child->bUseHeaders);
    dc->bExpireRedirects = ((child->bExpireRedirects==-1) ? parent->bExpireRedirects : child->bExpireRedirects);
    return dc;
}

class ShibTargetApache; // forward decl

// per-request module structure
struct shib_request_config
{
    apr_table_t* env;        // environment vars
#ifdef SHIB_DEFERRED_HEADERS
    apr_table_t* hdr_out;    // headers to browser
#endif
    ShibTargetApache* sta;  // SP per-request structure wrapped around Apache's request
};

// create or return a request record
static shib_request_config* get_request_config(request_rec *r)
{
    shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
    if (rc) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "get_request_config called redundantly");
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "get_request_config created per-request structure");
        rc = (shib_request_config*)apr_pcalloc(r->pool,sizeof(shib_request_config));
        memset(rc, 0, sizeof(shib_request_config));
        ap_set_module_config(r->request_config, &shib_module, rc);
    }
    return rc;
}

class ShibTargetApache : public AbstractSPRequest
{
  mutable string m_body;
  mutable bool m_gotBody,m_firsttime;
  set<string> m_allhttp;

public:
  bool m_handler;
  request_rec* m_req;
  shib_dir_config* m_dc;
  shib_server_config* m_sc;
  shib_request_config* m_rc;

  ShibTargetApache(request_rec* req) : AbstractSPRequest(SHIBSP_LOGCAT ".Apache"),
        m_gotBody(false),m_firsttime(true),
        m_handler(false), m_req(req), m_dc(nullptr), m_sc(nullptr), m_rc(nullptr) {
  }
  virtual ~ShibTargetApache() {
  }

  bool isInitialized() const {
      return (m_sc != nullptr);
  }

  bool init(bool handler, bool check_user) {
    m_handler = handler;
    if (m_sc)
        return !check_user; // only initialize once
    m_sc = (shib_server_config*)ap_get_module_config(m_req->server->module_config, &shib_module);
    m_dc = (shib_dir_config*)ap_get_module_config(m_req->per_dir_config, &shib_module);
    m_rc = (shib_request_config*)ap_get_module_config(m_req->request_config, &shib_module);

    setRequestURI(m_req->unparsed_uri);

    if (check_user && m_dc->bUseHeaders == 1) {
        // Try and see if this request was already processed, to skip spoof checking.
        if (!ap_is_initial_req(m_req)) {
            m_firsttime = false;
        }
        else if (!g_spoofKey.empty()) {
            const char* hdr = apr_table_get(m_req->headers_in, "Shib-Spoof-Check");
            if (hdr && g_spoofKey == hdr)
                m_firsttime = false;
        }
        if (!m_firsttime)
            log(Priority::SHIB_DEBUG, "shib_check_user running more than once");
    }
    return true;
  }

  const char* getScheme() const {
    return m_sc->szScheme ? m_sc->szScheme : ap_http_scheme(m_req);
  }
  bool isSecure() const {
      return HTTPRequest::isSecure();
  }
  const char* getHostname() const {
      return ap_get_server_name_for_url(m_req);
  }
  int getPort() const {
    return ap_get_server_port(m_req);
  }
  const char* getMethod() const {
    return m_req->method;
  }
  string getContentType() const {
    const char* type = apr_table_get(m_req->headers_in, "Content-Type");
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
    return m_req->useragent_ip;
  }
  void log(Priority::Value level, const string& msg) const {
    AbstractSPRequest::log(level,msg);
    ap_log_rerror(
        APLOG_MARK,
        (level == Priority::SHIB_DEBUG ? APLOG_DEBUG :
        (level == Priority::SHIB_INFO ? APLOG_INFO :
        (level == Priority::SHIB_WARN ? APLOG_WARNING :
        (level == Priority::SHIB_ERROR ? APLOG_ERR : APLOG_CRIT))))|APLOG_NOERRNO,
        0, m_req,
        "%s",
        msg.c_str()
        );
  }
  const char* getQueryString() const { return m_req->args; }
  const char* getRequestBody() const {
    if (m_gotBody || m_req->method_number==M_GET)
        return m_body.c_str();

    const char *data;
    apr_size_t len;
    int seen_eos = 0;
    apr_bucket_brigade* bb = apr_brigade_create(m_req->pool, m_req->connection->bucket_alloc);
    do {
        apr_bucket *bucket;
        apr_status_t rv = ap_get_brigade(m_req->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            log(Priority::SHIB_ERROR, "Apache function (ap_get_brigade) failed while reading request body.");
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
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0, m_req, "shib_clear_header: hdr\n");
        if (g_checkSpoofing && m_firsttime) {
            if (m_allhttp.empty()) {
                // First time, so populate set with "CGI" versions of client-supplied headers.
                const apr_array_header_t *hdrs_arr = apr_table_elts(m_req->headers_in);
                const apr_table_entry_t *hdrs = (const apr_table_entry_t *) hdrs_arr->elts;
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
                throw SessionException(string("Attempt to spoof header ") + rawname + " was detected.");
        }
        apr_table_unset(m_req->headers_in, rawname);
        apr_table_set(m_req->headers_in, rawname, g_unsetHeaderValue.c_str());
    }
  }
  void setHeader(const char* name, const char* value) {
    if (m_dc->bUseEnvVars != 0) {
       if (!m_rc) {
          // this happens on subrequests
          // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0, m_req, "shib_setheader: no_m_rc\n");
          m_rc = get_request_config(m_req);
       }
       if (!m_rc->env)
           m_rc->env = apr_table_make(m_req->pool, 10);
       // ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO,0, m_req, "shib_set_env: %s=%s\n", name, value?value:"Null");
       apr_table_set(m_rc->env, name, value ? value : "");
    }
    if (m_dc->bUseHeaders == 1)
       apr_table_set(m_req->headers_in, name, value);
  }
  string getHeader(const char* name) const {
    const char* hdr = apr_table_get(m_req->headers_in, name);
    return string(hdr ? hdr : "");
  }
  string getSecureHeader(const char* name) const {
    if (m_dc->bUseEnvVars != 0) {
       const char *hdr;
       if (m_rc && m_rc->env)
           hdr = apr_table_get(m_rc->env, name);
       else
           hdr = nullptr;
       return string(hdr ? hdr : "");
    }
    return getHeader(name);
  }
  void setRemoteUser(const char* user) {
      m_req->user = user ? apr_pstrdup(m_req->pool, user) : nullptr;
      if (m_dc->bUseHeaders == 1) {
          if (user) {
              apr_table_set(m_req->headers_in, "REMOTE_USER", user);
          }
          else {
              apr_table_unset(m_req->headers_in, "REMOTE_USER");
              apr_table_set(m_req->headers_in, "REMOTE_USER", g_unsetHeaderValue.c_str());
          }
      }
  }
  string getRemoteUser() const {
    return string(m_req->user ? m_req->user : "");
  }
  void setAuthType(const char* authtype) {
      if (authtype && m_dc->bBasicHijack == 1)
          authtype = "Basic";
      m_req->ap_auth_type = authtype ? apr_pstrdup(m_req->pool, authtype) : nullptr;
  }
  string getAuthType() const {
    return string(m_req->ap_auth_type ? m_req->ap_auth_type : "");
  }
  void setContentType(const char* type) {
      m_req->content_type = apr_psprintf(m_req->pool, "%s", type);
  }
  void setResponseHeader(const char* name, const char* value, bool replace=false) {
    HTTPResponse::setResponseHeader(name, value, replace);
    if (name && *name) {
#ifdef SHIB_DEFERRED_HEADERS
        if (!m_rc) {
            // this happens on subrequests
            m_rc = get_request_config(m_req);
        }
        if (m_handler) {
            if (!m_rc->hdr_out) {
                m_rc->hdr_out = apr_table_make(m_req->pool, 5);
            }
            if (replace || !value)
                apr_table_unset(m_rc->hdr_out, name);
            if (value && *value)
                apr_table_add(m_rc->hdr_out, name, value);
        }
        else {
            if (replace || !value)
                apr_table_unset(m_req->err_headers_out, name);
            if (value && *value)
                apr_table_add(m_req->err_headers_out, name, value);
        }
#else
        if (replace || !value)
            apr_table_unset(m_req->err_headers_out, name);
        if (value && *value)
            apr_table_add(m_req->err_headers_out, name, value);
#endif
    }
  }
  long sendResponse(istream& in, long status) {
    if (status != SHIBSP_HTTP_STATUS_OK)
        m_req->status = status;
    char buf[1024];
    while (in) {
        in.read(buf,1024);
        ap_rwrite(buf,in.gcount(),m_req);
    }
    if (status != SHIBSP_HTTP_STATUS_OK && status != SHIBSP_HTTP_STATUS_ERROR)
        return status;
    return DONE;
  }
  long sendRedirect(const char* url) {
    HTTPResponse::sendRedirect(url);
    apr_table_set(m_req->headers_out, "Location", url);
    if (m_dc->bExpireRedirects != 0) {
        apr_table_set(m_req->err_headers_out, "Expires", "Wed, 01 Jan 1997 12:00:00 GMT");
        apr_table_set(m_req->err_headers_out, "Cache-Control", "private,no-store,no-cache,max-age=0");
    }
    return HTTP_MOVED_TEMPORARILY;
  }
  long returnDecline(void) { return DECLINED; }
  long returnOK(void) { return OK; }
};

/********************************************************************************/
// Apache hooks

extern "C" apr_status_t shib_request_cleanup(void* rc)
{
    if (rc && reinterpret_cast<shib_request_config*>(rc)->sta) {
        delete reinterpret_cast<ShibTargetApache*>(reinterpret_cast<shib_request_config*>(rc)->sta);
        reinterpret_cast<shib_request_config*>(rc)->sta = nullptr;
    }
    return APR_SUCCESS;
}

// Initial look at a request - create the per-request structure if need be
static int shib_post_read(request_rec *r)
{
    shib_request_config* rc = get_request_config(r);
    if (!rc->sta) {
        rc->sta = new ShibTargetApache(r);
        apr_pool_cleanup_register(r->pool, rc, shib_request_cleanup, apr_pool_cleanup_null);
    }
    return DECLINED;
}

// Performs authentication and enforce session requirements.
// Also does header/env export from session, and will dispatch
// SP handler requests if it detects a handler URL.
extern "C" int shib_check_user(request_rec* r)
{
    static char _emptystr[] = "";

    // Short-circuit entirely?
    if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &shib_module))->bOff == 1)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_check_user entered in pid (%d)", (int)getpid());

    try {
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, "shib_check_user found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        }

        ShibTargetApache* psta = rc->sta;
        if (!psta->init(false, true)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_check_user unable to initialize SP request object");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        // Check user authentication and export information, then set the handler bypass
        pair<bool,long> res = psta->getAgent().doAuthentication(*psta, true);
        apr_pool_userdata_setn((const void*)42,g_UserDataKey,nullptr,r->pool);
        // If directed, install a spoof key to recognize when we've already cleared headers.
        if (!g_spoofKey.empty() && (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &shib_module))->bUseHeaders == 1))
            apr_table_set(r->headers_in, "Shib-Spoof-Check", g_spoofKey.c_str());
        if (res.first) {
            // This is insane, but Apache's internal request.c logic insists that an auth module
            // returning OK MUST set r->user to avoid a failure. But they check for NULL and not
            // for an empty string. If this turns out to cause trouble, there's no solution except
            // to set a dummy ID any time it's not set.
            if (res.second == OK && !r->user)
                r->user = _emptystr;
            return res.second;
        }

        // user auth was okay -- export the session data now
        res = psta->getAgent().doExport(*psta);
        if (res.first) {
            // See above for explanation of this hack.
            if (res.second == OK && !r->user)
                r->user = _emptystr;
            return res.second;
        }

        // See above for explanation of this hack.
        if (!r->user)
            r->user = _emptystr;
        return OK;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_check_user threw an exception: %s", e.what());
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_check_user threw an unknown exception!");
        if (g_catchAll)
            return HTTP_INTERNAL_SERVER_ERROR;
        throw;
    }
}

// Runs SP handler requests when invoked directly.
extern "C" int shib_handler(request_rec* r)
{
    // Short-circuit entirely?
    if (((shib_dir_config*)ap_get_module_config(r->per_dir_config, &shib_module))->bOff == 1)
        return DECLINED;

    // With 2.x, this handler always runs, though last.
    // We check if shib_check_user ran, because it will detect a handler request
    // and dispatch it directly.
    void* data;
    apr_pool_userdata_get(&data,g_UserDataKey,r->pool);
    if (data==(const void*)42) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_handler skipped since check_user ran");
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_handler entered in pid (%d): %s", (int)getpid(), r->handler);

    try {
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_handler found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        }

        ShibTargetApache* psta = rc->sta;
        if (!psta->init(true, false)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_handler unable to initialize SP request object");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        pair<bool,long> res = psta->getAgent().doHandler(*psta);
        if (res.first) return res.second;

        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "doHandler() did not handle the request");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_handler threw an exception: %s", e.what());
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_handler threw an unknown exception!");
        if (g_catchAll)
          return HTTP_INTERNAL_SERVER_ERROR;
        throw;
    }
}

// This performs authorization functions to limit access.
// On all versions, this runs any RequestMap-attached plugins.
// On 2.4+, we also let Apache run callbacks for each Require rule we handle.
extern "C" int shib_auth_checker(request_rec* r)
{
    // Short-circuit entirely?
    shib_dir_config* dc = (shib_dir_config*)ap_get_module_config(r->per_dir_config, &shib_module);
    if (dc->bOff == 1
        || dc->bRequestMapperAuthz == 0     // this allows for bypass of the full auth_checker hook if only htaccess is used
        ) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_auth_checker entered in pid (%d)", (int)getpid());

    try {
        shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        if (!rc || !rc->sta) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, "shib_auth_checker found no per-request structure");
            shib_post_read(r);  // ensures objects are created if post_read hook didn't run
            rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
        }

        ShibTargetApache* psta = rc->sta;
        if (!psta->init(false, false)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_auth_checker unable to initialize SP request object");
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        pair<bool,long> res = psta->getAgent().doAuthorization(*psta);
        if (res.first) return res.second;

        // The SP method should always return true, so if we get this far, something unusual happened.
        // Just let Apache (or some other module) decide what to do.
        return DECLINED;
    }
    catch (std::exception& e) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_auth_checker threw an exception: %s", e.what());
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    catch (...) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, "shib_auth_checker threw an unknown exception!");
        if (g_catchAll)
          return HTTP_INTERNAL_SERVER_ERROR;
        throw;
    }
}

// Overlays environment variables on top of subprocess table.
extern "C" int shib_fixups(request_rec* r)
{
    shib_dir_config *dc = (shib_dir_config*)ap_get_module_config(r->per_dir_config, &shib_module);
    if (dc->bOff==1 || dc->bUseEnvVars==0)
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_fixups entered in pid (%d)", (int)getpid());

    shib_request_config *rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
    if (rc==nullptr || rc->env==nullptr || apr_is_empty_table(rc->env))
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_fixups adding %d vars", apr_table_elts(rc->env)->nelts);
    r->subprocess_env = apr_table_overlay(r->pool, r->subprocess_env, rc->env);

    return OK;
}


// Access control plugin that used to enforce pre-2.4 htaccess rules.
// With 2.4+, we have to register individual methods to respond
// to each require rule we want to handle, and have those call
// into these methods directly.
class htAccessControl : virtual public AccessControl, public NoOpSharedLockable
{
public:
    htAccessControl() {}
    ~htAccessControl() {}
    aclresult_t authorized(const SPRequest& request, const Session* session) const;

    aclresult_t doAccessControl(const ShibTargetApache& sta, const Session* session, const char* plugin) const;
    aclresult_t doUser(const ShibTargetApache& sta, const char* params) const;
    aclresult_t doAuthnContext(const ShibTargetApache& sta, const char* acRef, const char* params) const;
    aclresult_t doShibAttr(const ShibTargetApache& sta, const Session* session, const char* rule, const char* params) const;

private:
    bool checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, bool isRegex=false) const;
};

AccessControl* htAccessFactory(const ptree&, bool)
{
    return new htAccessControl();
}

AccessControl::aclresult_t htAccessControl::doAccessControl(const ShibTargetApache& sta, const Session* session, const char* plugin) const
{
    aclresult_t result = shib_acl_false;
    try {
        ptree pt;
        xml_parser::read_xml(plugin, pt, xml_parser::no_comments|xml_parser::trim_whitespace);
        if (pt.size() != 1)
            throw ConfigurationException("AccessControl plugin configuration did not contain the expected XML document.");
        ptree& pt_root = pt.front().second;
        string t = pt_root.get("<xmlattr>.type", "");
        if (t.empty())
            throw ConfigurationException("Missing type attribute in AccessControl plugin configuration.");
        unique_ptr<AccessControl> aclplugin(AgentConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), pt_root, true));
#ifdef HAVE_CXX14
        shared_lock<AccessControl> acllock(*aclplugin);
#endif
        result = aclplugin->authorized(sta, session);
    }
    catch (const xml_parser_error& e) {
        sta.log(Priority::SHIB_ERROR, e.what());
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
                // TODO: support regex options?
                regexp::regex re(w, regexp::regex_constants::extended);
                match = regexp::regex_match(sta.getRemoteUser(), re, regexp::regex_constants::match_any | regexp::regex_constants::match_not_null);
            }
            catch (const regexp::regex_error& e) {
                sta.log(Priority::SHIB_ERROR,
                    string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + e.what());
            }
        }
        else if (sta.getRemoteUser() == w) {
            match = true;
        }

        if (match) {
            if (sta.isPriorityEnabled(Priority::SHIB_DEBUG))
                sta.log(Priority::SHIB_DEBUG,
                    string("htaccess: require user ") + (negated ? "rejecting (" : "accepting (") + sta.getRemoteUser() + ")");
            return (negated ? shib_acl_false : shib_acl_true);
        }
    }
    return (negated ? shib_acl_true : shib_acl_false);
}

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
                    regexp::regex re(w, regexp::regex_constants::extended);
                    match = regexp::regex_match(ref, re, regexp::regex_constants::match_any | regexp::regex_constants::match_not_null);
                }
                catch (const regexp::regex_error& e) {
                    sta.log(Priority::SHIB_ERROR,
                        string("htaccess plugin caught exception while parsing regular expression (") + w + "): " + e.what());
                }
            }
            else if (!strcmp(w, ref)) {
                match = true;
            }

            if (match) {
                if (sta.isPriorityEnabled(Priority::SHIB_DEBUG))
                    sta.log(Priority::SHIB_DEBUG,
                        string("htaccess: require authnContext ") + (negated ? "rejecting (" : "accepting (") + ref + ")");
                return (negated ? shib_acl_false : shib_acl_true);
            }
        }
        return (negated ? shib_acl_true : shib_acl_false);
    }

    if (sta.isPriorityEnabled(Priority::SHIB_DEBUG))
        sta.log(Priority::SHIB_DEBUG, "htaccess: require authnContext rejecting session with no context associated");
    return shib_acl_false;
}

bool htAccessControl::checkAttribute(const SPRequest& request, const Attribute* attr, const char* toMatch, bool isRegex) const
{
    bool caseSensitive = attr->isCaseSensitive();
    const vector<string>& vals = attr->getSerializedValues();
    for (vector<string>::const_iterator v = vals.begin(); v != vals.end(); ++v) {
        if (isRegex) {
            regexp::regex_constants::syntax_option_type flags = regexp::regex_constants::extended;
            if (!caseSensitive) {
                flags |= regexp::regex_constants::icase;
            }
            try {
                regexp::regex exp(toMatch, flags);
                if (regexp::regex_match(*v, exp, regexp::regex_constants::match_any | regexp::regex_constants::match_not_null)) {
                    if (request.isPriorityEnabled(Priority::SHIB_DEBUG))
                        request.log(Priority::SHIB_DEBUG, string("htaccess: expecting regexp ") + toMatch + ", got " + *v + ": accepted");
                    return true;
                }
            } catch (const regexp::regex_error& e) {
                request.log(Priority::SHIB_ERROR,
                    string("htaccess plugin caught exception while parsing regular expression (") + toMatch + "): " + e.what());
            }
        }
        else if ((caseSensitive && *v == toMatch) || (!caseSensitive && !strcasecmp(v->c_str(), toMatch))) {
            if (request.isPriorityEnabled(Priority::SHIB_DEBUG))
                request.log(Priority::SHIB_DEBUG, string("htaccess: expecting ") + toMatch + ", got " + *v + ": accepted");
            return true;
        }
        else if (request.isPriorityEnabled(Priority::SHIB_DEBUG)) {
            request.log(Priority::SHIB_DEBUG, string("htaccess: expecting ") + toMatch + ", got " + *v + ": rejected");
        }
    }
    return false;
}

AccessControl::aclresult_t htAccessControl::doShibAttr(
    const ShibTargetApache& sta, const Session* session, const char* rule, const char* params
    ) const
{
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

        pair<multimap<string,const Attribute*>::const_iterator,multimap<string,const Attribute*>::const_iterator> attrs2(attrs);
        for (; attrs2.first != attrs2.second; ++attrs2.first) {
            if (checkAttribute(sta, attrs2.first->second, w, regexp)) {
                return shib_acl_true;
            }
        }
    }
    return shib_acl_false;
}

AccessControl::aclresult_t htAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    // We should never be invoked in 2.4+ as an SP plugin.
    throw ConfigurationException("Save my walrus!");
}

class ApacheRequestMapper : public virtual RequestMapper, public virtual PropertySet
{
public:
    ApacheRequestMapper(ptree& pt, bool deprecationSupport=true);
    ~ApacheRequestMapper() {}
    void lock_shared() { m_mapper->lock_shared(); }
    bool try_lock_shared() { return m_mapper->try_lock_shared(); }
    void unlock_shared() { m_sta = nullptr; m_props = nullptr; m_mapper->unlock_shared(); }
    Settings getSettings(const HTTPRequest& request) const;

    bool hasProperty(const char* name) const;
    bool getBool(const char* name, bool defaultValue) const;
    const char* getString(const char* name, const char* defaultValue=nullptr) const;
    unsigned int getUnsignedInt(const char* name, unsigned int defaultValue) const;
    int getInt(const char* name, int defaultValue) const;

    const htAccessControl& getHTAccessControl() const { return m_htaccess; }

private:
    unique_ptr<RequestMapper> m_mapper;
     thread_local const ShibTargetApache* m_sta;
    thread_local const PropertySet* m_props;
    mutable htAccessControl m_htaccess;
};

RequestMapper* ApacheRequestMapFactory(ptree& pt, bool deprecationSupport)
{
    return new ApacheRequestMapper(pt, deprecationSupport);
}

ApacheRequestMapper::ApacheRequestMapper(ptree& pt, bool deprecationSupport)
    : m_mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(XML_REQUEST_MAPPER, pt, deprecationSupport))
{
}

RequestMapper::Settings ApacheRequestMapper::getSettings(const HTTPRequest& request) const
{
    Settings s = m_mapper->getSettings(request);
    m_sta = dynamic_cast<const ShibTargetApache*>(&request);
    m_props = s.first;
    return make_pair(this, s.second);
}

bool ApacheRequestMapper::hasProperty(const char* name) const
{
    if (m_sta) {
        // TODO, will need to enumerate all the built-in properties I imagine.
    }

    return m_props && (!m_sta->m_dc->tUnsettings || !apr_table_get(m_sta->m_dc->tUnsettings, name))
        ? m_props->hasProperty(name) : false;
}

bool ApacheRequestMapper::getBool(const char* name, bool defaultValue) const
{
    if (m_sta) {
        // Override Apache-settable boolean properties.
        if (name && !strcmp(name,"requireSession") && m_sta->m_dc->bRequireSession != -1)
            return m_sta->m_dc->bRequireSession == 1;
        else if (name && !strcmp(name,"exportAssertion") && m_sta->m_dc->bExportAssertion != -1)
            return m_sta->m_dc->bExportAssertion == 1;
        else if (m_sta->m_dc->tSettings) {
            const char* prop = apr_table_get(m_sta->m_dc->tSettings, name);
            if (prop)
                return !strcmp(prop, "true") || !strcmp(prop, "1") || !strcmp(prop, "On");
        }
    }
    return m_props && (!m_sta->m_dc->tUnsettings || !apr_table_get(m_sta->m_dc->tUnsettings, name))
        ? m_props->getBool(name, defaultValue) : defaultValue;
}

const char* ApacheRequestMapper::getString(const char* name, const char* defaultValue) const
{
    if (m_sta) {
        // Override Apache-settable string properties.
        if (name && !strcmp(name,"authType")) {
            const char* auth_type = ap_auth_type(m_sta->m_req);
            if (auth_type) {
                // Check for Basic Hijack
                if (!strcasecmp(auth_type, "basic") && m_sta->m_dc->bBasicHijack == 1)
                    auth_type = "shibboleth";
                return auth_type;
            }
        }
        else if (name && !strcmp(name,"applicationId") && m_sta->m_dc->szApplicationId)
            return m_sta->m_dc->szApplicationId;
        else if (name && !strcmp(name,"requireSessionWith") && m_sta->m_dc->szRequireWith)
            return m_sta->m_dc->szRequireWith;
        else if (name && !strcmp(name,"redirectToSSL") && m_sta->m_dc->szRedirectToSSL)
            return m_sta->m_dc->szRedirectToSSL;
        else if (m_sta->m_dc->tSettings) {
            const char* prop = apr_table_get(m_sta->m_dc->tSettings, name);
            if (prop)
                return prop;
        }
    }
    return m_props && (!m_sta->m_dc->tUnsettings || !apr_table_get(m_sta->m_dc->tUnsettings, name))
        ? m_props->getString(name, defaultValue) : defaultValue;
}

unsigned int ApacheRequestMapper::getUnsignedInt(const char* name, unsigned int defaultValue) const
{
    if (m_sta) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && m_sta->m_dc->szRedirectToSSL)
            return atoi(m_sta->m_dc->szRedirectToSSL);
        else if (m_sta->m_dc->tSettings) {
            const char* prop = apr_table_get(m_sta->m_dc->tSettings, name);
            if (prop)
                return atoi(prop);
        }
    }
    return m_props && (!m_sta->m_dc->tUnsettings || !apr_table_get(m_sta->m_dc->tUnsettings, name))
        ? m_props->getUnsignedInt(name, defaultValue) : defaultValue;
}

int ApacheRequestMapper::getInt(const char* name, int defaultValue) const
{
    if (m_sta) {
        // Override Apache-settable int properties.
        if (name && !strcmp(name,"redirectToSSL") && m_sta->m_dc->szRedirectToSSL)
            return atoi(m_sta->m_dc->szRedirectToSSL);
        else if (m_sta->m_dc->tSettings) {
            const char* prop = apr_table_get(m_sta->m_dc->tSettings, name);
            if (prop)
                return atoi(prop);
        }
    }
    return m_props && (!m_sta->m_dc->tUnsettings || !apr_table_get(m_sta->m_dc->tUnsettings, name))
        ? m_props->getInt(name, defaultValue) : defaultValue;
}

// Authz callbacks for Apache 2.4
// For some reason, these get run twice for each request, once before hooks like check_user, etc.
// and once after. The first time through, the request object exists, but isn't initialized.
// The other case is subrequests of some kinds: then post_read doesn't run, and the objects
// themselves don't exist. We do deferred creation of the objects in check_user to fix that case.
// In each screwed up case, we return "denied" so that nothing bad happens.
pair<ShibTargetApache*,authz_status> shib_base_check_authz(request_rec* r)
{
    shib_request_config* rc = (shib_request_config*)ap_get_module_config(r->request_config, &shib_module);
    if (!rc || !rc->sta) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_base_check_authz found no per-request structure");
        return make_pair((ShibTargetApache*)nullptr, AUTHZ_DENIED_NO_USER);
    }
    else if (!rc->sta->isInitialized()) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "shib_base_check_authz found uninitialized request object");
        return make_pair((ShibTargetApache*)nullptr, AUTHZ_DENIED_NO_USER);
    }
    return make_pair(rc->sta, AUTHZ_GRANTED);
}

extern "C" authz_status shib_shibboleth_check_authz(request_rec* r, const char*, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;
    return AUTHZ_GRANTED;
}

extern "C" authz_status shib_session_check_authz(request_rec* r, const char*, const void*)
{
    pair<ShibTargetApache*,authz_status> sta = shib_base_check_authz(r);
    if (!sta.first)
        return sta.second;

    try {
        Session* session = sta.first->getSession(false, true, false);
        lock_guard<Session> slocker(*session, adopt_lock);
        if (session) {
            sta.first->log(Priority::SHIB_DEBUG, "htaccess: accepting shib-session/valid-user based on active session");
            return AUTHZ_GRANTED;
        }
    }
    catch (std::exception& e) {
        sta.first->log(Priority::SHIB_WARN, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    sta.first->log(Priority::SHIB_DEBUG, "htaccess: denying shib-access/valid-user rule, no active session");
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

    shib_server_config* sc = (shib_server_config*)ap_get_module_config(r->server->module_config, &shib_module);
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

    shib_server_config* sc = (shib_server_config*)ap_get_module_config(r->server->module_config, &shib_module);
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
        lock_guard<Session> slocker(*session, adopt_lock);
        if (session && hta.doAuthnContext(*sta.first, session->getAuthnContextClassRef(), require_line) == AccessControl::shib_acl_true)
            return AUTHZ_GRANTED;
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(Priority::SHIB_WARN, string("htaccess: unable to obtain session for access control check: ") +  e.what());
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
        lock_guard<Session> slocker(*session, adopt_lock);
        if (session) {
            const char* rule = ap_getword_conf(r->pool, &require_line);
            if (rule && hta.doShibAttr(*sta.first, session, rule, require_line) == AccessControl::shib_acl_true)
                return AUTHZ_GRANTED;
        }
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(Priority::SHIB_WARN, string("htaccess: unable to obtain session for access control check: ") +  e.what());
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
        lock_guard<Session> slocker(*session, adopt_lock);
        if (session) {
            const char* config = ap_getword_conf(r->pool, &require_line);
            if (config && hta.doAccessControl(*sta.first, session, config) == AccessControl::shib_acl_true)
                return AUTHZ_GRANTED;
        }
        return session ? AUTHZ_DENIED : AUTHZ_DENIED_NO_USER;
    }
    catch (std::exception& e) {
        sta.first->log(Priority::SHIB_WARN, string("htaccess: unable to obtain session for access control check: ") +  e.what());
    }

    return AUTHZ_GENERAL_ERROR;
}

// Command manipulation functions

extern "C" const char* ap_set_global_string_slot(cmd_parms* parms, void*, const char* arg)
{
    *((char**)(parms->info))=apr_pstrdup(parms->pool,arg);
    return nullptr;
}

extern "C" const char* shib_set_server_string_slot(cmd_parms* parms, void*, const char* arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&shib_module);
    size_t offset=(size_t)parms->info;
    *((char**)(base + offset))=apr_pstrdup(parms->pool,arg);
    return nullptr;
}

extern "C" const char* shib_set_server_flag_slot(cmd_parms* parms, void*, int arg)
{
    char* base=(char*)ap_get_module_config(parms->server->module_config,&shib_module);
    size_t offset=(size_t)parms->info;
    *((int*)(base + offset)) = arg;
    return nullptr;
}

extern "C" const char* shib_ap_set_file_slot(cmd_parms* parms, void* arg1, const char* arg2)
{
  ap_set_file_slot(parms, arg1, arg2);
  return DECLINE_CMD;
}

extern "C" const char* shib_table_set(cmd_parms* parms, shib_dir_config* dc, const char* arg1, const char* arg2)
{
    if (!dc->tSettings)
        dc->tSettings = apr_table_make(parms->pool, 4);
    apr_table_set(dc->tSettings, arg1, arg2);
    return nullptr;
}

extern "C" const char* shib_table_unset(cmd_parms* parms, shib_dir_config* dc, const char* arg1)
{
    if (!dc->tUnsettings)
        dc->tUnsettings = apr_table_make(parms->pool, 4);
    apr_table_set(dc->tUnsettings, arg1, "");
    return nullptr;
}

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
    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, s, "shib_exit: shib_module shutdown in pid (%d)", (int)getpid());
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
    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, s, "post_config: shib_module initializing in pid (%d)", (int)getpid());

    if (g_Config) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, s, "post_config: shib_module already initialized");
        return !OK;
    }

    AgentConfig::getConfig().RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, &ApacheRequestMapFactory);

    g_Config = &AgentConfig::getConfig();
    if (!g_Config->init(g_szSchemaDir, g_szPrefix)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT|APLOG_NOERRNO, 0, s, "post_config: shib_module failed to initialize libraries");
        return !OK;
    }

    // Set the cleanup handler, passing in the server_rec for logging.
    apr_pool_cleanup_register(p, s, &shib_exit, apr_pool_cleanup_null);

    return OK;
}

/*
 * shib_child_init()
 *  Things to do when the child process is initialized.
 *  For now, we have no background threads, but if we introduce any, we'd have to switch
 *  back to deferring their creation until this step because only the forking thread shows
 *  up in the child, losing any internal threads spun up by plugins in the agent library.
 */
extern "C" void shib_child_init(apr_pool_t* p, server_rec* s)
{
    // Initialize runtime components.

    ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, s, "child_init: shib_module initializing in pid (%d)", (int)getpid());

    const Agent& agent = g_Config->getAgent();
    g_unsetHeaderValue = agent.getString("unsetHeaderValue");
    g_checkSpoofing = agent.getBool("checkSpoofing", true);
    if (g_checkSpoofing) {
        const char* altkey = agent.getString("spoofKey");
        if (altkey)
            g_spoofKey = altkey;
    }
    g_catchAll = agent.getBool("catchAll", false);

    // Set the cleanup handler, passing in the server_rec for logging.
    apr_pool_cleanup_register(p, s, &shib_exit, apr_pool_cleanup_null);

    ap_log_error(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, s, "child_init: shib_module config initialized");
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
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &shib_module);

    if (rc && rc->hdr_out) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "output_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
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
    shib_request_config *rc = (shib_request_config*) ap_get_module_config(r->request_config, &shib_module);

    if (rc && rc->hdr_out) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, "error_filter: merging %d headers", apr_table_elts(rc->hdr_out)->nelts);
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

extern "C" const authz_provider shib_authz_shibboleth_provider = { &shib_shibboleth_check_authz, nullptr };
extern "C" const authz_provider shib_authz_validuser_provider = { &shib_validuser_check_authz, nullptr };
extern "C" const authz_provider shib_authz_session_provider = { &shib_session_check_authz, nullptr };
extern "C" const authz_provider shib_authz_user_provider = { &shib_user_check_authz, nullptr };
extern "C" const authz_provider shib_authz_ext_user_provider = { &shib_ext_user_check_authz, nullptr };
extern "C" const authz_provider shib_authz_acclass_provider = { &shib_acclass_check_authz, nullptr };
extern "C" const authz_provider shib_authz_attr_provider = { &shib_attr_check_authz, nullptr };
extern "C" const authz_provider shib_authz_plugin_provider = { &shib_plugin_check_authz, nullptr };

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
    if (prereq && *prereq) {
        const char* const authnPre[] = { prereq, nullptr };
        ap_hook_check_authn(shib_check_user, authnPre, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
    }
    else {
        ap_hook_check_authn(shib_check_user, nullptr, nullptr, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
    }
    ap_hook_check_authz(shib_auth_checker, nullptr, nullptr, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_URI);
    ap_hook_handler(shib_handler, nullptr, nullptr, APR_HOOK_LAST);
    ap_hook_fixups(shib_fixups, nullptr, nullptr, APR_HOOK_MIDDLE);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shibboleth", AUTHZ_PROVIDER_VERSION, &shib_authz_shibboleth_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "valid-user", AUTHZ_PROVIDER_VERSION, &shib_authz_validuser_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-session", AUTHZ_PROVIDER_VERSION, &shib_authz_session_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "user", AUTHZ_PROVIDER_VERSION, &shib_authz_user_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-user", AUTHZ_PROVIDER_VERSION, &shib_authz_ext_user_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "authnContextClassRef", AUTHZ_PROVIDER_VERSION, &shib_authz_acclass_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-attr", AUTHZ_PROVIDER_VERSION, &shib_authz_attr_provider, AP_AUTH_INTERNAL_PER_CONF);
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "shib-plugin", AUTHZ_PROVIDER_VERSION, &shib_authz_plugin_provider, AP_AUTH_INTERNAL_PER_CONF);
}

// Module commands

extern "C" {
static command_rec shib_cmds[] = {
    AP_INIT_TAKE1("ShibPrefix", (config_fn_t)ap_set_global_string_slot, &g_szPrefix,
        RSRC_CONF, "Shibboleth installation directory"),
    AP_INIT_TAKE1("ShibConfig", (config_fn_t)ap_set_global_string_slot, &g_szSHIBConfig,
        RSRC_CONF, "Path to shibboleth2.xml config file"),
    AP_INIT_TAKE1("ShibCatalogs", (config_fn_t)ap_set_global_string_slot, &g_szSchemaDir,
        RSRC_CONF, "Paths of XML schema catalogs"),

    AP_INIT_TAKE1("ShibURLScheme", (config_fn_t)shib_set_server_string_slot,
        (void *) offsetof (shib_server_config, szScheme),
        RSRC_CONF, "URL scheme to force into generated URLs for a vhost"),

    AP_INIT_TAKE2("ShibRequestSetting", (config_fn_t)shib_table_set, nullptr,
        OR_AUTHCFG, "Set arbitrary Shibboleth request property for content"),
    AP_INIT_TAKE1("ShibRequestUnset", (config_fn_t)shib_table_unset, nullptr,
        OR_AUTHCFG, "Unset an arbitrary Shibboleth request property (blocking inheritance)"),

    AP_INIT_FLAG("ShibDisable", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bOff),
        OR_AUTHCFG, "Disable all Shib module activity here to save processing effort"),
    AP_INIT_TAKE1("ShibApplicationId", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szApplicationId),
        OR_AUTHCFG, "(DEPRECATED) Set Shibboleth applicationId property for content"),
    AP_INIT_FLAG("ShibBasicHijack", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bBasicHijack),
        OR_AUTHCFG, "(DEPRECATED) Respond to AuthType Basic and convert to shibboleth"),
    AP_INIT_FLAG("ShibRequireSession", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequireSession),
        OR_AUTHCFG, "(DEPRECATED) Initiates a new session if one does not exist"),
    AP_INIT_TAKE1("ShibRequireSessionWith", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRequireWith),
        OR_AUTHCFG, "(DEPRECATED) Initiates a new session if one does not exist using a specific SessionInitiator"),
    AP_INIT_FLAG("ShibExportAssertion", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bExportAssertion),
        OR_AUTHCFG, "(DEPRECATED) Export SAML attribute assertion(s) to Shib-Attributes header"),
    AP_INIT_TAKE1("ShibRedirectToSSL", (config_fn_t)ap_set_string_slot,
        (void *) offsetof (shib_dir_config, szRedirectToSSL),
        OR_AUTHCFG, "(DEPRECATED) Redirect non-SSL requests to designated port"),
    AP_INIT_FLAG("ShibRequestMapperAuthz", (config_fn_t)ap_set_flag_slot,
        (void *) offsetof (shib_dir_config, bRequestMapperAuthz),
        OR_AUTHCFG, "Support access control via shibboleth2.xml / RequestMapper"),
    AP_INIT_FLAG("ShibCompatValidUser", (config_fn_t)shib_set_server_flag_slot,
        (void *) offsetof (shib_server_config, bCompatValidUser),
        RSRC_CONF, "Handle 'require valid-user' in mod_authz_user-compatible fashion (requiring username)"),
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

module AP_MODULE_DECLARE_DATA shib_module = {
    STANDARD20_MODULE_STUFF,
    create_shib_dir_config,     /* create dir config */
    merge_shib_dir_config,      /* merge dir config --- default is to override */
    create_shib_server_config,  /* create server config */
    merge_shib_server_config,   /* merge server config */
    shib_cmds,                  /* command table */
    shib_register_hooks         /* register hooks */
};

}
