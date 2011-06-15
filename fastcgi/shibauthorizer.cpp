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

/* shibauthorizer.cpp - Shibboleth FastCGI Authorizer

   Andre Cruz
*/

#define SHIBSP_LITE
#include "config_win32.h"

#define _CRT_NONSTDC_NO_DEPRECATE 1
#define _CRT_SECURE_NO_DEPRECATE 1
#define _SCL_SECURE_NO_WARNINGS 1

#include <shibsp/AbstractSPRequest.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#include <stdexcept>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
# include <sys/mman.h>
#endif
#include <fcgio.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

static const XMLCh path[] =     UNICODE_LITERAL_4(p,a,t,h);
static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);

typedef enum {
    SHIB_RETURN_OK,
    SHIB_RETURN_KO,
    SHIB_RETURN_DONE
} shib_return_t;

class ShibTargetFCGIAuth : public AbstractSPRequest
{
    FCGX_Request* m_req;
    int m_port;
    string m_scheme,m_hostname;
    multimap<string,string> m_response_headers;
public:
    map<string,string> m_request_headers;

    ShibTargetFCGIAuth(FCGX_Request* req, const char* scheme=nullptr, const char* hostname=nullptr, int port=0)
            : AbstractSPRequest(SHIBSP_LOGCAT".FastCGI"), m_req(req) {
        const char* server_name_str = hostname;
        if (!server_name_str || !*server_name_str)
            server_name_str = FCGX_GetParam("SERVER_NAME", req->envp);
        m_hostname = server_name_str;

        m_port = port;
        if (!m_port) {
            char* server_port_str = FCGX_GetParam("SERVER_PORT", req->envp);
            m_port = strtol(server_port_str, &server_port_str, 10);
            if (*server_port_str) {
                cerr << "can't parse SERVER_PORT (" << FCGX_GetParam("SERVER_PORT", req->envp) << ")" << endl;
                throw runtime_error("Unable to determine server port.");
            }
        }

        const char* server_scheme_str = scheme;
        if (!server_scheme_str || !*server_scheme_str)
            server_scheme_str = (m_port == 443 || m_port == 8443) ? "https" : "http";
        m_scheme = server_scheme_str;

        setRequestURI(FCGX_GetParam("REQUEST_URI", m_req->envp));
    }

    ~ShibTargetFCGIAuth() { }

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
        return FCGX_GetParam("REQUEST_METHOD", m_req->envp);
    }
    string getContentType() const {
        const char* s = FCGX_GetParam("CONTENT_TYPE", m_req->envp);
        return s ? s : "";
    }
    long getContentLength() const {
        const char* s = FCGX_GetParam("CONTENT_LENGTH", m_req->envp);
        return s ? atol(s) : 0;
    }
    string getRemoteAddr() const {
        string ret = AbstractSPRequest::getRemoteAddr();
        if (!ret.empty())
            return ret;
        const char* s = FCGX_GetParam("REMOTE_ADDR", m_req->envp);
        return s ? s : "";
    }
    void log(SPLogLevel level, const string& msg) const {
        AbstractSPRequest::log(level,msg);
        if (level >= SPError)
            cerr << "shib: " << msg;
    }
    void clearHeader(const char* rawname, const char* cginame) {
        // No need, since we use environment variables.
    }
    void setHeader(const char* name, const char* value) {
        if (value)
            m_request_headers[name] = value;
        else
            m_request_headers.erase(name);
    }
    string getHeader(const char* name) const {
        // Look in the local map first.
        map<string,string>::const_iterator i = m_request_headers.find(name);
        if (i != m_request_headers.end())
            return i->second;
        // Nothing set locally and this isn't a "secure" call, so check the request.
        string hdr("HTTP_");
        for (; *name; ++name) {
            if (*name=='-')
                hdr += '_';
            else
                hdr += toupper(*name);
        }
        char* s = FCGX_GetParam(hdr.c_str(), m_req->envp);
        return s ? s : "";
    }
    string getSecureHeader(const char* name) const {
        // Look in the local map only.
        map<string,string>::const_iterator i = m_request_headers.find(name);
        if (i != m_request_headers.end())
            return i->second;
        return "";
    }
    void setRemoteUser(const char* user) {
        if (user)
            m_request_headers["REMOTE_USER"] = user;
        else
            m_request_headers.erase("REMOTE_USER");
    }
    string getRemoteUser() const {
        map<string,string>::const_iterator i = m_request_headers.find("REMOTE_USER");
        if (i != m_request_headers.end())
            return i->second;
        else {
            char* remote_user = FCGX_GetParam("REMOTE_USER", m_req->envp);
            if (remote_user)
                return remote_user;
        }
        return "";
    }
    void setAuthType(const char* authtype) {
        if (authtype)
            m_request_headers["AUTH_TYPE"] = authtype;
        else
            m_request_headers.erase("AUTH_TYPE");
    }
    string getAuthType() const {
        map<string,string>::const_iterator i = m_request_headers.find("AUTH_TYPE");
        if (i != m_request_headers.end())
            return i->second;
        else {
            char* auth_type = FCGX_GetParam("AUTH_TYPE", m_req->envp);
            if (auth_type)
                return auth_type;
        }
        return "";
    }
    void setResponseHeader(const char* name, const char* value) {
        HTTPResponse::setResponseHeader(name, value);
        // Set for later.
        if (value)
            m_response_headers.insert(make_pair(name,value));
        else
            m_response_headers.erase(name);
    }
    const char* getQueryString() const {
        return FCGX_GetParam("QUERY_STRING", m_req->envp);
    }
    const char* getRequestBody() const {
        throw runtime_error("getRequestBody not implemented by FastCGI authorizer.");
    }

    long sendResponse(istream& in, long status) {
        string hdr = string("Connection: close\r\n");
        for (multimap<string,string>::const_iterator i=m_response_headers.begin(); i!=m_response_headers.end(); ++i)
            hdr += i->first + ": " + i->second + "\r\n";

        // We can't return 200 OK here or else the filter is bypassed
        // so custom Shib errors will get turned into a generic page.
        const char* codestr="Status: 500 Server Error";
        switch (status) {
            case XMLTOOLING_HTTP_STATUS_NOTMODIFIED:    codestr="Status: 304 Not Modified"; break;
            case XMLTOOLING_HTTP_STATUS_UNAUTHORIZED:   codestr="Status: 401 Authorization Required"; break;
            case XMLTOOLING_HTTP_STATUS_FORBIDDEN:      codestr="Status: 403 Forbidden"; break;
            case XMLTOOLING_HTTP_STATUS_NOTFOUND:       codestr="Status: 404 Not Found"; break;
        }
        cout << codestr << "\r\n" << hdr << "\r\n";
        char buf[1024];
        while (in) {
            in.read(buf,1024);
            cout.write(buf, in.gcount());
        }
        return SHIB_RETURN_DONE;
    }

    long sendRedirect(const char* url) {
        HTTPResponse::sendRedirect(url);
        string hdr=string("Status: 302 Please Wait\r\nLocation: ") + url + "\r\n"
          "Content-Type: text/html\r\n"
          "Content-Length: 40\r\n"
          "Expires: 01-Jan-1997 12:00:00 GMT\r\n"
          "Cache-Control: private,no-store,no-cache\r\n";
        for (multimap<string,string>::const_iterator i=m_response_headers.begin(); i!=m_response_headers.end(); ++i)
            hdr += i->first + ": " + i->second + "\r\n";
        hdr += "\r\n";

        cout << hdr << "<HTML><BODY>Redirecting...</BODY></HTML>";
        return SHIB_RETURN_DONE;
    }

    long returnDecline() {
        return SHIB_RETURN_KO;
    }

    long returnOK() {
        return SHIB_RETURN_OK;
    }

    const vector<string>& getClientCertificates() const {
        static vector<string> g_NoCerts;
        return g_NoCerts;
    }
};

static void print_ok(const map<string,string>& headers)
{
    cout << "Status: 200 OK" << "\r\n";
    for (map<string,string>::const_iterator iter = headers.begin(); iter != headers.end(); iter++) {
        cout << "Variable-" << iter->first << ": " << iter->second << "\r\n";
    }
    cout << "\r\n";
}

static void print_error(const char* msg)
{
    cout << "Status: 500 Server Error" << "\r\n\r\n" << msg;
}

int main(void)
{
    SPConfig* g_Config=&SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
        );
    if (!g_Config->init()) {
        cerr << "failed to initialize Shibboleth libraries" << endl;
        exit(1);
    }

    try {
        if (!g_Config->instantiate(nullptr, true))
            throw runtime_error("unknown error");
    }
    catch (exception& ex) {
        g_Config->term();
        cerr << "exception while initializing Shibboleth configuration: " << ex.what() << endl;
        exit(1);
    }

    string g_ServerScheme;
    string g_ServerName;
    int g_ServerPort=0;

    // Load "authoritative" URL fields.
    char* var = getenv("SHIBSP_SERVER_NAME");
    if (var)
        g_ServerName = var;
    var = getenv("SHIBSP_SERVER_SCHEME");
    if (var)
        g_ServerScheme = var;
    var = getenv("SHIBSP_SERVER_PORT");
    if (var)
        g_ServerPort = atoi(var);

    streambuf* cout_streambuf = cout.rdbuf();
    streambuf* cerr_streambuf = cerr.rdbuf();

    FCGX_Request request;

    FCGX_Init();
    FCGX_InitRequest(&request, 0, 0);

    cout << "Shibboleth initialization complete. Starting request loop." << endl;
    while (FCGX_Accept_r(&request) == 0)
    {
        // Note that the default bufsize (0) will cause the use of iostream
        // methods that require positioning (such as peek(), seek(),
        // unget() and putback()) to fail (in favour of more efficient IO).
        fcgi_streambuf cout_fcgi_streambuf(request.out);
        fcgi_streambuf cerr_fcgi_streambuf(request.err);

        cout.rdbuf(&cout_fcgi_streambuf);
        cerr.rdbuf(&cerr_fcgi_streambuf);

        try {
            xmltooling::NDC ndc("FastCGI shibauthorizer");
            ShibTargetFCGIAuth sta(&request, g_ServerScheme.c_str(), g_ServerName.c_str(), g_ServerPort);

            pair<bool,long> res = sta.getServiceProvider().doAuthentication(sta);
            if (res.first) {
                sta.log(SPRequest::SPDebug, "shib: doAuthentication handled the request");
                switch(res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_KO:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;

                    default:
                        cerr << "shib: doAuthentication returned an unexpected result: " << res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }

            res = sta.getServiceProvider().doExport(sta);
            if (res.first) {
                sta.log(SPRequest::SPDebug, "shib: doExport handled request");
                switch(res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_KO:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;

                    default:
                        cerr << "shib: doExport returned an unexpected result: " << res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }

            res = sta.getServiceProvider().doAuthorization(sta);
            if (res.first) {
                sta.log(SPRequest::SPDebug, "shib: doAuthorization handled request");
                switch(res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_KO:
                        print_ok(sta.m_request_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;

                    default:
                        cerr << "shib: doAuthorization returned an unexpected result: " << res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }

            print_ok(sta.m_request_headers);

        }
        catch (exception& e) {
            cerr << "shib: FastCGI authorizer caught an exception: " << e.what() << endl;
            print_error("<html><body>FastCGI Shibboleth authorizer caught an exception, check log for details.</body></html>");
        }

        // If the output streambufs had non-zero bufsizes and
        // were constructed outside of the accept loop (i.e.
        // their destructor won't be called here), they would
        // have to be flushed here.
    }
    cout << "Request loop ended." << endl;

    cout.rdbuf(cout_streambuf);
    cerr.rdbuf(cerr_streambuf);

    if (g_Config)
        g_Config->term();

    return 0;
}
