/*
 *  Copyright 2001-2007 Internet2
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

/* shibauthorizer.cpp - Shibboleth FastCGI Authorizer

   Andre Cruz
*/

// SAML Runtime
#include <saml/saml.h>
#include <shib-target/shib-target.h>

#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
# include <sys/mman.h>
#endif
#include <fcgio.h>

using namespace shibtarget;
using namespace saml;
using namespace std;

typedef enum {
    SHIB_RETURN_OK,
    SHIB_RETURN_KO,
    SHIB_RETURN_DONE
} shib_return_t;

class ShibTargetFCGIAuth : public ShibTarget
{
    FCGX_Request* m_req;
    string m_cookie;
public:
    map<string,string> m_headers;

    ShibTargetFCGIAuth(FCGX_Request* req, const char* scheme=NULL, const char* hostname=NULL, int port=0) : m_req(req) {
        const char* server_name_str = hostname;
        if (!server_name_str || !*server_name_str)
            server_name_str = FCGX_GetParam("SERVER_NAME", req->envp);

        int server_port = port;
        if (!port) {
            char* server_port_str = FCGX_GetParam("SERVER_PORT", req->envp);
            server_port = strtol(server_port_str, &server_port_str, 10);
            if (*server_port_str) {
                cerr << "can't parse SERVER_PORT (" << FCGX_GetParam("SERVER_PORT", req->envp) << ")" << endl;
                throw SAMLException("Unable to determine server port.");
            }
        }

        const char* server_scheme_str = scheme;
        if (!server_scheme_str || !*server_scheme_str)
            server_scheme_str = (server_port == 443 || server_port == 8443) ? "https" : "http";

        const char* request_uri_str = FCGX_GetParam("REQUEST_URI", req->envp);
        const char* content_type_str = FCGX_GetParam("CONTENT_TYPE", req->envp);
        const char* remote_addr_str = FCGX_GetParam("REMOTE_ADDR", req->envp);
        const char* request_method_str = FCGX_GetParam("REQUEST_METHOD", req->envp);

        init(server_scheme_str,
             server_name_str,
             server_port,
             request_uri_str,
             content_type_str ? content_type_str : "",
             remote_addr_str,
             request_method_str
             );
    }

    ~ShibTargetFCGIAuth() { }

    virtual void log(ShibLogLevel level, const string& msg) {
        ShibTarget::log(level,msg);
        if (level == LogLevelError)
            cerr << "shib: " << msg;
    }
  
    virtual string getCookies(void) const {
        char* cookie = FCGX_GetParam("HTTP_COOKIE", m_req->envp);
        return cookie ? cookie : "";
    }
  
    virtual void setCookie(const string &name, const string &value) {
        m_cookie += "Set-Cookie: " + name + "=" + value + "\r\n";
    }

      virtual string getArgs(void) {
        char* args = FCGX_GetParam("QUERY_STRING", m_req->envp);
        return args ? args : "";
    }

    virtual string getPostData(void) {
        throw SAMLException("getPostData not implemented by FastCGI authorizer.");
    }

    virtual void clearHeader(const string& name) {
        // no need, since request headers turn into actual environment variables
    }
  
    virtual void setHeader(const string& name, const string &value) {
        m_headers[name] = value;
    }

    virtual string getHeader(const string& name) {
        if (m_headers.find(name) != m_headers.end())
            return m_headers[name];
        else
            return "";
    }

    virtual void setRemoteUser(const string& user) {
        m_headers["REMOTE_USER"] = user;
    }

    virtual string getRemoteUser(void) {
        if (m_headers.find("REMOTE_USER") != m_headers.end())
            return m_headers["REMOTE_USER"];
        else {
            char* remote_user = FCGX_GetParam("REMOTE_USER", m_req->envp);
            if (remote_user)
                return remote_user;
        }
        return "";
    }

    virtual void* sendPage(
        const string& msg,
        int code=200,
        const string& content_type="text/html",
        const Iterator<header_t>& headers=EMPTY(header_t)) {

        string hdr = m_cookie + "Connection: close\r\nContent-type: " + content_type + "\r\n";
        while (headers.hasNext()) {
            const header_t& h=headers.next();
            hdr += h.first + ": " + h.second + "\r\n";
        }

        // We can't return 200 OK here or else the filter is bypassed
        // so custom Shib errors will get turned into a generic page.
        const char* codestr="Status: 500 Server Error";
        switch (code) {
            case 403:   codestr="Status: 403 Forbidden"; break;
            case 404:   codestr="Status: 404 Not Found"; break;
        }

        cout << codestr << "\r\n" << hdr << "\r\n" << msg;
        return (void*)SHIB_RETURN_DONE;
    }

    virtual void* sendRedirect(const string& url) {
        cout << "Status: 302 Please Wait" << "\r\n"
             << "Location: " << url << "\r\n"
             <<  m_cookie << "\r\n"
             << "<HTML><BODY>Redirecting...</BODY></HTML>";
        return (void*)SHIB_RETURN_DONE;
    }

    virtual void* returnDecline(void) { 
        return (void*)SHIB_RETURN_KO;
    }

    virtual void* returnOK(void) {
        return (void*)SHIB_RETURN_OK;
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
    char* shib_config = getenv("SHIB_CONFIG");
    char* shib_schema = getenv("SHIB_SCHEMA");
    if ((shib_config == NULL) || (shib_schema == NULL)) {
      cerr << "SHIB_CONFIG or SHIB_SCHEMA not initialized!" << endl;
      exit(1);
    }
    cerr << "SHIB_CONFIG = " << shib_config << endl
         << "SHIB_SCHEMA = " << shib_schema << endl;

    string g_ServerScheme;
    string g_ServerName;
    int g_ServerPort = 0;
    ShibTargetConfig* g_Config;

    try {
        g_Config = &ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::AAP |
            ShibTargetConfig::RequestMapper |
            ShibTargetConfig::LocalExtensions |
            ShibTargetConfig::Logging
            );
        if (!g_Config->init(shib_schema)) {
            cerr << "failed to initialize Shibboleth libraries" << endl;
            exit(1);
        }
        
        if (!g_Config->load(shib_config)) {
            cerr << "failed to load Shibboleth configuration" << endl;
            exit(1);
        }
    }
    catch (...) {
        cerr << "exception while initializing Shibboleth configuration" << endl;
        exit(1);
    }

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
            saml::NDC ndc("FastCGI shibauthorizer");
            ShibTargetFCGIAuth sta(&request, g_ServerScheme.c_str(), g_ServerName.c_str(), g_ServerPort);
          
            pair<bool,void*> res = sta.doCheckAuthN();
            if (res.first) {
#ifdef _DEBUG
                cerr << "shib: doCheckAuthN handled the request" << endl;
#endif
                switch((long)res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_headers);
                        continue;
              
                    case SHIB_RETURN_KO:
                        print_ok(sta.m_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;
              
                    default:
                        cerr << "shib: doCheckAuthN returned an unexpected result: " << (long)res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }
          
            res = sta.doExportAssertions();
            if (res.first) {
#ifdef _DEBUG
                cerr << "shib: doExportAssertions handled request" << endl;
#endif
                switch((long)res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_headers);
                        continue;
              
                    case SHIB_RETURN_KO:
                        print_ok(sta.m_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;
              
                    default:
                        cerr << "shib: doExportAssertions returned an unexpected result: " << (long)res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }

            res = sta.doCheckAuthZ();
            if (res.first) {
#ifdef _DEBUG
                cerr << "shib: doCheckAuthZ handled request" << endl;
#endif
                switch((long)res.second) {
                    case SHIB_RETURN_OK:
                        print_ok(sta.m_headers);
                        continue;
              
                    case SHIB_RETURN_KO:
                        print_ok(sta.m_headers);
                        continue;

                    case SHIB_RETURN_DONE:
                        continue;
              
                    default:
                        cerr << "shib: doCheckAuthZ returned an unexpected result: " << (long)res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth authorizer returned an unexpected result.</body></html>");
                        continue;
                }
            }

            print_ok(sta.m_headers);
          
        }
        catch (SAMLException& e) {
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
        g_Config->shutdown();
 
    return 0;
}
