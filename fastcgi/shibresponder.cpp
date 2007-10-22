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

/* shibresponder.cpp - Shibboleth FastCGI Responder/Handler

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
using namespace std;

typedef enum {
    SHIB_RETURN_OK,
    SHIB_RETURN_KO,
    SHIB_RETURN_DONE
} shib_return_t;

class ShibTargetFCGI : public ShibTarget
{
    FCGX_Request* m_req;
    char* m_body;
    string m_cookie;
    map<string, string> m_headers;

public:
    ShibTargetFCGI(FCGX_Request* req, char* post_data, const char* scheme=NULL, const char* hostname=NULL, int port=0)
        : m_req(req), m_body(post_data) {

        const char* server_name_str = hostname;
        if (!server_name_str || !*server_name_str)
            server_name_str = FCGX_GetParam("SERVER_NAME", req->envp);

        int server_port = port;
        if (!port) {
            char* server_port_str = FCGX_GetParam("SERVER_PORT", req->envp);
            server_port = strtol(server_port_str, &server_port_str, 10);
            if (*server_port_str) {
                cerr << "can't parse SERVER_PORT (" << FCGX_GetParam("SERVER_PORT", req->envp) << ")" << endl;
                throw exception("Unable to determine server port.");
            }
        }

        const char* server_scheme_str = scheme;
        if (!server_scheme_str || !*server_scheme_str)
            server_scheme_str = (server_port == 443 || server_port == 8443) ? "https" : "http";

        const char* request_uri_str = FCGX_GetParam("REQUEST_URI", req->envp);
        const char* content_type_str = FCGX_GetParam("CONTENT_TYPE", req->envp);
        const char* remote_addr_str = FCGX_GetParam("REMOTE_ADDR", req->envp);
        const char* request_method_str = FCGX_GetParam("REQUEST_METHOD", req->envp);

#ifdef _DEBUG
        cerr << "server_name = " << server_name_str << endl
             << "server_port = " << server_port << endl
             << "request_uri_str = " << request_uri_str << endl
             << "content_type = " << content_type_str << endl
             << "remote_address = " << remote_addr_str << endl
             << "request_method = " << request_method_str << endl;
#endif

        init(server_scheme_str,
             server_name_str,
             server_port,
             request_uri_str,
             content_type_str ? content_type_str : "",
             remote_addr_str,
             request_method_str
             );
    }

    ~ShibTargetFCGI() { }

    virtual void log(ShibLogLevel level, const string& msg) {
        ShibTarget::log(level,msg);
    
        if (level == LogLevelError)
            cerr << "shib: " << msg;
    }
  
    virtual string getCookies(void) const {
        char * cookie = FCGX_GetParam("HTTP_COOKIE", m_req->envp);
        return cookie ? cookie : "";
    }
  
    virtual void setCookie(const string& name, const string& value) {
        m_cookie += "Set-Cookie: " + name + "=" + value + "\r\n";
    }

    virtual string getArgs(void) {
        char * args = FCGX_GetParam("QUERY_STRING", m_req->envp);
        return args ? args : "";
    }

    virtual string getPostData(void) {
        return m_body ? m_body : "";
    }

    virtual void clearHeader(const string &name) {
        throw runtime_error("clearHeader not implemented by FastCGI responder.");
    }
  
    virtual void setHeader(const string &name, const string &value) {
        throw runtime_error("setHeader not implemented by FastCGI responder.");
    }

    virtual string getHeader(const string &name) {
        throw runtime_error("getHeader not implemented by FastCGI responder.");
    }

    virtual void setRemoteUser(const string &user) {
        throw runtime_error("setRemoteUser not implemented by FastCGI responder.");
    }

    virtual string getRemoteUser(void) {
        throw runtime_error("getRemoteUser not implemented by FastCGI responder.");
    }

    virtual void* sendPage(
        const string& msg,
        int code=200,
        const string& content_type="text/html",
        const saml::Iterator<header_t>& headers=EMPTY(header_t)) {

        string hdr = string ("Connection: close\r\nContent-type: ") + content_type + "\r\n" + m_cookie;
        while (headers.hasNext()) {
            const header_t& h=headers.next();
            hdr += h.first + ": " + h.second + "\r\n";
        }

        const char* codestr="Status: 200 OK";
        switch (code) {
            case 500:   codestr="Status: 500 Server Error"; break;
            case 403:   codestr="Status: 403 Forbidden"; break;
            case 404:   codestr="Status: 404 Not Found"; break;
        }

        cout << codestr << "\r\n" << hdr << m_cookie << "\r\n" << msg;
        return (void*)SHIB_RETURN_DONE;
    }

    virtual void* sendRedirect(const string& url) {
        cout << "Status: 302 Please Wait" << "\r\n" << "Location: " << url << "\r\n" << m_cookie << "\r\n"
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

// Maximum number of bytes allowed to be read from stdin
static const unsigned long STDIN_MAX = 1000000;

static long gstdin(FCGX_Request* request, char** content)
{
    char* clenstr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    unsigned long clen = STDIN_MAX;

    if (clenstr) {
        clen = strtol(clenstr, &clenstr, 10);
        if (*clenstr) {
            cerr << "can't parse CONTENT_LENGTH (" << FCGX_GetParam("CONTENT_LENGTH", request->envp) << ")" << endl;
            clen = STDIN_MAX;
        }

        // *always* put a cap on the amount of data that will be read
        if (clen > STDIN_MAX)
            clen = STDIN_MAX;

        *content = new char[clen];

        cin.read(*content, clen);
        clen = cin.gcount();
    }
    else {
        // *never* read stdin when CONTENT_LENGTH is missing or unparsable
        *content = 0;
        clen = 0;
    }

    // Chew up any remaining stdin - this shouldn't be necessary
    // but is because mod_fastcgi doesn't handle it correctly.

    // ignore() doesn't set the eof bit in some versions of glibc++
    // so use gcount() instead of eof()...
    do cin.ignore(1024); while (cin.gcount() == 1024);

    return clen;
}

static void print_ok() {
    cout << "Status: 200 OK" << "\r\n\r\n";
}

static void print_error(const char* msg) {
    cout << "Status: 500 Server Error" << "\r\n\r\n" << msg;
}

int main(void)
{
    char* shib_config = getenv("SHIB_CONFIG");
    char* shib_schema = getenv("SHIB_SCHEMA");
    if ((shib_config == NULL) || (shib_schema == NULL)) {
        cerr << "SHIB_CONFIG or SHIB_SCHEMA not set." << endl;
        exit(1);
    }
    cerr << "SHIB_CONFIG = " << shib_config << endl
         << "SHIB_SCHEMA = " << shib_schema << endl;

    string g_ServerScheme;
    string g_ServerName;
    int g_ServerPort=0;
    ShibTargetConfig* g_Config;

    try {
        g_Config = &ShibTargetConfig::getConfig();
        g_Config->setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::Metadata |
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
    catch (exception& e) {
        cerr << "exception while initializing Shibboleth configuration:" << e.what() << endl;
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

    streambuf* cin_streambuf  = cin.rdbuf();
    streambuf* cout_streambuf = cout.rdbuf();
    streambuf* cerr_streambuf = cerr.rdbuf();

    FCGX_Request request;

    FCGX_Init();
    FCGX_InitRequest(&request, 0, 0);
    
    cout << "Shibboleth initialization complete. Starting request loop." << endl;
    while (FCGX_Accept_r(&request) == 0) {
        // Note that the default bufsize (0) will cause the use of iostream
        // methods that require positioning (such as peek(), seek(),
        // unget() and putback()) to fail (in favour of more efficient IO).
        fcgi_streambuf cin_fcgi_streambuf(request.in);
        fcgi_streambuf cout_fcgi_streambuf(request.out);
        fcgi_streambuf cerr_fcgi_streambuf(request.err);

        cin.rdbuf(&cin_fcgi_streambuf);
        cout.rdbuf(&cout_fcgi_streambuf);
        cerr.rdbuf(&cerr_fcgi_streambuf);

        // Although FastCGI supports writing before reading,
        // many http clients (browsers) don't support it (so
        // the connection deadlocks until a timeout expires!).
        char* content;
        gstdin(&request, &content);

        try {
            saml::NDC ndc("FastCGI shibresponder");
            ShibTargetFCGI stf(&request, content, g_ServerScheme.c_str(), g_ServerName.c_str(), g_ServerPort);
          
            pair<bool,void*> res = stf.doHandler();
            if (res.first) {
#ifdef _DEBUG
                cerr << "shib: doHandler handled the request" << endl;
#endif
                switch((long)res.second) {
                    case SHIB_RETURN_OK:
                        print_ok();
                        break;
              
                    case SHIB_RETURN_KO:
                        cerr << "shib: doHandler failed to handle the request" << endl;
                        print_error("<html><body>FastCGI Shibboleth responder should only be used for Shibboleth protocol requests.</body></html>");
                        break;

                    case SHIB_RETURN_DONE:
                        // response already handled
                        break;
              
                    default:
                        cerr << "shib: doHandler returned an unexpected result: " << (long)res.second << endl;
                        print_error("<html><body>FastCGI Shibboleth responder returned an unexpected result.</body></html>");
                        break;
                }
            }
            else {
                cerr << "shib: doHandler failed to handle request." << endl;
                print_error("<html><body>FastCGI Shibboleth responder failed to process request.</body></html>");
            }          
          
        }
        catch (exception& e) {
            cerr << "shib: FastCGI responder caught an exception: " << e.what() << endl;
            print_error("<html><body>FastCGI Shibboleth responder caught an exception, check log for details.</body></html>");
        }

        delete[] content;

        // If the output streambufs had non-zero bufsizes and
        // were constructed outside of the accept loop (i.e.
        // their destructor won't be called here), they would
        // have to be flushed here.
    }

    cout << "Request loop ended." << endl;

    cin.rdbuf(cin_streambuf);
    cout.rdbuf(cout_streambuf);
    cerr.rdbuf(cerr_streambuf);

    if (g_Config)
        g_Config->shutdown();
 
    return 0;
}
