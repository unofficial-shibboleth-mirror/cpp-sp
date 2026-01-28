/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * handler/impl/StatusHandler.cpp
 *
 * Handler for exposing information about the state of the agent.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/SecuredHandler.h"
#include "remoting/ddf.h"
#include "remoting/RemotingService.h"
#include "session/SessionCache.h"
#include "util/CGIParser.h"
#include "util/Date.h"
#include "util/Misc.h"

#include <cstring>
#include <sstream>

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#ifndef HAVE_STRCASECMP
# define strncasecmp _strnicmp
#endif
namespace {

    class SHIBSP_API StatusHandler : public SecuredHandler
    {
    public:
        StatusHandler(const ptree& pt);
        virtual ~StatusHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        ostream& systemInfo(ostream& os) const;
    };

    class DummyRequest : public virtual HTTPRequest
    {
    public:
        DummyRequest(const char* url) : m_parser(nullptr), m_url(url), m_scheme(nullptr), m_query(nullptr), m_port(0) {
            if (url && !strncasecmp(url,"http://", 7)) {
                m_scheme = "http";
                m_port = 80;
                url += 7;
            }
            else if (url && !strncasecmp(url,"https://", 8)) {
                m_scheme = "https";
                m_port = 443;
                url += 8;
            }
            else {
                throw invalid_argument("Target parameter was not an absolute URL.");
            }

            m_query = strchr(url,'?');
            if (m_query)
                m_query++;

            const char* slash = strchr(url, '/');
            const char* colon = strchr(url, ':');
            if (colon && colon < slash) {
                m_hostname.assign(url, colon-url);
                string port(colon + 1, slash - colon);
                m_port = atoi(port.c_str());
            }
            else {
                m_hostname.assign(url, slash - url);
            }

            while (*slash) {
                if (*slash == '?') {
                    m_uri += slash;
                    break;
                }
                else if (*slash != '%') {
                    m_uri += *slash;
                }
                else {
                    ++slash;
                    if (!isxdigit(*slash) || !isxdigit(*(slash+1)))
                        throw invalid_argument("Bad request, contained unsupported encoded characters.");
                    m_uri += x2c(slash);
                    ++slash;
                }
                ++slash;
            }
        }

        virtual ~DummyRequest() {}

        const char* getRequestURL() const {
            return m_url;
        }
        const char* getScheme() const {
            return m_scheme;
        }
        const char* getHostname() const {
            return m_hostname.c_str();
        }
        int getPort() const {
            return m_port;
        }
        const char* getRequestURI() const {
            return m_uri.c_str();
        }
        const char* getMethod() const {
            return "GET";
        }
        string getContentType() const {
            return "";
        }
        string getAuthType() const {
            return "";
        }
        long getContentLength() const {
            return 0;
        }
        string getRemoteAddr() const {
            return "";
        }
        string getLocalAddr() const {
            return "";
        }
        string getRemoteUser() const {
            return "";
        }
        const char* getRequestBody() const {
            return nullptr;
        }
        const char* getQueryString() const {
            return m_query;
        }
        const char* getParameter(const char* name) const
        {
            if (!m_parser)
                m_parser.reset(new CGIParser(*this));

            pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
            return (bounds.first == bounds.second) ? nullptr : bounds.first->second;
        }
        vector<const char*>::size_type getParameters(const char* name, vector<const char*>& values) const
        {
            if (!m_parser)
                m_parser.reset(new CGIParser(*this));

            pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
            while (bounds.first != bounds.second) {
                values.push_back(bounds.first->second);
                ++bounds.first;
            }
            return values.size();
        }
        string getHeader(const char* name) const {
            return "";
        }
        const map<string,string>& getCookies() const {
            return m_cookieMap;
        }

    private:
        mutable unique_ptr<CGIParser> m_parser;
        const char* m_url;
        const char* m_scheme;
        const char* m_query;
        int m_port;
        string m_hostname,m_uri;
        map<string,string> m_cookieMap;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL StatusHandlerFactory(const pair<ptree&, const char*>& p, bool) {
        return new StatusHandler(p.first);
    }
};

StatusHandler::StatusHandler(const ptree& pt) : SecuredHandler(pt)
{
}

pair<bool,long> StatusHandler::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first) {
        return ret;
    }

    auto now = chrono::system_clock::now();

    ostringstream ts;
    ts << date::format("%FT%TZ", date::floor<chrono::milliseconds>(now));
    string timestamp(ts.str());

    const char* target = request.getParameter(RequestMapper::TARGET_PROP_NAME);
    if (target) {
        // RequestMap query, so handle it inproc.
        DummyRequest dummy(target);
        RequestMapper::Settings settings = request.getAgent().getRequestMapper()->getSettings(dummy);
        request.setContentType("text/xml");
        stringstream msg;
        msg << "<StatusHandler time='" << timestamp << "'>";
            msg << "<Version Shibboleth='" << PACKAGE_VERSION << "'/>";
            const char* setting = request.getParameter("setting");
                systemInfo(msg) << "<RequestSettings";
                if (setting) {
                    const char* prop = settings.first->getString(setting);
                    if (prop)
                        msg << ' ' << setting << "='" << prop << "'";
                }
                msg << '>' << target << "</RequestSettings>";
            msg << "<Status><OK/></Status>";
        msg << "</StatusHandler>";
        return make_pair(true, request.sendResponse(msg));
    }

    try {
        request.debug("processing status request");

        stringstream s;
        s << "<StatusHandler time='" << timestamp << "'>"
            << "<Version Shibboleth='" << PACKAGE_VERSION << "'/>";
        const char* status = "<OK/>";

        systemInfo(s);

        // General configuration and status report.
        SessionCache* sc = request.getAgent().getSessionCache(false);
        if (sc) {
            s << "<SessionCache><OK/></SessionCache>";
        }
        else {
            s << "<SessionCache><None/></SessionCache>";
        }

        const RemotingService* remoter = request.getAgent().getRemotingService(false);
        if (remoter) {
            DDF in = remoter->build("ping", request);
            DDFJanitor jan(in);
            DDF out = remoter->send(in);
            out.destroy();
            s << "<RemotingService><OK/></RemotingService>";
        }
        else {
            s << "<RemotingService><None/></RemotingService>";
        }

        s << "<Status>" << status << "</Status></StatusHandler>";

        request.setContentType("text/xml");
        return make_pair(true, request.sendResponse(s));
    }

    catch (const exception& ex) {
        request.log(Priority::SHIB_ERROR, ex);
        request.setContentType("text/xml");
        stringstream msg;
        msg << "<StatusHandler time='" << timestamp << "'>"
            << "<Version Shibboleth='" << PACKAGE_VERSION << "'/>";
        systemInfo(msg) << "<Status><Exception typename='" << typeid(ex).name() << "'>" << ex.what() << "</Exception></Status>"
            << "</StatusHandler>";
        return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_ERROR));
    }
}

ostream& StatusHandler::systemInfo(ostream& os) const
{
#if defined(HAVE_SYS_UTSNAME_H)
    struct utsname sysinfo;
    if (uname(&sysinfo) == 0) {
        os << "<NonWindows";
        if (*sysinfo.sysname)
            os << " sysname='" << sysinfo.sysname << "'";
        if (*sysinfo.nodename)
            os << " nodename='" << sysinfo.nodename << "'";
        if (*sysinfo.release)
            os << " release='" << sysinfo.release << "'";
        if (*sysinfo.version)
            os << " version='" << sysinfo.version << "'";
        if (*sysinfo.machine)
            os << " machine='" << sysinfo.machine << "'";
        os << "/>";
    }
#elif defined(WIN32)
    OSVERSIONINFOEXA osvi;
    memset(&osvi, 0, sizeof(OSVERSIONINFOEXA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

    if(GetVersionExA((LPOSVERSIONINFOA)&osvi)) {
        os << "<Windows"
           << " version='" << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "'"
           << " build='" << osvi.dwBuildNumber << "'";
        if (osvi.wServicePackMajor > 0)
            os << " servicepack='" << osvi.wServicePackMajor << "." << osvi.wServicePackMinor << "'";
        switch (osvi.wProductType) {
            case VER_NT_WORKSTATION:
                os << " producttype='Workstation'";
                break;
            case VER_NT_SERVER:
            case VER_NT_DOMAIN_CONTROLLER:
                os << " producttype='Server'";
                break;
        }

        SYSTEM_INFO si;
        memset(&si, 0, sizeof(SYSTEM_INFO));
        GetNativeSystemInfo(&si);
        switch (si.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_INTEL:
                os << " arch='i386'";
                break;
            case PROCESSOR_ARCHITECTURE_AMD64:
                os << " arch='x86_64'";
                break;
            case PROCESSOR_ARCHITECTURE_IA64:
                os << " arch='IA64'";
                break;
            case PROCESSOR_ARCHITECTURE_ARM:
                os << " arch='ARM'";
                break;
            case PROCESSOR_ARCHITECTURE_ARM64:
                os << " arch='ARM64'";
                break;
        }
        os << " cpucount='" << si.dwNumberOfProcessors << "'";

        MEMORYSTATUSEX ms;
        memset(&ms, 0, sizeof(MEMORYSTATUSEX));
        ms.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&ms)) {
            os << " memory='" << (ms.ullTotalPhys / (1024 * 1024)) << "M'";
        }

        os << "/>";
    }
    else {
        os << "<Windows/>";
    }
#endif
    return os;
}
