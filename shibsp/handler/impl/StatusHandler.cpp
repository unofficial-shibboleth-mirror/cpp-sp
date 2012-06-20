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
 * StatusHandler.cpp
 *
 * Handler for exposing information about the internals of the SP.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"
#include "handler/SecuredHandler.h"
#include "util/CGIParser.h"

#include <boost/iterator/indirect_iterator.hpp>
#include <boost/scoped_ptr.hpp>
#include <xmltooling/version.h>
#include <xmltooling/util/DateTime.h>

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

using namespace shibsp;
#ifndef SHIBSP_LITE
# include "SessionCache.h"
# include "metadata/MetadataProviderCriteria.h"
# include <saml/version.h>
# include <saml/saml2/metadata/Metadata.h>
# include <xmltooling/security/Credential.h>
# include <xmltooling/security/CredentialCriteria.h>
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
#endif
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API StatusHandler : public SecuredHandler, public RemotedHandler
    {
    public:
        StatusHandler(const DOMElement* e, const char* appId);
        virtual ~StatusHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

    private:
        pair<bool,long> processMessage(const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse) const;
        ostream& systemInfo(ostream& os) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL StatusHandlerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new StatusHandler(p.first, p.second);
    }

#ifndef XMLTOOLING_NO_XMLSEC
    vector<XSECCryptoX509*> g_NoCerts;
#else
    vector<string> g_NoCerts;
#endif

    static char _x2c(const char *what)
    {
        register char digit;

        digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
        digit *= 16;
        digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
        return(digit);
    }

    class DummyRequest : public HTTPRequest
    {
    public:
        DummyRequest(const char* url) : m_parser(nullptr), m_url(url), m_scheme(nullptr), m_query(nullptr), m_port(0) {
#ifdef HAVE_STRCASECMP
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
            else
#else
            if (url && !strnicmp(url,"http://", 7)) {
                m_scheme = "http";
                m_port = 80;
                url += 7;
            }
            else if (url && !strnicmp(url,"https://", 8)) {
                m_scheme="https";
                m_port = 443;
                url += 8;
            }
            else
#endif
                throw invalid_argument("Target parameter was not an absolute URL.");

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
                    m_uri += _x2c(slash);
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
        long getContentLength() const {
            return 0;
        }
        string getRemoteAddr() const {
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
        virtual const
#ifndef XMLTOOLING_NO_XMLSEC
            std::vector<XSECCryptoX509*>&
#else
            std::vector<std::string>&
#endif
            getClientCertificates() const {
                return g_NoCerts;
        }

    private:
        mutable scoped_ptr<CGIParser> m_parser;
        const char* m_url;
        const char* m_scheme;
        const char* m_query;
        int m_port;
        string m_hostname,m_uri;
    };
};

StatusHandler::StatusHandler(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".StatusHandler"))
{
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
}

pair<bool,long> StatusHandler::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    const char* target = request.getParameter("target");
    if (target) {
        // RequestMap query, so handle it inproc.
        DummyRequest dummy(target);
        RequestMapper::Settings settings = request.getApplication().getServiceProvider().getRequestMapper()->getSettings(dummy);
        map<string,const char*> props;
        settings.first->getAll(props);

        DateTime now(time(nullptr));
        now.parseDateTime();
        auto_ptr_char timestamp(now.getFormattedString());
        request.setContentType("text/xml");
        stringstream msg;
        msg << "<StatusHandler time='" << timestamp.get() << "'>";
            msg << "<Version Xerces-C='" << XERCES_FULLVERSIONDOT
                << "' XML-Tooling-C='" << gXMLToolingDotVersionStr
#ifndef SHIBSP_LITE
                << "' XML-Security-C='" << XSEC_FULLVERSIONDOT
                << "' OpenSAML-C='" << gOpenSAMLDotVersionStr
#endif
                << "' Shibboleth='" << PACKAGE_VERSION << "'/>";
            systemInfo(msg) << "<RequestSettings";
            for (map<string,const char*>::const_iterator p = props.begin(); p != props.end(); ++p)
                msg << ' ' << p->first << "='" << p->second << "'";
            msg << '>' << target << "</RequestSettings>";
            msg << "<Status><OK/></Status>";
        msg << "</StatusHandler>";
        return make_pair(true, request.sendResponse(msg));
    }

    try {
        if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request, request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = wrap(request);
            DDFJanitor jin(in), jout(out);
            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (XMLToolingException& ex) {
        m_log.error("error while processing request: %s", ex.what());
        DateTime now(time(nullptr));
        now.parseDateTime();
        auto_ptr_char timestamp(now.getFormattedString());
        request.setContentType("text/xml");
        stringstream msg;
        msg << "<StatusHandler time='" << timestamp.get() << "'>";
            msg << "<Version Xerces-C='" << XERCES_FULLVERSIONDOT
                << "' XML-Tooling-C='" << gXMLToolingDotVersionStr
#ifndef SHIBSP_LITE
                << "' XML-Security-C='" << XSEC_FULLVERSIONDOT
                << "' OpenSAML-C='" << gOpenSAMLDotVersionStr
#endif
                << "' Shibboleth='" << PACKAGE_VERSION << "'/>";
            systemInfo(msg) << "<Status><Exception type='" << ex.getClassName() << "'>" << ex.what() << "</Exception></Status>";
        msg << "</StatusHandler>";
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        DateTime now(time(nullptr));
        now.parseDateTime();
        auto_ptr_char timestamp(now.getFormattedString());
        request.setContentType("text/xml");
        stringstream msg;
        msg << "<StatusHandler time='" << timestamp.get() << "'>";
            msg << "<Version Xerces-C='" << XERCES_FULLVERSIONDOT
                << "' XML-Tooling-C='" << gXMLToolingDotVersionStr
#ifndef SHIBSP_LITE
                << "' XML-Security-C='" << XSEC_FULLVERSIONDOT
                << "' OpenSAML-C='" << gOpenSAMLDotVersionStr
#endif
                << "' Shibboleth='" << PACKAGE_VERSION << "'/>";
            systemInfo(msg) << "<Status><Exception type='std::exception'>" << ex.what() << "</Exception></Status>";
        msg << "</StatusHandler>";
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void StatusHandler::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for status request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for status request, deleted?");
    }

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPRequest> req(getRequest(in));
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    processMessage(*app, *req, *resp);
    out << ret;
}

pair<bool,long> StatusHandler::processMessage(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing status request");

    DateTime now(time(nullptr));
    now.parseDateTime();
    auto_ptr_char timestamp(now.getFormattedString());

    stringstream s;
    s << "<StatusHandler time='" << timestamp.get() << "'>";
    const char* status = "<OK/>";

    s << "<Version Xerces-C='" << XERCES_FULLVERSIONDOT
        << "' XML-Tooling-C='" << gXMLToolingDotVersionStr
        << "' XML-Security-C='" << XSEC_FULLVERSIONDOT
        << "' OpenSAML-C='" << gOpenSAMLDotVersionStr
        << "' Shibboleth='" << PACKAGE_VERSION << "'/>";

    systemInfo(s);

    const char* param = nullptr;
    if (param) {
    }
    else {
        // General configuration and status report.
        try {
            SessionCache* sc = application.getServiceProvider().getSessionCache(false);
            if (sc) {
                sc->test();
                s << "<SessionCache><OK/></SessionCache>";
            }
            else {
                s << "<SessionCache><None/></SessionCache>";
            }
        }
        catch (XMLToolingException& ex) {
            s << "<SessionCache><Exception type='" << ex.getClassName() << "'>" << ex.what() << "</Exception></SessionCache>";
            status = "<Partial/>";
        }
        catch (std::exception& ex) {
            s << "<SessionCache><Exception type='std::exception'>" << ex.what() << "</Exception></SessionCache>";
            status = "<Partial/>";
        }

        MetadataProvider* m = application.getMetadataProvider(false);
        Locker mlock(m);

        const PropertySet* relyingParty = nullptr;
        param=httpRequest.getParameter("entityID");
        if (m && param)
            relyingParty = application.getRelyingParty(m->getEntityDescriptor(MetadataProviderCriteria(application, param)).first);
        else
            relyingParty = &application;

        s << "<Application id='" << application.getId() << "' entityID='" << relyingParty->getString("entityID").second << "'/>";

        if (m)
            m->outputStatus(s);

        s << "<Handlers>";
        vector<const Handler*> handlers;
        application.getHandlers(handlers);
        for (indirect_iterator<vector<const Handler*>::const_iterator> h = make_indirect_iterator(handlers.begin());
                h != make_indirect_iterator(handlers.end()); ++h) {
            s << "<Handler type='" << h->getType() << "' Location='" << h->getString("Location").second << "'";
            if (h->getString("Binding").first)
                s << " Binding='" << h->getString("Binding").second << "'";
            s << "/>";
        }
        s << "</Handlers>";

        CredentialResolver* credResolver = application.getCredentialResolver();
        if (credResolver) {
            Locker credLocker(credResolver);
            CredentialCriteria cc;
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            pair<bool,const char*> keyName = relyingParty->getString("keyName");
            if (keyName.first)
                cc.getKeyNames().insert(keyName.second);
            vector<const Credential*> creds;
            credResolver->resolve(creds, &cc);
            for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
                KeyInfo* kinfo = (*c)->getKeyInfo();
                if (kinfo) {
                    scoped_ptr<KeyDescriptor> kd(KeyDescriptorBuilder::buildKeyDescriptor());
                    kd->setUse(KeyDescriptor::KEYTYPE_SIGNING);
                    kd->setKeyInfo(kinfo);
                    s << *(kd.get());
                }
            }

            cc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
            creds.clear();
            cc.getKeyNames().clear();
            credResolver->resolve(creds, &cc);
            for (vector<const Credential*>::const_iterator c = creds.begin(); c != creds.end(); ++c) {
                KeyInfo* kinfo = (*c)->getKeyInfo();
                if (kinfo) {
                    scoped_ptr<KeyDescriptor> kd(KeyDescriptorBuilder::buildKeyDescriptor());
                    kd->setUse(KeyDescriptor::KEYTYPE_ENCRYPTION);
                    kd->setKeyInfo(kinfo);
                    s << *(kd.get());
                }
            }
        }
    }

    s << "<Status>" << status << "</Status></StatusHandler>";

    httpResponse.setContentType("text/xml");
    return make_pair(true, httpResponse.sendResponse(s));
#else
    return make_pair(false, 0L);
#endif
}

#ifdef WIN32
typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
#endif

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
    OSVERSIONINFOEX osvi;
    memset(&osvi, 0, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if(GetVersionEx((OSVERSIONINFO*)&osvi)) {
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
        PGNSI pGNSI = (PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
        if(pGNSI)
            pGNSI(&si);
        else
            GetSystemInfo(&si);
        switch (si.dwProcessorType) {
            case PROCESSOR_ARCHITECTURE_INTEL:
                os << " arch='i386'";
                break;
            case PROCESSOR_ARCHITECTURE_AMD64:
                os << " arch='x86_64'";
                break;
            case PROCESSOR_ARCHITECTURE_IA64:
                os << " arch='IA64'";
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
#endif
    return os;
}
