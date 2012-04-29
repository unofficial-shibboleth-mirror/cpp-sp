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
 * RemotedHandler.cpp
 * 
 * Base class for handlers that need SP request/response layer to be remoted. 
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "GSSRequest.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"

#include <algorithm>
#include <boost/scoped_ptr.hpp>
#include <xmltooling/unicode.h>
#include <xercesc/util/Base64.hpp>

#ifndef SHIBSP_LITE
# include "util/CGIParser.h"
# include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
# include <xsec/enc/XSECCryptoException.hpp>
# include <xsec/framework/XSECException.hpp>
# include <xsec/framework/XSECProvider.hpp>
#endif

#ifdef HAVE_GSSAPI_NAMINGEXTS
# ifdef SHIBSP_HAVE_GSSMIT
#  include <gssapi/gssapi_ext.h>
# endif
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

#ifndef SHIBSP_LITE
namespace shibsp {
    class SHIBSP_DLLLOCAL RemotedRequest : 
#ifdef SHIBSP_HAVE_GSSAPI
        public GSSRequest,
#endif
        public HTTPRequest
    {
        DDF& m_input;
        mutable scoped_ptr<CGIParser> m_parser;
        mutable vector<XSECCryptoX509*> m_certs;
#ifdef SHIBSP_HAVE_GSSAPI
        mutable gss_ctx_id_t m_gssctx;
        mutable gss_name_t m_gssname;
#endif
    public:
        RemotedRequest(DDF& input) : m_input(input), m_parser(nullptr)
#ifdef SHIBSP_HAVE_GSSAPI
            , m_gssctx(GSS_C_NO_CONTEXT), m_gssname(GSS_C_NO_NAME)
#endif
        {
        }

        virtual ~RemotedRequest() {
            for_each(m_certs.begin(), m_certs.end(), xmltooling::cleanup<XSECCryptoX509>());
#ifdef SHIBSP_HAVE_GSSAPI
            OM_uint32 minor;
            if (m_gssctx != GSS_C_NO_CONTEXT)
                gss_delete_sec_context(&minor, &m_gssctx, GSS_C_NO_BUFFER);
            if (m_gssname != GSS_C_NO_NAME)
                gss_release_name(&minor, &m_gssname);
#endif
        }

        // GenericRequest
        const char* getScheme() const {
            return m_input["scheme"].string();
        }
        bool isSecure() const {
            return HTTPRequest::isSecure();
        }
        const char* getHostname() const {
            return m_input["hostname"].string();
        }
        int getPort() const {
            return m_input["port"].integer();
        }
        std::string getContentType() const {
            DDF s = m_input["content_type"];
            return s.string() ? s.string() : "";
        }
        long getContentLength() const {
            return m_input["content_length"].integer();
        }
        const char* getRequestBody() const {
            return m_input["body"].string();
        }

        const char* getParameter(const char* name) const;
        std::vector<const char*>::size_type getParameters(const char* name, std::vector<const char*>& values) const;
        
        std::string getRemoteUser() const {
            DDF s = m_input["remote_user"];
            return s.string() ? s.string() : "";
        }
        std::string getRemoteAddr() const {
            DDF s = m_input["client_addr"];
            return s.string() ? s.string() : "";
        }

        const std::vector<XSECCryptoX509*>& getClientCertificates() const;
        
#ifdef SHIBSP_HAVE_GSSAPI
        // GSSRequest
        gss_ctx_id_t getGSSContext() const;
        gss_name_t getGSSName() const;
#endif

        // HTTPRequest
        const char* getMethod() const {
            return m_input["method"].string();
        }
        const char* getRequestURI() const {
            return m_input["uri"].string();
        }
        const char* getRequestURL() const {
            return m_input["url"].string();
        }
        const char* getQueryString() const {
            return m_input["query"].string();
        }
        std::string getHeader(const char* name) const {
            DDF s = m_input["headers"][name];
            return s.string() ? s.string() : "";
        }
    };

    class SHIBSP_DLLLOCAL RemotedResponse : public virtual HTTPResponse 
    {
        DDF& m_output;
    public:
        RemotedResponse(DDF& output) : m_output(output) {}
        virtual ~RemotedResponse() {}
       
        // GenericResponse
        long sendResponse(std::istream& inputStream, long status);
        
        // HTTPResponse
        void setResponseHeader(const char* name, const char* value);
        long sendRedirect(const char* url);
    };
}

const char* RemotedRequest::getParameter(const char* name) const
{
    if (!m_parser)
        m_parser.reset(new CGIParser(*this));
    
    pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
    return (bounds.first==bounds.second) ? nullptr : bounds.first->second;
}

std::vector<const char*>::size_type RemotedRequest::getParameters(const char* name, std::vector<const char*>& values) const
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

const std::vector<XSECCryptoX509*>& RemotedRequest::getClientCertificates() const
{
    if (m_certs.empty()) {
        DDF certs = m_input["certificates"];
        DDF cert = certs.first();
        while (cert.string()) {
            try {
                auto_ptr<XSECCryptoX509> x509(XSECPlatformUtils::g_cryptoProvider->X509());
                if (strstr(cert.string(), "BEGIN"))
                    x509->loadX509PEM(cert.string(), cert.strlen());
                else
                    x509->loadX509Base64Bin(cert.string(), cert.strlen());
                m_certs.push_back(x509.get());
                x509.release();
            }
            catch(XSECException& e) {
                auto_ptr_char temp(e.getMsg());
                Category::getInstance(SHIBSP_LOGCAT".SPRequest").error("XML-Security exception loading client certificate: %s", temp.get());
            }
            catch(XSECCryptoException& e) {
                Category::getInstance(SHIBSP_LOGCAT".SPRequest").error("XML-Security exception loading client certificate: %s", e.getMsg());
            }
            cert = certs.next();
        }
    }
    return m_certs;
}

#ifdef SHIBSP_HAVE_GSSAPI
gss_ctx_id_t RemotedRequest::getGSSContext() const
{
    if (m_gssctx == GSS_C_NO_CONTEXT) {
        const char* encoded = m_input["gss_context"].string();
        if (encoded) {
            xsecsize_t x;
            XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(encoded), &x);
            if (decoded) {
                gss_buffer_desc importbuf;
                importbuf.length = x;
                importbuf.value = decoded;
                OM_uint32 minor;
                OM_uint32 major = gss_import_sec_context(&minor, &importbuf, &m_gssctx);
                if (major != GSS_S_COMPLETE)
                    m_gssctx = GSS_C_NO_CONTEXT;
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                XMLString::release(&decoded);
#else
                XMLString::release((char**)&decoded);
#endif
            }
        }
    }
    return m_gssctx;
}

gss_name_t RemotedRequest::getGSSName() const
{
    if (m_gssname == GSS_C_NO_NAME) {
        const char* encoded = m_input["gss_name"].string();
        if (encoded) {
            xsecsize_t x;
            XMLByte* decoded = Base64::decode(reinterpret_cast<const XMLByte*>(encoded), &x);
            gss_buffer_desc importbuf;
            importbuf.length = x;
            importbuf.value = decoded;
            OM_uint32 major,minor;
#ifdef HAVE_GSSAPI_COMPOSITE_NAME
            major = gss_import_name(&minor, &importbuf, GSS_C_NT_EXPORT_NAME_COMPOSITE, &m_gssname);
#else
            major = gss_import_name(&minor, &importbuf, GSS_C_NT_EXPORT_NAME, &m_gssname);
#endif
            if (major != GSS_S_COMPLETE)
                m_gssname = GSS_C_NO_NAME;
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
            XMLString::release(&decoded);
#else
            XMLString::release((char**)&decoded);
#endif
        }

        if (m_gssname == GSS_C_NO_NAME) {
            gss_ctx_id_t ctx = getGSSContext();
             if (ctx != GSS_C_NO_CONTEXT) {
                 OM_uint32 minor;
                 OM_uint32 major = gss_inquire_context(&minor, ctx, &m_gssname, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                 if (major != GSS_S_COMPLETE)
                     m_gssname = GSS_C_NO_NAME;
             }
         }
    }
    return m_gssname;
}
#endif

long RemotedResponse::sendResponse(std::istream& in, long status)
{
    string msg;
    char buf[1024];
    while (in) {
        in.read(buf, 1024);
        msg.append(buf, in.gcount());
    }
    if (!m_output.isstruct())
        m_output.structure();
    m_output.addmember("response.data").string(msg.c_str());
    m_output.addmember("response.status").integer(status);
    return status;
}

void RemotedResponse::setResponseHeader(const char* name, const char* value)
{
    if (!m_output.isstruct())
        m_output.structure();
    DDF hdrs = m_output["headers"];
    if (hdrs.isnull())
        hdrs = m_output.addmember("headers").list();
    DDF h = DDF(name).string(value);
    hdrs.add(h);
}

long RemotedResponse::sendRedirect(const char* url)
{
    if (!m_output.isstruct())
        m_output.structure();
    m_output.addmember("redirect").unsafe_string(url);
    return HTTPResponse::XMLTOOLING_HTTP_STATUS_MOVED;
}

#endif

void RemotedHandler::setAddress(const char* address)
{
    if (!m_address.empty())
        throw ConfigurationException("Cannot register a remoting address twice for the same Handler.");
    m_address = address;
    SPConfig& conf = SPConfig::getConfig();
    if (!conf.isEnabled(SPConfig::InProcess)) {
        ListenerService* listener = conf.getServiceProvider()->getListenerService(false);
        if (listener)
            listener->regListener(m_address.c_str(), this);
        else
            Category::getInstance(SHIBSP_LOGCAT".Handler").info("no ListenerService available, handler remoting disabled");
    }
}

set<string> RemotedHandler::m_remotedHeaders;

RemotedHandler::RemotedHandler()
{
}

RemotedHandler::~RemotedHandler()
{
    SPConfig& conf = SPConfig::getConfig();
    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (listener && conf.isEnabled(SPConfig::OutOfProcess) && !conf.isEnabled(SPConfig::InProcess))
        listener->unregListener(m_address.c_str(),this);
}

void RemotedHandler::addRemotedHeader(const char* header)
{
    m_remotedHeaders.insert(header);
}

DDF RemotedHandler::wrap(const SPRequest& request, const vector<string>* headers, bool certs) const
{
    DDF in = DDF(m_address.c_str()).structure();
    in.addmember("application_id").string(request.getApplication().getId());
    in.addmember("scheme").string(request.getScheme());
    in.addmember("hostname").unsafe_string(request.getHostname());
    in.addmember("port").integer(request.getPort());
    in.addmember("content_type").string(request.getContentType().c_str());
    in.addmember("body").string(request.getRequestBody());
    in.addmember("content_length").integer(request.getContentLength());
    in.addmember("remote_user").string(request.getRemoteUser().c_str());
    in.addmember("client_addr").string(request.getRemoteAddr().c_str());
    in.addmember("method").string(request.getMethod());
    in.addmember("uri").unsafe_string(request.getRequestURI());
    in.addmember("url").unsafe_string(request.getRequestURL());
    in.addmember("query").string(request.getQueryString());

    if (headers || !m_remotedHeaders.empty()) {
        string hdr;
        DDF hin = in.addmember("headers").structure();
        if (headers) {
            for (vector<string>::const_iterator h = headers->begin(); h != headers->end(); ++h) {
                hdr = request.getHeader(h->c_str());
                if (!hdr.empty())
                    hin.addmember(h->c_str()).unsafe_string(hdr.c_str());
            }
        }
        for (set<string>::const_iterator hh = m_remotedHeaders.begin(); hh != m_remotedHeaders.end(); ++hh) {
            hdr = request.getHeader(hh->c_str());
            if (!hdr.empty())
                hin.addmember(hh->c_str()).unsafe_string(hdr.c_str());
        }
    }

    if (certs) {
#ifndef SHIBSP_LITE
        const vector<XSECCryptoX509*>& xvec = request.getClientCertificates();
        if (!xvec.empty()) {
            DDF clist = in.addmember("certificates").list();
            for (vector<XSECCryptoX509*>::const_iterator x = xvec.begin(); x!=xvec.end(); ++x) {
                DDF x509 = DDF(nullptr).string((*x)->getDEREncodingSB().rawCharBuffer());
                clist.add(x509);
            }
        }
#else
        const vector<string>& xvec = request.getClientCertificates();
        if (!xvec.empty()) {
            DDF clist = in.addmember("certificates").list();
            for (vector<string>::const_iterator x = xvec.begin(); x!=xvec.end(); ++x) {
                DDF x509 = DDF(nullptr).string(x->c_str());
                clist.add(x509);
            }
        }
#endif
    }

#ifdef SHIBSP_HAVE_GSSAPI
    const GSSRequest* gss = dynamic_cast<const GSSRequest*>(&request);
    if (gss) {
        gss_ctx_id_t ctx = gss->getGSSContext();
        if (ctx != GSS_C_NO_CONTEXT) {
            OM_uint32 minor;
            gss_buffer_desc contextbuf = GSS_C_EMPTY_BUFFER;
            OM_uint32 major = gss_export_sec_context(&minor, &ctx, &contextbuf);
            if (major == GSS_S_COMPLETE) {
                xsecsize_t len = 0;
                XMLByte* out = Base64::encode(reinterpret_cast<const XMLByte*>(contextbuf.value), contextbuf.length, &len);
                gss_release_buffer(&minor, &contextbuf);
                if (out) {
                    string ctx;
                    ctx.append(reinterpret_cast<char*>(out), len);
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                    XMLString::release(&out);
#else
                    XMLString::release((char**)&out);
#endif
                    in.addmember("gss_context").string(ctx.c_str());
                }
                else {
                    request.log(SPRequest::SPError, "error while base64-encoding GSS context");
                }
            }
            else {
                request.log(SPRequest::SPError, "error while exporting GSS context");
            }
        }
#ifdef HAVE_GSSAPI_NAMINGEXTS
        else {
            gss_name_t name = gss->getGSSName();
            if (name != GSS_C_NO_NAME) {
                OM_uint32 minor;
                gss_buffer_desc namebuf = GSS_C_EMPTY_BUFFER;
                OM_uint32 major = gss_export_name_composite(&minor, name, &namebuf);
                if (major == GSS_S_COMPLETE) {
                    xsecsize_t len = 0;
                    XMLByte* out = Base64::encode(reinterpret_cast<const XMLByte*>(namebuf.value), namebuf.length, &len);
                    gss_release_buffer(&minor, &namebuf);
                    if (out) {
                        string nm;
                        nm.append(reinterpret_cast<char*>(out), len);
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                        XMLString::release(&out);
#else
                        XMLString::release((char**)&out);
#endif
                        in.addmember("gss_name").string(nm.c_str());
                    }
                    else {
                        request.log(SPRequest::SPError, "error while base64-encoding GSS name");
                    }
                }
                else {
                    request.log(SPRequest::SPError, "error while exporting GSS name");
                }
            }
        }
#endif
    }
#endif

    return in;
}

pair<bool,long> RemotedHandler::unwrap(SPRequest& request, DDF& out) const
{
    DDF h = out["headers"];
    DDF hdr = h.first();
    while (hdr.isstring()) {
#ifdef HAVE_STRCASECMP
        if (!strcasecmp(hdr.name(), "Content-Type"))
#else
        if (!stricmp(hdr.name(), "Content-Type"))
#endif
            request.setContentType(hdr.string());
        else
            request.setResponseHeader(hdr.name(), hdr.string());
        hdr = h.next();
    }
    h = out["redirect"];
    if (h.isstring())
        return make_pair(true, request.sendRedirect(h.string()));
    h = out["response"];
    if (h.isstruct()) {
        istringstream s(h["data"].string());
        return make_pair(true, request.sendResponse(s, h["status"].integer()));
    }
    return make_pair(false, 0L);
}

HTTPRequest* RemotedHandler::getRequest(DDF& in) const
{
#ifndef SHIBSP_LITE
    return new RemotedRequest(in);
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

HTTPResponse* RemotedHandler::getResponse(DDF& out) const
{
#ifndef SHIBSP_LITE
    return new RemotedResponse(out);
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}
