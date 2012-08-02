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
 * ExternalAuthHandler.cpp
 *
 * Handler for integrating with external authentication mechanisms.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"
#include "handler/SecuredHandler.h"

#include <sstream>
#include <boost/scoped_ptr.hpp>

#ifndef SHIBSP_LITE
# include "SessionCache.h"
# include "TransactionLog.h"
# include "attribute/SimpleAttribute.h"
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/filtering/BasicFilteringContext.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "attribute/resolver/ResolutionContext.h"
# include <boost/tokenizer.hpp>
# include <boost/iterator/indirect_iterator.hpp>
# include <saml/exceptions.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/util/DateTime.h>
# include <xmltooling/util/ParserPool.h>
# include <xmltooling/util/XMLHelper.h>
# include <xercesc/framework/MemBufInputSource.hpp>
# include <xercesc/framework/Wrapper4InputSource.hpp>
using namespace opensaml::saml2md;
using namespace opensaml;
using saml2::NameID;
using saml2::AuthnStatement;
using saml2::AuthnContext;
# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif
#endif

using namespace shibspconstants;
using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API ExternalAuth : public SecuredHandler, public RemotedHandler
    {
    public:
        ExternalAuth(const DOMElement* e, const char* appId);
        virtual ~ExternalAuth() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

        const char* getType() const {
            return "ExternalAuth";
        }

    private:
        pair<bool,long> processMessage(
            const Application& application,
            HTTPRequest& httpRequest,
            HTTPResponse& httpResponse,
            DDF& reqDDF,
            const DDF* respDDF=nullptr
            ) const;
#ifndef SHIBSP_LITE
        LoginEvent* newLoginEvent(const Application& application, const HTTPRequest& request) const;
        ResolutionContext* resolveAttributes(
            const Application& application,
            const GenericRequest* request,
            const saml2md::RoleDescriptor* issuer,
            const XMLCh* protocol,
            const saml2::NameID* nameid,
            const saml2::AuthnStatement* statement,
            const XMLCh* authncontext_class,
            const XMLCh* authncontext_decl,
            const vector<const Assertion*>* tokens=nullptr,
            const vector<Attribute*>* inputAttributes=nullptr
            ) const;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL ExternalAuthFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ExternalAuth(p.first, p.second);
    }

};

namespace {
    static ostream& json_safe(ostream& os, const char* buf)
    {
        os << '"';
        for (; *buf; ++buf) {
            switch (*buf) {
                case '\\':
                case '"':
                    os << '\\';
                    os << *buf;
                    break;
                case '\b':
                    os << "\\b";
                    break;
                case '\t':
                    os << "\\t";
                    break;
                case '\n':
                    os << "\\n";
                    break;
                case '\f':
                    os << "\\f";
                    break;
                case '\r':
                    os << "\\r";
                    break;
                default:
                    os << *buf;
            }
        }
        os << '"';
        return os;
    }
};

ExternalAuth::ExternalAuth(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".ExternalAuth"), "acl", "127.0.0.1 ::1")
{
    setAddress("run::ExternalAuth");
}

pair<bool,long> ExternalAuth::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    try {
        if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message, except that we
            // have to indirect the request anyway in order to override the client address. This is
            // the simplest way to get a delegated HTTPRequest object, and since this code path is
            // not really one we expect to use, it's good enough.
            vector<string> headers(1, "User-Agent");
            headers.push_back("Accept");
            headers.push_back("Accept-Language");
            headers.push_back("Cookie");
            DDF in = wrap(request, &headers);
            DDFJanitor jin(in);
            scoped_ptr<HTTPRequest> fakedreq(getRequest(in));
            return processMessage(request.getApplication(), *fakedreq, request, in);
        }
        else {
            // When not out of process, we remote all the message processing.
            vector<string> headers(1, "User-Agent");
            headers.push_back("Accept");
            headers.push_back("Accept-Language");
            headers.push_back("Cookie");
            DDF out,in = wrap(request, &headers);
            DDFJanitor jin(in), jout(out);
            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        istringstream msg("External Authentication Failed");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void ExternalAuth::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for external authentication", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for external authentication, deleted?");
    }

    // Unpack the request.
    scoped_ptr<HTTPRequest> req(getRequest(in));

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    try {
        processMessage(*app, *req, *resp, in, &ret);
    }
    catch (std::exception& ex) {
        m_log.error("raising exception: %s", ex.what());
        throw;
    }
    out << ret;
}

pair<bool,long> ExternalAuth::processMessage(
    const Application& application, HTTPRequest& httpRequest, HTTPResponse& httpResponse, DDF& reqDDF, const DDF* respDDF
    ) const
{
#ifndef SHIBSP_LITE
    string session_id;
    SessionCache* cache = application.getServiceProvider().getSessionCache();
    MetadataProvider* m = application.getMetadataProvider(false);
    Locker mocker(m);

    scoped_ptr<TransactionLog::Event> event;
    LoginEvent* login_event = nullptr;
    if (SPConfig::getConfig().isEnabled(SPConfig::Logging)) {
        event.reset(SPConfig::getConfig().EventManager.newPlugin(LOGIN_EVENT, nullptr));
        login_event = dynamic_cast<LoginEvent*>(event.get());
        if (login_event)
            login_event->m_app = &application;
        else
            m_log.warn("unable to audit event, log event object was of an incorrect type");
    }

    string ctype(httpRequest.getContentType());
    if (ctype == "text/xml" || ctype == "application/samlassertion+xml") {
        const char* body = httpRequest.getRequestBody();
        if (!body)
            throw FatalProfileException("Request body was empty.");

        // Parse and bind the document into an XMLObject.
        MemBufInputSource src(reinterpret_cast<const XMLByte*>(body), httpRequest.getContentLength(), "SAMLAssertion");
        Wrapper4InputSource dsrc(&src, false);
        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(dsrc);
        XercesJanitor<DOMDocument> janitor(doc);
        auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        janitor.release();

        saml2::Assertion* token = dynamic_cast<saml2::Assertion*>(xmlObject.get());
        if (!token)
            throw FatalProfileException("Request body did not contain a SAML 2.0 assertion.");
        else if (token->getAuthnStatements().empty())
            throw FatalProfileException("Assertion in request did not contain an AuthnStatement.");

        // We're not implementing a full SAML profile here, only a minimal one that ignores most
        // security checking, conditions, etc. The caller is in full control here and we just consume
        // what we're given. The only thing we're honoring is the authentication information we find
        // and processing any attributes.

        const XMLCh* protocol = nullptr;
        pair<const EntityDescriptor*, const RoleDescriptor*> issuer = pair<const EntityDescriptor*, const RoleDescriptor*>(nullptr,nullptr);
        if (m && token->getIssuer() && token->getIssuer()->getName()) {
            MetadataProvider::Criteria mc;
            mc.entityID_unicode = token->getIssuer()->getName();
            mc.role = &IDPSSODescriptor::ELEMENT_QNAME;
            mc.protocol = samlconstants::SAML20P_NS;
            issuer = m->getEntityDescriptor(mc);
            if (!issuer.first) {
                auto_ptr_char iname(token->getIssuer()->getName());
                m_log.warn("no metadata found for issuer (%s)", iname.get());
            }
            else if (!issuer.second) {
                auto_ptr_char iname(token->getIssuer()->getName());
                m_log.warn("no IdP role found in metadata for issuer (%s)", iname.get());
            }
            protocol = mc.protocol;
        }

        const saml2::NameID* nameid = nullptr;
        if (token->getSubject())
            nameid = token->getSubject()->getNameID();
        const AuthnStatement* ssoStatement = token->getAuthnStatements().front();

        // authnskew allows rejection of SSO if AuthnInstant is too old.
        const PropertySet* sessionProps = application.getPropertySet("Sessions");
        pair<bool,unsigned int> authnskew = sessionProps ? sessionProps->getUnsignedInt("maxTimeSinceAuthn") : pair<bool,unsigned int>(false,0);

        time_t now(time(nullptr));
        if (ssoStatement->getAuthnInstant() &&
                ssoStatement->getAuthnInstantEpoch() - XMLToolingConfig::getConfig().clock_skew_secs > now) {
            throw FatalProfileException("The AuthnInstant was future-dated.");
        }
        else if (authnskew.first && authnskew.second && ssoStatement->getAuthnInstant() &&
                ssoStatement->getAuthnInstantEpoch() <= now && (now - ssoStatement->getAuthnInstantEpoch() > authnskew.second)) {
            throw FatalProfileException("The gap between now and the AuthnInstant exceeds the allowed limit.");
        }
        else if (authnskew.first && authnskew.second && ssoStatement->getAuthnInstant() == nullptr) {
            throw FatalProfileException("No AuthnInstant was supplied, violating local policy.");
        }

        // Session expiration for SAML 2.0 is jointly IdP- and SP-driven.
        time_t sessionExp = ssoStatement->getSessionNotOnOrAfter() ?
            (ssoStatement->getSessionNotOnOrAfterEpoch() + XMLToolingConfig::getConfig().clock_skew_secs) : 0;
        pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
        if (!lifetime.first || lifetime.second == 0)
            lifetime.second = 28800;
        if (sessionExp == 0)
            sessionExp = now + lifetime.second;     // IdP says nothing, calulate based on SP.
        else
            sessionExp = min(sessionExp, now + lifetime.second);    // Use the lowest.

        const XMLCh* authncontext_class = nullptr;
        const XMLCh* authncontext_decl = nullptr;
        const AuthnContext* authnContext = ssoStatement->getAuthnContext();
        if (authnContext) {
            authncontext_class = authnContext->getAuthnContextClassRef() ? authnContext->getAuthnContextClassRef()->getReference() : nullptr;
            authncontext_decl = authnContext->getAuthnContextDeclRef() ? authnContext->getAuthnContextDeclRef()->getReference() : nullptr;
        }

        // Extract client address.
        reqDDF.addmember("client_addr").string((const char*)nullptr);
        if (ssoStatement->getSubjectLocality() && ssoStatement->getSubjectLocality()->getAddress()) {
            auto_ptr_char addr(ssoStatement->getSubjectLocality()->getAddress());
            if (addr.get())
                reqDDF.getmember("client_addr").string(addr.get());
        }

        // The context will handle deleting attributes and tokens.
        vector<const Assertion*> tokens(1, token);
        scoped_ptr<ResolutionContext> ctx(
            resolveAttributes(
                application,
                &httpRequest,
                issuer.second,
                protocol,
                nameid,
                ssoStatement,
                authncontext_class,
                authncontext_decl,
                &tokens
                )
            );
        tokens.clear(); // don't store the original token in the session, since it was contrived

        if (ctx) {
            // Copy over any new tokens, but leave them in the context for cleanup.
            tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
        }

        cache->insert(
            session_id,
            application,
            httpRequest,
            httpResponse,
            sessionExp,
            issuer.first,
            protocol,
            nameid,
            ssoStatement->getAuthnInstant() ? ssoStatement->getAuthnInstant()->getRawData() : nullptr,
            ssoStatement->getSessionIndex(),
            authncontext_class,
            authncontext_decl,
            &tokens,
            &ctx->getResolvedAttributes()
            );

        if (login_event) {
            login_event->m_binding = "ExternalAuth/XML";
            login_event->m_sessionID = session_id.c_str();
            login_event->m_peer = issuer.first;
            auto_ptr_char prot(protocol);
            login_event->m_protocol = prot.get();
            login_event->m_nameID = nameid;
            login_event->m_saml2AuthnStatement = ssoStatement;
            if (ctx)
                login_event->m_attributes = &ctx->getResolvedAttributes();
            try {
                application.getServiceProvider().getTransactionLog()->write(*login_event);
            }
            catch (std::exception& ex) {
                m_log.warn("exception auditing event: %s", ex.what());
            }
        }
    }
    else if (ctype == "application/x-www-form-urlencoded") {
        auto_ptr_XMLCh protocol(httpRequest.getParameter("protocol"));
        const char* param = httpRequest.getParameter("issuer");
        pair<const EntityDescriptor*, const RoleDescriptor*> issuer = pair<const EntityDescriptor*, const RoleDescriptor*>(nullptr,nullptr);
        if (m && param && *param) {
            MetadataProvider::Criteria mc;
            mc.entityID_ascii = param;
            mc.role = &IDPSSODescriptor::ELEMENT_QNAME;
            mc.protocol = protocol.get();
            issuer = m->getEntityDescriptor(mc);
            if (!issuer.first)
                m_log.warn("no metadata found for issuer (%s)", param);
            else if (!issuer.second)
                m_log.warn("no IdP role found in metadata for issuer (%s)", param);
        }

        scoped_ptr<saml2::NameID> nameid;
        param = httpRequest.getParameter("NameID");
        if (param && *param) {
            nameid.reset(saml2::NameIDBuilder::buildNameID());
            auto_arrayptr<XMLCh> n(fromUTF8(param));
            nameid->setName(n.get());
            param = httpRequest.getParameter("Format");
            if (param && param) {
                auto_ptr_XMLCh f(param);
                nameid->setFormat(f.get());
            }
        }

        scoped_ptr<DateTime> authn_instant;
        param = httpRequest.getParameter("AuthnInstant");
        if (param && *param) {
            auto_ptr_XMLCh d(param);
            authn_instant.reset(new DateTime(d.get()));
            authn_instant->parseDateTime();
        }

        auto_ptr_XMLCh session_index(httpRequest.getParameter("SessionIndex"));
        auto_ptr_XMLCh authncontext_class(httpRequest.getParameter("AuthnContextClassRef"));
        auto_ptr_XMLCh authncontext_decl(httpRequest.getParameter("AuthnContextDeclRef"));

        time_t sessionExp = 0;
        param = httpRequest.getParameter("lifetime");
        if (param && param)
            sessionExp = atol(param);
        if (sessionExp) {
            sessionExp += time(nullptr);
        }
        else {
            const PropertySet* sessionProps = application.getPropertySet("Sessions");
            pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
            if (!lifetime.first || lifetime.second == 0)
                lifetime.second = 28800;
            sessionExp = time(nullptr) + lifetime.second;
        }

        // Create simple attributes around whatever parameters are specified.
        vector<Attribute*> resolvedAttributes;
        param = httpRequest.getParameter("attributes");
        if (param && *param) {
            char_separator<char> sep(", ");
            string dup(param);
            tokenizer< char_separator<char> > tokens(dup, sep);
            try {
                for (tokenizer< char_separator<char> >::iterator t = tokens.begin(); t != tokens.end(); ++t) {
                    vector<const char*> vals;
                    if (httpRequest.getParameters(t->c_str(), vals)) {
                        vector<string> ids(1, *t);
                        auto_ptr<SimpleAttribute> attr(new SimpleAttribute(ids));
                        vector<string>& dest = attr->getValues();
                        for (vector<const char*>::const_iterator v = vals.begin(); v != vals.end(); ++v)
                            dest.push_back(*v);
                        resolvedAttributes.push_back(attr.get());
                        attr.release();
                    }
                }
            }
            catch (std::exception&) {
                for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
                throw;
            }
        }

        // Get actual client address.
        reqDDF.addmember("client_addr").string(httpRequest.getParameter("address"));

        scoped_ptr<ResolutionContext> ctx(
            resolveAttributes(
                application,
                &httpRequest,
                issuer.second,
                protocol.get(),
                nameid.get(),
                nullptr,
                authncontext_class.get(),
                authncontext_decl.get(),
                nullptr,
                &resolvedAttributes
                )
            );

        vector<const Assertion*> tokens;
        if (ctx) {
            // Copy over any new tokens, but leave them in the context for cleanup.
            tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
        }

        cache->insert(
            session_id,
            application,
            httpRequest,
            httpResponse,
            sessionExp,
            issuer.first,
            protocol.get(),
            nameid.get(),
            authn_instant ? authn_instant->getRawData() : nullptr,
            session_index.get(),
            authncontext_class.get(),
            authncontext_decl.get(),
            &tokens,
            &ctx->getResolvedAttributes()
            );

        if (login_event) {
            login_event->m_binding = "ExternalAuth/POST";
            login_event->m_sessionID = session_id.c_str();
            login_event->m_peer = issuer.first;
            login_event->m_protocol = httpRequest.getParameter("protocol");
            login_event->m_nameID = nameid.get();
            if (ctx)
                login_event->m_attributes = &ctx->getResolvedAttributes();
            try {
                application.getServiceProvider().getTransactionLog()->write(*login_event);
            }
            catch (std::exception& ex) {
                m_log.warn("exception auditing event: %s", ex.what());
            }
        }
    }
    else {
        throw FatalProfileException("Submission was not in a recognized SAML assertion or form-encoded format.");
    }

    const char* param = httpRequest.getParameter("RelayState");
    string target(param ? param : "");
    try {
        recoverRelayState(application, httpRequest, httpResponse, target);
    }
    catch (std::exception& ex) {
        m_log.error("error recovering relay state: %s", ex.what());
        target.erase();
    }

    stringstream os;
    string accept = httpRequest.getHeader("Accept");
    if (accept.find("application/json") != string::npos) {
        httpResponse.setContentType("application/json");
        os << "{ \"SessionID\": "; json_safe(os, session_id.c_str());
        bool firstCookie = true;
        if (respDDF) {
            DDF hdr;
            DDF hdrs = respDDF->getmember("headers");
            hdr = hdrs.first();
            while (hdr.isstring()) {
                if (!strcmp(hdr.name(), "Set-Cookie")) {
                    if (firstCookie) {
                        os << ", \"Cookies\": [ ";
                        firstCookie = false;
                    }
                    else {
                        os << ", ";
                    }
                    json_safe(os, hdr.string());
                }
                hdr = hdrs.next();
            }
        }
        os << " ]";
        if (!target.empty())
            os << ", \"RelayState\": "; json_safe(os, target.c_str());
        os << " }";
    }
    else {
        httpResponse.setContentType("text/xml");
        static const XMLCh _ExternalAuth[] = UNICODE_LITERAL_12(E,x,t,e,r,n,a,l,A,u,t,h);
        static const XMLCh _SessionID[] = UNICODE_LITERAL_9(S,e,s,s,i,o,n,I,D);
        static const XMLCh _RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
        static const XMLCh _Cookie[] = UNICODE_LITERAL_6(C,o,o,k,i,e);
        DOMDocument* retdoc = XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<DOMDocument> retjanitor(retdoc);
        retdoc->appendChild(retdoc->createElement(_ExternalAuth));
        auto_ptr_XMLCh wideid(session_id.c_str());
        DOMElement* child = retdoc->createElement(_SessionID);
        child->appendChild(retdoc->createTextNode(wideid.get()));
        retdoc->getDocumentElement()->appendChild(child);
        if (respDDF) {
            DDF hdr;
            DDF hdrs = respDDF->getmember("headers");
            hdr = hdrs.first();
            while (hdr.isstring()) {
                if (!strcmp(hdr.name(), "Set-Cookie")) {
                    child = retdoc->createElement(_Cookie);
                    auto_ptr_XMLCh wideval(hdr.string());
                    child->appendChild(retdoc->createTextNode(wideval.get()));
                    retdoc->getDocumentElement()->appendChild(child);
                }
                hdr = hdrs.next();
            }
        }
        if (!target.empty()) {
            auto_ptr_XMLCh widetar(target.c_str());
            child = retdoc->createElement(_RelayState);
            child->appendChild(retdoc->createTextNode(widetar.get()));
            retdoc->getDocumentElement()->appendChild(child);
        }
        XMLHelper::serialize(retdoc->getDocumentElement(), os, true);
    }
    return make_pair(true, httpResponse.sendResponse(os));
#else
    return make_pair(false, 0L);
#endif
}

#ifndef SHIBSP_LITE

namespace {
    class SHIBSP_DLLLOCAL DummyContext : public ResolutionContext
    {
    public:
        DummyContext(const vector<Attribute*>& attributes) : m_attributes(attributes) {
        }

        virtual ~DummyContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
        }

        vector<Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<Assertion*>& getResolvedAssertions() {
            return m_tokens;
        }

    private:
        vector<Attribute*> m_attributes;
        static vector<Assertion*> m_tokens; // never any tokens, so just share an empty vector
    };
};

vector<Assertion*> DummyContext::m_tokens;

ResolutionContext* ExternalAuth::resolveAttributes(
    const Application& application,
    const GenericRequest* request,
    const RoleDescriptor* issuer,
    const XMLCh* protocol,
    const saml2::NameID* nameid,
    const saml2::AuthnStatement* statement,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const Assertion*>* tokens,
    const vector<Attribute*>* inputAttributes
    ) const
{
    vector<Attribute*> resolvedAttributes;
    if (inputAttributes)
        resolvedAttributes = *inputAttributes;

    // First we do the extraction of any pushed information, including from metadata.
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        Locker extlocker(extractor);
        if (issuer) {
            pair<bool,const char*> mprefix = application.getString("metadataAttributePrefix");
            if (mprefix.first) {
                m_log.debug("extracting metadata-derived attributes...");
                try {
                    // We pass nullptr for "issuer" because the IdP isn't the one asserting metadata-based attributes.
                    extractor->extractAttributes(application, request, nullptr, *issuer, resolvedAttributes);
                    for (indirect_iterator<vector<Attribute*>::iterator> a = make_indirect_iterator(resolvedAttributes.begin());
                            a != make_indirect_iterator(resolvedAttributes.end()); ++a) {
                        vector<string>& ids = a->getAliases();
                        for (vector<string>::iterator id = ids.begin(); id != ids.end(); ++id)
                            *id = mprefix.second + *id;
                    }
                }
                catch (std::exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        m_log.debug("extracting pushed attributes...");

        if (nameid) {
            try {
                extractor->extractAttributes(application, request, issuer, *nameid, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        if (statement) {
            try {
                extractor->extractAttributes(application, request, issuer, *statement, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        if (tokens) {
            for (indirect_iterator<vector<const Assertion*>::const_iterator> t = make_indirect_iterator(tokens->begin());
                    t != make_indirect_iterator(tokens->end()); ++t) {
                try {
                    extractor->extractAttributes(application, request, issuer, *t, resolvedAttributes);
                }
                catch (std::exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter && !resolvedAttributes.empty()) {
            BasicFilteringContext fc(application, resolvedAttributes, issuer, authncontext_class, authncontext_decl);
            Locker filtlocker(filter);
            try {
                filter->filterAttributes(fc, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception filtering attributes: %s", ex.what());
                m_log.error("dumping extracted attributes due to filtering exception");
                for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
                resolvedAttributes.clear();
            }
        }
    }
    else {
        m_log.warn("no AttributeExtractor plugin installed, check log during startup");
    }

    try {
        AttributeResolver* resolver = application.getAttributeResolver();
        if (resolver) {
            m_log.debug("resolving attributes...");

            Locker locker(resolver);
            auto_ptr<ResolutionContext> ctx(
                resolver->createResolutionContext(
                    application,
                    request,
                    issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent()) : nullptr,
                    protocol,
                    nameid,
                    authncontext_class,
                    authncontext_decl,
                    tokens,
                    &resolvedAttributes
                    )
                );
            resolver->resolveAttributes(*ctx);
            // Copy over any pushed attributes.
            while (!resolvedAttributes.empty()) {
                ctx->getResolvedAttributes().push_back(resolvedAttributes.back());
                resolvedAttributes.pop_back();
            }
            return ctx.release();
        }
    }
    catch (std::exception& ex) {
        m_log.error("attribute resolution failed: %s", ex.what());
    }

    if (!resolvedAttributes.empty()) {
        try {
            return new DummyContext(resolvedAttributes);
        }
        catch (bad_alloc&) {
            for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
        }
    }
    return nullptr;
}

LoginEvent* ExternalAuth::newLoginEvent(const Application& application, const HTTPRequest& request) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::Logging))
        return nullptr;
    try {
        auto_ptr<TransactionLog::Event> event(SPConfig::getConfig().EventManager.newPlugin(LOGIN_EVENT, nullptr));
        LoginEvent* login_event = dynamic_cast<LoginEvent*>(event.get());
        if (login_event) {
            login_event->m_request = &request;
            login_event->m_app = &application;
            login_event->m_binding = "ExternalAuth";
            event.release();
            return login_event;
        }
        else {
            m_log.warn("unable to audit event, log event object was of an incorrect type");
        }
    }
    catch (std::exception& ex) {
        m_log.warn("exception auditing event: %s", ex.what());
    }
    return nullptr;
}

#endif