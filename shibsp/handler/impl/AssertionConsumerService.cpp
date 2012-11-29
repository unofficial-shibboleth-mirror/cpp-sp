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
 * AssertionConsumerService.cpp
 *
 * Base class for handlers that create sessions by consuming SSO protocol responses.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AssertionConsumerService.h"
#include "util/CGIParser.h"
#include "util/SPConstants.h"

# include <ctime>
#ifndef SHIBSP_LITE
# include "attribute/Attribute.h"
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/filtering/BasicFilteringContext.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "attribute/resolver/ResolutionContext.h"
# include "metadata/MetadataProviderCriteria.h"
# include "security/SecurityPolicy.h"
# include "security/SecurityPolicyProvider.h"
# include <boost/iterator/indirect_iterator.hpp>
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml1/core/Protocols.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/util/CommonDomainCookie.h>
using namespace samlconstants;
using opensaml::saml2md::MetadataProvider;
using opensaml::saml2md::RoleDescriptor;
using opensaml::saml2md::EntityDescriptor;
using opensaml::saml2md::IDPSSODescriptor;
using opensaml::saml2md::SPSSODescriptor;
#else
# include "lite/CommonDomainCookie.h"
#endif

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibspconstants;
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

AssertionConsumerService::AssertionConsumerService(
    const DOMElement* e, const char* appId, Category& log, DOMNodeFilter* filter, const map<string,string>* remapper
    ) : AbstractHandler(e, log, filter, remapper)
{
    if (!e)
        return;
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        m_decoder.reset(
            SAMLConfig::getConfig().MessageDecoderManager.newPlugin(
                getString("Binding").second, pair<const DOMElement*,const XMLCh*>(e,shibspconstants::SHIB2SPCONFIG_NS)
                )
            );
        m_decoder->setArtifactResolver(SPConfig::getConfig().getArtifactResolver());
    }
#endif
}

AssertionConsumerService::~AssertionConsumerService()
{
}

pair<bool,long> AssertionConsumerService::run(SPRequest& request, bool isHandler) const
{
    // Check for a message back to the ACS from a post-session hook.
    if (request.getQueryString() && strstr(request.getQueryString(), "hook=1")) {
        // Parse the query string only to preserve any POST data.
        CGIParser cgi(request, true);
        pair<CGIParser::walker,CGIParser::walker> param = cgi.getParameters("hook");
        if (param.first != param.second && param.first->second && !strcmp(param.first->second, "1")) {
            string target;
            param = cgi.getParameters("target");
            if (param.first != param.second && param.first->second)
                target = param.first->second;
            return finalizeResponse(request.getApplication(), request, request, target);
        }
    }

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively and directly process the message.
        return processMessage(request.getApplication(), request, request);
    }
    else {
        // When not out of process, we remote all the message processing.
        vector<string> headers(1, "Cookie");
        headers.push_back("User-Agent");
        headers.push_back("Accept-Language");
        DDF out,in = wrap(request, &headers);
        DDFJanitor jin(in), jout(out);
        out = request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void AssertionConsumerService::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for new session", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
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
    processMessage(*app, *req, *resp);
    out << ret;
}

pair<bool,long> AssertionConsumerService::processMessage(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    // Locate policy key.
    pair<bool,const char*> prop = getString("policyId", m_configNS.get());  // may be namespace-qualified if inside handler element
    if (!prop.first)
        prop = getString("policyId");   // try unqualified
    if (!prop.first)
        prop = application.getString("policyId");   // unqualified in Application(s) element

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    scoped_ptr<opensaml::SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(
            application, &IDPSSODescriptor::ELEMENT_QNAME, prop.second
            )
        );

    string relayState;
    scoped_ptr<XMLObject> msg;
    try {
        // Decode the message and process it in a protocol-specific way.
        msg.reset(m_decoder->decode(relayState, httpRequest, *(policy.get())));
        if (!msg)
            throw BindingException("Failed to decode an SSO protocol response.");
        implementProtocol(application, httpRequest, httpResponse, *policy, nullptr, *msg);

        // History cookie.
        auto_ptr_char issuer(policy->getIssuer() ? policy->getIssuer()->getName() : nullptr);
        if (issuer.get() && *issuer.get())
            maintainHistory(application, httpRequest, httpResponse, issuer.get());

        const EntityDescriptor* entity =
            dynamic_cast<const EntityDescriptor*>(policy->getIssuerMetadata() ? policy->getIssuerMetadata()->getParent() : nullptr);
        prop = application.getRelyingParty(entity)->getString("sessionHook");
        if (prop.first) {
            string hook(prop.second);
            httpRequest.absolutize(hook);

            // Compute the return URL. We use a self-referential link plus a hook indicator to break the cycle
            // and the relay state.
            const URLEncoder* encoder = XMLToolingConfig::getConfig().getURLEncoder();
            string returnURL = httpRequest.getRequestURL();
            returnURL = returnURL.substr(0, returnURL.find('?')) + "?hook=1";
            if (!relayState.empty())
                returnURL += "&target=" + encoder->encode(relayState.c_str());
            if (hook.find('?') == string::npos)
                hook += '?';
            else
                hook += '&';
            hook += "return=" + encoder->encode(returnURL.c_str());

            // Add the translated target resource in case it's of interest.
            if (!relayState.empty()) {
                try {
                    recoverRelayState(application, httpRequest, httpResponse, relayState, false);
                    hook += "&target=" + encoder->encode(relayState.c_str());
                }
                catch (std::exception& ex) {
                    m_log.warn("error recovering relay state: %s", ex.what());
                }
            }

            return make_pair(true, httpResponse.sendRedirect(hook.c_str()));
        }

        return finalizeResponse(application, httpRequest, httpResponse, relayState);
    }
    catch (XMLToolingException& ex) {
        // Recover relay state.
        if (!relayState.empty()) {
            try {
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
            catch (std::exception& rsex) {
                m_log.warn("error recovering relay state: %s", rsex.what());
                relayState.erase();
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
        }

        // Check for isPassive error condition.
        const char* sc2 = ex.getProperty("statusCode2");
        if (sc2 && !strcmp(sc2, "urn:oasis:names:tc:SAML:2.0:status:NoPassive")) {
            pair<bool,bool> ignore = getBool("ignoreNoPassive", m_configNS.get());  // may be namespace-qualified inside handler element
            if (!ignore.first)
                ignore = getBool("ignoreNoPassive");    // try unqualified
            if (ignore.first && ignore.second && !relayState.empty()) {
                m_log.debug("ignoring SAML status of NoPassive and redirecting to resource...");
                return make_pair(true, httpResponse.sendRedirect(relayState.c_str()));
            }
        }
        
        if (!relayState.empty()) {
            ex.addProperty("RelayState", relayState.c_str());
        }

        // Log the error.
        try {
            scoped_ptr<TransactionLog::Event> event(SPConfig::getConfig().EventManager.newPlugin(LOGIN_EVENT, nullptr));
            LoginEvent* error_event = dynamic_cast<LoginEvent*>(event.get());
            if (error_event) {
                error_event->m_exception = &ex;
                error_event->m_request = &httpRequest;
                error_event->m_app = &application;
                if (policy->getIssuerMetadata())
                    error_event->m_peer = dynamic_cast<const EntityDescriptor*>(policy->getIssuerMetadata()->getParent());
                auto_ptr_char prot(getProtocolFamily());
                error_event->m_protocol = prot.get();
                error_event->m_binding = getString("Binding").second;
                error_event->m_saml2Response = dynamic_cast<const saml2p::StatusResponseType*>(msg.get());
                if (!error_event->m_saml2Response)
                    error_event->m_saml1Response = dynamic_cast<const saml1p::Response*>(msg.get());
                application.getServiceProvider().getTransactionLog()->write(*error_event);
            }
            else {
                m_log.warn("unable to audit event, log event object was of an incorrect type");
            }
        }
        catch (std::exception& ex2) {
            m_log.warn("exception auditing event: %s", ex2.what());
        }

        // If no sign of annotation, try to annotate it now.
        if (!ex.getProperty("statusCode")) {
            annotateException(&ex, policy->getIssuerMetadata(), nullptr, false);    // wait to throw it
        }

        throw;
    }
#else
    throw ConfigurationException("Cannot process message using lite version of shibsp library.");
#endif
}

pair<bool,long> AssertionConsumerService::finalizeResponse(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, string& relayState
    ) const
{
    DDF postData = recoverPostData(application, httpRequest, httpResponse, relayState.c_str());
    DDFJanitor postjan(postData);
    recoverRelayState(application, httpRequest, httpResponse, relayState);
    application.limitRedirect(httpRequest, relayState.c_str());

    // Now redirect to the state value. By now, it should be set to *something* usable.
    // First check for POST data.
    if (!postData.islist()) {
        m_log.debug("ACS returning via redirect to: %s", relayState.c_str());
        return make_pair(true, httpResponse.sendRedirect(relayState.c_str()));
    }
    else {
        m_log.debug("ACS returning via POST to: %s", relayState.c_str());
        return make_pair(true, sendPostResponse(application, httpResponse, relayState.c_str(), postData));
    }
}

void AssertionConsumerService::checkAddress(const Application& application, const HTTPRequest& httpRequest, const char* issuedTo) const
{
    if (!issuedTo || !*issuedTo)
        return;

    const PropertySet* props = application.getPropertySet("Sessions");
    pair<bool,bool> checkAddress = props ? props->getBool("checkAddress") : make_pair(false,true);
    if (!checkAddress.first)
        checkAddress.second = true;

    if (checkAddress.second) {
        m_log.debug("checking client address");
        if (httpRequest.getRemoteAddr() != issuedTo) {
            throw FatalProfileException(
               "Your client's current address ($client_addr) differs from the one used when you authenticated "
                "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                "Please contact your local support staff or help desk for assistance.",
                namedparams(1, "client_addr", httpRequest.getRemoteAddr().c_str())
                );
        }
    }
}

#ifndef SHIBSP_LITE

const XMLCh* AssertionConsumerService::getProtocolFamily() const
{
    return m_decoder ? m_decoder->getProtocolFamily() : nullptr;
}

const char* AssertionConsumerService::getType() const
{
    return "AssertionConsumerService";
}

void AssertionConsumerService::generateMetadata(SPSSODescriptor& role, const char* handlerURL) const
{
    // Initial guess at index to use.
    pair<bool,unsigned int> ix = pair<bool,unsigned int>(false,0);
    if (!strncmp(handlerURL, "https", 5))
        ix = getUnsignedInt("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
    if (!ix.first)
        ix = getUnsignedInt("index");
    if (!ix.first)
        ix.second = 1;

    // Find maximum index in use and go one higher.
    const vector<saml2md::AssertionConsumerService*>& services = const_cast<const SPSSODescriptor&>(role).getAssertionConsumerServices();
    if (!services.empty() && ix.second <= services.back()->getIndex().second)
        ix.second = services.back()->getIndex().second + 1;

    const char* loc = getString("Location").second;
    string hurl(handlerURL);
    if (*loc != '/')
        hurl += '/';
    hurl += loc;
    auto_ptr_XMLCh widen(hurl.c_str());

    saml2md::AssertionConsumerService* ep = saml2md::AssertionConsumerServiceBuilder::buildAssertionConsumerService();
    ep->setLocation(widen.get());
    ep->setBinding(getXMLString("Binding").second);
    ep->setIndex(ix.second);
    role.getAssertionConsumerServices().push_back(ep);
}

opensaml::SecurityPolicy* AssertionConsumerService::createSecurityPolicy(
    const Application& application, const xmltooling::QName* role, bool validate, const char* policyId
    ) const
{
    return new SecurityPolicy(application, role, validate, policyId);
}

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

ResolutionContext* AssertionConsumerService::resolveAttributes(
    const Application& application,
    const saml2md::RoleDescriptor* issuer,
    const XMLCh* protocol,
    const saml1::NameIdentifier* v1nameid,
    const saml2::NameID* nameid,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const Assertion*>* tokens
    ) const
{
    return resolveAttributes(
        application,
        nullptr,
        issuer,
        protocol,
        nullptr,
        v1nameid,
        nullptr,
        nameid,
        nullptr,
        authncontext_class,
        authncontext_decl,
        tokens
        );
}

ResolutionContext* AssertionConsumerService::resolveAttributes(
    const Application& application,
    const GenericRequest* request,
    const RoleDescriptor* issuer,
    const XMLCh* protocol,
    const xmltooling::XMLObject* protmsg,
    const saml1::NameIdentifier* v1nameid,
    const saml1::AuthenticationStatement* v1statement,
    const saml2::NameID* nameid,
    const saml2::AuthnStatement* statement,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const Assertion*>* tokens
    ) const
{
    // First we do the extraction of any pushed information, including from metadata.
    vector<Attribute*> resolvedAttributes;
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

        if (protmsg) {
            try {
                extractor->extractAttributes(application, request, issuer, *protmsg, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        if (v1nameid || nameid) {
            try {
                if (v1nameid)
                    extractor->extractAttributes(application, request, issuer, *v1nameid, resolvedAttributes);
                else
                    extractor->extractAttributes(application, request, issuer, *nameid, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        if (v1statement || statement) {
            try {
                if (v1statement)
                    extractor->extractAttributes(application, request, issuer, *v1statement, resolvedAttributes);
                else
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
                    issuer ? dynamic_cast<const saml2md::EntityDescriptor*>(issuer->getParent()) : nullptr,
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

void AssertionConsumerService::extractMessageDetails(const Assertion& assertion, const XMLCh* protocol, opensaml::SecurityPolicy& policy) const
{
    policy.setMessageID(assertion.getID());
    policy.setIssueInstant(assertion.getIssueInstantEpoch());

    if (XMLString::equals(assertion.getElementQName().getNamespaceURI(), samlconstants::SAML20_NS)) {
        const saml2::Assertion* a2 = dynamic_cast<const saml2::Assertion*>(&assertion);
        if (a2) {
            m_log.debug("extracting issuer from SAML 2.0 assertion");
            policy.setIssuer(a2->getIssuer());
        }
    }
    else {
        const saml1::Assertion* a1 = dynamic_cast<const saml1::Assertion*>(&assertion);
        if (a1) {
            m_log.debug("extracting issuer from SAML 1.x assertion");
            policy.setIssuer(a1->getIssuer());
        }
    }

    if (policy.getIssuer() && !policy.getIssuerMetadata() && policy.getMetadataProvider()) {
        if (policy.getIssuer()->getFormat() && !XMLString::equals(policy.getIssuer()->getFormat(), saml2::NameIDType::ENTITY)) {
            m_log.warn("non-system entity issuer, skipping metadata lookup");
            return;
        }
        m_log.debug("searching metadata for assertion issuer...");
        pair<const EntityDescriptor*,const RoleDescriptor*> entity;
        MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
        mc.entityID_unicode = policy.getIssuer()->getName();
        mc.role = &IDPSSODescriptor::ELEMENT_QNAME;
        mc.protocol = protocol;
        entity = policy.getMetadataProvider()->getEntityDescriptor(mc);
        if (!entity.first) {
            auto_ptr_char iname(policy.getIssuer()->getName());
            m_log.warn("no metadata found, can't establish identity of issuer (%s)", iname.get());
        }
        else if (!entity.second) {
            m_log.warn("unable to find compatible IdP role in metadata");
        }
        else {
            policy.setIssuerMetadata(entity.second);
        }
    }
}

LoginEvent* AssertionConsumerService::newLoginEvent(const Application& application, const HTTPRequest& request) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::Logging))
        return nullptr;
    try {
        auto_ptr<TransactionLog::Event> event(SPConfig::getConfig().EventManager.newPlugin(LOGIN_EVENT, nullptr));
        LoginEvent* login_event = dynamic_cast<LoginEvent*>(event.get());
        if (login_event) {
            login_event->m_request = &request;
            login_event->m_app = &application;
            login_event->m_binding = getString("Binding").second;
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

void AssertionConsumerService::maintainHistory(
    const Application& application, const HTTPRequest& request, HTTPResponse& response, const char* entityID
    ) const
{
    static const char* defProps="; path=/";
    static const char* sslProps="; path=/; secure";

    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,bool> idpHistory = sessionProps->getBool("idpHistory");

    if (idpHistory.first && idpHistory.second) {
        pair<bool,const char*> cookieProps = sessionProps->getString("idpHistoryProps");
        if (!cookieProps.first)
            cookieProps = sessionProps->getString("cookieProps");
        if (!cookieProps.first || !strcmp(cookieProps.second, "http"))
            cookieProps.second = defProps;
        else if (!strcmp(cookieProps.second, "https"))
            cookieProps.second = sslProps;

        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(request.getCookie(CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days = sessionProps->getUnsignedInt("idpHistoryDays");
        if (!days.first || days.second == 0) {
            string c = string(cdc.set(entityID)) + cookieProps.second;
            response.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
        else {
            time_t now = time(nullptr) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
            struct tm res;
            struct tm* ptime = gmtime_r(&now,&res);
#else
            struct tm* ptime = gmtime(&now);
#endif
            char timebuf[64];
            strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT", ptime);
            string c = string(cdc.set(entityID)) + cookieProps.second + "; expires=" + timebuf;
            response.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
    }
}
