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

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibspconstants;
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

AssertionConsumerService::AssertionConsumerService(
    const DOMElement* e, const char* appId, Category& log, DOMNodeFilter* filter, const Remapper* remapper, bool deprecationSupport
    ) : AbstractHandler(e, log, filter, remapper)
{
    if (!e)
        return;
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        m_decoder.reset(SAMLConfig::getConfig().MessageDecoderManager.newPlugin(getString("Binding").second, e, deprecationSupport));
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
        out = send(request, in);
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
    scoped_ptr<HTTPRequest> req(getRequest(*app, in));

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(*app, ret));

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
    pair<bool,const char*> prop = getString("policyId", shibspconstants::ASCII_SHIBSPCONFIG_NS);  // may be namespace-qualified if inside handler element
    if (!prop.first)
        prop = getString("policyId");   // try unqualified
    if (!prop.first)
        prop = application.getString("policyId");   // unqualified in Application(s) element

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    scoped_ptr<opensaml::SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(
            getProfile(), application, &IDPSSODescriptor::ELEMENT_QNAME, prop.second
            )
        );

    string relayState;
    scoped_ptr<XMLObject> msg;
    try {
        // Decode the message and process it in a protocol-specific way.
        msg.reset(m_decoder->decode(relayState, httpRequest, &httpResponse, *(policy.get())));
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
                catch (const std::exception& ex) {
                    m_log.warn("error recovering relay state: %s", ex.what());
                }
            }

            return make_pair(true, httpResponse.sendRedirect(hook.c_str()));
        }

        return finalizeResponse(application, httpRequest, httpResponse, relayState);
    }
    catch (XMLToolingException& ex) {
        m_log.warn("error processing incoming assertion: %s", ex.what());

        // Recover relay state.
        if (!relayState.empty()) {
            try {
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
            catch (const std::exception& rsex) {
                m_log.warn("error recovering relay state: %s", rsex.what());
                relayState.erase();
                recoverRelayState(application, httpRequest, httpResponse, relayState, false);
            }
        }

        // Check for isPassive error condition.
        const char* sc2 = ex.getProperty("statusCode2");
        if (sc2 && !strcmp(sc2, "urn:oasis:names:tc:SAML:2.0:status:NoPassive")) {
            pair<bool,bool> ignore = getBool("ignoreNoPassive", shibspconstants::ASCII_SHIBSPCONFIG_NS);  // may be namespace-qualified inside handler element
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

const char* AssertionConsumerService::getProfile() const
{
    return nullptr;
}

const XMLCh* AssertionConsumerService::getProtocolFamily() const
{
    return m_decoder ? m_decoder->getProtocolFamily() : nullptr;
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
                catch (const std::exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        m_log.debug("extracting pushed attributes...");

        if (protmsg) {
            try {
                extractor->extractAttributes(application, request, issuer, *protmsg, resolvedAttributes);
            }
            catch (const std::exception& ex) {
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
            catch (const std::exception& ex) {
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
            catch (const std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        if (tokens) {
            for (indirect_iterator<vector<const Assertion*>::const_iterator> t = make_indirect_iterator(tokens->begin());
                    t != make_indirect_iterator(tokens->end()); ++t) {
                try {
                    extractor->extractAttributes(application, request, issuer, *t, resolvedAttributes);
                }
                catch (const std::exception& ex) {
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
            catch (const std::exception& ex) {
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
    catch (const std::exception&) {
        // Logging should be handled by the resolver plugin at whatever level is appropriate.
    }

    if (!resolvedAttributes.empty()) {
        try {
            return new DummyContext(resolvedAttributes);
        }
        catch (...) {
            for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            throw;
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

#endif
