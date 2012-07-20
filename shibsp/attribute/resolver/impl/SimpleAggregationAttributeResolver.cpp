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
 * SimpleAggregationAttributeResolver.cpp
 *
 * AttributeResolver based on SAML queries to third-party AA sources.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/NameIDAttribute.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/BasicFilteringContext.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "binding/SOAPClient.h"
#include "metadata/MetadataProviderCriteria.h"
#include "security/SecurityPolicy.h"
#include "security/SecurityPolicyProvider.h"
#include "util/SPConstants.h"

#include <boost/algorithm/string.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <saml/exceptions.h>
#include <saml/SAMLConfig.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/TrustEngine.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL SimpleAggregationContext : public ResolutionContext
    {
    public:
        SimpleAggregationContext(const Application& application, const Session& session)
            : m_app(application),
              m_request(nullptr),
              m_session(&session),
              m_nameid(nullptr),
              m_class(session.getAuthnContextClassRef()),
              m_decl(session.getAuthnContextDeclRef()),
              m_inputTokens(nullptr),
              m_inputAttributes(nullptr) {
        }

        SimpleAggregationContext(
            const Application& application,
            const GenericRequest* request=nullptr,
            const NameID* nameid=nullptr,
            const XMLCh* entityID=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<shibsp::Attribute*>* attributes=nullptr
            ) : m_app(application),
                m_request(request),
                m_session(nullptr),
                m_nameid(nameid),
                m_entityid(entityID),
                m_class(authncontext_class),
                m_decl(authncontext_decl),
                m_inputTokens(tokens),
                m_inputAttributes(attributes) {
        }

        ~SimpleAggregationContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        const Application& getApplication() const {
            return m_app;
        }
        const GenericRequest* getRequest() const {
            return m_request;
        }
        const char* getEntityID() const {
            return m_session ? m_session->getEntityID() : m_entityid.get();
        }
        const NameID* getNameID() const {
            return m_session ? m_session->getNameID() : m_nameid;
        }
        const XMLCh* getClassRef() const {
            return m_class.get();
        }
        const XMLCh* getDeclRef() const {
            return m_decl.get();
        }
        const Session* getSession() const {
            return m_session;
        }
        const vector<shibsp::Attribute*>* getInputAttributes() const {
            return m_inputAttributes;
        }
        const vector<const opensaml::Assertion*>* getInputTokens() const {
            return m_inputTokens;
        }
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const Application& m_app;
        const GenericRequest* m_request;
        const Session* m_session;
        const NameID* m_nameid;
        auto_ptr_char m_entityid;
        auto_ptr_XMLCh m_class;
        auto_ptr_XMLCh m_decl;
        const vector<const opensaml::Assertion*>* m_inputTokens;
        const vector<shibsp::Attribute*>* m_inputAttributes;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };

    class SHIBSP_DLLLOCAL SimpleAggregationResolver : public AttributeResolver
    {
    public:
        SimpleAggregationResolver(const DOMElement* e);
        ~SimpleAggregationResolver() {}

        Lockable* lock() {return this;}
        void unlock() {}

        // deprecated method
        ResolutionContext* createResolutionContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<shibsp::Attribute*>* attributes=nullptr
            ) const {
            return createResolutionContext(application, nullptr, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const GenericRequest* request,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<shibsp::Attribute*>* attributes=nullptr
            ) const {
            return new SimpleAggregationContext(
                application, request, nameid, (issuer ? issuer->getEntityID() : nullptr), authncontext_class, authncontext_decl, tokens, attributes
                );
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new SimpleAggregationContext(application,session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            if (m_extractor)
                m_extractor->getAttributeIds(attributes);
        }

    private:
        void doQuery(SimpleAggregationContext& ctx, const char* entityID, const NameID* name) const;

        Category& m_log;
        string m_policyId;
        bool m_subjectMatch;
        vector<string> m_attributeIds;
        xstring m_format;
        scoped_ptr<MetadataProvider> m_metadata;
        scoped_ptr<TrustEngine> m_trust;
        scoped_ptr<AttributeExtractor> m_extractor;
        scoped_ptr<AttributeFilter> m_filter;
        ptr_vector<saml2::Attribute> m_designators;
        vector< pair<string,bool> > m_sources;
        vector<string> m_exceptionId;
    };

    AttributeResolver* SHIBSP_DLLLOCAL SimpleAggregationResolverFactory(const DOMElement* const & e)
    {
        return new SimpleAggregationResolver(e);
    }

    static const XMLCh _AttributeExtractor[] =  UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,E,x,t,r,a,c,t,o,r);
    static const XMLCh _AttributeFilter[] =     UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh attributeId[] =          UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,d);
    static const XMLCh Entity[] =               UNICODE_LITERAL_6(E,n,t,i,t,y);
    static const XMLCh EntityReference[] =      UNICODE_LITERAL_15(E,n,t,i,t,y,R,e,f,e,r,e,n,c,e);
    static const XMLCh exceptionId[] =          UNICODE_LITERAL_11(e,x,c,e,p,t,i,o,n,I,d);
    static const XMLCh format[] =               UNICODE_LITERAL_6(f,o,r,m,a,t);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh policyId[] =             UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
    static const XMLCh subjectMatch[] =         UNICODE_LITERAL_12(s,u,b,j,e,c,t,M,a,t,c,h);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
};

SimpleAggregationResolver::SimpleAggregationResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.SimpleAggregation")),
        m_policyId(XMLHelper::getAttrString(e, nullptr, policyId)),
        m_subjectMatch(XMLHelper::getAttrBool(e, false, subjectMatch))
{
#ifdef _DEBUG
    xmltooling::NDC ndc("SimpleAggregationResolver");
#endif

    const XMLCh* aid = e ? e->getAttributeNS(nullptr, attributeId) : nullptr;
    if (aid && *aid) {
        auto_ptr_char dup(aid);
        string sdup(dup.get());
        split(m_attributeIds, sdup, is_space(), algorithm::token_compress_on);

        aid = e->getAttributeNS(nullptr, format);
        if (aid && *aid)
            m_format = aid;
    }

    string exid(XMLHelper::getAttrString(e, nullptr, exceptionId));
    if (!exid.empty())
        m_exceptionId.push_back(exid);

    DOMElement* child = XMLHelper::getFirstChildElement(e, _MetadataProvider);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (t.empty())
            throw ConfigurationException("MetadataProvider element missing type attribute.");
        m_log.info("building MetadataProvider of type %s...", t.c_str());
        m_metadata.reset(SAMLConfig::getConfig().MetadataProviderManager.newPlugin(t.c_str(), child));
        m_metadata->init();
    }

    child = XMLHelper::getFirstChildElement(e,  _TrustEngine);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (t.empty())
            throw ConfigurationException("TrustEngine element missing type attribute.");
        m_log.info("building TrustEngine of type %s...", t.c_str());
        m_trust.reset(XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t.c_str(), child));
    }

    child = XMLHelper::getFirstChildElement(e,  _AttributeExtractor);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (t.empty())
            throw ConfigurationException("AttributeExtractor element missing type attribute.");
        m_log.info("building AttributeExtractor of type %s...", t.c_str());
        m_extractor.reset(SPConfig::getConfig().AttributeExtractorManager.newPlugin(t.c_str(), child));
    }

    child = XMLHelper::getFirstChildElement(e,  _AttributeFilter);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (t.empty())
            throw ConfigurationException("AttributeFilter element missing type attribute.");
        m_log.info("building AttributeFilter of type %s...", t.c_str());
        m_filter.reset(SPConfig::getConfig().AttributeFilterManager.newPlugin(t.c_str(), child));
    }

    child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (child->hasChildNodes() && XMLString::equals(child->getLocalName(), Entity)) {
            aid = child->getFirstChild()->getNodeValue();
            if (aid && *aid) {
                auto_ptr_char taid(aid);
                m_sources.push_back(pair<string,bool>(taid.get(),true));
            }
        }
        else if (child->hasChildNodes() && XMLString::equals(child->getLocalName(), EntityReference)) {
            aid = child->getFirstChild()->getNodeValue();
            if (aid && *aid) {
                auto_ptr_char taid(aid);
                m_sources.push_back(pair<string,bool>(taid.get(),false));
            }
        }
        else if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME)) {
            try {
                auto_ptr<XMLObject> obj(saml2::AttributeBuilder::buildOneFromElement(child));
                saml2::Attribute* down = dynamic_cast<saml2::Attribute*>(obj.get());
                if (down) {
                    m_designators.push_back(down);
                    obj.release();
                }
            }
            catch (std::exception& ex) {
                m_log.error("exception loading attribute designator: %s", ex.what());
            }
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

void SimpleAggregationResolver::doQuery(SimpleAggregationContext& ctx, const char* entityID, const NameID* name) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("doQuery");
#endif
    const Application& application = ctx.getApplication();
    MetadataProviderCriteria mc(application, entityID, &AttributeAuthorityDescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
    Locker mlocker(m_metadata.get());
    const AttributeAuthorityDescriptor* AA=nullptr;
    pair<const EntityDescriptor*,const RoleDescriptor*> mdresult =
        (m_metadata ? m_metadata.get() : application.getMetadataProvider())->getEntityDescriptor(mc);
    if (!mdresult.first) {
        m_log.warn("unable to locate metadata for provider (%s)", entityID);
        return;
    }
    else if (!(AA=dynamic_cast<const AttributeAuthorityDescriptor*>(mdresult.second))) {
        m_log.warn("no SAML 2 AttributeAuthority role found in metadata for (%s)", entityID);
        return;
    }

    const PropertySet* relyingParty = application.getRelyingParty(mdresult.first);
    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    pair<bool,const char*> encryption = relyingParty->getString("encryption");

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Set up policy and SOAP client.
    scoped_ptr<SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(application, nullptr, policyId)
        );
    if (m_metadata)
        policy->setMetadataProvider(m_metadata.get());
    if (m_trust)
        policy->setTrustEngine(m_trust.get());
    policy->getAudiences().push_back(relyingParty->getXMLString("entityID").second);

    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(*policy.get());

    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    auto_ptr<saml2p::StatusResponseType> srt;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (indirect_iterator<vector<AttributeService*>::const_iterator> ep = make_indirect_iterator(endpoints.begin());
            !srt.get() && ep != make_indirect_iterator(endpoints.end()); ++ep) {
        if (!XMLString::equals(ep->getBinding(), binding.get())  || !ep->getLocation())
            continue;
        auto_ptr_char loc(ep->getLocation());
        try {
            auto_ptr<saml2::Subject> subject(saml2::SubjectBuilder::buildSubject());

            // Encrypt the NameID?
            if (encryption.first && (!strcmp(encryption.second, "true") || !strcmp(encryption.second, "back"))) {
                auto_ptr<EncryptedID> encrypted(EncryptedIDBuilder::buildEncryptedID());
                encrypted->encrypt(
                    *name,
                    *(policy->getMetadataProvider()),
                    mcc,
                    false,
                    relyingParty->getXMLString("encryptionAlg").second
                    );
                subject->setEncryptedID(encrypted.get());
                encrypted.release();
            }
            else {
                subject->setNameID(name->cloneNameID());
            }

            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject.release());
            Issuer* iss = IssuerBuilder::buildIssuer();
            iss->setName(relyingParty->getXMLString("entityID").second);
            query->setIssuer(iss);
            for (ptr_vector<saml2::Attribute>::const_iterator ad = m_designators.begin(); ad != m_designators.end(); ++ad) {
                auto_ptr<saml2::Attribute> adwrapper(ad->cloneAttribute());
                query->getAttributes().push_back(adwrapper.get());
                adwrapper.release();
            }

            SAML2SOAPClient client(soaper, false);
            client.sendSAML(query, application.getId(), mcc, loc.get());
            srt.reset(client.receiveSAML());
        }
        catch (std::exception& ex) {
            m_log.error("exception during SAML query to %s: %s", loc.get(), ex.what());
            soaper.reset();
        }
    }

    if (!srt.get()) {
        m_log.error("unable to obtain a SAML response from attribute authority (%s)", entityID);
        throw BindingException("Unable to obtain a SAML response from attribute authority.");
    }

    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt.get());
    if (!response) {
        m_log.error("message was not a samlp:Response");
        throw FatalProfileException("Attribute authority returned an unrecognized message.");
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
            !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        m_log.error("attribute authority (%s) returned a SAML error", entityID);
        throw FatalProfileException("Attribute authority returned a SAML error.");
    }

    saml2::Assertion* newtoken = nullptr;
    auto_ptr<saml2::Assertion> newtokenwrapper;
    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.empty()) {
        // Check for encryption.
        const vector<saml2::EncryptedAssertion*>& encassertions =
            const_cast<const saml2p::Response*>(response)->getEncryptedAssertions();
        if (encassertions.empty()) {
            m_log.warn("response from attribute authority was empty");
            return;
        }
        else if (encassertions.size() > 1) {
            m_log.warn("simple resolver only supports one assertion in the query response");
        }

        CredentialResolver* cr=application.getCredentialResolver();
        if (!cr) {
            m_log.warn("found encrypted assertion, but no CredentialResolver was available");
            throw FatalProfileException("Assertion was encrypted, but no decryption credentials are available.");
        }

        // With this flag on, we block unauthenticated ciphertext when decrypting,
        // unless the protocol was authenticated.
        pair<bool,bool> authenticatedCipher = application.getBool("requireAuthenticatedEncryption");
        if (policy->isAuthenticated())
            authenticatedCipher.second = false;

        // Attempt to decrypt it.
        try {
            Locker credlocker(cr);
            auto_ptr<XMLObject> tokenwrapper(
                encassertions.front()->decrypt(
                    *cr, relyingParty->getXMLString("entityID").second, &mcc, authenticatedCipher.first && authenticatedCipher.second
                    )
                );
            newtoken = dynamic_cast<saml2::Assertion*>(tokenwrapper.get());
            if (newtoken) {
                tokenwrapper.release();
                newtokenwrapper.reset(newtoken);
                if (m_log.isDebugEnabled())
                    m_log.debugStream() << "decrypted assertion: " << *newtoken << logging::eol;
            }
        }
        catch (std::exception& ex) {
            m_log.error("failed to decrypt assertion: %s", ex.what());
            throw;
        }
    }
    else {
        if (assertions.size() > 1)
            m_log.warn("simple resolver only supports one assertion in the query response");
        newtoken = assertions.front();
    }

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        throw SecurityPolicyException("Rejected unsigned assertion based on local policy.");
    }

    try {
        // We're going to insist that the assertion issuer is the same as the peer.
        // Reset the policy's message bits and extract them from the assertion.
        policy->reset(true);
        policy->setMessageID(newtoken->getID());
        policy->setIssueInstant(newtoken->getIssueInstantEpoch());
        policy->setIssuer(newtoken->getIssuer());
        policy->evaluate(*newtoken);

        // Now we can check the security status of the policy.
        if (!policy->isAuthenticated())
            throw SecurityPolicyException("Security of SAML 2.0 query result not established.");

        if (m_subjectMatch) {
            // Check for subject match.
            auto_ptr<NameID> nameIDwrapper;
            NameID* respName = newtoken->getSubject() ? newtoken->getSubject()->getNameID() : nullptr;
            if (!respName) {
                // Check for encryption.
                EncryptedID* encname = newtoken->getSubject() ? newtoken->getSubject()->getEncryptedID() : nullptr;
                if (encname) {
                    CredentialResolver* cr=application.getCredentialResolver();
                    if (!cr)
                        m_log.warn("found EncryptedID, but no CredentialResolver was available");
                    else {
                        Locker credlocker(cr);
                        auto_ptr<XMLObject> decryptedID(encname->decrypt(*cr, relyingParty->getXMLString("entityID").second, &mcc));
                        respName = dynamic_cast<NameID*>(decryptedID.get());
                        if (respName) {
                            decryptedID.release();
                            nameIDwrapper.reset(respName);
                            if (m_log.isDebugEnabled())
                                m_log.debugStream() << "decrypted NameID: " << *respName << logging::eol;
                        }
                    }
                }
            }

            if (!respName || !XMLString::equals(respName->getName(), name->getName()) ||
                !XMLString::equals(respName->getFormat(), name->getFormat()) ||
                !XMLString::equals(respName->getNameQualifier(), name->getNameQualifier()) ||
                !XMLString::equals(respName->getSPNameQualifier(), name->getSPNameQualifier())) {
                if (respName)
                    m_log.warnStream() << "ignoring Assertion without strongly matching NameID in Subject: " <<
                        *respName << logging::eol;
                else
                    m_log.warn("ignoring Assertion without NameID in Subject");
                return;
            }
        }
    }
    catch (std::exception& ex) {
        m_log.error("assertion failed policy validation: %s", ex.what());
        throw;
    }

    // If the token's embedded, detach it.
    if (!newtokenwrapper.get()) {
        newtoken->detach();
        srt.release();  // detach blows away the Response, so avoid a double free
        newtokenwrapper.reset(newtoken);
    }
    ctx.getResolvedAssertions().push_back(newtoken);
    newtokenwrapper.release();

    // Finally, extract and filter the result.
    try {
        AttributeExtractor* extractor = m_extractor ? m_extractor.get() : application.getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            extractor->extractAttributes(application, ctx.getRequest(), AA, *newtoken, ctx.getResolvedAttributes());
        }

        AttributeFilter* filter = m_filter ? m_filter.get() : application.getAttributeFilter();
        if (filter) {
            BasicFilteringContext fc(application, ctx.getResolvedAttributes(), AA, ctx.getClassRef(), ctx.getDeclRef());
            Locker filtlocker(filter);
            filter->filterAttributes(fc, ctx.getResolvedAttributes());
        }
    }
    catch (std::exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
        for_each(ctx.getResolvedAttributes().begin(), ctx.getResolvedAttributes().end(), xmltooling::cleanup<shibsp::Attribute>());
        ctx.getResolvedAttributes().clear();
        throw;
    }
}

void SimpleAggregationResolver::resolveAttributes(ResolutionContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif

    SimpleAggregationContext& qctx = dynamic_cast<SimpleAggregationContext&>(ctx);

    // First we manufacture the appropriate NameID to use.
    scoped_ptr<NameID> n;
    for (vector<string>::const_iterator a = m_attributeIds.begin(); !n.get() && a != m_attributeIds.end(); ++a) {
        const Attribute* attr=nullptr;
        if (qctx.getSession()) {
            // Input attributes should be available via multimap.
            pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> range =
                qctx.getSession()->getIndexedAttributes().equal_range(*a);
            for (; !attr && range.first != range.second; ++range.first) {
                if (range.first->second->valueCount() > 0)
                    attr = range.first->second;
            }
        }
        else if (qctx.getInputAttributes()) {
            // Have to loop over unindexed set.
            const vector<Attribute*>* matches = qctx.getInputAttributes();
            for (indirect_iterator<vector<Attribute*>::const_iterator> match = make_indirect_iterator(matches->begin());
                    !attr && match != make_indirect_iterator(matches->end()); ++match) {
                if (*a == match->getId() && match->valueCount() > 0)
                    attr = &(*match);
            }
        }

        if (attr) {
            m_log.debug("using input attribute (%s) as identifier for queries", attr->getId());
            n.reset(NameIDBuilder::buildNameID());
            const NameIDAttribute* down = dynamic_cast<const NameIDAttribute*>(attr);
            if (down) {
                // We can create a NameID directly from the source material.
                const NameIDAttribute::Value& v = down->getValues().front();
                auto_arrayptr<XMLCh> val(fromUTF8(v.m_Name.c_str()));
                n->setName(val.get());

                if (!v.m_Format.empty()) {
                    auto_arrayptr<XMLCh> format(fromUTF8(v.m_Format.c_str()));
                    n->setFormat(format.get());
                }
                if (!v.m_NameQualifier.empty()) {
                    auto_arrayptr<XMLCh> nq(fromUTF8(v.m_NameQualifier.c_str()));
                    n->setNameQualifier(nq.get());
                }
                if (!v.m_SPNameQualifier.empty()) {
                    auto_arrayptr<XMLCh> spnq(fromUTF8(v.m_SPNameQualifier.c_str()));
                    n->setSPNameQualifier(spnq.get());
                }
                if (!v.m_SPProvidedID.empty()) {
                    auto_arrayptr<XMLCh> sppid(fromUTF8(v.m_SPProvidedID.c_str()));
                    n->setSPProvidedID(sppid.get());
                }
            }
            else {
                // We have to mock up the NameID.
                auto_arrayptr<XMLCh> val(fromUTF8(attr->getSerializedValues().front().c_str()));
                n->setName(val.get());
                if (!m_format.empty())
                    n->setFormat(m_format.c_str());
            }
        }
    }

    if (!n) {
        if (qctx.getNameID() && m_attributeIds.empty()) {
            m_log.debug("using authenticated NameID as identifier for queries");
        }
        else {
            m_log.warn("unable to resolve attributes, no suitable query identifier found");
            return;
        }
    }

    set<string> history;

    // Put initial IdP into history to prevent extra query.
    if (qctx.getEntityID())
        history.insert(qctx.getEntityID());

    // Prepare to track exceptions.
    auto_ptr<SimpleAttribute> exceptAttr;
    if (!m_exceptionId.empty())
        exceptAttr.reset(new SimpleAttribute(m_exceptionId));

    // We have a master loop over all the possible sources of material.
    for (vector< pair<string,bool> >::const_iterator source = m_sources.begin(); source != m_sources.end(); ++source) {
        if (source->second) {
            // A literal entityID to query.
            if (history.count(source->first) == 0) {
                m_log.debug("issuing SAML query to (%s)", source->first.c_str());
                try {
                    doQuery(qctx, source->first.c_str(), n ? n.get() : qctx.getNameID());
                }
                catch (std::exception& ex) {
                    if (exceptAttr.get())
                        exceptAttr->getValues().push_back(XMLToolingConfig::getConfig().getURLEncoder()->encode(ex.what()));
                }
                history.insert(source->first);
            }
            else {
                m_log.debug("skipping previously queried attribute source (%s)", source->first.c_str());
            }
        }
        else {
            m_log.debug("using attribute sources referenced in attribute (%s)", source->first.c_str());
            if (qctx.getSession()) {
                // Input attributes should be available via multimap.
                pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> range =
                    qctx.getSession()->getIndexedAttributes().equal_range(source->first);
                for (; range.first != range.second; ++range.first) {
                    const vector<string>& links = range.first->second->getSerializedValues();
                    for (vector<string>::const_iterator link = links.begin(); link != links.end(); ++link) {
                        if (history.count(*link) == 0) {
                            m_log.debug("issuing SAML query to (%s)", link->c_str());
                            try {
                                doQuery(qctx, link->c_str(), n ? n.get() : qctx.getNameID());
                            }
                            catch (std::exception& ex) {
                                if (exceptAttr.get())
                                    exceptAttr->getValues().push_back(XMLToolingConfig::getConfig().getURLEncoder()->encode(ex.what()));
                            }
                            history.insert(*link);
                        }
                        else {
                            m_log.debug("skipping previously queried attribute source (%s)", link->c_str());
                        }
                    }
                }
            }
            else if (qctx.getInputAttributes()) {
                // Have to loop over unindexed set.
                const vector<Attribute*>* matches = qctx.getInputAttributes();
                for (indirect_iterator<vector<Attribute*>::const_iterator> match = make_indirect_iterator(matches->begin());
                        match != make_indirect_iterator(matches->end()); ++match) {
                    if (source->first == match->getId()) {
                        const vector<string>& links = match->getSerializedValues();
                        for (vector<string>::const_iterator link = links.begin(); link != links.end(); ++link) {
                            if (history.count(*link) == 0) {
                                m_log.debug("issuing SAML query to (%s)", link->c_str());
                                try {
                                    doQuery(qctx, link->c_str(), n ? n.get() : qctx.getNameID());
                                }
                                catch (std::exception& ex) {
                                    if (exceptAttr.get())
                                        exceptAttr->getValues().push_back(XMLToolingConfig::getConfig().getURLEncoder()->encode(ex.what()));
                                }
                                history.insert(*link);
                            }
                            else {
                                m_log.debug("skipping previously queried attribute source (%s)", link->c_str());
                            }
                        }
                    }
                }
            }
        }
    }

    if (exceptAttr.get()) {
        qctx.getResolvedAttributes().push_back(exceptAttr.get());
        exceptAttr.release();
    }
}
