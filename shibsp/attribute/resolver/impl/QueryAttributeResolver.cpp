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
 * QueryAttributeResolver.cpp
 *
 * AttributeResolver based on SAML queries.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
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

#include <boost/iterator/indirect_iterator.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <saml/exceptions.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL QueryContext : public ResolutionContext
    {
    public:
        QueryContext(const Application& application, const Session& session)
                : m_query(true), m_app(application), m_request(nullptr), m_session(&session), m_metadata(nullptr), m_entity(nullptr), m_nameid(nullptr) {
            m_protocol = XMLString::transcode(session.getProtocol());
            m_class = XMLString::transcode(session.getAuthnContextClassRef());
            m_decl = XMLString::transcode(session.getAuthnContextDeclRef());
        }

        QueryContext(
            const Application& application,
            const GenericRequest* request,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr
            ) : m_query(true), m_app(application), m_request(request), m_session(nullptr), m_metadata(nullptr), m_entity(issuer),
                m_protocol(protocol), m_nameid(nameid), m_class(authncontext_class), m_decl(authncontext_decl) {

            if (tokens) {
                for (vector<const opensaml::Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                    const saml2::Assertion* token2 = dynamic_cast<const saml2::Assertion*>(*t);
                    if (token2 && !token2->getAttributeStatements().empty()) {
                        m_query = false;
                    }
                    else {
                        const saml1::Assertion* token1 = dynamic_cast<const saml1::Assertion*>(*t);
                        if (token1 && !token1->getAttributeStatements().empty()) {
                            m_query = false;
                        }
                    }
                }
            }
        }

        ~QueryContext() {
            if (m_session) {
                XMLString::release((XMLCh**)&m_protocol);
                XMLString::release((XMLCh**)&m_class);
                XMLString::release((XMLCh**)&m_decl);
            }
            if (m_metadata)
                m_metadata->unlock();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        bool doQuery() const {
            return m_query;
        }

        const Application& getApplication() const {
            return m_app;
        }
        const GenericRequest* getRequest() const {
            return m_request;
        }
        const EntityDescriptor* getEntityDescriptor() const {
            if (m_entity)
                return m_entity;
            if (m_session && m_session->getEntityID()) {
                m_metadata = m_app.getMetadataProvider(false);
                if (m_metadata) {
                    m_metadata->lock();
                    return m_entity = m_metadata->getEntityDescriptor(MetadataProviderCriteria(m_app, m_session->getEntityID())).first;
                }
            }
            return nullptr;
        }
        const XMLCh* getProtocol() const {
            return m_protocol;
        }
        const NameID* getNameID() const {
            return m_session ? m_session->getNameID() : m_nameid;
        }
        const XMLCh* getClassRef() const {
            return m_class;
        }
        const XMLCh* getDeclRef() const {
            return m_decl;
        }
        const Session* getSession() const {
            return m_session;
        }
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        bool m_query;
        const Application& m_app;
        const GenericRequest* m_request;
        const Session* m_session;
        mutable MetadataProvider* m_metadata;
        mutable const EntityDescriptor* m_entity;
        const XMLCh* m_protocol;
        const NameID* m_nameid;
        const XMLCh* m_class;
        const XMLCh* m_decl;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };

    class SHIBSP_DLLLOCAL QueryResolver : public AttributeResolver
    {
    public:
        QueryResolver(const DOMElement* e);
        ~QueryResolver() {}

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
            return createResolutionContext(application, nullptr, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens);
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
            return new QueryContext(application, request, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new QueryContext(application,session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            // Nothing to do, only the extractor would actually generate them.
        }

    private:
        void SAML1Query(QueryContext& ctx) const;
        void SAML2Query(QueryContext& ctx) const;

        Category& m_log;
        string m_policyId;
        bool m_subjectMatch;
        ptr_vector<AttributeDesignator> m_SAML1Designators;
        ptr_vector<saml2::Attribute> m_SAML2Designators;
        vector<string> m_exceptionId;
    };

    AttributeResolver* SHIBSP_DLLLOCAL QueryResolverFactory(const DOMElement* const & e)
    {
        return new QueryResolver(e);
    }

    static const XMLCh exceptionId[] =  UNICODE_LITERAL_11(e,x,c,e,p,t,i,o,n,I,d);
    static const XMLCh policyId[] =     UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
    static const XMLCh subjectMatch[] = UNICODE_LITERAL_12(s,u,b,j,e,c,t,M,a,t,c,h);
};

QueryResolver::QueryResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.Query")),
        m_policyId(XMLHelper::getAttrString(e, nullptr, policyId)),
        m_subjectMatch(XMLHelper::getAttrBool(e, false, subjectMatch))
{
#ifdef _DEBUG
    xmltooling::NDC ndc("QueryResolver");
#endif

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        try {
            if (XMLHelper::isNodeNamed(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME)) {
                auto_ptr<XMLObject> obj(saml2::AttributeBuilder::buildOneFromElement(child));
                saml2::Attribute* down = dynamic_cast<saml2::Attribute*>(obj.get());
                if (down) {
                    m_SAML2Designators.push_back(down);
                    obj.release();
                }
            }
            else if (XMLHelper::isNodeNamed(child, samlconstants::SAML1_NS, AttributeDesignator::LOCAL_NAME)) {
                auto_ptr<XMLObject> obj(AttributeDesignatorBuilder::buildOneFromElement(child));
                AttributeDesignator* down = dynamic_cast<AttributeDesignator*>(obj.get());
                if (down) {
                    m_SAML1Designators.push_back(down);
                    obj.release();
                }
            }
        }
        catch (exception& ex) {
            m_log.error("exception loading attribute designator: %s", ex.what());
        }
        child = XMLHelper::getNextSiblingElement(child);
    }

    string exid(XMLHelper::getAttrString(e, nullptr, exceptionId));
    if (!exid.empty())
        m_exceptionId.push_back(exid);
}

void QueryResolver::SAML1Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    int version = XMLString::equals(ctx.getProtocol(), samlconstants::SAML11_PROTOCOL_ENUM) ? 1 : 0;
    const AttributeAuthorityDescriptor* AA =
        find_if(ctx.getEntityDescriptor()->getAttributeAuthorityDescriptors(), isValidForProtocol(ctx.getProtocol()));
    if (!AA) {
        m_log.warn("no SAML 1.%d AttributeAuthority role found in metadata", version);
        return;
    }

    const Application& application = ctx.getApplication();
    const PropertySet* relyingParty = application.getRelyingParty(ctx.getEntityDescriptor());

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Set up policy and SOAP client.
    scoped_ptr<SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(application, nullptr, policyId)
        );
    policy->getAudiences().push_back(relyingParty->getXMLString("entityID").second);
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(*policy);

    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    auto_ptr<saml1p::Response> response;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (indirect_iterator<vector<AttributeService*>::const_iterator> ep = make_indirect_iterator(endpoints.begin());
            !response.get() && ep != make_indirect_iterator(endpoints.end()); ++ep) {
        if (!XMLString::equals(ep->getBinding(), binding.get()) || !ep->getLocation())
            continue;
        auto_ptr_char loc(ep->getLocation());
        try {
            NameIdentifier* nameid = NameIdentifierBuilder::buildNameIdentifier();
            nameid->setName(ctx.getNameID()->getName());
            nameid->setFormat(ctx.getNameID()->getFormat());
            nameid->setNameQualifier(ctx.getNameID()->getNameQualifier());
            saml1::Subject* subject = saml1::SubjectBuilder::buildSubject();
            subject->setNameIdentifier(nameid);
            saml1p::AttributeQuery* query = saml1p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            query->setResource(relyingParty->getXMLString("entityID").second);
            for (ptr_vector<AttributeDesignator>::const_iterator ad = m_SAML1Designators.begin(); ad != m_SAML1Designators.end(); ++ad) {
                auto_ptr<AttributeDesignator> adwrapper(ad->cloneAttributeDesignator());
                query->getAttributeDesignators().push_back(adwrapper.get());
                adwrapper.release();
            }
            Request* request = RequestBuilder::buildRequest();
            request->setAttributeQuery(query);
            request->setMinorVersion(version);

            SAML1SOAPClient client(soaper, false);
            client.sendSAML(request, application.getId(), mcc, loc.get());
            response.reset(client.receiveSAML());
        }
        catch (exception& ex) {
            m_log.error("exception during SAML query to %s: %s", loc.get(), ex.what());
            soaper.reset();
        }
    }

    if (!response.get()) {
        m_log.error("unable to obtain a SAML response from attribute authority");
        throw BindingException("Unable to obtain a SAML response from attribute authority.");
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() || response->getStatus()->getStatusCode()->getValue()==nullptr ||
            *(response->getStatus()->getStatusCode()->getValue()) != saml1p::StatusCode::SUCCESS) {
        m_log.error("attribute authority returned a SAML error");
        throw FatalProfileException("Attribute authority returned a SAML error.");
    }

    const vector<saml1::Assertion*>& assertions = const_cast<const saml1p::Response*>(response.get())->getAssertions();
    if (assertions.empty()) {
        m_log.warn("response from attribute authority was empty");
        return;
    }
    else if (assertions.size() > 1) {
        m_log.warn("simple resolver only supports one assertion in the query response");
    }

    saml1::Assertion* newtoken = assertions.front();

    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        throw SecurityPolicyException("Rejected unsigned assertion based on local policy.");
    }

    try {
        // We're going to insist that the assertion issuer is the same as the peer.
        // Reset the policy's message bits and extract them from the assertion.
        policy->reset(true);
        policy->setMessageID(newtoken->getAssertionID());
        policy->setIssueInstant(newtoken->getIssueInstantEpoch());
        policy->setIssuer(newtoken->getIssuer());
        policy->evaluate(*newtoken);

        // Now we can check the security status of the policy.
        if (!policy->isAuthenticated())
            throw SecurityPolicyException("Security of SAML 1.x query result not established.");
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy validation: %s", ex.what());
        throw;
    }

    newtoken->detach();
    response.release();  // detach blows away the Response
    ctx.getResolvedAssertions().push_back(newtoken);

    // Finally, extract and filter the result.
    try {
        AttributeExtractor* extractor = application.getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            const vector<saml1::AttributeStatement*>& statements = const_cast<const saml1::Assertion*>(newtoken)->getAttributeStatements();
            for (indirect_iterator<vector<saml1::AttributeStatement*>::const_iterator> s = make_indirect_iterator(statements.begin());
                    s != make_indirect_iterator(statements.end()); ++s) {
                if (m_subjectMatch) {
                    // Check for subject match.
                    const NameIdentifier* respName = s->getSubject() ? s->getSubject()->getNameIdentifier() : nullptr;
                    if (!respName || !XMLString::equals(respName->getName(), ctx.getNameID()->getName()) ||
                        !XMLString::equals(respName->getFormat(), ctx.getNameID()->getFormat()) ||
                        !XMLString::equals(respName->getNameQualifier(), ctx.getNameID()->getNameQualifier())) {
                        if (respName)
                            m_log.warnStream() << "ignoring AttributeStatement without strongly matching NameIdentifier in Subject: " <<
                                *respName << logging::eol;
                        else
                            m_log.warn("ignoring AttributeStatement without NameIdentifier in Subject");
                        continue;
                    }
                }
                extractor->extractAttributes(application, ctx.getRequest(), AA, *s, ctx.getResolvedAttributes());
            }
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter) {
            BasicFilteringContext fc(application, ctx.getResolvedAttributes(), AA, ctx.getClassRef(), ctx.getDeclRef());
            Locker filtlocker(filter);
            filter->filterAttributes(fc, ctx.getResolvedAttributes());
        }
    }
    catch (exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
        for_each(ctx.getResolvedAttributes().begin(), ctx.getResolvedAttributes().end(), xmltooling::cleanup<shibsp::Attribute>());
        ctx.getResolvedAttributes().clear();
        throw;
    }
}

void QueryResolver::SAML2Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    const AttributeAuthorityDescriptor* AA =
        find_if(ctx.getEntityDescriptor()->getAttributeAuthorityDescriptors(), isValidForProtocol(samlconstants::SAML20P_NS));
    if (!AA) {
        m_log.warn("no SAML 2 AttributeAuthority role found in metadata");
        return;
    }

    const Application& application = ctx.getApplication();
    const PropertySet* relyingParty = application.getRelyingParty(ctx.getEntityDescriptor());
    pair<bool,bool> signedAssertions = relyingParty->getBool("requireSignedAssertions");
    pair<bool,const char*> encryption = relyingParty->getString("encryption");

    // Locate policy key.
    const char* policyId = m_policyId.empty() ? application.getString("policyId").second : m_policyId.c_str();

    // Set up policy and SOAP client.
    scoped_ptr<SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(application, nullptr, policyId)
        );
    policy->getAudiences().push_back(relyingParty->getXMLString("entityID").second);
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(*policy);

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
                    *ctx.getNameID(),
                    *(application.getMetadataProvider()),
                    mcc,
                    false,
                    relyingParty->getXMLString("encryptionAlg").second
                    );
                subject->setEncryptedID(encrypted.get());
                encrypted.release();
            }
            else {
                auto_ptr<NameID> namewrapper(ctx.getNameID()->cloneNameID());
                subject->setNameID(namewrapper.get());
                namewrapper.release();
            }

            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject.release());
            Issuer* iss = IssuerBuilder::buildIssuer();
            iss->setName(relyingParty->getXMLString("entityID").second);
            query->setIssuer(iss);
            for (ptr_vector<saml2::Attribute>::const_iterator ad = m_SAML2Designators.begin(); ad != m_SAML2Designators.end(); ++ad) {
                auto_ptr<saml2::Attribute> adwrapper(ad->cloneAttribute());
                query->getAttributes().push_back(adwrapper.get());
                adwrapper.release();
            }

            SAML2SOAPClient client(soaper, false);
            client.sendSAML(query, application.getId(), mcc, loc.get());
            srt.reset(client.receiveSAML());
        }
        catch (exception& ex) {
            m_log.error("exception during SAML query to %s: %s", loc.get(), ex.what());
            soaper.reset();
        }
    }

    if (!srt.get()) {
        m_log.error("unable to obtain a SAML response from attribute authority");
        throw BindingException("Unable to obtain a SAML response from attribute authority.");
    }

    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt.get());
    if (!response) {
        m_log.error("message was not a samlp:Response");
        throw FatalProfileException("Attribute authority returned an unrecognized message.");
    }
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
            !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        m_log.error("attribute authority returned a SAML error");
        throw FatalProfileException("Attribute authority returned a SAML error.");
    }

    saml2::Assertion* newtoken = nullptr;
    auto_ptr<saml2::Assertion> newtokenwrapper;
    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.empty()) {
        // Check for encryption.
        const vector<saml2::EncryptedAssertion*>& encassertions = const_cast<const saml2p::Response*>(response)->getEncryptedAssertions();
        if (encassertions.empty()) {
            m_log.warn("response from attribute authority was empty");
            return;
        }
        else if (encassertions.size() > 1) {
            m_log.warn("simple resolver only supports one assertion in the query response");
        }

        CredentialResolver* cr = application.getCredentialResolver();
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
        catch (exception& ex) {
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

            if (!respName || !XMLString::equals(respName->getName(), ctx.getNameID()->getName()) ||
                !XMLString::equals(respName->getFormat(), ctx.getNameID()->getFormat()) ||
                !XMLString::equals(respName->getNameQualifier(), ctx.getNameID()->getNameQualifier()) ||
                !XMLString::equals(respName->getSPNameQualifier(), ctx.getNameID()->getSPNameQualifier())) {
                if (respName)
                    m_log.warnStream() << "ignoring Assertion without strongly matching NameID in Subject: " <<
                        *respName << logging::eol;
                else
                    m_log.warn("ignoring Assertion without NameID in Subject");
                return;
            }
        }
    }
    catch (exception& ex) {
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
        AttributeExtractor* extractor = application.getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            extractor->extractAttributes(application, ctx.getRequest(), AA, *newtoken, ctx.getResolvedAttributes());
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter) {
            BasicFilteringContext fc(application, ctx.getResolvedAttributes(), AA, ctx.getClassRef(), ctx.getDeclRef());
            Locker filtlocker(filter);
            filter->filterAttributes(fc, ctx.getResolvedAttributes());
        }
    }
    catch (exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
        for_each(ctx.getResolvedAttributes().begin(), ctx.getResolvedAttributes().end(), xmltooling::cleanup<shibsp::Attribute>());
        ctx.getResolvedAttributes().clear();
        throw;
    }
}

void QueryResolver::resolveAttributes(ResolutionContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif

    QueryContext& qctx = dynamic_cast<QueryContext&>(ctx);
    if (!qctx.doQuery()) {
        m_log.debug("found AttributeStatement in input to new session, skipping query");
        return;
    }

    try {
        if (qctx.getNameID() && qctx.getEntityDescriptor()) {
            if (XMLString::equals(qctx.getProtocol(), samlconstants::SAML20P_NS)) {
                m_log.debug("attempting SAML 2.0 attribute query");
                SAML2Query(qctx);
            }
            else if (XMLString::equals(qctx.getProtocol(), samlconstants::SAML11_PROTOCOL_ENUM) ||
                    XMLString::equals(qctx.getProtocol(), samlconstants::SAML10_PROTOCOL_ENUM)) {
                m_log.debug("attempting SAML 1.x attribute query");
                SAML1Query(qctx);
            }
            else {
                m_log.info("SSO protocol does not allow for attribute query");
            }
        }
        else {
            m_log.warn("can't attempt attribute query, either no NameID or no metadata to use");
        }
    }
    catch (exception& ex) {
        // Already logged.
        if (!m_exceptionId.empty()) {
            auto_ptr<SimpleAttribute> attr(new SimpleAttribute(m_exceptionId));
            attr->getValues().push_back(XMLToolingConfig::getConfig().getURLEncoder()->encode(ex.what()));
            qctx.getResolvedAttributes().push_back(attr.get());
            attr.release();
        }
    }
}
