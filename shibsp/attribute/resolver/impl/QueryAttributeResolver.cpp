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

/**
 * QueryAttributeResolver.cpp
 * 
 * AttributeResolver based on SAML queries.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "binding/SOAPClient.h"
#include "util/SPConstants.h"

#include <log4cpp/Category.hh>
#include <saml/exceptions.h>
#include <saml/binding/SecurityPolicy.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml1/profile/AssertionValidator.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/profile/AssertionValidator.h>
#include <xmltooling/util/NDC.h>
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
using namespace log4cpp;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL QueryContext : public ResolutionContext
    {
    public:
        QueryContext(const Application& application, const Session& session)
            : m_query(true), m_app(application), m_session(&session), m_metadata(NULL), m_entity(NULL), m_nameid(session.getNameID()) {
        }
        
        QueryContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const NameID* nameid,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const multimap<string,Attribute*>* attributes=NULL
            ) : m_query(true), m_app(application), m_session(NULL), m_metadata(NULL), m_entity(issuer), m_nameid(nameid) {

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
            if (m_metadata)
                m_metadata->unlock();
            for_each(m_attributes.begin(), m_attributes.end(), cleanup_pair<string,shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }
    
        bool doQuery() const {
            return m_query;
        }

        const Application& getApplication() const {
            return m_app;
        }
        const EntityDescriptor* getEntityDescriptor() const {
            if (m_entity)
                return m_entity;
            if (m_session && m_session->getEntityID()) {
                m_metadata = m_app.getMetadataProvider();
                if (m_metadata) {
                    m_metadata->lock();
                    return m_entity = m_metadata->getEntityDescriptor(m_session->getEntityID());
                }
            }
            return NULL;
        }
        const NameID* getNameID() const {
            return m_nameid;
        }
        const Session* getSession() const {
            return m_session;
        }        
        multimap<string,shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        bool m_query;
        const Application& m_app;
        const Session* m_session;
        mutable MetadataProvider* m_metadata;
        mutable const EntityDescriptor* m_entity;
        const NameID* m_nameid;
        multimap<string,shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };
    
    class SHIBSP_DLLLOCAL QueryResolver : public AttributeResolver
    {
    public:
        QueryResolver(const DOMElement* e);
        ~QueryResolver() {
            for_each(m_SAML1Designators.begin(), m_SAML1Designators.end(), xmltooling::cleanup<AttributeDesignator>());
            for_each(m_SAML2Designators.begin(), m_SAML2Designators.end(), xmltooling::cleanup<saml2::Attribute>());
        }
        
        ResolutionContext* createResolutionContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const NameID* nameid,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const multimap<string,shibsp::Attribute*>* attributes=NULL
            ) const {
            return new QueryContext(application,issuer,nameid,tokens,attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new QueryContext(application,session);
        }

        Lockable* lock() {return this;}
        void unlock() {}
        
        void resolveAttributes(ResolutionContext& ctx) const;

    private:
        bool SAML1Query(QueryContext& ctx) const;
        bool SAML2Query(QueryContext& ctx) const;

        Category& m_log;
        vector<AttributeDesignator*> m_SAML1Designators;
        vector<saml2::Attribute*> m_SAML2Designators;
    };

    AttributeResolver* SHIBSP_DLLLOCAL QueryResolverFactory(const DOMElement* const & e)
    {
        return new QueryResolver(e);
    }
    
};

void SHIBSP_API shibsp::registerAttributeResolvers()
{
    SPConfig::getConfig().AttributeResolverManager.registerFactory(QUERY_ATTRIBUTE_RESOLVER, QueryResolverFactory);
}

QueryResolver::QueryResolver(const DOMElement* e) : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver"))
{
#ifdef _DEBUG
    xmltooling::NDC ndc("QueryResolver");
#endif
    
    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        try {
            if (XMLHelper::isNodeNamed(e, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME)) {
                auto_ptr<XMLObject> obj(saml2::AttributeBuilder::buildOneFromElement(child));
                saml2::Attribute* down = dynamic_cast<saml2::Attribute*>(obj.get());
                if (down) {
                    m_SAML2Designators.push_back(down);
                    obj.release();
                }
            }
            else if (XMLHelper::isNodeNamed(e, samlconstants::SAML1P_NS, AttributeDesignator::LOCAL_NAME)) {
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
}

bool QueryResolver::SAML1Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    int version = 1;
    const AttributeAuthorityDescriptor* AA = ctx.getEntityDescriptor()->getAttributeAuthorityDescriptor(samlconstants::SAML11_PROTOCOL_ENUM);
    if (!AA) {
        AA = ctx.getEntityDescriptor()->getAttributeAuthorityDescriptor(samlconstants::SAML10_PROTOCOL_ENUM);
        version = 0;
    }
    if (!AA) {
        m_log.info("no SAML 1.x AttributeAuthority role found in metadata");
        return false;
    }

    shibsp::SecurityPolicy policy(ctx.getApplication());
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(policy);
    const PropertySet* policySettings =
        ctx.getApplication().getServiceProvider().getPolicySettings(ctx.getApplication().getString("policyId").second);
    pair<bool,bool> signedAssertions = policySettings->getBool("signedAssertions");

    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    saml1p::Response* response=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("entityID").second);
            NameIdentifier* nameid = NameIdentifierBuilder::buildNameIdentifier();
            nameid->setName(ctx.getNameID()->getName());
            nameid->setFormat(ctx.getNameID()->getFormat());
            nameid->setNameQualifier(ctx.getNameID()->getNameQualifier());
            saml1::Subject* subject = saml1::SubjectBuilder::buildSubject();
            subject->setNameIdentifier(nameid);
            saml1p::AttributeQuery* query = saml1p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            query->setResource(issuer.get());
            for (vector<AttributeDesignator*>::const_iterator ad = m_SAML1Designators.begin(); ad!=m_SAML1Designators.end(); ++ad)
                query->getAttributeDesignators().push_back((*ad)->cloneAttributeDesignator());
            Request* request = RequestBuilder::buildRequest();
            request->setAttributeQuery(query);
            request->setMinorVersion(version);

            SAML1SOAPClient client(soaper);
            client.sendSAML(request, mcc, loc.get());
            response = client.receiveSAML();
        }
        catch (exception& ex) {
            m_log.error("exception making SAML query: %s", ex.what());
            soaper.reset();
        }
    }

    if (!response) {
        m_log.error("unable to successfully query for attributes");
        return false;
    }

    const vector<saml1::Assertion*>& assertions = const_cast<const saml1p::Response*>(response)->getAssertions();
    if (assertions.size()>1)
        m_log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml1p::Response> wrapper(response);
    saml1::Assertion* newtoken = assertions.front();

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        return true;
    }

    try {
        policy.evaluate(*newtoken);
        if (!policy.isSecure())
            throw SecurityPolicyException("Security of SAML 1.x query result not established.");
        saml1::AssertionValidator tokval(ctx.getApplication().getAudiences(), time(NULL));
        tokval.validateAssertion(*newtoken);
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy/validation: %s", ex.what());
        return true;
    }

    newtoken->detach();
    wrapper.release();
    ctx.getResolvedAssertions().push_back(newtoken);

    // Finally, extract and filter the result.
    try {
        AttributeExtractor* extractor = ctx.getApplication().getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            extractor->extractAttributes(ctx.getApplication(), AA, *newtoken, ctx.getResolvedAttributes());
        }
    }
    catch (exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
    }

    return true;
}

bool QueryResolver::SAML2Query(QueryContext& ctx) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif

    const AttributeAuthorityDescriptor* AA = ctx.getEntityDescriptor()->getAttributeAuthorityDescriptor(samlconstants::SAML20P_NS);
    if (!AA) {
        m_log.info("no SAML 2 AttributeAuthority role found in metadata");
        return false;
    }

    shibsp::SecurityPolicy policy(ctx.getApplication());
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(policy);
    const PropertySet* policySettings =
        ctx.getApplication().getServiceProvider().getPolicySettings(ctx.getApplication().getString("policyId").second);
    pair<bool,bool> signedAssertions = policySettings->getBool("signedAssertions");

    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    saml2p::StatusResponseType* srt=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !srt && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("entityID").second);
            saml2::Subject* subject = saml2::SubjectBuilder::buildSubject();
            subject->setNameID(ctx.getNameID()->cloneNameID());
            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            Issuer* iss = IssuerBuilder::buildIssuer();
            iss->setName(issuer.get());
            query->setIssuer(iss);
            for (vector<saml2::Attribute*>::const_iterator ad = m_SAML2Designators.begin(); ad!=m_SAML2Designators.end(); ++ad)
                query->getAttributes().push_back((*ad)->cloneAttribute());

            SAML2SOAPClient client(soaper);
            client.sendSAML(query, mcc, loc.get());
            srt = client.receiveSAML();
        }
        catch (exception& ex) {
            m_log.error("exception making SAML query: %s", ex.what());
            soaper.reset();
        }
    }

    if (!srt) {
        m_log.error("unable to successfully query for attributes");
        return false;
    }
    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt);
    if (!response) {
        delete srt;
        m_log.error("message was not a samlp:Response");
        return true;
    }

    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.size()>1)
        m_log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml2p::Response> wrapper(response);
    saml2::Assertion* newtoken = assertions.front();

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        m_log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        return true;
    }

    try {
        policy.evaluate(*newtoken);
        if (!policy.isSecure())
            throw SecurityPolicyException("Security of SAML 2.0 query result not established.");
        saml2::AssertionValidator tokval(ctx.getApplication().getAudiences(), time(NULL));
        tokval.validateAssertion(*newtoken);
    }
    catch (exception& ex) {
        m_log.error("assertion failed policy/validation: %s", ex.what());
        return true;
    }

    newtoken->detach();
    wrapper.release();
    ctx.getResolvedAssertions().push_back(newtoken);

    // Finally, extract and filter the result.
    try {
        AttributeExtractor* extractor = ctx.getApplication().getAttributeExtractor();
        if (extractor) {
            Locker extlocker(extractor);
            extractor->extractAttributes(ctx.getApplication(), AA, *newtoken, ctx.getResolvedAttributes());
        }
    }
    catch (exception& ex) {
        m_log.error("caught exception extracting/filtering attributes from query result: %s", ex.what());
    }

    return true;
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

    if (qctx.getNameID() && qctx.getEntityDescriptor()) {
        m_log.debug("attempting SAML 2.0 attribute query");
        if (!SAML2Query(qctx)) {
            m_log.debug("attempting SAML 1.x attribute query");
            SAML1Query(qctx);
        }
    }
    m_log.warn("can't attempt attribute query, either no NameID or no metadata to use");
}
