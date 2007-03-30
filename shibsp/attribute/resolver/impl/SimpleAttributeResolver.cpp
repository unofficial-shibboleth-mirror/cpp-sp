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
 * SimpleAttributeResolver.cpp
 * 
 * AttributeResolver based on a simple mapping of SAML information.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "binding/SOAPClient.h"
#include "util/SPConstants.h"


#include <log4cpp/Category.hh>
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
#include <xmltooling/util/ReloadableXMLFile.h>
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

    class SHIBSP_DLLLOCAL SimpleContext : public ResolutionContext
    {
    public:
        SimpleContext(const Application& application, const Session& session)
            : m_app(application), m_session(&session), m_client_addr(NULL), m_metadata(NULL), m_entity(NULL),
                m_nameid(session.getNameID()), m_tokens(NULL) {
        }
        
        SimpleContext(
            const Application& application,
            const char* client_addr,
            const EntityDescriptor* issuer,
            const NameID* nameid,
            const vector<const opensaml::Assertion*>* tokens=NULL
            ) : m_app(application), m_session(NULL), m_client_addr(client_addr), m_metadata(NULL), m_entity(issuer),
                m_nameid(nameid), m_tokens(tokens) {
        }
        
        ~SimpleContext() {
            if (m_metadata)
                m_metadata->unlock();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }
    
        const Application& getApplication() const {
            return m_app;
        }
        const char* getClientAddress() const {
            return m_session ? m_session->getClientAddress() : m_client_addr;
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
        const vector<const opensaml::Assertion*>* getTokens() const {
            return m_tokens;
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
        const Application& m_app;
        const Session* m_session;
        const char* m_client_addr;
        mutable MetadataProvider* m_metadata;
        mutable const EntityDescriptor* m_entity;
        const NameID* m_nameid;
        const vector<const opensaml::Assertion*>* m_tokens;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };
    
#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SimpleResolverImpl
    {
    public:
        SimpleResolverImpl(const DOMElement* e);
        ~SimpleResolverImpl() {
            for_each(m_decoderMap.begin(), m_decoderMap.end(), cleanup_pair<string,AttributeDecoder>());
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void query(
            ResolutionContext& ctx, const NameIdentifier& nameid, const vector<const char*>* attributes=NULL
            ) const;
        void query(
            ResolutionContext& ctx, const NameID& nameid, const vector<const char*>* attributes=NULL
            ) const;
        void resolve(
            ResolutionContext& ctx, const saml1::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;
        void resolve(
            ResolutionContext& ctx, const saml2::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;

        bool m_allowQuery;
    private:
        DOMDocument* m_document;
        map<string,AttributeDecoder*> m_decoderMap;
#ifdef HAVE_GOOD_STL
        map< pair<xstring,xstring>,pair<const AttributeDecoder*,string> > m_attrMap;
#else
        map< pair<string,string>,pair<const AttributeDecoder*,string> > m_attrMap;
#endif
    };
    
    class SimpleResolver : public AttributeResolver, public ReloadableXMLFile
    {
    public:
        SimpleResolver(const DOMElement* e) : ReloadableXMLFile(e), m_impl(NULL) {
            load();
        }
        ~SimpleResolver() {
            delete m_impl;
        }
        
        ResolutionContext* createResolutionContext(
            const Application& application,
            const char* client_addr,
            const EntityDescriptor* issuer,
            const NameID* nameid,
            const vector<const opensaml::Assertion*>* tokens=NULL
            ) const {
            return new SimpleContext(application,client_addr,issuer,nameid,tokens);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new SimpleContext(application,session);
        }
        
        void resolveAttributes(ResolutionContext& ctx, const vector<const char*>* attributes=NULL) const;

    protected:
        pair<bool,DOMElement*> load();
        SimpleResolverImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeResolver* SHIBSP_DLLLOCAL SimpleAttributeResolverFactory(const DOMElement* const & e)
    {
        return new SimpleResolver(e);
    }
    
    static const XMLCh SIMPLE_NS[] = {
        chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
        chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
        chDigit_2, chPeriod, chDigit_0, chColon,
        chLatin_r, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chColon,
        chLatin_s, chLatin_i, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chNull
    };
    static const XMLCh _AttributeDecoder[] =    UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh allowQuery[] =           UNICODE_LITERAL_10(a,l,l,o,w,Q,u,e,r,y);
    static const XMLCh decoderId[] =            UNICODE_LITERAL_9(d,e,c,o,d,e,r,I,d);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
};

SimpleResolverImpl::SimpleResolverImpl(const DOMElement* e) : m_document(NULL), m_allowQuery(true)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("SimpleResolverImpl");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");
    
    if (!XMLHelper::isNodeNamed(e, SIMPLE_NS, _AttributeResolver))
        throw ConfigurationException("Simple resolver requires resolver:AttributeResolver at root of configuration.");
    
    const XMLCh* flag = e->getAttributeNS(NULL,allowQuery);
    if (flag && (*flag==chLatin_f || *flag==chDigit_0)) {
        log.info("SAML attribute queries disabled");
        m_allowQuery = false;
    }

    DOMElement* child = XMLHelper::getFirstChildElement(e, SIMPLE_NS, _AttributeDecoder);
    while (child) {
        auto_ptr_char id(child->getAttributeNS(NULL, _id));
        auto_ptr_char type(child->getAttributeNS(NULL, _type));
        try {
            log.info("building AttributeDecoder (%s) of type %s", id.get(), type.get());
            m_decoderMap[id.get()] = SPConfig::getConfig().AttributeDecoderManager.newPlugin(type.get(), child);
        }
        catch (exception& ex) {
            log.error("error building AttributeDecoder (%s): %s", id.get(), ex.what());
        }
        child = XMLHelper::getNextSiblingElement(child, SIMPLE_NS, _AttributeDecoder);
    }
    
    child = XMLHelper::getFirstChildElement(e, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME);
    while (child) {
        // Check for missing Name.
        const XMLCh* name = child->getAttributeNS(NULL, saml2::Attribute::NAME_ATTRIB_NAME);
        if (!name || !*name) {
            log.warn("skipping saml:Attribute declared with no Name");
            child = XMLHelper::getNextSiblingElement(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME);
            continue;
        }

        const AttributeDecoder* decoder=NULL;
        auto_ptr_char id(child->getAttributeNS(NULL, saml2::Attribute::FRIENDLYNAME_ATTRIB_NAME));
        auto_ptr_char d(child->getAttributeNS(SIMPLE_NS, decoderId));
        if (!id.get() || !*id.get() || !d.get() || !*d.get() || !(decoder=m_decoderMap[d.get()])) {
            log.warn("skipping saml:Attribute declared with no FriendlyName or resolvable AttributeDecoder");
            child = XMLHelper::getNextSiblingElement(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME);
            continue;
        }
        
        // Empty NameFormat implies the usual Shib URI naming defaults.
        const XMLCh* format = child->getAttributeNS(NULL, saml2::Attribute::NAMEFORMAT_ATTRIB_NAME);
        if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI) ||
                XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
            format = &chNull;  // ignore default Format/Namespace values

        // Fetch/create the map entry and see if it's a duplicate rule.
#ifdef HAVE_GOOD_STL
        pair<const AttributeDecoder*,string>& decl = m_attrMap[make_pair(name,format)];
#else
        auto_ptr_char n(name);
        auto_ptr_char f(format);
        pair<const AttributeDecoder*,string>& decl = m_attrMap[make_pair(n.get(),f.get())];
#endif
        if (decl.first) {
            log.warn("skipping duplicate saml:Attribute declaration (same Name and NameFormat)");
            child = XMLHelper::getNextSiblingElement(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME);
            continue;
        }

        if (log.isInfoEnabled()) {
#ifdef HAVE_GOOD_STL
            auto_ptr_char n(name);
            auto_ptr_char f(format);
#endif
            log.info("creating declaration for Attribute %s%s%s", n.get(), *f.get() ? ", Format/Namespace:" : "", f.get());
        }
        
        decl.first = decoder;
        decl.second = id.get();
        
        child = XMLHelper::getNextSiblingElement(child, samlconstants::SAML20_NS, saml2::Attribute::LOCAL_NAME);
    }
}

void SimpleResolverImpl::resolve(
    ResolutionContext& ctx, const saml1::Assertion* token, const vector<const char*>* attributes
    ) const
{
    set<string> aset;
    if (attributes)
        for(vector<const char*>::const_iterator i=attributes->begin(); i!=attributes->end(); ++i)
            aset.insert(*i);

    vector<shibsp::Attribute*>& resolved = ctx.getResolvedAttributes();

    auto_ptr_char assertingParty(ctx.getEntityDescriptor() ? ctx.getEntityDescriptor()->getEntityID() : NULL);
    const char* relyingParty = ctx.getApplication().getString("providerId").second;

#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#else
    map< pair<string,string>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#endif

    const XMLCh* name;
    const XMLCh* format;
    
    // Check the NameID based on the format.
    if (ctx.getNameID()) {
        format = ctx.getNameID()->getFormat();
        if (!format || !*format)
            format = NameID::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
        if ((rule=m_attrMap.find(make_pair(format,xstring()))) != m_attrMap.end()) {
#else
        auto_ptr_char temp(format);
        if ((rule=m_attrMap.find(make_pair(temp.get(),string()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second)) {
                resolved.push_back(
                    rule->second.first->decode(
                        rule->second.second.c_str(), ctx.getNameID(), assertingParty.get(), relyingParty
                        )
                    );
            }
        }
    }

    const vector<saml1::AttributeStatement*>& statements = token->getAttributeStatements();
    for (vector<saml1::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
        const vector<saml1::Attribute*>& attrs = const_cast<const saml1::AttributeStatement*>(*s)->getAttributes();
        for (vector<saml1::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a) {
            name = (*a)->getAttributeName();
            format = (*a)->getAttributeNamespace();
            if (!name || !*name)
                continue;
            if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI))
                format = &chNull;
#ifdef HAVE_GOOD_STL
            if ((rule=m_attrMap.find(make_pair(name,format))) != m_attrMap.end()) {
#else
            auto_ptr_char temp1(name);
            auto_ptr_char temp2(format);
            if ((rule=m_attrMap.find(make_pair(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
                if (aset.empty() || aset.count(rule->second.second)) {
                    resolved.push_back(
                        rule->second.first->decode(rule->second.second.c_str(), *a, assertingParty.get(), relyingParty)
                        );
                }
            }
        }
    }
}

void SimpleResolverImpl::resolve(
    ResolutionContext& ctx, const saml2::Assertion* token, const vector<const char*>* attributes
    ) const
{
    set<string> aset;
    if (attributes)
        for(vector<const char*>::const_iterator i=attributes->begin(); i!=attributes->end(); ++i)
            aset.insert(*i);

    vector<shibsp::Attribute*>& resolved = ctx.getResolvedAttributes();

    auto_ptr_char assertingParty(ctx.getEntityDescriptor() ? ctx.getEntityDescriptor()->getEntityID() : NULL);
    const char* relyingParty = ctx.getApplication().getString("providerId").second;

#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#else
    map< pair<string,string>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#endif

    const XMLCh* name;
    const XMLCh* format;
    
    // Check the NameID based on the format.
    if (ctx.getNameID()) {
        format = ctx.getNameID()->getFormat();
        if (!format || !*format)
            format = NameID::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
        if ((rule=m_attrMap.find(make_pair(format,xstring()))) != m_attrMap.end()) {
#else
        auto_ptr_char temp(format);
        if ((rule=m_attrMap.find(make_pair(temp.get(),string()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second)) {
                resolved.push_back(
                    rule->second.first->decode(
                        rule->second.second.c_str(), ctx.getNameID(), assertingParty.get(), relyingParty
                        )
                    );
            }
        }
    }

    const vector<saml2::AttributeStatement*>& statements = token->getAttributeStatements();
    for (vector<saml2::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
        const vector<saml2::Attribute*>& attrs = const_cast<const saml2::AttributeStatement*>(*s)->getAttributes();
        for (vector<saml2::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a) {
            name = (*a)->getName();
            format = (*a)->getNameFormat();
            if (!name || !*name)
                continue;
            if (!format || !*format)
                format = saml2::Attribute::UNSPECIFIED;
            else if (XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
                format = &chNull;
#ifdef HAVE_GOOD_STL
            if ((rule=m_attrMap.find(make_pair(name,format))) != m_attrMap.end()) {
#else
            auto_ptr_char temp1(name);
            auto_ptr_char temp2(format);
            if ((rule=m_attrMap.find(make_pair(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
                if (aset.empty() || aset.count(rule->second.second)) {
                    resolved.push_back(
                        rule->second.first->decode(rule->second.second.c_str(), *a, assertingParty.get(), relyingParty)
                        );
                }
            }
        }

        const vector<saml2::EncryptedAttribute*>& encattrs = const_cast<const saml2::AttributeStatement*>(*s)->getEncryptedAttributes();
        if (!encattrs.empty()) {
            const XMLCh* recipient = ctx.getApplication().getXMLString("providerId").second;
            CredentialResolver* cr = ctx.getApplication().getCredentialResolver();
            if (!cr) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeResolver").warn(
                    "found encrypted attributes, but no CredentialResolver was available"
                    );
                return;
            }

            // We look up credentials based on the peer who did the encrypting.
            CredentialCriteria cc;
            cc.setPeerName(assertingParty.get());

            Locker credlocker(cr);
            for (vector<saml2::EncryptedAttribute*>::const_iterator ea = encattrs.begin(); ea!=encattrs.end(); ++ea) {
                auto_ptr<XMLObject> decrypted((*ea)->decrypt(*cr, recipient, &cc));
                const saml2::Attribute* decattr = dynamic_cast<const saml2::Attribute*>(decrypted.get());
                name = decattr->getName();
                format = decattr->getNameFormat();
                if (!name || !*name)
                    continue;
                if (!format || !*format)
                    format = saml2::Attribute::UNSPECIFIED;
                else if (XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
                    format = &chNull;
#ifdef HAVE_GOOD_STL
                if ((rule=m_attrMap.find(make_pair(name,format))) != m_attrMap.end()) {
#else
                auto_ptr_char temp1(name);
                auto_ptr_char temp2(format);
                if ((rule=m_attrMap.find(make_pair(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
                    if (aset.empty() || aset.count(rule->second.second)) {
                        resolved.push_back(
                            rule->second.first->decode(rule->second.second.c_str(), decattr, assertingParty.get(), relyingParty)
                            );
                    }
                }
            }
        }
    }
}

void SimpleResolverImpl::query(ResolutionContext& ctx, const NameIdentifier& nameid, const vector<const char*>* attributes) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");

    const EntityDescriptor* entity = ctx.getEntityDescriptor();
    if (!entity) {
        log.debug("no issuer information available, skipping query");
        return;
    }

    int version = 1;
    const AttributeAuthorityDescriptor* AA = entity->getAttributeAuthorityDescriptor(samlconstants::SAML11_PROTOCOL_ENUM);
    if (!AA) {
        AA = entity->getAttributeAuthorityDescriptor(samlconstants::SAML10_PROTOCOL_ENUM);
        version = 0;
    }
    if (!AA) {
        log.info("no SAML 1.x AttributeAuthority role found in metadata");
        return;
    }

    SecurityPolicy policy;
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(ctx.getApplication(),policy);
    const PropertySet* policySettings = ctx.getApplication().getServiceProvider().getPolicySettings(ctx.getApplication().getString("policyId").second);
    pair<bool,bool> signedAssertions = policySettings->getBool("signedAssertions");

    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    saml1p::Response* response=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("providerId").second);
            saml1::Subject* subject = saml1::SubjectBuilder::buildSubject();
            subject->setNameIdentifier(nameid.cloneNameIdentifier());
            saml1p::AttributeQuery* query = saml1p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            Request* request = RequestBuilder::buildRequest();
            request->setAttributeQuery(query);
            query->setResource(issuer.get());
            request->setMinorVersion(version);
            SAML1SOAPClient client(soaper);
            client.sendSAML(request, mcc, loc.get());
            response = client.receiveSAML();
        }
        catch (exception& ex) {
            log.error("exception making SAML query: %s", ex.what());
            soaper.reset();
        }
    }

    if (!response) {
        log.error("unable to successfully query for attributes");
        return;
    }

    const vector<saml1::Assertion*>& assertions = const_cast<const saml1p::Response*>(response)->getAssertions();
    if (assertions.size()>1)
        log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml1p::Response> wrapper(response);
    saml1::Assertion* newtoken = assertions.front();

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        return;
    }

    try {
        policy.evaluate(*newtoken);
        if (!policy.isSecure())
            throw SecurityPolicyException("Security of SAML 1.x query result not established.");
        saml1::AssertionValidator tokval(ctx.getApplication().getAudiences(), time(NULL));
        tokval.validateAssertion(*newtoken);
    }
    catch (exception& ex) {
        log.error("assertion failed policy/validation: %s", ex.what());
    }
    newtoken->detach();
    wrapper.release();
    ctx.getResolvedAssertions().push_back(newtoken);
    resolve(ctx, newtoken, attributes);
}

void SimpleResolverImpl::query(ResolutionContext& ctx, const NameID& nameid, const vector<const char*>* attributes) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");

    const EntityDescriptor* entity = ctx.getEntityDescriptor();
    if (!entity) {
        log.debug("no issuer information available, skipping query");
        return;
    }
    const AttributeAuthorityDescriptor* AA = entity->getAttributeAuthorityDescriptor(samlconstants::SAML20P_NS);
    if (!AA) {
        log.info("no SAML 2 AttributeAuthority role found in metadata");
        return;
    }

    SecurityPolicy policy;
    MetadataCredentialCriteria mcc(*AA);
    shibsp::SOAPClient soaper(ctx.getApplication(),policy);
    const PropertySet* policySettings = ctx.getApplication().getServiceProvider().getPolicySettings(ctx.getApplication().getString("policyId").second);
    pair<bool,bool> signedAssertions = policySettings->getBool("signedAssertions");

    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    saml2p::StatusResponseType* srt=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !srt && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("providerId").second);
            saml2::Subject* subject = saml2::SubjectBuilder::buildSubject();
            subject->setNameID(nameid.cloneNameID());
            saml2p::AttributeQuery* query = saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            Issuer* iss = IssuerBuilder::buildIssuer();
            query->setIssuer(iss);
            iss->setName(issuer.get());
            SAML2SOAPClient client(soaper);
            client.sendSAML(query, mcc, loc.get());
            srt = client.receiveSAML();
        }
        catch (exception& ex) {
            log.error("exception making SAML query: %s", ex.what());
            soaper.reset();
        }
    }

    if (!srt) {
        log.error("unable to successfully query for attributes");
        return;
    }
    saml2p::Response* response = dynamic_cast<saml2p::Response*>(srt);
    if (!response) {
        delete srt;
        log.error("message was not a samlp:Response");
        return;
    }

    const vector<saml2::Assertion*>& assertions = const_cast<const saml2p::Response*>(response)->getAssertions();
    if (assertions.size()>1)
        log.warn("simple resolver only supports one assertion in the query response");

    auto_ptr<saml2p::Response> wrapper(response);
    saml2::Assertion* newtoken = assertions.front();

    if (!newtoken->getSignature() && signedAssertions.first && signedAssertions.second) {
        log.error("assertion unsigned, rejecting it based on signedAssertions policy");
        return;
    }

    try {
        policy.evaluate(*newtoken);
        if (!policy.isSecure())
            throw SecurityPolicyException("Security of SAML 2.0 query result not established.");
        saml2::AssertionValidator tokval(ctx.getApplication().getAudiences(), time(NULL));
        tokval.validateAssertion(*newtoken);
    }
    catch (exception& ex) {
        log.error("assertion failed policy/validation: %s", ex.what());
    }
    newtoken->detach();
    wrapper.release();
    ctx.getResolvedAssertions().push_back(newtoken);
    resolve(ctx, newtoken, attributes);
}

void SimpleResolver::resolveAttributes(ResolutionContext& ctx, const vector<const char*>* attributes) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");
    
    log.debug("examining tokens to resolve");

    bool query = m_impl->m_allowQuery;
    const saml1::Assertion* token1;
    const saml2::Assertion* token2;
    if (ctx.getTokens()) {
        for (vector<const opensaml::Assertion*>::const_iterator t = ctx.getTokens()->begin(); t!=ctx.getTokens()->end(); ++t) {
            token2 = dynamic_cast<const saml2::Assertion*>(*t);
            if (token2 && !token2->getAttributeStatements().empty()) {
                log.debug("resolving SAML 2 token with an AttributeStatement");
                m_impl->resolve(ctx, token2, attributes);
                query = false;
            }
            else {
                token1 = dynamic_cast<const saml1::Assertion*>(*t);
                if (token1 && !token1->getAttributeStatements().empty()) {
                    log.debug("resolving SAML 1 token with an AttributeStatement");
                    m_impl->resolve(ctx, token1, attributes);
                    query = false;
                }
            }
        }
    }

    if (query) {
        if (token1 && !token1->getAuthenticationStatements().empty()) {
            const AuthenticationStatement* statement = token1->getAuthenticationStatements().front();
            if (statement && statement->getSubject() && statement->getSubject()->getNameIdentifier()) {
                log.debug("attempting SAML 1.x attribute query");
                return m_impl->query(ctx, *(statement->getSubject()->getNameIdentifier()), attributes);
            }
        }
        else if (token2 && ctx.getNameID()) {
            log.debug("attempting SAML 2.0 attribute query");
            return m_impl->query(ctx, *ctx.getNameID(), attributes);
        }
        log.warn("can't attempt attribute query, no identifier in assertion subject");
    }
}

pair<bool,DOMElement*> SimpleResolver::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    SimpleResolverImpl* impl = new SimpleResolverImpl(raw.second);
    
    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}
