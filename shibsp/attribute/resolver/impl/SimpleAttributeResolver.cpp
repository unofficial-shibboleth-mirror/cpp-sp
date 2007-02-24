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
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
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
            : m_app(application), m_session(&session), m_metadata(NULL), m_entity(NULL),
                m_nameid(session.getNameID()), m_token(NULL) {
        }
        
        SimpleContext(
            const Application& application,
            const char* client_addr,
            const EntityDescriptor* issuer,
            const NameID& nameid,
            const opensaml::RootObject* ssoToken=NULL
            ) : m_app(application), m_session(NULL), m_entity(issuer), m_nameid(nameid), m_token(ssoToken) {
            if (client_addr)
                m_client_addr = client_addr;
        }
        
        ~SimpleContext() {
            if (m_metadata)
                m_metadata->unlock();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::RootObject>());
        }
    
        const Application& getApplication() const {
            return m_app;
        }
        const char* getClientAddress() const {
            return m_session ? m_session->getClientAddress() : m_client_addr.c_str();
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
        const NameID& getNameID() const {
            return m_nameid;
        }
        const opensaml::RootObject* getSSOToken() const {
            if (m_token)
                return m_token;
            if (m_session) {
                const vector<const char*>& ids = m_session->getAssertionIDs();
                if (!ids.empty())
                    return m_token = m_session->getAssertion(ids.front());
            }
            return NULL;
        }
        const Session* getSession() const {
            return m_session;
        }        
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::RootObject*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const Application& m_app;
        const Session* m_session;
        string m_client_addr;
        mutable MetadataProvider* m_metadata;
        mutable const EntityDescriptor* m_entity;
        const NameID& m_nameid;
        mutable const opensaml::RootObject* m_token;
        vector<shibsp::Attribute*> m_attributes;
        vector<opensaml::RootObject*> m_assertions;
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
            ResolutionContext& ctx, const opensaml::saml1::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;
        void query(
            ResolutionContext& ctx, const opensaml::saml2::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;
        void resolve(
            ResolutionContext& ctx, const opensaml::saml1::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;
        void resolve(
            ResolutionContext& ctx, const opensaml::saml2::Assertion* token, const vector<const char*>* attributes=NULL
            ) const;

    private:
        DOMDocument* m_document;
        bool m_allowQuery;
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
            const NameID& nameid,
            const opensaml::RootObject* ssoToken=NULL
            ) const {
            return new SimpleContext(application,client_addr,issuer,nameid,ssoToken);
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
    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh allowQuery[] =           UNICODE_LITERAL_10(a,l,l,o,w,Q,u,e,r,y);
    static const XMLCh decoderType[] =          UNICODE_LITERAL_11(d,e,c,o,d,e,r,T,y,p,e);
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
    
    e = XMLHelper::getFirstChildElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
    while (e) {
        // Check for missing Name.
        const XMLCh* name = e->getAttributeNS(NULL, opensaml::saml2::Attribute::NAME_ATTRIB_NAME);
        if (!name || !*name) {
            log.warn("skipping saml:Attribute declared with no Name");
            e = XMLHelper::getNextSiblingElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
            continue;
        }

        auto_ptr_char id(e->getAttributeNS(NULL, opensaml::saml2::Attribute::FRIENDLYNAME_ATTRIB_NAME));
        if (!id.get() || !*id.get()) {
            log.warn("skipping saml:Attribute declared with no FriendlyName");
            e = XMLHelper::getNextSiblingElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
            continue;
        }
        
        auto_ptr_char d(e->getAttributeNS(SIMPLE_NS, decoderType));
        const char* dtype = d.get();
        if (!dtype || !*dtype)
            dtype = SIMPLE_ATTRIBUTE_DECODER;
        AttributeDecoder*& decoder = m_decoderMap[dtype];
        if (!decoder) {
            try {
                decoder = SPConfig::getConfig().AttributeDecoderManager.newPlugin(dtype, NULL);
            }
            catch (exception& ex) {
                log.error("error building AttributeDecoder: %s", ex.what());
                e = XMLHelper::getNextSiblingElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
                continue;
            }
        }
                
        // Empty NameFormat implies the usual Shib URI naming defaults.
        const XMLCh* format = e->getAttributeNS(NULL, opensaml::saml2::Attribute::NAMEFORMAT_ATTRIB_NAME);
        if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI) ||
                XMLString::equals(format, opensaml::saml2::Attribute::URI_REFERENCE))
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
            e = XMLHelper::getNextSiblingElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
            continue;
        }

        if (log.isDebugEnabled()) {
#ifdef HAVE_GOOD_STL
            auto_ptr_char n(name);
            auto_ptr_char f(format);
#endif
            log.debug("creating declaration for (Name=%s) %s%s)", n.get(), *f.get() ? "(Format/Namespace=" : "", f.get());
        }
        
        decl.first = decoder;
        decl.second = id.get();
        
        e = XMLHelper::getNextSiblingElement(e, samlconstants::SAML20_NS, opensaml::saml2::Attribute::LOCAL_NAME);
    }
}

void SimpleResolverImpl::resolve(
    ResolutionContext& ctx, const opensaml::saml1::Assertion* token, const vector<const char*>* attributes
    ) const
{
    set<string> aset;
    if (attributes)
        for(vector<const char*>::const_iterator i=attributes->begin(); i!=attributes->end(); ++i)
            aset.insert(*i);

    vector<shibsp::Attribute*>& resolved = ctx.getResolvedAttributes();

#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#else
    map< pair<string,string>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#endif

    // Check the NameID based on the format.
    const XMLCh* name;
    const XMLCh* format = ctx.getNameID().getFormat();
    if (!format) {
        format = NameID::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
        if ((rule=m_attrMap.find(make_pair(format,xstring()))) != m_attrMap.end()) {
#else
        auto_ptr_char temp(format);
        if ((rule=m_attrMap.find(make_pair(temp.get(),string()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second))
                resolved.push_back(rule->second.first->decode(rule->second.second.c_str(), &ctx.getNameID()));
        }
    }

    const vector<opensaml::saml1::AttributeStatement*>& statements = token->getAttributeStatements();
    for (vector<opensaml::saml1::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
        const vector<opensaml::saml1::Attribute*>& attrs = const_cast<const opensaml::saml1::AttributeStatement*>(*s)->getAttributes();
        for (vector<opensaml::saml1::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a) {
            name = (*a)->getAttributeName();
            format = (*a)->getAttributeNamespace();
            if (!name || !*name)
                continue;
            if (!format)
                format = &chNull;
#ifdef HAVE_GOOD_STL
            if ((rule=m_attrMap.find(make_pair(name,format))) != m_attrMap.end()) {
#else
            auto_ptr_char temp1(name);
            auto_ptr_char temp2(format);
            if ((rule=m_attrMap.find(make_pair(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second))
                resolved.push_back(rule->second.first->decode(rule->second.second.c_str(), *a));
            }
        }
    }
}

void SimpleResolverImpl::resolve(
    ResolutionContext& ctx, const opensaml::saml2::Assertion* token, const vector<const char*>* attributes
    ) const
{
    set<string> aset;
    if (attributes)
        for(vector<const char*>::const_iterator i=attributes->begin(); i!=attributes->end(); ++i)
            aset.insert(*i);

    vector<shibsp::Attribute*>& resolved = ctx.getResolvedAttributes();

#ifdef HAVE_GOOD_STL
    map< pair<xstring,xstring>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#else
    map< pair<string,string>,pair<const AttributeDecoder*,string> >::const_iterator rule;
#endif

    // Check the NameID based on the format.
    const XMLCh* name;
    const XMLCh* format = ctx.getNameID().getFormat();
    if (!format) {
        format = NameID::UNSPECIFIED;
#ifdef HAVE_GOOD_STL
        if ((rule=m_attrMap.find(make_pair(format,xstring()))) != m_attrMap.end()) {
#else
        auto_ptr_char temp(format);
        if ((rule=m_attrMap.find(make_pair(temp.get(),string()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second))
                resolved.push_back(rule->second.first->decode(rule->second.second.c_str(), &ctx.getNameID()));
        }
    }

    const vector<opensaml::saml2::AttributeStatement*>& statements = token->getAttributeStatements();
    for (vector<opensaml::saml2::AttributeStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
        const vector<opensaml::saml2::Attribute*>& attrs = const_cast<const opensaml::saml2::AttributeStatement*>(*s)->getAttributes();
        for (vector<opensaml::saml2::Attribute*>::const_iterator a = attrs.begin(); a!=attrs.end(); ++a) {
            name = (*a)->getName();
            format = (*a)->getNameFormat();
            if (!name || !*name)
                continue;
            if (!format)
                format = &chNull;
#ifdef HAVE_GOOD_STL
            if ((rule=m_attrMap.find(make_pair(name,format))) != m_attrMap.end()) {
#else
            auto_ptr_char temp1(name);
            auto_ptr_char temp2(format);
            if ((rule=m_attrMap.find(make_pair(temp1.get(),temp2.get()))) != m_attrMap.end()) {
#endif
            if (aset.empty() || aset.count(rule->second.second))
                resolved.push_back(rule->second.first->decode(rule->second.second.c_str(), *a));
            }
        }
    }
}

void SimpleResolverImpl::query(ResolutionContext& ctx, const opensaml::saml1::Assertion* token, const vector<const char*>* attributes) const
{
    if (!m_allowQuery)
        return;

#ifdef _DEBUG
    xmltooling::NDC ndc("query");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");

    const EntityDescriptor* entity = ctx.getEntityDescriptor();
    if (!entity) {
        log.debug("no issuer information available, skipping query");
        return;
    }
    const AttributeAuthorityDescriptor* AA =
        entity->getAttributeAuthorityDescriptor(
            token->getMinorVersion().second==1 ? samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM
            );
    if (!AA) {
        log.debug("no SAML 1.%d AttributeAuthority role found in metadata", token->getMinorVersion().second);
        return;
    }

    SecurityPolicy policy;
    shibsp::SOAPClient soaper(ctx.getApplication(),policy);

    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    opensaml::saml1p::Response* response=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("providerId").second);
            opensaml::saml1::Subject* subject = opensaml::saml1::SubjectBuilder::buildSubject();
            subject->setNameIdentifier(token->getAuthenticationStatements().front()->getSubject()->getNameIdentifier()->cloneNameIdentifier());
            opensaml::saml1p::AttributeQuery* query = opensaml::saml1p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            Request* request = RequestBuilder::buildRequest();
            request->setAttributeQuery(query);
            query->setResource(issuer.get());
            request->setMinorVersion(token->getMinorVersion().second);
            SAML1SOAPClient client(soaper);
            client.sendSAML(request, *AA, loc.get());
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

    time_t now = time(NULL);
    const Validator* tokval = ctx.getApplication().getTokenValidator(now, AA);
    const vector<opensaml::saml1::Assertion*>& assertions = const_cast<const opensaml::saml1p::Response*>(response)->getAssertions();
    if (assertions.size()==1) {
        auto_ptr<opensaml::saml1p::Response> wrapper(response);
        opensaml::saml1::Assertion* newtoken = assertions.front();
        if (!XMLString::equals(policy.getIssuer() ? policy.getIssuer()->getName() : NULL, newtoken->getIssuer())) {
            log.error("assertion issued by someone other than AA, rejecting it");
            return;
        }
        try {
            tokval->validate(newtoken);
        }
        catch (exception& ex) {
            log.error("assertion failed validation check: %s", ex.what());
        }
        newtoken->detach();
        wrapper.release();
        ctx.getResolvedAssertions().push_back(newtoken);
        resolve(ctx, newtoken, attributes);
    }
    else {
        auto_ptr<opensaml::saml1p::Response> wrapper(response);
        for (vector<opensaml::saml1::Assertion*>::const_iterator a = assertions.begin(); a!=assertions.end(); ++a) {
            if (!XMLString::equals(policy.getIssuer() ? policy.getIssuer()->getName() : NULL, (*a)->getIssuer())) {
                log.error("assertion issued by someone other than AA, rejecting it");
                continue;
            }
            try {
                tokval->validate(*a);
            }
            catch (exception& ex) {
                log.error("assertion failed validation check: %s", ex.what());
            }
            resolve(ctx, *a, attributes);
            ctx.getResolvedAssertions().push_back((*a)->cloneAssertion());
        }
    }
}

void SimpleResolverImpl::query(ResolutionContext& ctx, const opensaml::saml2::Assertion* token, const vector<const char*>* attributes) const
{
    if (!m_allowQuery)
        return;

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
        log.debug("no SAML 2 AttributeAuthority role found in metadata");
        return;
    }

    SecurityPolicy policy;
    shibsp::SOAPClient soaper(ctx.getApplication(),policy);

    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    opensaml::saml2p::StatusResponseType* srt=NULL;
    const vector<AttributeService*>& endpoints=AA->getAttributeServices();
    for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !srt && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            auto_ptr_char loc((*ep)->getLocation());
            auto_ptr_XMLCh issuer(ctx.getApplication().getString("providerId").second);
            opensaml::saml2::Subject* subject = opensaml::saml2::SubjectBuilder::buildSubject();
            subject->setNameID(token->getSubject()->getNameID()->cloneNameID());
            opensaml::saml2p::AttributeQuery* query = opensaml::saml2p::AttributeQueryBuilder::buildAttributeQuery();
            query->setSubject(subject);
            Issuer* iss = IssuerBuilder::buildIssuer();
            query->setIssuer(iss);
            iss->setName(issuer.get());
            SAML2SOAPClient client(soaper);
            client.sendSAML(query, *AA, loc.get());
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
    opensaml::saml2p::Response* response = dynamic_cast<opensaml::saml2p::Response*>(srt);
    if (!response) {
        delete srt;
        log.error("message was not a samlp:Response");
        return;
    }

    time_t now = time(NULL);
    const Validator* tokval = ctx.getApplication().getTokenValidator(now, AA);
    const vector<opensaml::saml2::Assertion*>& assertions = const_cast<const opensaml::saml2p::Response*>(response)->getAssertions();
    if (assertions.size()==1) {
        auto_ptr<opensaml::saml2p::Response> wrapper(response);
        opensaml::saml2::Assertion* newtoken = assertions.front();
        if (!XMLString::equals(policy.getIssuer() ? policy.getIssuer()->getName() : NULL, newtoken->getIssuer() ? newtoken->getIssuer()->getName() : NULL)) {
            log.error("assertion issued by someone other than AA, rejecting it");
            return;
        }
        try {
            tokval->validate(newtoken);
        }
        catch (exception& ex) {
            log.error("assertion failed validation check: %s", ex.what());
        }
        newtoken->detach();
        wrapper.release();
        ctx.getResolvedAssertions().push_back(newtoken);
        resolve(ctx, newtoken, attributes);
    }
    else {
        auto_ptr<opensaml::saml2p::Response> wrapper(response);
        for (vector<opensaml::saml2::Assertion*>::const_iterator a = assertions.begin(); a!=assertions.end(); ++a) {
            if (!XMLString::equals(policy.getIssuer() ? policy.getIssuer()->getName() : NULL, (*a)->getIssuer() ? (*a)->getIssuer()->getName() : NULL)) {
                log.error("assertion issued by someone other than AA, rejecting it");
                return;
            }
            try {
                tokval->validate(*a);
            }
            catch (exception& ex) {
                log.error("assertion failed validation check: %s", ex.what());
            }
            resolve(ctx, *a, attributes);
            ctx.getResolvedAssertions().push_back((*a)->cloneAssertion());
        }
    }
}

void SimpleResolver::resolveAttributes(ResolutionContext& ctx, const vector<const char*>* attributes) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("resolveAttributes");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".AttributeResolver");
    
    log.debug("examining incoming SSO token");

    const opensaml::RootObject* token = ctx.getSSOToken();
    if (!token) {
        log.warn("no SSO token supplied to resolver, returning nothing");
        return;
    }
    const opensaml::saml2::Assertion* token2 = dynamic_cast<const opensaml::saml2::Assertion*>(token);
    if (token2) {
        if (!token2->getAttributeStatements().empty()) {
            log.debug("found SAML 2 SSO token with an AttributeStatement");
            return m_impl->resolve(ctx, token2, attributes);
        }
        return m_impl->query(ctx, token2, attributes);
    }

    const opensaml::saml1::Assertion* token1 = dynamic_cast<const opensaml::saml1::Assertion*>(token);
    if (token1) {
        if (!token1->getAttributeStatements().empty()) {
            log.debug("found SAML 1 SSO token with an AttributeStatement");
            return m_impl->resolve(ctx, token1, attributes);
        }
        return m_impl->query(ctx, token1, attributes);
    }

    log.warn("unrecognized token type, returning nothing");
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
