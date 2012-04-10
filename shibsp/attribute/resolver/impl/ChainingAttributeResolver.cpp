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
 * ChainingAttributeResolver.cpp
 *
 * Chains together multiple AttributeResolver plugins.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"

#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <saml/Assertion.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    struct SHIBSP_DLLLOCAL ChainingContext : public ResolutionContext
    {
        ChainingContext(
            const Application& application,
            const GenericRequest* request,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid,
            const XMLCh* authncontext_class,
            const XMLCh* authncontext_decl,
            const vector<const opensaml::Assertion*>* tokens,
            const vector<shibsp::Attribute*>* attributes
            ) : m_app(application), m_request(request), m_issuer(issuer), m_protocol(protocol), m_nameid(nameid),
                m_authclass(authncontext_class), m_authdecl(authncontext_decl), m_session(nullptr) {
            if (tokens)
                m_tokens.assign(tokens->begin(), tokens->end());
            if (attributes)
                m_attributes.assign(attributes->begin(), attributes->end());
        }

        ChainingContext(const Application& application, const Session& session)
            : m_app(application), m_request(nullptr), m_issuer(nullptr), m_protocol(nullptr), m_nameid(nullptr),
                m_authclass(nullptr), m_authdecl(nullptr), m_session(&session) {
        }

        ~ChainingContext() {
            for_each(m_ownedAttributes.begin(), m_ownedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_ownedAssertions.begin(), m_ownedAssertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_ownedAttributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_ownedAssertions;
        }

        vector<shibsp::Attribute*> m_ownedAttributes;
        vector<opensaml::Assertion*> m_ownedAssertions;

        const Application& m_app;
        const GenericRequest* m_request;
        const EntityDescriptor* m_issuer;
        const XMLCh* m_protocol;
        const NameID* m_nameid;
        const XMLCh* m_authclass;
        const XMLCh* m_authdecl;
        vector<const opensaml::Assertion*> m_tokens;
        vector<shibsp::Attribute*> m_attributes;

        const Session* m_session;
    };

    class SHIBSP_DLLLOCAL ChainingAttributeResolver : public AttributeResolver
    {
    public:
        ChainingAttributeResolver(const DOMElement* e);
        virtual ~ChainingAttributeResolver() {}

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

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
            // Make sure new method gets run.
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
            return new ChainingContext(application, request, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new ChainingContext(application, session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            for (ptr_vector<AttributeResolver>::iterator i = m_resolvers.begin(); i != m_resolvers.end(); ++i) {
                Locker locker(&(*i));
                i->getAttributeIds(attributes);
            }
        }

    private:
        mutable ptr_vector<AttributeResolver> m_resolvers;
    };

    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    SHIBSP_DLLLOCAL PluginManager<AttributeResolver,string,const DOMElement*>::Factory QueryResolverFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeResolver,string,const DOMElement*>::Factory SimpleAggregationResolverFactory;

    AttributeResolver* SHIBSP_DLLLOCAL ChainingResolverFactory(const DOMElement* const & e)
    {
        return new ChainingAttributeResolver(e);
    }
};

void SHIBSP_API shibsp::registerAttributeResolvers()
{
    SPConfig::getConfig().AttributeResolverManager.registerFactory(QUERY_ATTRIBUTE_RESOLVER, QueryResolverFactory);
    SPConfig::getConfig().AttributeResolverManager.registerFactory(SIMPLEAGGREGATION_ATTRIBUTE_RESOLVER, SimpleAggregationResolverFactory);
    SPConfig::getConfig().AttributeResolverManager.registerFactory(CHAINING_ATTRIBUTE_RESOLVER, ChainingResolverFactory);
}

ResolutionContext::ResolutionContext()
{
}

ResolutionContext::~ResolutionContext()
{
}

AttributeResolver::AttributeResolver()
{
}

AttributeResolver::~AttributeResolver()
{
}

ResolutionContext* AttributeResolver::createResolutionContext(
    const Application& application,
    const GenericRequest* request,
    const EntityDescriptor* issuer,
    const XMLCh* protocol,
    const NameID* nameid,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const opensaml::Assertion*>* tokens,
    const vector<shibsp::Attribute*>* attributes
    ) const
{
    // Default call into deprecated method.
    return createResolutionContext(application, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
}

ResolutionContext* AttributeResolver::createResolutionContext(
    const Application& application,
    const EntityDescriptor* issuer,
    const XMLCh* protocol,
    const NameID* nameid,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const opensaml::Assertion*>* tokens,
    const vector<shibsp::Attribute*>* attributes
    ) const
{
    // Default for deprecated method.
    throw ConfigurationException("Deprecated method implementation should always be overridden.");
}


ChainingAttributeResolver::ChainingAttributeResolver(const DOMElement* e)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = XMLHelper::getFirstChildElement(e, _AttributeResolver);
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (!t.empty()) {
            try {
                Category::getInstance(SHIBSP_LOGCAT".AttributeResolver."CHAINING_ATTRIBUTE_RESOLVER).info(
                    "building AttributeResolver of type (%s)...", t.c_str()
                    );
                auto_ptr<AttributeResolver> np(conf.AttributeResolverManager.newPlugin(t.c_str(), e));
                m_resolvers.push_back(np.get());
                np.release();
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeResolver."CHAINING_ATTRIBUTE_RESOLVER).error(
                    "caught exception processing embedded AttributeResolver element: %s", ex.what()
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeResolver);
    }
}

void ChainingAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    ChainingContext& chain = dynamic_cast<ChainingContext&>(ctx);
    for (ptr_vector<AttributeResolver>::iterator i = m_resolvers.begin(); i != m_resolvers.end(); ++i) {
        try {
            Locker locker(&(*i));
            scoped_ptr<ResolutionContext> context(
                chain.m_session ?
                    i->createResolutionContext(chain.m_app, *chain.m_session) :
                    i->createResolutionContext(
                        chain.m_app, chain.m_request, chain.m_issuer, chain.m_protocol, chain.m_nameid, chain.m_authclass, chain.m_authdecl, &chain.m_tokens, &chain.m_attributes
                        )
                );

            i->resolveAttributes(*context);

            chain.m_attributes.insert(chain.m_attributes.end(), context->getResolvedAttributes().begin(), context->getResolvedAttributes().end());
            chain.m_ownedAttributes.insert(chain.m_ownedAttributes.end(), context->getResolvedAttributes().begin(), context->getResolvedAttributes().end());
            context->getResolvedAttributes().clear();

            chain.m_tokens.insert(chain.m_tokens.end(), context->getResolvedAssertions().begin(), context->getResolvedAssertions().end());
            chain.m_ownedAssertions.insert(chain.m_ownedAssertions.end(), context->getResolvedAssertions().begin(), context->getResolvedAssertions().end());
            context->getResolvedAssertions().clear();
        }
        catch (exception& ex) {
            Category::getInstance(SHIBSP_LOGCAT".AttributeResolver."CHAINING_ATTRIBUTE_RESOLVER).error(
                "caught exception applying AttributeResolver in chain: %s", ex.what()
                );
        }
    }
}
