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
 * ChainingAttributeResolver.cpp
 * 
 * Chains together multiple AttributeResolver plugins.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    struct SHIBSP_DLLLOCAL ChainingContext : public ResolutionContext
    {
        ~ChainingContext() {
            for_each(m_contexts.begin(), m_contexts.end(), xmltooling::cleanup<ResolutionContext>());
            for_each(m_attributes.begin(), m_attributes.end(), cleanup_pair<string,shibsp::Attribute>());
            for_each(m_assertions.begin(), m_assertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        multimap<string,shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

        vector<ResolutionContext*> m_contexts;
        multimap<string,shibsp::Attribute*> m_attributes;
        vector<opensaml::Assertion*> m_assertions;
    };

    class SHIBSP_DLLLOCAL ChainingAttributeResolver : public AttributeResolver
    {
    public:
        ChainingAttributeResolver(const DOMElement* e);
        virtual ~ChainingAttributeResolver() {
            for_each(m_resolvers.begin(), m_resolvers.end(), xmltooling::cleanup<AttributeResolver>());
        }
        
        Lockable* lock() {
            for_each(m_resolvers.begin(), m_resolvers.end(), mem_fun(&AttributeResolver::lock));
            return this;
        }
        void unlock() {
            for_each(m_resolvers.begin(), m_resolvers.end(), mem_fun(&AttributeResolver::unlock));
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const multimap<string,shibsp::Attribute*>* attributes=NULL
            ) const {
            auto_ptr<ChainingContext> chain(new ChainingContext());
            for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i)
                chain->m_contexts.push_back(
                    (*i)->createResolutionContext(application, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes)
                    );
            return chain.release();
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            auto_ptr<ChainingContext> chain(new ChainingContext());
            for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i)
                chain->m_contexts.push_back((*i)->createResolutionContext(application, session));
            return chain.release();
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i)
                (*i)->getAttributeIds(attributes);
        }
        
    private:
        vector<AttributeResolver*> m_resolvers;
    };

    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    AttributeResolver* SHIBSP_DLLLOCAL ChainingAttributeResolverFactory(const DOMElement* & e)
    {
        return new ChainingAttributeResolver(e);
    }
};

ChainingAttributeResolver::ChainingAttributeResolver(const DOMElement* e)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _AttributeResolver) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_resolvers.push_back(conf.AttributeResolverManager.newPlugin(type.get(),e));
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeResolver").error(
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
    vector<ResolutionContext*>::iterator ictx = chain.m_contexts.begin();
    for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i, ++ictx) {
        (*i)->resolveAttributes(*(*ictx));
        chain.getResolvedAttributes().insert((*ictx)->getResolvedAttributes().begin(), (*ictx)->getResolvedAttributes().end());
        (*ictx)->getResolvedAttributes().clear();
        chain.getResolvedAssertions().insert(chain.getResolvedAssertions().end(), (*ictx)->getResolvedAssertions().begin(), (*ictx)->getResolvedAssertions().end());
        (*ictx)->getResolvedAssertions().clear();
    }
}
