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
 * CaseFoldingAttributeResolver.cpp
 * 
 * Attribute Resolver plugins for upcasing and downcasing.
 */

#include "internal.h"

#include <algorithm>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL FoldingContext : public ResolutionContext
    {
    public:
        FoldingContext(const vector<Attribute*>* attributes) : m_inputAttributes(attributes) {
        }

        ~FoldingContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
        }

        const vector<Attribute*>* getInputAttributes() const {
            return m_inputAttributes;
        }
        vector<Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const vector<Attribute*>* m_inputAttributes;
        vector<Attribute*> m_attributes;
        static vector<opensaml::Assertion*> m_assertions;   // empty dummy
    };


    class SHIBSP_DLLLOCAL CaseFoldingAttributeResolver : public AttributeResolver
    {
    public:
        enum case_t {
            _up,
            _down
        };

        CaseFoldingAttributeResolver(const DOMElement* e, case_t direction);
        virtual ~CaseFoldingAttributeResolver() {}

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const XMLCh* protocol,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<Attribute*>* attributes=nullptr
            ) const {
            // Make sure new method gets run.
            return createResolutionContext(application, nullptr, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const GenericRequest* request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const XMLCh* protocol,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const opensaml::Assertion*>* tokens=nullptr,
            const vector<Attribute*>* attributes=nullptr
            ) const {
            return new FoldingContext(attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new FoldingContext(&session.getAttributes());
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            if (!m_dest.empty() && !m_dest.front().empty())
                attributes.push_back(m_dest.front());
        }

    private:
        Category& m_log;
        case_t m_direction;
        string m_source;
        vector<string> m_dest;
    };

    static const XMLCh dest[] =             UNICODE_LITERAL_4(d,e,s,t);
    static const XMLCh source[] =           UNICODE_LITERAL_6(s,o,u,r,c,e);

    AttributeResolver* SHIBSP_DLLLOCAL UpperCaseAttributeResolverFactory(const DOMElement* const & e)
    {
        return new CaseFoldingAttributeResolver(e, CaseFoldingAttributeResolver::_up);
    }

    AttributeResolver* SHIBSP_DLLLOCAL LowerCaseAttributeResolverFactory(const DOMElement* const & e)
    {
        return new CaseFoldingAttributeResolver(e, CaseFoldingAttributeResolver::_down);
    }
};

vector<opensaml::Assertion*> FoldingContext::m_assertions;

CaseFoldingAttributeResolver::CaseFoldingAttributeResolver(const DOMElement* e, case_t direction)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.CaseFolding")),
        m_direction(direction),
        m_source(XMLHelper::getAttrString(e, nullptr, source)),
        m_dest(1, XMLHelper::getAttrString(e, nullptr, dest))
{
    if (m_source.empty())
        throw ConfigurationException("CaseFolding AttributeResolver requires source attribute.");
}


void CaseFoldingAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    FoldingContext& fctx = dynamic_cast<FoldingContext&>(ctx);
    if (!fctx.getInputAttributes())
        return;

    auto_ptr<SimpleAttribute> destwrapper;

    for (vector<Attribute*>::const_iterator a = fctx.getInputAttributes()->begin(); a != fctx.getInputAttributes()->end(); ++a) {
        if (m_source != (*a)->getId() || (*a)->valueCount() == 0) {
            continue;
        }

        SimpleAttribute* dest = nullptr;
        if (m_dest.empty() || m_dest.front().empty()) {
            // Can we transform in-place?
            dest = dynamic_cast<SimpleAttribute*>(*a);
            if (!dest) {
                m_log.warn("can't %scase non-simple attribute (%s) 'in place'", (m_direction==_up ? "up" : "down"), m_source.c_str());
                continue;
            }
            m_log.debug("applying in-place transform to source attribute (%s)", m_source.c_str());
        }
        else if (!destwrapper.get()) {
            // Create a destination attribute.
            destwrapper.reset(new SimpleAttribute(m_dest));
            m_log.debug("applying transform from source attribute (%s) to dest attribute (%s)", m_source.c_str(), m_dest.front().c_str());
        }

        for (size_t i = 0; i < (*a)->valueCount(); ++i) {
            try {
                XMLCh* srcval = fromUTF8((*a)->getSerializedValues()[i].c_str());
                if (srcval) {
                    auto_arrayptr<XMLCh> valjanitor(srcval);
                    (m_direction == _up) ? XMLString::upperCase(srcval) : XMLString::lowerCase(srcval);
                    auto_arrayptr<char> narrow(toUTF8(srcval));
                    if (dest) {
                        // Modify in place.
                        dest->getValues()[i] = narrow.get();
                    }
                    else {
                        // Add to new object.
                        destwrapper->getValues().push_back(narrow.get());
                    }
                }
            }
            catch (XMLException& ex) {
                auto_ptr_char msg(ex.getMessage());
                m_log.error("caught error performing conversion: %s", msg.get());
            }
        }
    }

    // Save off new object.
    if (destwrapper.get()) {
        ctx.getResolvedAttributes().push_back(destwrapper.get());
        destwrapper.release();
    }
}
