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
 * TransformAttributeResolver.cpp
 * 
 * Attribute Resolver plugin for transforming input values.
 */

#include "internal.h"

#include <algorithm>
#include <boost/shared_ptr.hpp>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL TransformContext : public ResolutionContext
    {
    public:
        TransformContext(const Session& session) : m_inputAttributes(&session.getAttributes()) {
        }

        TransformContext(const vector<shibsp::Attribute*>* attributes) : m_inputAttributes(attributes) {
        }

        ~TransformContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<shibsp::Attribute>());
        }

        const vector<shibsp::Attribute*>* getInputAttributes() const {
            return m_inputAttributes;
        }
        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_assertions;
        }

    private:
        const vector<shibsp::Attribute*>* m_inputAttributes;
        vector<shibsp::Attribute*> m_attributes;
        static vector<opensaml::Assertion*> m_assertions;   // empty dummy
    };


    class SHIBSP_DLLLOCAL TransformAttributeResolver : public AttributeResolver
    {
    public:
        TransformAttributeResolver(const DOMElement* e);
        virtual ~TransformAttributeResolver() {}

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
            const vector<shibsp::Attribute*>* attributes=nullptr
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
            const vector<shibsp::Attribute*>* attributes=nullptr
            ) const {
            return new TransformContext(attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new TransformContext(session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            if (!m_dest.empty())
                attributes.push_back(m_dest.front());
        }

    private:
        Category& m_log;
        string m_source;
        vector<string> m_dest;
        vector< pair<boost::shared_ptr<RegularExpression>,const XMLCh*> > m_regex;
    };

    static const XMLCh dest[] =         UNICODE_LITERAL_4(d,e,s,t);
    static const XMLCh match[] =        UNICODE_LITERAL_5(m,a,t,c,h);
    static const XMLCh source[] =       UNICODE_LITERAL_6(s,o,u,r,c,e);
    static const XMLCh Regex[] =        UNICODE_LITERAL_5(R,e,g,e,x);

    AttributeResolver* SHIBSP_DLLLOCAL TransformAttributeResolverFactory(const DOMElement* const & e)
    {
        return new TransformAttributeResolver(e);
    }

};

vector<opensaml::Assertion*> TransformContext::m_assertions;

TransformAttributeResolver::TransformAttributeResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.Transform")),
        m_source(XMLHelper::getAttrString(e, nullptr, source)),
        m_dest(1, XMLHelper::getAttrString(e, nullptr, dest))
{
    if (m_source.empty())
        throw ConfigurationException("Transform AttributeResolver requires source attribute.");

    e = XMLHelper::getFirstChildElement(e, Regex);
    while (e) {
        if (e->hasChildNodes() && e->hasAttributeNS(nullptr, match)) {
            const XMLCh* repl = e->getTextContent();
            if (repl && *repl) {
                try {
                    boost::shared_ptr<RegularExpression> re(new RegularExpression(e->getAttributeNS(nullptr, match)));
                    m_regex.push_back(pair<boost::shared_ptr<RegularExpression>,const XMLCh*>(re, repl));
                }
                catch (XMLException& ex) {
                    auto_ptr_char msg(ex.getMessage());
                    auto_ptr_char m(e->getAttributeNS(nullptr, match));
                    m_log.error("exception parsing regular expression (%s): %s", m.get(), msg.get());
                }
            }
        }
        e = XMLHelper::getNextSiblingElement(e, Regex);
    }

    if (m_regex.empty())
        throw ConfigurationException("Transform AttributeResolver requires at least one Regex element.");
}


void TransformAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    TransformContext& tctx = dynamic_cast<TransformContext&>(ctx);
    if (!tctx.getInputAttributes())
        return;

    SimpleAttribute* dest = nullptr;
    auto_ptr<SimpleAttribute> destwrapper;

    for (vector<Attribute*>::const_iterator a = tctx.getInputAttributes()->begin(); a != tctx.getInputAttributes()->end(); ++a) {
        if (m_source != (*a)->getId() || (*a)->valueCount() == 0) {
            continue;
        }
        else if (m_dest.empty() || m_dest.front().empty()) {
            // Can we transform in-place?
            dest = dynamic_cast<SimpleAttribute*>(*a);
            if (!dest) {
                m_log.warn("can't transform non-simple attribute (%s) in place, skipping it", m_source.c_str());
                continue;
            }
        }
        else if (!destwrapper.get()) {
            destwrapper.reset(new SimpleAttribute(m_dest));
        }

        m_log.debug("applying transform to source attribute (%s) with %lu value(s)", m_source.c_str(), (*a)->valueCount());

        // Apply transforms to each value.
        for (size_t i = 0; i < (*a)->valueCount(); ++i) {
            // Run the transform set in sequence against the initial value, substituting the result into the next step.
            XMLCh* destval = nullptr;
            auto_arrayptr<XMLCh> srcval(fromUTF8((*a)->getSerializedValues()[i].c_str()));
            for (vector< pair<boost::shared_ptr<RegularExpression>,const XMLCh*> >::const_iterator r = m_regex.begin(); r != m_regex.end(); ++r) {
                try {
                    XMLCh* temp = r->first->replace(destval ? destval : srcval.get(), r->second);
                    if (temp) {
                        XMLString::release(&destval);
                        destval = temp;
                    }
                }
                catch (XMLException& ex) {
                    auto_ptr_char msg(ex.getMessage());
                    m_log.error("caught error applying regular expression: %s", msg.get());
                }
            }

            // Save the result.
            if (destval) {
                auto_arrayptr<char> narrow(toUTF8(destval));
                XMLString::release(&destval);
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
    }

    // Save off new object.
    if (destwrapper.get()) {
        ctx.getResolvedAttributes().push_back(destwrapper.get());
        destwrapper.release();
    }
}
