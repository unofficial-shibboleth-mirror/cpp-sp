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
 * TemplateAttributeResolver.cpp
 * 
 * AttributeResolver plugin for composing input values.
 */

#include "internal.h"

#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <shibsp/exceptions.h>
#include <shibsp/SessionCache.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/Predicates.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL TemplateContext : public ResolutionContext
    {
    public:
        TemplateContext(const vector<Attribute*>* attributes) : m_inputAttributes(attributes) {
        }

        ~TemplateContext() {
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


    class SHIBSP_DLLLOCAL TemplateAttributeResolver : public AttributeResolver
    {
    public:
        TemplateAttributeResolver(const DOMElement* e);
        virtual ~TemplateAttributeResolver() {}

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
            return new TemplateContext(attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new TemplateContext(&session.getAttributes());
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            attributes.push_back(m_dest.front());
        }

    private:
        Category& m_log;
        string m_template;
        vector<string> m_sources,m_dest;
    };

    static const XMLCh dest[] =     UNICODE_LITERAL_4(d,e,s,t);
    static const XMLCh _sources[] = UNICODE_LITERAL_7(s,o,u,r,c,e,s);
    static const XMLCh Template[] = UNICODE_LITERAL_8(T,e,m,p,l,a,t,e);

    AttributeResolver* SHIBSP_DLLLOCAL TemplateAttributeResolverFactory(const DOMElement* const & e)
    {
        return new TemplateAttributeResolver(e);
    }

};

vector<opensaml::Assertion*> TemplateContext::m_assertions;

TemplateAttributeResolver::TemplateAttributeResolver(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.Template")),
        m_dest(1, XMLHelper::getAttrString(e, nullptr, dest))
{
    if (m_dest.front().empty())
        throw ConfigurationException("Template AttributeResolver requires dest attribute.");

    string s(XMLHelper::getAttrString(e, nullptr, _sources));
    split(m_sources, s, is_space(), algorithm::token_compress_on);
    if (m_sources.empty())
        throw ConfigurationException("Template AttributeResolver requires sources attribute.");

    e = e ? XMLHelper::getFirstChildElement(e, Template) : nullptr;
    auto_ptr_char t(e ? e->getTextContent() : nullptr);
    if (t.get()) {
        m_template = t.get();
        trim(m_template);
    }
    if (m_template.empty())
        throw ConfigurationException("Template AttributeResolver requires <Template> child element.");
}


void TemplateAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    TemplateContext& tctx = dynamic_cast<TemplateContext&>(ctx);
    if (!tctx.getInputAttributes())
        return;

    map<string,const Attribute*> attrmap;
    for (vector<string>::const_iterator a = m_sources.begin(); a != m_sources.end(); ++a) {
        static bool (*eq)(const string&, const char*) = operator==;
        const Attribute* attr = find_if(*tctx.getInputAttributes(), boost::bind(eq, boost::cref(*a), boost::bind(&Attribute::getId, _1)));
        if (!attr) {
            m_log.warn("source attribute (%s) missing, cannot resolve attribute (%s)", a->c_str(), m_dest.front().c_str());
            return;
        }
        else if (!attrmap.empty() && attr->valueCount() != attrmap.begin()->second->valueCount()) {
            m_log.warn("all source attributes must contain equal number of values, cannot resolve attribute (%s)", m_dest.front().c_str());
            return;
        }
        attrmap[*a] = attr;
    }

    auto_ptr<SimpleAttribute> dest(new SimpleAttribute(m_dest));

    for (size_t ix = 0; ix < attrmap.begin()->second->valueCount(); ++ix) {
        static const char* legal="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890_-.[]";

        dest->getValues().push_back(string());
        string& processed = dest->getValues().back();

        string::size_type i=0, start=0;
        while (start != string::npos && start < m_template.length() && (i = m_template.find("$", start)) != string::npos) {
            if (i > start)
                processed += m_template.substr(start, i - start);   // append everything in between
            start = i + 1;                                          // move start to the beginning of the token name
            i = m_template.find_first_not_of(legal, start);         // find token delimiter
            if (i == start) {                                       // append a non legal character
                processed += m_template[start++];
                continue;
            }
                    
            map<string,const Attribute*>::const_iterator iter = attrmap.find(m_template.substr(start, (i==string::npos) ? i : i - start));
            if (iter != attrmap.end())
                processed += iter->second->getSerializedValues()[ix];
            start = i;
        }
        if (start != string::npos && start < m_template.length())
            processed += m_template.substr(start, i);    // append rest of string

        trim(processed);
        if (processed.empty())
            dest->getValues().pop_back();
    }

    // Save off new object.
    if (dest.get() && dest->valueCount()) {
        ctx.getResolvedAttributes().push_back(dest.get());
        dest.release();
    }
}
