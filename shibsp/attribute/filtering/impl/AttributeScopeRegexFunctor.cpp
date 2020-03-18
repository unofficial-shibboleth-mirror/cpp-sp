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
 * AttributeScopeRegexFunctor.cpp
 * 
 * A match function that evaluates an attribute value's scope against the
 * provided regular expression.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/regx/RegularExpression.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    static const XMLCh attributeID[] =      UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh caseSensitive[] =    UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh options[] =          UNICODE_LITERAL_7(o,p,t,i,o,n,s);
    static const XMLCh regex[] =            UNICODE_LITERAL_5(r,e,g,e,x);

    /**
     * A match function that evaluates an attribute value's scope against the provided regular expression.
     */
    class SHIBSP_DLLLOCAL AttributeScopeRegexFunctor : public MatchFunctor
    {
        string m_attributeID;
        scoped_ptr<RegularExpression> m_regex;

        bool hasScope(const FilteringContext& filterContext) const;
        bool matches(const Attribute& attribute, size_t index) const;

    public:
        AttributeScopeRegexFunctor(const DOMElement* e) : m_attributeID(XMLHelper::getAttrString(e, nullptr, attributeID)) {
            const XMLCh* r = e ? e->getAttributeNS(nullptr, regex) : nullptr;
            if (!r || !*r)
                throw ConfigurationException("AttributeScopeRegex MatchFunctor requires non-empty regex attribute.");

            try {
                const XMLCh* opts = e->getAttributeNS(nullptr, options);
                if (!opts) {
                    bool flag = xmltooling::XMLHelper::getAttrBool(e, true, caseSensitive);
                    if (!flag) {
                        static const XMLCh i_option[] = UNICODE_LITERAL_1(i);
                        opts = i_option;
                    }
                }

                m_regex.reset(new RegularExpression(r, opts));
            }
            catch (const XMLException& ex) {
                xmltooling::auto_ptr_char temp(ex.getMessage());
                throw ConfigurationException(temp.get());
            }
        }

        virtual ~AttributeScopeRegexFunctor() {}

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_attributeID.empty())
                throw AttributeFilteringException("No attributeID specified.");
            return hasScope(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_attributeID.empty() || m_attributeID == attribute.getId())
                return matches(attribute, index);
            return hasScope(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeRegexFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeScopeRegexFunctor(p.second);
    }

};

bool AttributeScopeRegexFunctor::hasScope(const FilteringContext& filterContext) const
{
    size_t count;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID);
    for (; attrs.first != attrs.second; ++attrs.first) {
        count = attrs.first->second->valueCount();
        for (size_t index = 0; index < count; ++index) {
            if (matches(*(attrs.first->second), index))
                return true;
        }
    }
    return false;
}

bool AttributeScopeRegexFunctor::matches(const Attribute& attribute, size_t index) const
{
    const char* val = attribute.getScope(index);
    if (!val)
        return false;
    auto_arrayptr<XMLCh> temp(fromUTF8(val));
    try {
        return m_regex->matches(temp.get());
    }
    catch (const XMLException& ex) {
        xmltooling::auto_ptr_char temp(ex.getMessage());
        throw AttributeFilteringException(temp.get());
    }
}
