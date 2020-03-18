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
 * AttributeRequesterStringFunctor.cpp
 * 
 * A match function that matches the attribute requester's name against the specified value.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xmltooling/util/XMLHelper.h>
using xmltooling::XMLHelper;

namespace shibsp {

    static const XMLCh caseSensitive[] =    UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh ignoreCase[] =       UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh value[] =            UNICODE_LITERAL_5(v,a,l,u,e);

    /**
     * A match function that matches the attribute requester's name against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeRequesterStringFunctor : public MatchFunctor
    {
        const XMLCh* m_value;
        bool m_caseSensitive;
    public:
        AttributeRequesterStringFunctor(const DOMElement* e)
                : m_value(e ? e->getAttributeNS(nullptr,value) : nullptr), m_caseSensitive(true) {
            if (!m_value || !*m_value)
                throw ConfigurationException("AttributeRequesterString MatchFunctor requires non-empty value attribute.");

            if (e->hasAttributeNS(nullptr, caseSensitive)) {
                m_caseSensitive = XMLHelper::getAttrBool(e, true, caseSensitive);
            }
            else if (e->hasAttributeNS(nullptr, ignoreCase)) {
                m_caseSensitive = !XMLHelper::getAttrBool(e, false, ignoreCase);
            }
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_caseSensitive)
                return XMLString::equals(m_value, filterContext.getAttributeRequester());
            else
                return (XMLString::compareIString(m_value, filterContext.getAttributeRequester()) == 0);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeRequesterStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeRequesterStringFunctor(p.second);
    }

};
