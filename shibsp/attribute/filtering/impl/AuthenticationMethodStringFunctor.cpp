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
 * AuthenticationMethodStringFunctor.cpp
 * 
 * Match functor that compares the user's authentication method against
 * a given string.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xmltooling/util/XMLHelper.h>

using xmltooling::XMLHelper;

namespace shibsp {

    static const XMLCh value[] = UNICODE_LITERAL_5(v,a,l,u,e);
    static const XMLCh ignoreCase[] = UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);

    /**
     * Match functor that compares the user's authentication method against a given string.
     */
    class SHIBSP_DLLLOCAL AuthenticationMethodStringFunctor : public MatchFunctor
    {
        const XMLCh* m_value;
        bool m_ignoreCase;
    public:
        AuthenticationMethodStringFunctor(const DOMElement* e)
            : m_value(e ? e->getAttributeNS(nullptr,value) : nullptr), m_ignoreCase(XMLHelper::getAttrBool(e, false, ignoreCase)) {
            if (!m_value || !*m_value)
                throw ConfigurationException("AuthenticationMethodString MatchFunctor requires non-empty value attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_ignoreCase)
                return (XMLString::compareIString(m_value, filterContext.getAuthnContextClassRef()) == 0 ||
                    XMLString::compareIString(m_value, filterContext.getAuthnContextDeclRef()) == 0);
            else
                return XMLString::equals(m_value, filterContext.getAuthnContextClassRef()) ||
                    XMLString::equals(m_value, filterContext.getAuthnContextDeclRef());
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AuthenticationMethodStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AuthenticationMethodStringFunctor(p.second);
    }

};
