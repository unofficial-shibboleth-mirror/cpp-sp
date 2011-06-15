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
 * AttributeIssuerRegexFunctor.cpp
 * 
 * A match function that evaluates to true if the Attribute issuer matches the provided regular
 * expression.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xercesc/util/regx/RegularExpression.hpp>

namespace shibsp {

    static const XMLCh options[] =  UNICODE_LITERAL_7(o,p,t,i,o,n,s);
    static const XMLCh regex[] =    UNICODE_LITERAL_5(r,e,g,e,x);
    
    /**
     * A match function that evaluates to true if the Attribute issuer matches the provided regular
     * expression.
     */
    class SHIBSP_DLLLOCAL AttributeIssuerRegexFunctor : public MatchFunctor
    {
        RegularExpression* m_regex;
    public:
        AttributeIssuerRegexFunctor(const DOMElement* e) : m_regex(nullptr) {
            const XMLCh* r = e ? e->getAttributeNS(nullptr,regex) : nullptr;
            if (!r || !*r)
                throw ConfigurationException("AttributeIssuerRegex MatchFunctor requires non-empty regex attribute.");
            try {
                m_regex = new RegularExpression(r, e->getAttributeNS(nullptr,options));
            }
            catch (XMLException& ex) {
                xmltooling::auto_ptr_char temp(ex.getMessage());
                throw ConfigurationException(temp.get());
            }
        }

        virtual ~AttributeIssuerRegexFunctor() {
            delete m_regex;
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            return m_regex->matches(filterContext.getAttributeIssuer());
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return m_regex->matches(filterContext.getAttributeIssuer());
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerRegexFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeIssuerRegexFunctor(p.second);
    }

};
