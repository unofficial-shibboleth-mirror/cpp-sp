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
 * AttributeRequesterRegexFunctor.cpp
 * 
 * A match function that evaluates to true if the Attribute requester matches the provided regular
 * expression.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xmltooling/util/XMLHelper.h>

#include <xercesc/util/regx/RegularExpression.hpp>

namespace shibsp {

    static const XMLCh caseSensitive[] =    UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh options[] =          UNICODE_LITERAL_7(o,p,t,i,o,n,s);
    static const XMLCh regex[] =            UNICODE_LITERAL_5(r,e,g,e,x);
    
    /**
     * A match function that evaluates to true if the Attribute requester matches the provided regular
     * expression.
     */
    class SHIBSP_DLLLOCAL AttributeRequesterRegexFunctor : public MatchFunctor
    {
        boost::scoped_ptr<RegularExpression> m_regex;
    public:
        AttributeRequesterRegexFunctor(const DOMElement* e) {
            const XMLCh* r = e ? e->getAttributeNS(nullptr, regex) : nullptr;
            if (!r || !*r)
                throw ConfigurationException("AttributeRequesterRegex MatchFunctor requires non-empty regex attribute.");

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

        virtual ~AttributeRequesterRegexFunctor() {}

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            try {
                return m_regex->matches(filterContext.getAttributeRequester());
            }
            catch (const XMLException& ex) {
                xmltooling::auto_ptr_char temp(ex.getMessage());
                throw AttributeFilteringException(temp.get());
            }
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeRequesterRegexFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeRequesterRegexFunctor(p.second);
    }

};
