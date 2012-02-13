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
 * NotMatchFunctor.cpp
 * 
 * A MatchFunctor that negates the result of a contained functor.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"
#include "util/SPConstants.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    /**
     * A MatchFunctor that negates the result of a contained functor.
     */
    class SHIBSP_DLLLOCAL NotMatchFunctor : public MatchFunctor
    {
    public:
        NotMatchFunctor(const pair<const FilterPolicyContext*,const DOMElement*>& p);

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_functor)
                return !(m_functor->evaluatePolicyRequirement(filterContext));
            return false;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_functor)
                return !(m_functor->evaluatePermitValue(filterContext, attribute, index));
            return false;
        }

    private:
        MatchFunctor* buildFunctor(const DOMElement* e, const FilterPolicyContext* functorMap);

        const MatchFunctor* m_functor;
    };

    MatchFunctor* SHIBSP_DLLLOCAL NotMatchFunctorFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new NotMatchFunctor(p);
    }

    static XMLCh _id[] =            UNICODE_LITERAL_2(i,d);
    static XMLCh _ref[] =           UNICODE_LITERAL_3(r,e,f);
    static XMLCh Rule[] =           UNICODE_LITERAL_4(R,u,l,e);
    static XMLCh RuleReference[] =  UNICODE_LITERAL_13(R,u,l,e,R,e,f,e,r,e,n,c,e);
};

NotMatchFunctor::NotMatchFunctor(const pair<const FilterPolicyContext*,const DOMElement*>& p) : m_functor(nullptr)
{
    const DOMElement* e = XMLHelper::getFirstChildElement(p.second);
    if (e) {
        if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, Rule)) {
            m_functor = buildFunctor(e, p.first);
        }
        else if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, RuleReference)) {
            string ref = XMLHelper::getAttrString(e, nullptr, _ref);
            if (!ref.empty()) {
                multimap<string,MatchFunctor*>::const_iterator rule = p.first->getMatchFunctors().find(ref);
                m_functor = (rule!=p.first->getMatchFunctors().end()) ? rule->second : nullptr;
            }
        }
    }

    if (!m_functor)
        throw ConfigurationException("No child Rule installed into NotMatchFunctor.");
}

MatchFunctor* NotMatchFunctor::buildFunctor(const DOMElement* e, const FilterPolicyContext* functorMap)
{
    // We'll track and map IDs just for consistency, but don't require them or worry about dups.
    string id = XMLHelper::getAttrString(e, nullptr, _id);
    if (!id.empty() && functorMap->getMatchFunctors().count(id))
        id.clear();

    scoped_ptr<xmltooling::QName> type(XMLHelper::getXSIType(e));
    if (!type)
        throw ConfigurationException("Child Rule found with no xsi:type.");

    auto_ptr<MatchFunctor> func(SPConfig::getConfig().MatchFunctorManager.newPlugin(*type, make_pair(functorMap,e)));
    functorMap->getMatchFunctors().insert(multimap<string,MatchFunctor*>::value_type(id, func.get()));
    return func.release();
}
