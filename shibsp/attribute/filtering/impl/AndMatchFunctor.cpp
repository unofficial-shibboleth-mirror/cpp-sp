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
 * AndMatchFunctor.cpp
 * 
 * A MatchFunctor that logical ANDs the results of contained functors.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"
#include "util/SPConstants.h"

#include <boost/bind.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    /**
     * A MatchFunctor that logical ANDs the results of contained functors.
     */
    class SHIBSP_DLLLOCAL AndMatchFunctor : public MatchFunctor
    {
    public:
        AndMatchFunctor(const pair<const FilterPolicyContext*,const DOMElement*>& p);

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_functors.empty())
                return false;
            vector<const MatchFunctor*>::const_iterator i = find_if(
                m_functors.begin(), m_functors.end(),
                boost::bind(&MatchFunctor::evaluatePolicyRequirement, _1, boost::cref(filterContext)) == false
                );
            return (i == m_functors.end());
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_functors.empty())
                return false;
            vector<const MatchFunctor*>::const_iterator i = find_if(
                m_functors.begin(), m_functors.end(),
                boost::bind(&MatchFunctor::evaluatePermitValue, _1, boost::cref(filterContext), boost::cref(attribute), index) == false
                );
            return (i == m_functors.end());
        }

    private:
        MatchFunctor* buildFunctor(const DOMElement* e, const FilterPolicyContext* functorMap);

        vector<const MatchFunctor*> m_functors;
    };

    MatchFunctor* SHIBSP_DLLLOCAL AndMatchFunctorFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AndMatchFunctor(p);
    }

    static XMLCh _id[] =            UNICODE_LITERAL_2(i,d);
    static XMLCh _ref[] =           UNICODE_LITERAL_3(r,e,f);
    static XMLCh Rule[] =           UNICODE_LITERAL_4(R,u,l,e);
    static XMLCh RuleReference[] =  UNICODE_LITERAL_13(R,u,l,e,R,e,f,e,r,e,n,c,e);
};

AndMatchFunctor::AndMatchFunctor(const pair<const FilterPolicyContext*,const DOMElement*>& p)
{
    MatchFunctor* func;
    const DOMElement* e = XMLHelper::getFirstChildElement(p.second);
    while (e) {
        func = nullptr;
        if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, Rule)) {
            func = buildFunctor(e, p.first);
        }
        else if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_MF_BASIC_NS, RuleReference)) {
            string ref = XMLHelper::getAttrString(e, nullptr, _ref);
            if (!ref.empty()) {
                multimap<string,MatchFunctor*>::const_iterator rule = p.first->getMatchFunctors().find(ref);
                func = (rule!=p.first->getMatchFunctors().end()) ? rule->second : nullptr;
            }
        }

        if (func)
            m_functors.push_back(func);

        e = XMLHelper::getNextSiblingElement(e);
    }
}

MatchFunctor* AndMatchFunctor::buildFunctor(const DOMElement* e, const FilterPolicyContext* functorMap)
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
