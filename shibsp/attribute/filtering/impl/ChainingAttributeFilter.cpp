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
 * ChainingAttributeFilter.cpp
 * 
 * Chains together multiple AttributeFilter plugins.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/FilteringContext.h"

#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL ChainingAttributeFilter : public AttributeFilter
    {
    public:
        ChainingAttributeFilter(const DOMElement* e);
        virtual ~ChainingAttributeFilter() {}
        
        Lockable* lock() {
            return this;
        }
        void unlock() {
        }
        
        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const {
            for (ptr_vector<AttributeFilter>::iterator i = m_filters.begin(); i != m_filters.end(); ++i) {
                Locker locker(&(*i));
                i->filterAttributes(context, attributes);
            }
        }

    private:
        mutable ptr_vector<AttributeFilter> m_filters;
    };

    static const XMLCh _AttributeFilter[] = UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);

    AttributeFilter* SHIBSP_DLLLOCAL ChainingAttributeFilterFactory(const DOMElement* const & e)
    {
        return new ChainingAttributeFilter(e);
    }
};

ChainingAttributeFilter::ChainingAttributeFilter(const DOMElement* e)
{
    // Load up the chain of handlers.
    e = XMLHelper::getFirstChildElement(e, _AttributeFilter);
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (!t.empty()) {
            Category::getInstance(SHIBSP_LOGCAT".AttributeFilter.Chaining").info("building AttributeFilter of type (%s)...", t.c_str());
            auto_ptr<AttributeFilter> np(SPConfig::getConfig().AttributeFilterManager.newPlugin(t.c_str(), e));
            m_filters.push_back(np.get());
            np.release();
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeFilter);
    }
    if (m_filters.empty())
        throw ConfigurationException("Chaining AttributeFilter plugin requires at least one child plugin.");
}
