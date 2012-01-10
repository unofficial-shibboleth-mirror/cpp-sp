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
 * AttributeValueStringFunctor.cpp
 * 
 * A match function that matches the value of an attribute against the
 * specified value.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    static const XMLCh attributeID[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh value[] =        UNICODE_LITERAL_5(v,a,l,u,e);
    static const XMLCh ignoreCase[] =   UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);

    /**
     * A match function that matches the value of an attribute against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeValueStringFunctor : public MatchFunctor
    {
        string m_attributeID;
        auto_arrayptr<char> m_value;

        bool hasValue(const FilteringContext& filterContext) const;
        bool matches(const Attribute& attribute, size_t index) const;

    public:
        AttributeValueStringFunctor(const DOMElement* e)
            	: m_attributeID(XMLHelper::getAttrString(e, nullptr, attributeID)),
            	  m_value(e ? toUTF8(e->getAttributeNS(nullptr, value)) : nullptr) {
            if (!m_value.get() || !*m_value.get()) {
                throw ConfigurationException("AttributeValueString MatchFunctor requires non-empty value attribute.");
            }
            if (e && e->hasAttributeNS(nullptr, ignoreCase)) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                    "ignoreCase property ignored by AttributeValueString MatchFunctor in favor of attribute's caseSensitive property"
                    );
            }
        }

        virtual ~AttributeValueStringFunctor() {}

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_attributeID.empty())
                throw AttributeFilteringException("No attributeID specified.");
            return hasValue(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_attributeID.empty() || m_attributeID == attribute.getId())
                return matches(attribute, index);
            return hasValue(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeValueStringFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeValueStringFunctor(p.second);
    }

};

bool AttributeValueStringFunctor::hasValue(const FilteringContext& filterContext) const
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

bool AttributeValueStringFunctor::matches(const Attribute& attribute, size_t index) const
{
    const char* val = attribute.getString(index);
    if (!val)
        return false;
    if (attribute.isCaseSensitive())
        return !strcmp(m_value.get(), val);

#ifdef HAVE_STRCASECMP
    return !strcasecmp(m_value.get(), val);
#else
    return !stricmp(m_value.get(), val);
#endif
}
