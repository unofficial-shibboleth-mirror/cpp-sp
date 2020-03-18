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
 * AttributeScopeStringFunctor.cpp
 * 
 * A match function that matches the scope of an attribute value against
 * the specified value.
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

    static const XMLCh attributeID[] =      UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh caseSensitive[] =    UNICODE_LITERAL_13(c,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh ignoreCase[] =       UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh value[] =            UNICODE_LITERAL_5(v,a,l,u,e);

    /**
     * A match function that matches the scope of an attribute value against the specified value.
     */
    class SHIBSP_DLLLOCAL AttributeScopeStringFunctor : public MatchFunctor
    {
        string m_attributeID;
        auto_arrayptr<char> m_value;
        bool m_caseSensitive;

        bool hasScope(const FilteringContext& filterContext) const;

    public:
        AttributeScopeStringFunctor(const DOMElement* e)
            : m_attributeID(XMLHelper::getAttrString(e, nullptr, attributeID)),
                m_value(e ? toUTF8(e->getAttributeNS(nullptr, value)) : nullptr),
                m_caseSensitive(true) {
            if (!m_value.get() || !*m_value.get()) {
                throw ConfigurationException("AttributeScopeString MatchFunctor requires non-empty value attribute.");
            }

            if (e->hasAttributeNS(nullptr, caseSensitive)) {
                m_caseSensitive = XMLHelper::getAttrBool(e, true, caseSensitive);
            }
            else if (e->hasAttributeNS(nullptr, ignoreCase)) {
                m_caseSensitive = !XMLHelper::getAttrBool(e, false, ignoreCase);
            }
        }

        virtual ~AttributeScopeStringFunctor() {}

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_attributeID.empty())
                throw AttributeFilteringException("No attributeID specified.");
            return hasScope(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_attributeID.empty() || m_attributeID == attribute.getId()) {
                const char* scope = attribute.getScope(index);
                if (!scope) {
                    return false;
                }
                else if (!m_caseSensitive) {
#ifdef HAVE_STRCASECMP
                    return !strcasecmp(scope, m_value.get());
#else
                    return !stricmp(scope, m_value.get());
#endif
                }
                else {
                    return !strcmp(scope, m_value.get());
                }
            }
            return hasScope(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeStringFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeScopeStringFunctor(p.second);
    }

};

bool AttributeScopeStringFunctor::hasScope(const FilteringContext& filterContext) const
{
    size_t count;
    const char* scope;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID);
    for (; attrs.first != attrs.second; ++attrs.first) {
        count = attrs.first->second->valueCount();
        for (size_t index = 0; index < count; ++index) {
            scope = attrs.first->second->getScope(index);
            if (!scope) {
                return false;
            }
            else if (!m_caseSensitive) {
#ifdef HAVE_STRCASECMP
                if (!strcasecmp(scope, m_value.get()))
                    return true;
#else
                if (!stricmp(scope, m_value.get()))
                    return true;
#endif
            }
            else {
                if (!strcmp(scope, m_value.get()))
                    return true;
            }
        }
    }
    return false;
}
