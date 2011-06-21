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
 * NameIDQualifierStringFunctor.cpp
 * 
 * A match function that ensures that a NameID-valued attribute's qualifier(s)
 * match particular values.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/NameIDAttribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <saml/saml2/core/Assertions.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;
using opensaml::saml2::NameID;

namespace shibsp {

    static const XMLCh attributeID[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);

    /**
     * A match function that ensures that a NameID-valued attribute's qualifier(s)
     * match particular values.
     */
    class SHIBSP_DLLLOCAL NameIDQualifierStringFunctor : public MatchFunctor
    {
        string m_attributeID,m_matchNameQualifier,m_matchSPNameQualifier;

        bool hasValue(const FilteringContext& filterContext) const;
        bool matches(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const;

    public:
        NameIDQualifierStringFunctor(const DOMElement* e)
            : m_attributeID(XMLHelper::getAttrString(e, nullptr, attributeID)),
                m_matchNameQualifier(XMLHelper::getAttrString(e, nullptr, NameID::NAMEQUALIFIER_ATTRIB_NAME)),
                m_matchSPNameQualifier(XMLHelper::getAttrString(e, nullptr, NameID::SPNAMEQUALIFIER_ATTRIB_NAME)) {
        }

        virtual ~NameIDQualifierStringFunctor() {
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (m_attributeID.empty())
                throw AttributeFilteringException("No attributeID specified.");
            return hasValue(filterContext);
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            if (m_attributeID.empty() || m_attributeID == attribute.getId())
                return matches(filterContext, attribute, index);
            return hasValue(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL NameIDQualifierStringFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new NameIDQualifierStringFunctor(p.second);
    }

};

bool NameIDQualifierStringFunctor::hasValue(const FilteringContext& filterContext) const
{
    size_t count;
    pair<multimap<string,Attribute*>::const_iterator,multimap<string,Attribute*>::const_iterator> attrs =
        filterContext.getAttributes().equal_range(m_attributeID);
    for (; attrs.first != attrs.second; ++attrs.first) {
        count = attrs.first->second->valueCount();
        for (size_t index = 0; index < count; ++index) {
            if (matches(filterContext, *(attrs.first->second), index))
                return true;
        }
    }
    return false;
}

bool NameIDQualifierStringFunctor::matches(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const
{
    const NameIDAttribute* nameattr = dynamic_cast<const NameIDAttribute*>(&attribute);
    if (!nameattr) {
        Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
            "NameIDQualifierString MatchFunctor applied to non-NameID-valued attribute (%s)", attribute.getId()
            );
        return false;
    }

    const NameIDAttribute::Value& val = nameattr->getValues()[index];
    if (!val.m_NameQualifier.empty()) {
        if (m_matchNameQualifier.empty()) {
            auto_ptr_char issuer(filterContext.getAttributeIssuer());
            if (issuer.get() && *issuer.get()) {
                if (val.m_NameQualifier != issuer.get()) {
                    Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                        "NameIDQualifierString MatchFunctor rejecting NameQualifier (%s), should be (%s)",
                        val.m_NameQualifier.c_str(), issuer.get()
                        );
                    return false;
                }
            }
            else {
                Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                    "NameIDQualifierString MatchFunctor rejecting NameQualifier (%s), attribute issuer unknown",
                    val.m_NameQualifier.c_str()
                    );
                return false;
            }
        }
        else if (m_matchNameQualifier != val.m_NameQualifier) {
            Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                "NameIDQualifierString MatchFunctor rejecting NameQualifier (%s), should be (%s)",
                val.m_NameQualifier.c_str(), m_matchNameQualifier.c_str()
                );
            return false;
        }
    }
    if (!val.m_SPNameQualifier.empty()) {
        if (m_matchSPNameQualifier.empty()) {
            auto_ptr_char req(filterContext.getAttributeRequester());
            if (req.get() && *req.get()) {
                if (val.m_SPNameQualifier != req.get()) {
                    Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                        "NameIDQualifierString MatchFunctor rejecting SPNameQualifier (%s), should be (%s)",
                        val.m_SPNameQualifier.c_str(), req.get()
                        );
                    return false;
                }
            }
            else {
                Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                    "NameIDQualifierString MatchFunctor rejecting SPNameQualifier (%s), attribute requester unknown",
                    val.m_SPNameQualifier.c_str()
                    );
                return false;
            }
        }
        else if (m_matchSPNameQualifier != val.m_SPNameQualifier) {
            Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").warn(
                "NameIDQualifierString MatchFunctor rejecting SPNameQualifier (%s), should be (%s)",
                val.m_SPNameQualifier.c_str(), m_matchSPNameQualifier.c_str()
                );
            return false;
        }
    }

    return true;
}
