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
 * AttributeIssuerEntityAttributeFunctor.cpp
 * 
 * A match function that checks if the attribute issuer contains an entity attribute with the
 * specified value or regex.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/EntityMatcher.h>
#include <saml/saml2/metadata/Metadata.h>

using namespace opensaml::saml2md;
using opensaml::SAMLConfig;

namespace shibsp {

    /**
     * A match function that checks if the attribute issuer contains an entity attribute with the
     * specified value or regex.
     */
    class SHIBSP_DLLLOCAL AttributeIssuerEntityAttributeFunctor : public MatchFunctor
    {
        boost::scoped_ptr<EntityMatcher> m_matcher;
    public:
        AttributeIssuerEntityAttributeFunctor(const DOMElement* e)
            : m_matcher(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(ENTITYATTR_ENTITY_MATCHER, e)) {
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (filterContext.getAttributeIssuerMetadata()) {
                const EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(filterContext.getAttributeIssuerMetadata()->getParent());
                if (entity)
                    return m_matcher->matches(*entity);
            }
            return false;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerEntityAttributeExactMatchFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeIssuerEntityAttributeFunctor(p.second);
    }

    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerEntityAttributeRegexMatchFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeIssuerEntityAttributeFunctor(p.second);
    }

};
