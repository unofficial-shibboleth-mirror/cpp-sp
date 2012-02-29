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
 * AttributeRequesterEntityMatcherFunctor.cpp
 * 
 * A match function that checks if the attribute requester matches pluggable criteria.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/EntityMatcher.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/util/XMLHelper.h>

using namespace opensaml::saml2md;
using opensaml::SAMLConfig;
using xmltooling::XMLHelper;

namespace shibsp {

    /**
     * A match function that checks if the attribute requester matches pluggable criteria.
     */
    class SHIBSP_DLLLOCAL AttributeRequesterEntityMatcherFunctor : public MatchFunctor
    {
        boost::scoped_ptr<EntityMatcher> m_matcher;
    public:
        AttributeRequesterEntityMatcherFunctor(const DOMElement* e) {
            static const XMLCh matcher[] = UNICODE_LITERAL_7(m,a,t,c,h,e,r);
            std::string type(XMLHelper::getAttrString(e, nullptr, matcher));
            if (!type.empty())
                m_matcher.reset(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(type.c_str(), e));
            else
                throw ConfigurationException("AttributeRequesterEntityMatcher MatchFunctor requires a matcher attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            if (filterContext.getAttributeRequesterMetadata()) {
                const EntityDescriptor* entity = dynamic_cast<EntityDescriptor*>(filterContext.getAttributeRequesterMetadata()->getParent());
                if (entity)
                    return m_matcher->matches(*entity);
            }
            return false;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeRequesterEntityMatcherFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeRequesterEntityMatcherFunctor(p.second);
    }

};
