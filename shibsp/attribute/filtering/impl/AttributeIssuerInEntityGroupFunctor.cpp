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
 * AttributeIssuerInEntityGroupFunctor.cpp
 * 
 * A match function that evaluates to true if the attribute issuer is found in metadata and is a member
 * of the given entity group.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"
#include "metadata/MetadataProviderCriteria.h"

#include <xmltooling/Lockable.h>
#include <xmltooling/util/XMLHelper.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    static const XMLCh checkAffiliations[] =    UNICODE_LITERAL_17(c,h,e,c,k,A,f,f,i,l,i,a,t,i,o,n,s);
    static const XMLCh groupID[] =              UNICODE_LITERAL_7(g,r,o,u,p,I,D);

    /**
     * A match function that evaluates to true if the attribute issuer is found in metadata and is a member
     * of the given entity group.
     */
    class SHIBSP_DLLLOCAL AttributeIssuerInEntityGroupFunctor : public MatchFunctor
    {
        const XMLCh* m_group;
        bool m_checkAffiliations;
    public:
        AttributeIssuerInEntityGroupFunctor(const DOMElement* e)
                : m_checkAffiliations(XMLHelper::getAttrBool(e, false, checkAffiliations)) {
            m_group = e ? e->getAttributeNS(nullptr,groupID) : nullptr;
            if (!m_group || !*m_group)
                throw ConfigurationException("AttributeIssuerInEntityGroup MatchFunctor requires non-empty groupID attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            const RoleDescriptor* issuer = filterContext.getAttributeIssuerMetadata();
            if (!issuer)
                return false;
            const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(issuer->getParent()->getParent());
            while (group) {
                if (XMLString::equals(group->getName(), m_group))
                    return true;
                group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
            }

            if (m_checkAffiliations) {
                // Use metadata to invoke the SSO service directly.
                MetadataProvider* m = filterContext.getApplication().getMetadataProvider();
                Locker locker(m);
                MetadataProviderCriteria mc(filterContext.getApplication(), m_group);
                pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
                if (entity.first) {
                    const AffiliationDescriptor* affiliation = entity.first->getAffiliationDescriptor();
                    if (affiliation) {
                        const vector<AffiliateMember*>& members = affiliation->getAffiliateMembers();
                        for (vector<AffiliateMember*>::const_iterator i = members.begin(); i != members.end(); ++i) {
                            if (XMLString::equals(filterContext.getAttributeIssuer(), (*i)->getID())) {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerInEntityGroupFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeIssuerInEntityGroupFunctor(p.second);
    }

};
