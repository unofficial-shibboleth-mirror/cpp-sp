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
 * AttributeIssuerRegistrationAuthority.cpp
 * 
 * A match function that evaluates to true if the attribute issuer's metadata includes
 * a matching RegistrationAuthority extension.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"

#include <set>
#include <boost/algorithm/string.hpp>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/casts.hpp>
#include <boost/lambda/lambda.hpp>
#include <xmltooling/util/XMLHelper.h>
#include <saml/saml2/metadata/Metadata.h>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace boost::lambda;
using namespace boost;
using namespace std;

namespace shibsp {

    static const XMLCh registrars[] = UNICODE_LITERAL_10(r,e,g,i,s,t,r,a,r,s);
    static const XMLCh matchIfMetadataSilent[] = UNICODE_LITERAL_21(m,a,t,c,h,I,f,M,e,t,a,d,a,t,a,S,i,l,e,n,t);

    /**
     * A match function base class that evaluates to true if the supplied metadata includes
     * a matching RegistrationAuthority extension.
     */
    class SHIBSP_DLLLOCAL AbstractRegistrationAuthorityFunctor : public MatchFunctor
    {
        bool m_matchIfMetadataSilent;
        set<string> m_registrars;
    public:
        AbstractRegistrationAuthorityFunctor(const DOMElement* e)
                : m_matchIfMetadataSilent(XMLHelper::getAttrBool(e, false, matchIfMetadataSilent)) {
            const XMLCh* prop = e ? e->getAttributeNS(nullptr,registrars) : nullptr;
            if (!prop || !*prop)
                throw ConfigurationException("AttributeIssuerRegistrationAuthorityFunctor MatchFunctor requires non-empty registrars attribute.");
            auto_ptr_char regs(prop);
            string dup(regs.get());
            split(m_registrars, dup, is_space(), algorithm::token_compress_on);
            if (m_registrars.empty())
                throw ConfigurationException("AttributeIssuerRegistrationAuthorityFunctor MatchFunctor requires non-empty registrars attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            const RoleDescriptor* issuer = getMetadata(filterContext);
            if (!issuer)
                return m_matchIfMetadataSilent;

            const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(issuer->getParent());
            const RegistrationInfo* info = getRegistrationInfo(entity->getExtensions());
            if (!info) {
                const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(entity->getParent());
                while (!info && group) {
                    info = getRegistrationInfo(group->getExtensions());
                    group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
                }
            }

            if (info) {
                auto_ptr_char authority(info->getRegistrationAuthority());
                return authority.get() &&  m_registrars.find(authority.get()) != m_registrars.end();
            }
            return m_matchIfMetadataSilent;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }

    protected:
        virtual const RoleDescriptor* getMetadata(const FilteringContext& filterContext) const = 0;

    private:
        const RegistrationInfo* getRegistrationInfo(const Extensions* extensions) const {
            if (extensions) {
                const vector<XMLObject*>& exts = extensions->getUnknownXMLObjects();
                const XMLObject* xo = find_if(exts, ll_dynamic_cast<RegistrationInfo*>(_1) != ((RegistrationInfo*)nullptr));
                if (xo) {
                    return dynamic_cast<const RegistrationInfo*>(xo);
                }
            }
            return nullptr;
        }
    };

    class SHIBSP_DLLLOCAL AttributeIssuerRegistrationAuthorityFunctor : public AbstractRegistrationAuthorityFunctor
    {
    public:
        AttributeIssuerRegistrationAuthorityFunctor(const DOMElement* e) : AbstractRegistrationAuthorityFunctor(e) {}

    protected:
        const RoleDescriptor* getMetadata(const FilteringContext& filterContext) const {
            return filterContext.getAttributeIssuerMetadata();
        }
    };

    class SHIBSP_DLLLOCAL AttributeRequesterRegistrationAuthorityFunctor : public AbstractRegistrationAuthorityFunctor
    {
    public:
        AttributeRequesterRegistrationAuthorityFunctor(const DOMElement* e) : AbstractRegistrationAuthorityFunctor(e) {}

    protected:
        const RoleDescriptor* getMetadata(const FilteringContext& filterContext) const {
            return filterContext.getAttributeRequesterMetadata();
        }
    };


    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerRegistrationAuthorityFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeIssuerRegistrationAuthorityFunctor(p.second);
    }

    MatchFunctor* SHIBSP_DLLLOCAL RegistrationAuthorityFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeRequesterRegistrationAuthorityFunctor(p.second);
    }

};
