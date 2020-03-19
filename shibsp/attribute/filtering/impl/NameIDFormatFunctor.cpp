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

#include <boost/iterator/indirect_iterator.hpp>
#include <saml/saml2/metadata/Metadata.h>


using namespace opensaml::saml2md;
using namespace boost;
using namespace std;

namespace shibsp {

    static const XMLCh nameIdFormat[] = UNICODE_LITERAL_12(n,a,m,e,I,d,F,o,r,m,a,t);

    /**
     * A match function base class that evaluates to true if the supplied metadata includes
     * a matching NameIDFormat.
     */
    class SHIBSP_DLLLOCAL AbstractNameIDFormatFunctor : public MatchFunctor
    {
        const XMLCh* m_format;
    public:
        AbstractNameIDFormatFunctor(const DOMElement* e) : m_format(e ? e->getAttributeNS(nullptr, nameIdFormat) : nullptr) {
            if (!m_format || !*m_format)
                throw ConfigurationException("NameIDFormat MatchFunctor requires non-empty nameIdFormat attribute.");
        }

        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            const vector<NameIDFormat*>* formats = getFormats(filterContext);
            if (!formats)
                return false;

            for (indirect_iterator<vector<NameIDFormat*>::const_iterator> i = make_indirect_iterator(formats->begin());
                    i != make_indirect_iterator(formats->end()); ++i) {
                if (XMLString::equals(m_format, i->getFormat()))
                    return true;
            }

            return false;
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            return evaluatePolicyRequirement(filterContext);
        }

    protected:
        virtual const vector<NameIDFormat*>* getFormats(const FilteringContext& filterContext) const = 0;
    };

    class SHIBSP_DLLLOCAL AttributeIssuerNameIDFormatFunctor : public AbstractNameIDFormatFunctor
    {
    public:
        AttributeIssuerNameIDFormatFunctor(const DOMElement* e) : AbstractNameIDFormatFunctor(e) {}

    protected:
        const vector<NameIDFormat*>* getFormats(const FilteringContext& filterContext) const {
            if (filterContext.getAttributeIssuerMetadata()) {
                const IDPSSODescriptor* idp = dynamic_cast<const IDPSSODescriptor*>(filterContext.getAttributeIssuerMetadata());
                if (idp)
                    return &(idp->getNameIDFormats());
                const AttributeAuthorityDescriptor* aa =
                    dynamic_cast<const AttributeAuthorityDescriptor*>(filterContext.getAttributeIssuerMetadata());
                if (aa)
                    return &(aa->getNameIDFormats());
            }
            return nullptr;
        }
    };

    class SHIBSP_DLLLOCAL AttributeRequesterNameIDFormatFunctor : public AbstractNameIDFormatFunctor
    {
    public:
        AttributeRequesterNameIDFormatFunctor(const DOMElement* e) : AbstractNameIDFormatFunctor(e) {}

    protected:
        const vector<NameIDFormat*>* getFormats(const FilteringContext& filterContext) const {
            const SPSSODescriptor* sp = dynamic_cast<const SPSSODescriptor*>(filterContext.getAttributeRequesterMetadata());
            if (sp)
                return &(sp->getNameIDFormats());
            return nullptr;
        }
    };


    MatchFunctor* SHIBSP_DLLLOCAL AttributeIssuerNameIDFormatFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeIssuerNameIDFormatFunctor(p.second);
    }

    MatchFunctor* SHIBSP_DLLLOCAL AttributeRequesterNameIDFormatFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeRequesterNameIDFormatFunctor(p.second);
    }

};
