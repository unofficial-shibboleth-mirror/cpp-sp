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
 * DelegationAttributeExtractor.cpp
 *
 * AttributeExtractor for DelegationRestriction information.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class AuthnAuthorityExtractor : public AttributeExtractor
    {
    public:
        AuthnAuthorityExtractor(const DOMElement* e);
        ~AuthnAuthorityExtractor() {}

        Lockable* lock() {
            return this;
        }

        void unlock() {
        }

        void extractAttributes(
            const Application& application,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<shibsp::Attribute*>& attributes
            ) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            attributes.push_back(m_attributeId);
        }

    private:
        string m_attributeId;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL AuthnAuthorityAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new AuthnAuthorityExtractor(e);
    }

    static const XMLCh attributeId[] =  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,d);
};

AuthnAuthorityExtractor::AuthnAuthorityExtractor(const DOMElement* e)
    : m_attributeId(XMLHelper::getAttrString(e, "AuthenticatingAuthority", attributeId))
{
}

void AuthnAuthorityExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<shibsp::Attribute*>& attributes
    ) const
{
    const saml2::Assertion* assertion = dynamic_cast<const saml2::Assertion*>(&xmlObject);
    if (!assertion || assertion->getAuthnStatements().empty())
        return;

    auto_ptr<SimpleAttribute> attr(new SimpleAttribute(vector<string>(1,m_attributeId)));

    const vector<AuthnStatement*>& statements = assertion->getAuthnStatements();
    for (vector<AuthnStatement*>::const_iterator s = statements.begin(); s != statements.end(); ++s) {

        if (!(*s)->getAuthnContext() || (*s)->getAuthnContext()->getAuthenticatingAuthoritys().empty())
            continue;

        const vector<AuthenticatingAuthority*>& authorities =
            const_cast<const AuthnContext*>((*s)->getAuthnContext())->getAuthenticatingAuthoritys();
        for (vector<AuthenticatingAuthority*>::const_iterator a = authorities.begin(); a != authorities.end(); ++a) {
            const XMLCh* n = (*a)->getID();
            if (n && *n) {
                auto_ptr_char temp(n);
                attr->getValues().push_back(temp.get());
            }
        }

        if (attr->valueCount() > 0) {
            attributes.push_back(attr.release());
            return;
        }
    }
}
