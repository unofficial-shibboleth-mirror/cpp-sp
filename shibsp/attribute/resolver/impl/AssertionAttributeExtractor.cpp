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
 * AssertionAttributeExtractor.cpp
 *
 * AttributeExtractor for SAML assertion content.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace opensaml::saml1;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class AssertionExtractor : public AttributeExtractor
    {
    public:
        AssertionExtractor(const DOMElement* e);
        ~AssertionExtractor() {}

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
        void getAttributeIds(vector<string>& attributes) const;

    private:
        string m_authnAuthority,
            m_authnClass,
            m_authnDecl,
            m_authnInstant,
            m_issuer,
            m_notOnOrAfter,
            m_sessionIndex,
            m_sessionNotOnOrAfter,
            m_subjectAddress,
            m_subjectDNS,
            m_consent;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL AssertionAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new AssertionExtractor(e);
    }

};

AssertionExtractor::AssertionExtractor(const DOMElement* e)
    : m_authnAuthority(XMLHelper::getAttrString(e, nullptr, AuthenticatingAuthority::LOCAL_NAME)),
        m_authnClass(XMLHelper::getAttrString(e, nullptr, AuthnContextClassRef::LOCAL_NAME)),
        m_authnDecl(XMLHelper::getAttrString(e, nullptr, AuthnContextDeclRef::LOCAL_NAME)),
        m_authnInstant(XMLHelper::getAttrString(e, nullptr, AuthnStatement::AUTHNINSTANT_ATTRIB_NAME)),
        m_issuer(XMLHelper::getAttrString(e, nullptr, Issuer::LOCAL_NAME)),
        m_notOnOrAfter(XMLHelper::getAttrString(e, nullptr, saml2::Conditions::NOTONORAFTER_ATTRIB_NAME)),
        m_sessionIndex(XMLHelper::getAttrString(e, nullptr, AuthnStatement::SESSIONINDEX_ATTRIB_NAME)),
        m_sessionNotOnOrAfter(XMLHelper::getAttrString(e, nullptr, AuthnStatement::SESSIONNOTONORAFTER_ATTRIB_NAME)),
        m_subjectAddress(XMLHelper::getAttrString(e, nullptr, saml2::SubjectLocality::ADDRESS_ATTRIB_NAME)),
        m_subjectDNS(XMLHelper::getAttrString(e, nullptr, saml2::SubjectLocality::DNSNAME_ATTRIB_NAME)),
        m_consent(XMLHelper::getAttrString(e, nullptr, saml2p::StatusResponseType::CONSENT_ATTRIB_NAME))
{
}

void AssertionExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<shibsp::Attribute*>& attributes
    ) const
{
    const saml2p::StatusResponseType* srt = dynamic_cast<const saml2p::StatusResponseType*>(&xmlObject);
    if (srt) {
        // Consent
        if (!m_consent.empty() && srt->getConsent()) {
            auto_ptr_char temp(srt->getConsent());
            if (temp.get() && *temp.get()) {
                auto_ptr<SimpleAttribute> consent(new SimpleAttribute(vector<string>(1, m_consent)));
                consent->getValues().push_back(temp.get());
                attributes.push_back(consent.get());
                consent.release();
            }
        }
        return;
    }

    const saml2::Assertion* saml2assertion = dynamic_cast<const saml2::Assertion*>(&xmlObject);
    if (saml2assertion) {
        // Issuer
        if (!m_issuer.empty()) {
            const Issuer* i = saml2assertion->getIssuer();
            if (i && (!i->getFormat() || !*(i->getFormat()) || XMLString::equals(i->getFormat(), NameIDType::ENTITY))) {
                auto_ptr_char temp(i->getName());
                if (temp.get() && *temp.get()) {
                    auto_ptr<SimpleAttribute> issuer(new SimpleAttribute(vector<string>(1, m_issuer)));
                    issuer->getValues().push_back(temp.get());
                    attributes.push_back(issuer.get());
                    issuer.release();
                }
            }
        }

        // NotOnOrAfter
        if (!m_notOnOrAfter.empty() && saml2assertion->getConditions() && saml2assertion->getConditions()->getNotOnOrAfter()) {
            auto_ptr_char temp(saml2assertion->getConditions()->getNotOnOrAfter()->getRawData());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> notonorafter(new SimpleAttribute(vector<string>(1, m_notOnOrAfter)));
                notonorafter->getValues().push_back(temp.get());
                attributes.push_back(notonorafter.get());
                notonorafter.release();
            }
        }

        return;
    }

    const AuthnStatement* saml2statement = dynamic_cast<const AuthnStatement*>(&xmlObject);
    if (saml2statement) {
        // AuthnInstant
        if (!m_authnInstant.empty() && saml2statement->getAuthnInstant()) {
            auto_ptr_char temp(saml2statement->getAuthnInstant()->getRawData());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> authninstant(new SimpleAttribute(vector<string>(1, m_authnInstant)));
                authninstant->getValues().push_back(temp.get());
                attributes.push_back(authninstant.get());
                authninstant.release();
            }
        }

        // SessionIndex
        if (!m_sessionIndex.empty() && saml2statement->getSessionIndex() && *(saml2statement->getSessionIndex())) {
            auto_ptr_char temp(saml2statement->getSessionIndex());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> sessionindex(new SimpleAttribute(vector<string>(1, m_sessionIndex)));
                sessionindex->getValues().push_back(temp.get());
                attributes.push_back(sessionindex.get());
                sessionindex.release();
            }
        }

        // SessionNotOnOrAfter
        if (!m_sessionNotOnOrAfter.empty() && saml2statement->getSessionNotOnOrAfter()) {
            auto_ptr_char temp(saml2statement->getSessionNotOnOrAfter()->getRawData());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> sessionnotonorafter(new SimpleAttribute(vector<string>(1, m_sessionNotOnOrAfter)));
                sessionnotonorafter->getValues().push_back(temp.get());
                attributes.push_back(sessionnotonorafter.get());
                sessionnotonorafter.release();
            }
        }

        if (saml2statement->getSubjectLocality()) {
            const saml2::SubjectLocality* locality = saml2statement->getSubjectLocality();
            // Address
            if (!m_subjectAddress.empty() && locality->getAddress() && *(locality->getAddress())) {
                auto_ptr_char temp(locality->getAddress());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> address(new SimpleAttribute(vector<string>(1, m_subjectAddress)));
                    address->getValues().push_back(temp.get());
                    attributes.push_back(address.get());
                    address.release();
                }
            }

            // DNSName
            if (!m_subjectDNS.empty() && locality->getDNSName() && *(locality->getDNSName())) {
                auto_ptr_char temp(locality->getDNSName());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> dns(new SimpleAttribute(vector<string>(1, m_subjectDNS)));
                    dns->getValues().push_back(temp.get());
                    attributes.push_back(dns.get());
                    dns.release();
                }
            }
        }

        if (saml2statement->getAuthnContext()) {
            const AuthnContext* ac = saml2statement->getAuthnContext();
            // AuthnContextClassRef
            if (!m_authnClass.empty() && ac->getAuthnContextClassRef() && ac->getAuthnContextClassRef()->getReference()) {
                auto_ptr_char temp(ac->getAuthnContextClassRef()->getReference());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> classref(new SimpleAttribute(vector<string>(1, m_authnClass)));
                    classref->getValues().push_back(temp.get());
                    attributes.push_back(classref.get());
                    classref.release();
                }
            }

            // AuthnContextDeclRef
            if (!m_authnDecl.empty() && ac->getAuthnContextDeclRef() && ac->getAuthnContextDeclRef()->getReference()) {
                auto_ptr_char temp(ac->getAuthnContextDeclRef()->getReference());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> declref(new SimpleAttribute(vector<string>(1, m_authnDecl)));
                    declref->getValues().push_back(temp.get());
                    attributes.push_back(declref.get());
                    declref.release();
                }
            }

            // AuthenticatingAuthority
            if (!m_authnAuthority.empty() && !ac->getAuthenticatingAuthoritys().empty()) {
                auto_ptr<SimpleAttribute> attr(new SimpleAttribute(vector<string>(1, m_authnAuthority)));
                const vector<AuthenticatingAuthority*>& authorities = ac->getAuthenticatingAuthoritys();
                for (vector<AuthenticatingAuthority*>::const_iterator a = authorities.begin(); a != authorities.end(); ++a) {
                    auto_ptr_char temp((*a)->getID());
                    if (temp.get())
                        attr->getValues().push_back(temp.get());
                }
                if (attr->valueCount() > 0) {
                    attributes.push_back(attr.get());
                    attr.release();
                }
            }
        }

        return;
    }

    const saml1::Assertion* saml1assertion = dynamic_cast<const saml1::Assertion*>(&xmlObject);
    if (saml1assertion) {
        // Issuer
        if (!m_issuer.empty()) {
            if (saml1assertion->getIssuer() && *(saml1assertion->getIssuer())) {
                auto_ptr_char temp(saml1assertion->getIssuer());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> issuer(new SimpleAttribute(vector<string>(1, m_issuer)));
                    issuer->getValues().push_back(temp.get());
                    attributes.push_back(issuer.get());
                    issuer.release();
                }
            }
        }

        // NotOnOrAfter
        if (!m_notOnOrAfter.empty() && saml1assertion->getConditions() && saml1assertion->getConditions()->getNotOnOrAfter()) {
            auto_ptr_char temp(saml1assertion->getConditions()->getNotOnOrAfter()->getRawData());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> notonorafter(new SimpleAttribute(vector<string>(1, m_notOnOrAfter)));
                notonorafter->getValues().push_back(temp.get());
                attributes.push_back(notonorafter.get());
                notonorafter.release();
            }
        }

        return;
    }

    const AuthenticationStatement* saml1statement = dynamic_cast<const AuthenticationStatement*>(&xmlObject);
    if (saml1statement) {
        // AuthnInstant
        if (!m_authnInstant.empty() && saml1statement->getAuthenticationInstant()) {
            auto_ptr_char temp(saml1statement->getAuthenticationInstant()->getRawData());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> authninstant(new SimpleAttribute(vector<string>(1, m_authnInstant)));
                authninstant->getValues().push_back(temp.get());
                attributes.push_back(authninstant.get());
                authninstant.release();
            }
        }

        // AuthenticationMethod
        if (!m_authnClass.empty() && saml1statement->getAuthenticationMethod() && *(saml1statement->getAuthenticationMethod())) {
            auto_ptr_char temp(saml1statement->getAuthenticationMethod());
            if (temp.get()) {
                auto_ptr<SimpleAttribute> authnmethod(new SimpleAttribute(vector<string>(1, m_authnClass)));
                authnmethod->getValues().push_back(temp.get());
                attributes.push_back(authnmethod.get());
                authnmethod.release();
            }
        }

        if (saml1statement->getSubjectLocality()) {
            const saml1::SubjectLocality* locality = saml1statement->getSubjectLocality();
            // IPAddress
            if (!m_subjectAddress.empty() && locality->getIPAddress() && *(locality->getIPAddress())) {
                auto_ptr_char temp(locality->getIPAddress());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> address(new SimpleAttribute(vector<string>(1, m_subjectAddress)));
                    address->getValues().push_back(temp.get());
                    attributes.push_back(address.get());
                    address.release();
                }
            }

            // DNSAddress
            if (!m_subjectDNS.empty() && locality->getDNSAddress() && *(locality->getDNSAddress())) {
                auto_ptr_char temp(locality->getDNSAddress());
                if (temp.get()) {
                    auto_ptr<SimpleAttribute> dns(new SimpleAttribute(vector<string>(1, m_subjectDNS)));
                    dns->getValues().push_back(temp.get());
                    attributes.push_back(dns.get());
                    dns.release();
                }
            }
        }
    }
}

void AssertionExtractor::getAttributeIds(vector<string>& attributes) const
{
    if (!m_authnAuthority.empty())
        attributes.push_back(m_authnAuthority);
    if (!m_authnClass.empty())
        attributes.push_back(m_authnClass);
    if (!m_authnDecl.empty())
        attributes.push_back(m_authnDecl);
    if (!m_authnInstant.empty())
        attributes.push_back(m_authnInstant);
    if (!m_issuer.empty())
        attributes.push_back(m_issuer);
    if (!m_notOnOrAfter.empty())
        attributes.push_back(m_notOnOrAfter);
    if (!m_sessionIndex.empty())
        attributes.push_back(m_sessionIndex);
    if (!m_sessionNotOnOrAfter.empty())
        attributes.push_back(m_sessionNotOnOrAfter);
    if (!m_subjectAddress.empty())
        attributes.push_back(m_subjectAddress);
    if (!m_subjectDNS.empty())
        attributes.push_back(m_subjectDNS);
    if (!m_consent.empty())
        attributes.push_back(m_consent);
}
