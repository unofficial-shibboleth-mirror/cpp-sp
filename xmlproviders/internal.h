/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* internal.h

   Scott Cantor
   2/14/04

   $History:$
*/

#ifndef __internal_h__
#define __internal_h__

#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>
#include <openssl/ssl.h>

#define XMLPROVIDERS_LOGCAT "XMLProviders"

#define SHIB_L(s) ::XML::Literals::s
#define SHIB_L_QNAME(p,s) ::XML::Literals::p##_##s

// direct OpenSSL error content to log4cpp
void log_openssl();

// build an OpenSSL object out of a base-64 encoded DER buffer (XML style)
X509_CRL* B64_to_CRL(const char* buf);
X509* B64_to_X509(const char* buf);
   
class ScopedAttribute : public saml::SAMLAttribute
{
public:
    ScopedAttribute(const XMLCh* name, const XMLCh* ns, long lifetime=0,
                    const saml::Iterator<const XMLCh*>& scopes=EMPTY(const XMLCh*),
                    const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*));
    ScopedAttribute(DOMElement* e);
    virtual ~ScopedAttribute();

    virtual saml::SAMLObject* clone() const;
    
    virtual saml::Iterator<const XMLCh*> getValues() const;
    virtual saml::Iterator<std::string> getSingleByteValues() const;
    virtual void setValues(const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*));
    virtual void addValue(const XMLCh* value);
    virtual void removeValue(unsigned int index);
    
protected:
    virtual void valueToDOM(unsigned int index, DOMElement* e) const;
    
    const XMLCh* m_originSite;
    std::vector<const XMLCh*> m_scopes;
    mutable std::vector<const XMLCh*> m_scopedValues;
};
    
class XML
{
public:
        // URI constants
    static const XMLCh SHIB_NS[];
    static const XMLCh SHIB_SCHEMA_ID[];
    static const XMLCh CREDS_NS[];
    static const XMLCh CREDS_SCHEMA_ID[];
    static const XMLCh TRUST_NS[];
    static const XMLCh TRUST_SCHEMA_ID[];
    static const XMLCh SAML2ASSERT_NS[];
    static const XMLCh SAML2ASSERT_SCHEMA_ID[];
    static const XMLCh SAML2META_NS[];
    static const XMLCh SAML2META_SCHEMA_ID[];
    static const XMLCh XMLENC_NS[];
    static const XMLCh XMLENC_SCHEMA_ID[];
        
    // ds:KeyInfo RetrievalMethods
    static const XMLCh XMLSIG_RETMETHOD_RAWX509[];  // http://www.w3.org/2000/09/xmldsig#rawX509Certificate
    static const XMLCh XMLSIG_RETMETHOD_RAWX509CRL[]; // http://www.w3.org/2000/09/xmldsig-more#rawX509CRL
    static const XMLCh SHIB_RETMETHOD_PEMX509[];    // urn:mace:shibboleth:RetrievalMethod:pemX509Certificate
    static const XMLCh SHIB_RETMETHOD_PEMX509CRL[]; // urn:mace:shibboleth:RetrievalMethod:pemX509CRL

    struct Literals
    {
        // old metadata constants
        static const XMLCh AttributeAuthority[];
        static const XMLCh Contact[];
        static const XMLCh Domain[];
        static const XMLCh Email[];
        static const XMLCh ErrorURL[];
        static const XMLCh HandleService[];
        static const XMLCh InvalidHandle[];
        static const XMLCh Location[];
        static const XMLCh Name[];
        static const XMLCh OriginSite[];
        static const XMLCh SiteGroup[];

        static const XMLCh administrative[];
        static const XMLCh billing[];
        static const XMLCh other[];
        static const XMLCh support[];
        static const XMLCh technical[];

        // credentials constants
        static const XMLCh CAPath[];
        static const XMLCh Class[];
        static const XMLCh Credentials[];
        static const XMLCh CustomResolver[];
        static const XMLCh FileResolver[];
        static const XMLCh format[];
        static const XMLCh Id[];
        static const XMLCh password[];
        static const XMLCh Path[];
        
        // trust constants
        static const XMLCh Exponent[];
        static const XMLCh KeyAuthority[];
        static const XMLCh KeyName[];
        static const XMLCh Modulus[];
        static const XMLCh RetrievalMethod[];
        static const XMLCh RSAKeyValue[];
        static const XMLCh Trust[];
        static const XMLCh URI[];
        static const XMLCh VerifyDepth[];
        static const XMLCh X509CRL[];

        // SAML attribute constants
        static const XMLCh Scope[];

        static const XMLCh Accept[];
        static const XMLCh Alias[];
        static const XMLCh AnyAttribute[];
        static const XMLCh AnySite[];
        static const XMLCh AnyValue[];
        static const XMLCh AttributeAcceptancePolicy[];
        static const XMLCh AttributeRule[];
        static const XMLCh CaseSensitive[];
        static const XMLCh Factory[];
        static const XMLCh Header[];
        static const XMLCh Namespace[];
        static const XMLCh Scoped[];
        static const XMLCh SiteRule[];
        static const XMLCh Type[];
        static const XMLCh Value[];

        static const XMLCh literal[];
        static const XMLCh regexp[];
        static const XMLCh xpath[];

        static const XMLCh url[];
        
        // new metadata constants
        static const XMLCh AdditionalMetadataLocation[];
        static const XMLCh AffiliateMember[];
        static const XMLCh AffiliationDescriptor[];
        static const XMLCh affiliationOwnerID[];
        static const XMLCh Algorithm[];
        static const XMLCh ArtifactResolutionService[];
        static const XMLCh AssertionConsumerService[];
        static const XMLCh AssertionIDRequestService[];
        static const XMLCh AttributeAuthorityDescriptor[];
        static const XMLCh AttributeConsumingService[];
        static const XMLCh AttributeProfile[];
        static const XMLCh AttributeService[];
        static const XMLCh AuthnAuthorityDescriptor[];
        static const XMLCh AuthnQueryService[];
        static const XMLCh AuthnRequestsSigned[];
        static const XMLCh AuthzService[];
        static const XMLCh cacheDuration[];
        static const XMLCh Company[];
        static const XMLCh ContactPerson[];
        static const XMLCh contactType[];
        static const XMLCh EmailAddress[];
        static const XMLCh encryption[];
        static const XMLCh EncryptionMethod[];
        static const XMLCh EntitiesDescriptor[];
        static const XMLCh EntityDescriptor[];
        static const XMLCh entityID[];
        static const XMLCh errorURL[];
        static const XMLCh Extensions[];
        static const XMLCh GivenName[];
        static const XMLCh IDPSSODescriptor[];
        static const XMLCh index[];
        static const XMLCh isDefault[];
        static const XMLCh isRequired[];
        static const XMLCh KeyDescriptor[];
        static const XMLCh KeySize[];
        static const XMLCh ManageNameIDService[];
        static const XMLCh NameIDFormat[];
        static const XMLCh NameIDMappingService[];
        static const XMLCh OAEPparams[];
        static const XMLCh Organization[];
        static const XMLCh OrganizationName[];
        static const XMLCh OrganizationDisplayName[];
        static const XMLCh OrganizationURL[];
        static const XMLCh PDPDescriptor[];
        static const XMLCh protocolSupportEnumeration[];
        static const XMLCh RequestedAttribute[];
        static const XMLCh ResponseLocation[];
        static const XMLCh RoleDescriptor[];
        static const XMLCh ServiceDescription[];
        static const XMLCh ServiceName[];
        static const XMLCh signing[];
        static const XMLCh SingleLogoutService[];
        static const XMLCh SingleSignOnService[];
        static const XMLCh SPSSODescriptor[];
        static const XMLCh SurName[];
        static const XMLCh TelephoneNumber[];
        static const XMLCh use[];
        static const XMLCh validUntil[];
        static const XMLCh WantAuthnRequestsSigned[];
        static const XMLCh WantAssertionsSigned[];
    };
};

#endif
