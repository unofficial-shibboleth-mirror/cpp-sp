/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* internal.h

   Scott Cantor
   2/14/04

   $History:$
*/

#ifndef __internal_h__
#define __internal_h__

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shib-target/shib-target.h>
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
   
class XML
{
public:
        // URI constants
    static const XMLCh SHIB_NS[];
    static const XMLCh SHIB_SCHEMA_ID[];
    static const XMLCh SHIBMETA_NS[];
    static const XMLCh SHIBMETA_SCHEMA_ID[];
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
        static const XMLCh Certificate[];
        static const XMLCh Class[];
        static const XMLCh Credentials[];
        static const XMLCh CustomResolver[];
        static const XMLCh Key[];
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
        static const XMLCh Scope[];
        static const XMLCh Scoped[];
        static const XMLCh SiteRule[];
        static const XMLCh Type[];
        static const XMLCh Value[];

        static const XMLCh literal[];
        static const XMLCh regexp[];
        static const XMLCh xpath[];

        static const XMLCh Include[];
        static const XMLCh Exclude[];
        static const XMLCh url[];
        static const XMLCh verify[];
        
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
        static const XMLCh DigestMethod[];
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
        static const XMLCh _namespace[];
        static const XMLCh NameFormat[];
        static const XMLCh NameIDFormat[];
        static const XMLCh NameIDMappingService[];
        static const XMLCh OAEParams[];
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
        static const XMLCh SourceID[];
        static const XMLCh SPSSODescriptor[];
        static const XMLCh SurName[];
        static const XMLCh TelephoneNumber[];
        static const XMLCh use[];
        static const XMLCh validUntil[];
        static const XMLCh WantAuthnRequestsSigned[];
        static const XMLCh WantAssertionsSigned[];

        // access control constants
        static const XMLCh AccessControl[];
        static const XMLCh AND[];
        static const XMLCh NOT[];
        static const XMLCh OR[];
        static const XMLCh require[];
        static const XMLCh Rule[];
    };
};

#endif
