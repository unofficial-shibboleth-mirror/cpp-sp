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

/* ShibBrowserProfile.cpp - Shibboleth-specific wrapper around SAML browser profile

   Scott Cantor
   2/6/05

   $History:$
*/

#include "internal.h"

#include <ctime>

#include <openssl/x509v3.h>

using namespace shibboleth::logging;
using namespace shibboleth;
using namespace saml;
using namespace std;

ShibBrowserProfile::ShibBrowserProfile(const Iterator<IMetadata*>& metadatas, const Iterator<ITrust*>& trusts)
    : m_metadatas(metadatas), m_trusts(trusts)
{
    m_profile=SAMLBrowserProfile::getInstance();
}

ShibBrowserProfile::~ShibBrowserProfile()
{
    delete m_profile;
}

SAMLBrowserProfile::BrowserProfileResponse ShibBrowserProfile::receive(
    const char* packet,
    const XMLCh* recipient,
    int supportedProfiles,
    IReplayCache* replayCache,
    SAMLBrowserProfile::ArtifactMapper* callback,
    int minorVersion
    ) const
{
#ifdef _DEBUG
    saml::NDC("recieve");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibBrowserProfile");
 
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    SAMLBrowserProfile::BrowserProfileResponse bpr;
    try {
        bpr=m_profile->receive(packet, recipient, supportedProfiles, replayCache, callback, minorVersion);
    }
    catch (SAMLException& e) {
        // Try our best to attach additional information.
        if (e.getProperty("issuer")) {
            Metadata m(m_metadatas);
            const IEntityDescriptor* provider=m.lookup(e.getProperty("issuer"),false);
            if (provider) {
                const IIDPSSODescriptor* role=provider->getIDPSSODescriptor(
                    minorVersion==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
                    );
                if (role) annotateException(&e,role); // throws it
                annotateException(&e,provider);  // throws it
            }
        }
        throw;
    }
    
    // Try and locate metadata for the IdP. We try Issuer first.
    log.debug("searching metadata for assertion issuer...");
    Metadata m(m_metadatas);
    const IEntityDescriptor* provider=m.lookup(bpr.assertion->getIssuer());
    if (provider)
        log.debug("matched assertion issuer against metadata");
    else if (bpr.authnStatement->getSubject()->getNameIdentifier() &&
             bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier()) {
        // Might be a down-level origin.
        provider=m.lookup(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        if (provider)
            log.debug("matched subject name qualifier against metadata");
    }

    // No metadata at all.
    if (!provider) {
        auto_ptr_char issuer(bpr.assertion->getIssuer());
        auto_ptr_char nq(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        log.error("assertion issuer not found in metadata (Issuer='%s', NameQualifier='%s')",
            issuer.get(), (nq.get() ? nq.get() : "none"));
        
        // Try a non-strict lookup for more contact info.
        const IEntityDescriptor* provider=m.lookup(bpr.assertion->getIssuer(),false);
        if (provider) {
    		log.debug("found invalid metadata for assertion issuer, using for contact info");
            bpr.clear();
            MetadataException ex("metadata lookup failed, unable to process assertion");
            annotateException(&ex,provider);  // throws it
        }
        bpr.clear();
        throw MetadataException("metadata lookup failed, unable to process assertion",namedparams(1,"issuer",issuer.get()));
    }

    // Is this provider an IdP?
    const IIDPSSODescriptor* role=provider->getIDPSSODescriptor(
        minorVersion==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
        );
    if (role) {
        // Use this role to evaluate the signature(s). If the response is unsigned, we know
        // it was an artifact profile run.
        Trust t(m_trusts);
        if (bpr.response->isSigned()) {        
            log.debug("passing signed response to trust layer");
            if (!t.validate(*bpr.response,role)) {
                bpr.clear();
                log.error("unable to verify signed profile response");
                TrustException ex("unable to verify signed profile response");
                annotateException(&ex,role); // throws it
            }
            log.info("verified digital signature over SSO response");
        }    
        // SSO assertion signed?
        if (bpr.assertion->isSigned()) {
            log.debug("passing signed authentication assertion to trust layer"); 
            if (!t.validate(*bpr.assertion,role)) {
                bpr.clear();
                log.error("unable to verify signed authentication assertion");
                TrustException ex("unable to verify signed authentication assertion");
                annotateException(&ex,role); // throws it
            }
            log.info("verified digital signature over SSO assertion");
        }
        
        // Finally, discard any assertions not issued by the same entity that issued the authn.
        Iterator<SAMLAssertion*> assertions=bpr.response->getAssertions();
        for (unsigned long a=0; a<assertions.size();) {
            if (XMLString::compareString(bpr.assertion->getIssuer(),assertions[a]->getIssuer())) {
                auto_ptr_char bad(assertions[a]->getIssuer());
                log.warn("discarding assertion not issued by authenticating IdP, instead by (%s)",bad.get());
                bpr.response->removeAssertion(a);
                continue;
            }
            a++;
        }
        
        return bpr;
    }

    auto_ptr_char issuer(bpr.assertion->getIssuer());
    auto_ptr_char nq(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
    log.error("metadata for assertion issuer indicates no SAML 1.%d identity provider role (Issuer='%s', NameQualifier='%s'",
        minorVersion, issuer.get(), (nq.get() ? nq.get() : "none"));
    bpr.clear();
    MetadataException ex("metadata lookup failed, issuer not registered as SAML 1.x identity provider");
    annotateException(&ex,provider,false);
    throw ex;
}
