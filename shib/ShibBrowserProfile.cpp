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

/* ShibBrowserProfile.cpp - Shibboleth-specific wrapper around SAML browser profile

   Scott Cantor
   2/6/05

   $History:$
*/

#include "internal.h"

#include <ctime>

#include <openssl/x509v3.h>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
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

void ShibBrowserProfile::setVersion(int major, int minor)
{
    m_profile->setVersion(major,minor);
}

SAMLBrowserProfile::BrowserProfileResponse ShibBrowserProfile::receive(
    const char* packet,
    const XMLCh* recipient,
    int supportedProfiles,
    IReplayCache* replayCache,
    SAMLBrowserProfile::ArtifactMapper* callback
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
        bpr=m_profile->receive(packet, recipient, supportedProfiles, replayCache, callback);
    }
    catch (SAMLException& e) {
        // Try our best to attach additional information.
        if (e.getProperty("issuer")) {
            Metadata m(m_metadatas);
            const IEntityDescriptor* provider=m.lookup(e.getProperty("issuer"),false);
            if (provider) {
                const IIDPSSODescriptor* role=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
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
    else if (bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier()) {
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
            bpr.clear();
            MetadataException ex("metadata lookup failed, unable to process assertion");
            annotateException(&ex,provider);  // throws it
        }
        bpr.clear();
        throw MetadataException("metadata lookup failed, unable to process assertion",namedparams(1,"issuer",issuer.get()));
    }

    // Is this provider an IdP?
    const IIDPSSODescriptor* role=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
    if (role) {
        // Use this role to evaluate the signature(s). If the response is unsigned, we know
        // it was an artifact profile run.
        Trust t(m_trusts);
        if (bpr.response->isSigned()) {        
            log.debug("passing signed response to trust layer");
            if (!t.validate(*bpr.response,role)) {
                bpr.clear();
                TrustException ex("unable to verify signed profile response");
                annotateException(&ex,role); // throws it
            }
        }    
        // SSO assertion signed?
        if (bpr.assertion->isSigned()) {
            log.debug("passing signed authentication assertion to trust layer"); 
            if (!t.validate(*bpr.assertion,role)) {
                bpr.clear();
                TrustException ex("unable to verify signed authentication assertion");
                annotateException(&ex,role); // throws it
            }
        }
        return bpr;
    }

    auto_ptr_char issuer(bpr.assertion->getIssuer());
    auto_ptr_char nq(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
    log.error("metadata for assertion issuer indicates no SAML 1.x identity provider role (Issuer='%s', NameQualifier='%s'",
        issuer.get(), (nq.get() ? nq.get() : "none"));
    bpr.clear();
    MetadataException ex("metadata lookup failed, issuer not registered as SAML 1.x identity provider");
    annotateException(&ex,provider,false);
    throw ex;
}
