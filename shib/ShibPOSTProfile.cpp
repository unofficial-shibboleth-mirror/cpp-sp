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

/* ShibPOSTProfile.cpp - Shibboleth-specific wrapper around SAML POST profile

   Scott Cantor
   8/12/02

   $History:$
*/

#include "internal.h"

#include <ctime>

#include <openssl/x509v3.h>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

ShibPOSTProfile::ShibPOSTProfile(
    const Iterator<IMetadata*>& metadatas,
    const Iterator<IRevocation*>& revocations,
    const Iterator<ITrust*>& trusts,
    const Iterator<ICredentials*>& creds
    ) : m_metadatas(metadatas), m_revocations(revocations), m_trusts(trusts), m_creds(creds) {}

const SAMLAssertion* ShibPOSTProfile::getSSOAssertion(const SAMLResponse& r, const Iterator<const XMLCh*>& audiences)
{
    return SAMLPOSTProfile::getSSOAssertion(r,audiences);
}

const SAMLAuthenticationStatement* ShibPOSTProfile::getSSOStatement(const SAMLAssertion& a)
{
    return SAMLPOSTProfile::getSSOStatement(a);
}

const XMLCh* ShibPOSTProfile::getProviderId(const saml::SAMLResponse& r)
{
    // Favor an AuthnStatement Subject NameQualifier, but use Issuer if need be.
    const XMLCh* ret=NULL;
    Iterator<SAMLAssertion*> ia=r.getAssertions();
    while (ia.hasNext()) {
        SAMLAssertion* a=ia.next();
        ret=a->getIssuer();
        Iterator<SAMLStatement*> is=a->getStatements();
        while (is.hasNext()) {
            SAMLAuthenticationStatement* as=dynamic_cast<SAMLAuthenticationStatement*>(is.next());
            if (as && as->getSubject()->getNameIdentifier()->getNameQualifier())
                return as->getSubject()->getNameIdentifier()->getNameQualifier();
        }
    }
    return ret;
}

SAMLResponse* ShibPOSTProfile::accept(
    const XMLByte* buf,
    const XMLCh* recipient,
    int ttlSeconds,
    const saml::Iterator<const XMLCh*>& audiences,
    XMLCh** pproviderId)
{
    saml::NDC("accept");
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibPOSTProfile");
 
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    auto_ptr<SAMLResponse> r(SAMLPOSTProfile::accept(buf, recipient, ttlSeconds, false));

    // Now we do some more non-crypto (ie. cheap) work to match up the origin site
    // with its associated data.
    const SAMLAssertion* assertion = NULL;
    const SAMLAuthenticationStatement* sso = NULL;

    try {
        assertion = getSSOAssertion(*(r.get()),audiences);
        sso = getSSOStatement(*assertion);
    }
    catch (...) {
        // We want to try our best to locate an origin site name so we can fill it in.
        if (pproviderId)
            *pproviderId=XMLString::replicate(getProviderId(*(r.get())));
        throw;
    }
    
    // Finish SAML processing.
    SAMLPOSTProfile::process(*(r.get()), recipient, ttlSeconds);

    // Try and locate metadata for the IdP. With this new version, we try Issuer first.
    log.debug("searching metadata for assertion issuer...");
    Metadata m(m_metadatas);
    const IProvider* provider=m.lookup(assertion->getIssuer());
    if (provider) {
        if (pproviderId)
            *pproviderId=XMLString::replicate(assertion->getIssuer());
        log.debug("matched assertion issuer against metadata");
    }
    else {
        // Might be a down-level origin.
        provider=m.lookup(sso->getSubject()->getNameIdentifier()->getNameQualifier());
        if (provider) {
            if (pproviderId)
                *pproviderId=XMLString::replicate(sso->getSubject()->getNameIdentifier()->getNameQualifier());
            log.debug("matched subject name qualifier against metadata");
        }
    }

    // No metadata at all.        
    if (!provider) {
        auto_ptr_char issuer(assertion->getIssuer());
        auto_ptr_char nq(sso->getSubject()->getNameIdentifier()->getNameQualifier());
        log.error("assertion issuer not found in metadata (Issuer='%s', NameQualifier='%s'",
            issuer.get(), (nq.get() ? nq.get() : "null"));
        throw MetadataException("ShibPOSTProfile::accept() metadata lookup failed, unable to process assertion");
    }

    // Is this provider an IdP?
    Iterator<const IProviderRole*> roles=provider->getRoles();
    while (roles.hasNext()) {
        const IProviderRole* role=roles.next();
        if (dynamic_cast<const IIDPProviderRole*>(role)) {
            // Check for Shibboleth 1.x protocol support.
            if (role->hasSupport(Constants::SHIB_NS)) {
                log.debug("passing response to trust layer");
                
                // Use this role to evaluate the signature.
                Trust t(m_trusts);
                if (!t.validate(m_revocations,role,*r))
                    throw TrustException("ShibPOSTProfile::accept() unable to verify signed response");
                
                // Assertion(s) signed?
                Iterator<SAMLAssertion*> itera=r->getAssertions();
                while (itera.hasNext()) {
                    SAMLAssertion* _a=itera.next();
                    if (_a->isSigned()) {
                        log.debug("passing signed assertion to trust layer"); 
                        if (!t.validate(m_revocations,role,*_a))
                            throw TrustException("ShibPOSTProfile::accept() unable to verify signed assertion");
                    }
                }
                return r.release();
            }
        }
    }

    auto_ptr_char issuer(assertion->getIssuer());
    auto_ptr_char nq(sso->getSubject()->getNameIdentifier()->getNameQualifier());
    log.error("metadata for assertion issuer indicates no SAML 1.x identity provider role (Issuer='%s', NameQualifier='%s'",
        issuer.get(), (nq.get() ? nq.get() : "null"));
    throw MetadataException("ShibPOSTProfile::accept() metadata lookup failed, issuer not registered as SAML identity provider");
}

SAMLResponse* ShibPOSTProfile::prepare(
    const IIDPProviderRole* role,
    const char* credResolverId,
    const XMLCh* recipient,
    const XMLCh* authMethod,
    time_t authInstant,
    const XMLCh* name,
    const XMLCh* format,
    const XMLCh* nameQualifier,
    const XMLCh* subjectIP,
    const saml::Iterator<const XMLCh*>& audiences,
    const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings)
{
#ifdef WIN32
    struct tm* ptime=gmtime(&authInstant);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&authInstant,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
    auto_ptr_XMLCh timeptr(timebuf);
    XMLDateTime authDateTime(timeptr.get());
    authDateTime.parseDateTime();

    SAMLResponse* r = SAMLPOSTProfile::prepare(
        recipient,
        role->getProvider()->getId(),
        audiences,
        name,
        nameQualifier,
        format,
        subjectIP,
        authMethod,
        authDateTime,
        bindings
        );

    Credentials c(m_creds);
    const ICredResolver* cr=c.lookup(credResolverId);
    if (!cr) {
        delete r;
        throw CredentialException("ShibPOSTProfile::prepare() unable to access credential resolver");
    }
    XSECCryptoKey* key=cr->getKey();
    if (!key) {
        delete r;
        throw CredentialException("ShibPOSTProfile::prepare() unable to resolve signing key");
    }
    
    r->sign(SIGNATURE_RSA,key,cr->getCertificates());
    return r;
}

bool ShibPOSTProfile::checkReplayCache(const SAMLAssertion& a)
{
    // Default implementation uses the basic replay cache implementation.
    return SAMLPOSTProfile::checkReplayCache(a);
}
