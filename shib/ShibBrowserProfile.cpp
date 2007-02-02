/*
 *  Copyright 2001-2007 Internet2
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
#include <saml/saml1/core/Protocols.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>

using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml1p;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

ShibBrowserProfile::ShibBrowserProfile(
    const ITokenValidator* validator, MetadataProvider* metadata, TrustEngine* trust
    ) : m_validator(validator), m_metadata(metadata), m_trust(trust)
{
    m_profile=SAMLBrowserProfile::getInstance();
}

ShibBrowserProfile::~ShibBrowserProfile()
{
    delete m_profile;
}

SAMLBrowserProfile::BrowserProfileResponse ShibBrowserProfile::receive(
    const char* samlResponse,
    const XMLCh* recipient,
    saml::IReplayCache* replayCache,
    int minorVersion
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC("recieve");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibBrowserProfile");
 
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    SAMLBrowserProfile::BrowserProfileResponse bpr=m_profile->receive(samlResponse, recipient, replayCache, minorVersion);
    
    try {
        postprocess(bpr,minorVersion);
        return bpr;
    }
    catch (...) {
        bpr.clear();
        throw;
    }
}

SAMLBrowserProfile::BrowserProfileResponse ShibBrowserProfile::receive(
    Iterator<const char*> artifacts,
    const XMLCh* recipient,
    SAMLBrowserProfile::ArtifactMapper* artifactMapper,
    IReplayCache* replayCache,
    int minorVersion
    ) const
{
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    SAMLBrowserProfile::BrowserProfileResponse bpr=m_profile->receive(artifacts, recipient, artifactMapper, replayCache, minorVersion);
    
    try {
        postprocess(bpr,minorVersion);
        return bpr;
    }
    catch (...) {
        bpr.clear();
        throw;
    }
}

void ShibBrowserProfile::postprocess(SAMLBrowserProfile::BrowserProfileResponse& bpr, int minorVersion) const
{
#ifdef _DEBUG
    xmltooling::NDC("postprocess");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibBrowserProfile");

    if (!m_metadata)
        throw MetadataException("No metadata found, unable to process assertion.");

    // Try and locate metadata for the IdP. We try Issuer first.
    log.debug("searching metadata for assertion issuer...");
    xmltooling::Locker locker(m_metadata);
    const EntityDescriptor* provider=m_metadata->getEntityDescriptor(bpr.assertion->getIssuer());
    if (provider)
        log.debug("matched assertion issuer against metadata");
    else if (bpr.authnStatement->getSubject()->getNameIdentifier() &&
             bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier()) {
        // Might be a down-level origin.
        provider=m_metadata->getEntityDescriptor(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        if (provider)
            log.debug("matched subject name qualifier against metadata");
    }

    // No metadata at all.
    if (!provider) {
        xmltooling::auto_ptr_char issuer(bpr.assertion->getIssuer());
        xmltooling::auto_ptr_char nq(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        log.error("assertion issuer not found in metadata (Issuer='%s', NameQualifier='%s')",
            issuer.get(), (nq.get() ? nq.get() : "none"));
        
        // Try a non-strict lookup for more contact info.
        const EntityDescriptor* provider=m_metadata->getEntityDescriptor(bpr.assertion->getIssuer(),false);
        if (provider) {
    		log.debug("found invalid metadata for assertion issuer, using for contact info");
            MetadataException ex("metadata lookup failed, unable to process assertion");
            annotateException(&ex,provider);  // throws it
        }
        throw MetadataException("Metadata lookup failed, unable to process assertion",xmltooling::namedparams(1,"issuer",issuer.get()));
    }

    // Is this provider an IdP?
    const IDPSSODescriptor* role=provider->getIDPSSODescriptor(
        minorVersion==1 ? samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM
        );
    if (!role) {
        xmltooling::auto_ptr_char issuer(bpr.assertion->getIssuer());
        xmltooling::auto_ptr_char nq(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        log.error("metadata for assertion issuer indicates no SAML 1.%d identity provider role (Issuer='%s', NameQualifier='%s'",
            minorVersion, issuer.get(), (nq.get() ? nq.get() : "none"));
        MetadataException ex("Metadata lookup failed, issuer not registered as SAML 1.x identity provider");
        annotateException(&ex,provider); // throws it
    }

    // Use this role to evaluate the signature(s). If the response is unsigned, we know
    // it was an artifact profile run.
    if (bpr.response->isSigned()) {
        log.debug("passing signed response to trust layer");
        if (!m_trust) {
            XMLSecurityException ex("No trust provider, unable to verify signed profile response.");
            annotateException(&ex,role); // throws it
        }
        
        // This will all change, but for fun, we'll port the object from OS1->OS2 for validation.
        stringstream s;
        s << *bpr.response;
        DOMDocument* doc = XMLToolingConfig::getConfig().getValidatingParser().parse(s);
        XercesJanitor<DOMDocument> jdoc(doc);
        auto_ptr<Response> os2resp(ResponseBuilder::buildResponse());
        os2resp->unmarshall(doc->getDocumentElement(),true);
        jdoc.release();

        if (!m_trust->validate(*(os2resp->getSignature()),*role,m_metadata->getKeyResolver())) {
            log.error("unable to verify signed profile response");
            XMLSecurityException ex("Unable to verify signed profile response.");
            annotateException(&ex,role); // throws it
        }
    }

    time_t now=time(NULL);
    Iterator<SAMLAssertion*> assertions=bpr.response->getAssertions();
    for (unsigned int a=0; a<assertions.size();) {
        // Discard any assertions not issued by the same entity that issued the authn.
        if (bpr.assertion!=assertions[a] && XMLString::compareString(bpr.assertion->getIssuer(),assertions[a]->getIssuer())) {
            xmltooling::auto_ptr_char bad(assertions[a]->getIssuer());
            log.warn("discarding assertion not issued by authenticating IdP, instead by (%s)",bad.get());
            bpr.response->removeAssertion(a);
            continue;
        }

        // Validate the token.
        try {
            m_validator->validateToken(assertions[a],now,role,m_trust);
            a++;
        }
        catch (SAMLException&) {
            if (assertions[a]==bpr.assertion) {
                // If the authn token fails, we have to fail the whole profile run.
                log.error("authentication assertion failed to validate");
                //annotateException(&e,role,false);
                throw;
            }
            log.warn("token failed to validate, removing it from response");
            bpr.response->removeAssertion(a);
        }
    }
}
