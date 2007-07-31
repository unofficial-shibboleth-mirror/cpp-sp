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

/**
 * SAML2Consumer.cpp
 * 
 * SAML 2.0 assertion consumer service 
 */

#include "internal.h"
#include "handler/AssertionConsumerService.h"

#ifndef SHIBSP_LITE
# include "exceptions.h"
# include "Application.h"
# include "ServiceProvider.h"
# include "SessionCache.h"
# include "attribute/Attribute.h"
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/filtering/BasicFilteringContext.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/ResolutionContext.h"
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/profile/BrowserSSOProfileValidator.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
# ifndef min
#  define min(a,b)            (((a) < (b)) ? (a) : (b))
# endif
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif
    
    class SHIBSP_DLLLOCAL SAML2Consumer : public AssertionConsumerService
    {
    public:
        SAML2Consumer(const DOMElement* e, const char* appId)
            : AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".SSO.SAML2")) {
        }
        virtual ~SAML2Consumer() {}
        
    private:
#ifndef SHIBSP_LITE
        string implementProtocol(
            const Application& application,
            const HTTPRequest& httpRequest,
            SecurityPolicy& policy,
            const PropertySet* settings,
            const XMLObject& xmlObject
            ) const;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2ConsumerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2Consumer(p.first, p.second);
    }
    
};

#ifndef SHIBSP_LITE

string SAML2Consumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    SecurityPolicy& policy,
    const PropertySet* settings,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of SAML 2.0 SSO profile(s).
    m_log.debug("processing message against SAML 2.0 SSO profile");

    // Remember whether we already established trust.
    // None of the SAML 2 bindings require security at the protocol layer.
    bool alreadySecured = policy.isSecure();

    // Check for errors...this will throw if it's not a successful message.
    checkError(&xmlObject);

    const Response* response = dynamic_cast<const Response*>(&xmlObject);
    if (!response)
        throw FatalProfileException("Incoming message was not a samlp:Response.");

    const vector<saml2::Assertion*>& assertions = response->getAssertions();
    const vector<saml2::EncryptedAssertion*>& encassertions = response->getEncryptedAssertions();
    if (assertions.empty() && encassertions.empty())
        throw FatalProfileException("Incoming message contained no SAML assertions.");

    // Maintain list of "legit" tokens to feed to SP subsystems.
    const Subject* ssoSubject=NULL;
    const AuthnStatement* ssoStatement=NULL;
    vector<const opensaml::Assertion*> tokens;

    // Also track "bad" tokens that we'll cache but not use.
    // This is necessary because there may be valid tokens not aimed at us.
    vector<const opensaml::Assertion*> badtokens;

    // And also track "owned" tokens that we decrypt here.
    vector<saml2::Assertion*> ownedtokens;

    // Profile validator.
    time_t now = time(NULL);
    string dest = httpRequest.getRequestURL();
    BrowserSSOProfileValidator ssoValidator(application.getAudiences(), now, dest.substr(0,dest.find('?')).c_str());

    // With this flag on, we ignore any unsigned assertions.
    pair<bool,bool> flag = settings->getBool("signedAssertions");

    // Saves off IP-mismatch error message because it's potentially helpful for users.
    string addressMismatch;

    for (vector<saml2::Assertion*>::const_iterator a = assertions.begin(); a!=assertions.end(); ++a) {
        // Skip unsigned assertion?
        if (!(*a)->getSignature() && flag.first && flag.second) {
            m_log.warn("found unsigned assertion in SAML response, ignoring it per signedAssertions policy");
            badtokens.push_back(*a);
            continue;
        }

        try {
            // We clear the security flag, so we can tell whether the token was secured on its own.
            policy.setSecure(false);
            
            // Run the policy over the assertion. Handles issuer consistency, replay, freshness,
            // and signature verification, assuming the relevant rules are configured.
            policy.evaluate(*(*a));
            
            // If no security is in place now, we kick it.
            if (!alreadySecured && !policy.isSecure()) {
                m_log.warn("unable to establish security of assertion");
                badtokens.push_back(*a);
                continue;
            }

            // Now do profile and core semantic validation to ensure we can use it for SSO.
            ssoValidator.validateAssertion(*(*a));

            // Address checking.
            try {
                if (ssoValidator.getAddress())
                    checkAddress(application, httpRequest, ssoValidator.getAddress());
            }
            catch (exception& ex) {
                // We save off the message if there's no SSO statement yet.
                if (!ssoStatement)
                    addressMismatch = ex.what();
                throw;
            }

            // Track it as a valid token.
            tokens.push_back(*a);

            // Save off the first valid SSO statement, but favor the "soonest" session expiration.
            const vector<AuthnStatement*>& statements = const_cast<const saml2::Assertion*>(*a)->getAuthnStatements();
            for (vector<AuthnStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                if (!ssoStatement || (*s)->getSessionNotOnOrAfterEpoch() < ssoStatement->getSessionNotOnOrAfterEpoch())
                    ssoStatement = *s;
            }

            // Save off the first valid Subject, but favor an unencrypted NameID over anything else.
            if (!ssoSubject || (!ssoSubject->getNameID() && (*a)->getSubject()->getNameID()))
                ssoSubject = (*a)->getSubject();
        }
        catch (exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            badtokens.push_back(*a);
        }
    }

    // In case we need decryption...
    CredentialResolver* cr=application.getCredentialResolver();
    if (!cr && !encassertions.empty())
        m_log.warn("found encrypted assertions, but no CredentialResolver was available");

    for (vector<saml2::EncryptedAssertion*>::const_iterator ea = encassertions.begin(); cr && ea!=encassertions.end(); ++ea) {
        // Attempt to decrypt it.
        saml2::Assertion* decrypted=NULL;
        try {
            Locker credlocker(cr);
            auto_ptr<MetadataCredentialCriteria> mcc(
                policy.getIssuerMetadata() ? new MetadataCredentialCriteria(*policy.getIssuerMetadata()) : NULL
                );
            auto_ptr<XMLObject> wrapper((*ea)->decrypt(*cr, application.getXMLString("entityID").second, mcc.get()));
            decrypted = dynamic_cast<saml2::Assertion*>(wrapper.get());
            if (decrypted) {
                wrapper.release();
                ownedtokens.push_back(decrypted);
            }
        }
        catch (exception& ex) {
            m_log.error(ex.what());
        }
        if (!decrypted)
            continue;

        // Skip unsigned assertion?
        if (!decrypted->getSignature() && flag.first && flag.second) {
            m_log.warn("found unsigned assertion in SAML response, ignoring it per signedAssertions policy");
            badtokens.push_back(decrypted);
            continue;
        }

        try {
            // We clear the security flag, so we can tell whether the token was secured on its own.
            policy.setSecure(false);
            
            // Run the policy over the assertion. Handles issuer consistency, replay, freshness,
            // and signature verification, assuming the relevant rules are configured.
            // We have to marshall the object first to ensure signatures can be checked.
            policy.evaluate(*decrypted);
            
            // If no security is in place now, we kick it.
            if (!alreadySecured && !policy.isSecure()) {
                m_log.warn("unable to establish security of assertion");
                badtokens.push_back(decrypted);
                continue;
            }

            // Now do profile and core semantic validation to ensure we can use it for SSO.
            ssoValidator.validateAssertion(*decrypted);

            // Address checking.
            try {
                if (ssoValidator.getAddress())
                    checkAddress(application, httpRequest, ssoValidator.getAddress());
            }
            catch (exception& ex) {
                // We save off the message if there's no SSO statement yet.
                if (!ssoStatement)
                    addressMismatch = ex.what();
                throw;
            }

            // Track it as a valid token.
            tokens.push_back(decrypted);

            // Save off the first valid SSO statement, but favor the "soonest" session expiration.
            const vector<AuthnStatement*>& statements = const_cast<const saml2::Assertion*>(decrypted)->getAuthnStatements();
            for (vector<AuthnStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                if (!ssoStatement || (*s)->getSessionNotOnOrAfterEpoch() < ssoStatement->getSessionNotOnOrAfterEpoch())
                    ssoStatement = *s;
            }

            // Save off the first valid Subject, but favor an unencrypted NameID over anything else.
            if (!ssoSubject || (!ssoSubject->getNameID() && decrypted->getSubject()->getNameID()))
                ssoSubject = decrypted->getSubject();
        }
        catch (exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            badtokens.push_back(decrypted);
        }
    }

    if (!ssoStatement) {
        for_each(ownedtokens.begin(), ownedtokens.end(), xmltooling::cleanup<saml2::Assertion>());
        if (addressMismatch.empty())
            throw FatalProfileException("A valid authentication statement was not found in the incoming message.");
        throw FatalProfileException(addressMismatch.c_str());
    }

    // May need to decrypt NameID.
    bool ownedName = false;
    NameID* ssoName = ssoSubject->getNameID();
    if (!ssoName) {
        EncryptedID* encname = ssoSubject->getEncryptedID();
        if (encname) {
            if (!cr)
                m_log.warn("found encrypted NameID, but no decryption credential was available");
            else {
                Locker credlocker(cr);
                auto_ptr<MetadataCredentialCriteria> mcc(
                    policy.getIssuerMetadata() ? new MetadataCredentialCriteria(*policy.getIssuerMetadata()) : NULL
                    );
                try {
                    auto_ptr<XMLObject> decryptedID(encname->decrypt(*cr,application.getXMLString("entityID").second,mcc.get()));
                    ssoName = dynamic_cast<NameID*>(decryptedID.get());
                    if (ssoName) {
                        ownedName = true;
                        decryptedID.release();
                    }
                }
                catch (exception& ex) {
                    m_log.error(ex.what());
                }
            }
        }
    }

    m_log.debug("SSO profile processing completed successfully");

    // We've successfully "accepted" at least one SSO token, along with any additional valid tokens.
    // To complete processing, we need to extract and resolve attributes and then create the session.

    // Now we have to extract the authentication details for session setup.

    // Session expiration for SAML 2.0 is jointly IdP- and SP-driven.
    time_t sessionExp = ssoStatement->getSessionNotOnOrAfter() ? ssoStatement->getSessionNotOnOrAfterEpoch() : 0;
    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
    if (!lifetime.first || lifetime.second == 0)
        lifetime.second = 28800;
    if (sessionExp == 0)
        sessionExp = now + lifetime.second;     // IdP says nothing, calulate based on SP.
    else
        sessionExp = min(sessionExp, now + lifetime.second);    // Use the lowest.

    multimap<string,Attribute*> resolvedAttributes;
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        m_log.debug("extracting pushed attributes...");
        Locker extlocker(extractor);
        try {
            extractor->extractAttributes(application, policy.getIssuerMetadata(), *ssoName, resolvedAttributes);
        }
        catch (exception& ex) {
            m_log.error("caught exception extracting attributes: %s", ex.what());
        }
        for (vector<const opensaml::Assertion*>::const_iterator t = tokens.begin(); t!=tokens.end(); ++t) {
            try {
                extractor->extractAttributes(application, policy.getIssuerMetadata(), *(*t), resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }
    }

    const AuthnContext* authnContext = ssoStatement->getAuthnContext();

    AttributeFilter* filter = application.getAttributeFilter();
    if (filter && !resolvedAttributes.empty()) {
        BasicFilteringContext fc(
            application,
            resolvedAttributes,
            policy.getIssuerMetadata(),
            (authnContext && authnContext->getAuthnContextClassRef()) ? authnContext->getAuthnContextClassRef()->getReference() : NULL,
            (authnContext && authnContext->getAuthnContextDeclRef()) ? authnContext->getAuthnContextDeclRef()->getReference() : NULL
            );
        Locker filtlocker(filter);
        try {
            filter->filterAttributes(fc, resolvedAttributes);
        }
        catch (exception& ex) {
            m_log.error("caught exception filtering attributes: %s", ex.what());
            m_log.error("dumping extracted attributes due to filtering exception");
            for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,shibsp::Attribute>());
            resolvedAttributes.clear();
        }
    }

    try {
        const EntityDescriptor* issuerMetadata =
            policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;
        auto_ptr<ResolutionContext> ctx(
            resolveAttributes(
                application,
                issuerMetadata,
                samlconstants::SAML20P_NS,
                ssoName,
                (authnContext && authnContext->getAuthnContextClassRef()) ? authnContext->getAuthnContextClassRef()->getReference() : NULL,
                (authnContext && authnContext->getAuthnContextDeclRef()) ? authnContext->getAuthnContextDeclRef()->getReference() : NULL,
                &tokens,
                &resolvedAttributes
                )
            );

        if (ctx.get()) {
            // Copy over any new tokens, but leave them in the context for cleanup.
            tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());

            // Copy over new attributes, and transfer ownership.
            resolvedAttributes.insert(ctx->getResolvedAttributes().begin(), ctx->getResolvedAttributes().end());
            ctx->getResolvedAttributes().clear();
        }

        // Now merge in bad tokens for caching.
        tokens.insert(tokens.end(), badtokens.begin(), badtokens.end());

        string key = application.getServiceProvider().getSessionCache()->insert(
            sessionExp,
            application,
            httpRequest.getRemoteAddr().c_str(),
            issuerMetadata,
            samlconstants::SAML20P_NS,
            ssoName,
            ssoStatement->getAuthnInstant() ? ssoStatement->getAuthnInstant()->getRawData() : NULL,
            ssoStatement->getSessionIndex(),
            (authnContext && authnContext->getAuthnContextClassRef()) ? authnContext->getAuthnContextClassRef()->getReference() : NULL,
            (authnContext && authnContext->getAuthnContextDeclRef()) ? authnContext->getAuthnContextDeclRef()->getReference() : NULL,
            &tokens,
            &resolvedAttributes
            );

        if (ownedName)
            delete ssoName;
        for_each(ownedtokens.begin(), ownedtokens.end(), xmltooling::cleanup<saml2::Assertion>());
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        return key;
    }
    catch (exception&) {
        if (ownedName)
            delete ssoName;
        for_each(ownedtokens.begin(), ownedtokens.end(), xmltooling::cleanup<saml2::Assertion>());
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        throw;
    }
}

#endif
