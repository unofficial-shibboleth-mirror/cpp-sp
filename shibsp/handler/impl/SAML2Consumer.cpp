/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * handler/impl/SAML2Consumer.cpp
 *
 * SAML 2.0 assertion consumer service.
 */

#include "internal.h"
#include "handler/AssertionConsumerService.h"

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2Consumer : public AssertionConsumerService
    {
    public:
        SAML2Consumer(const DOMElement* e, const char* appId, bool deprecationSupport=true)
            : AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT ".SSO.SAML2"), nullptr, nullptr, deprecationSupport) {
        }
        virtual ~SAML2Consumer() {}
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2ConsumerFactory(const pair<const DOMElement*,const char*>& p, bool deprecationSupport)
    {
        return new SAML2Consumer(p.first, p.second, deprecationSupport);
    }
};

#ifndef SHIBSP_LITE

void SAML2Consumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    HTTPResponse& httpResponse,
    SecurityPolicy& policy,
    const PropertySet*,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of SAML 2.0 SSO profile(s).
    m_log.debug("processing message against SAML 2.0 SSO profile");

    // Remember whether we already established trust.
    // None of the SAML 2 bindings require security at the protocol layer.
    bool alreadySecured = policy.isAuthenticated();

    // Check for errors...this will throw if it's not a successful message.
    checkError(&xmlObject, policy.getIssuerMetadata());

    const Response* response = dynamic_cast<const Response*>(&xmlObject);
    if (!response)
        throw FatalProfileException("Incoming message was not a samlp:Response.");

    const vector<saml2::Assertion*>& assertions = response->getAssertions();
    const vector<saml2::EncryptedAssertion*>& encassertions = response->getEncryptedAssertions();
    if (assertions.empty() && encassertions.empty())
        throw FatalProfileException("Incoming message contained no SAML assertions.");

    // Maintain list of "legit" tokens to feed to SP subsystems.
    const Subject* ssoSubject=nullptr;
    const AuthnStatement* ssoStatement=nullptr;
    vector<const opensaml::Assertion*> tokens;

    // Also track "bad" tokens that we'll cache but not use.
    // This is necessary because there may be valid tokens not aimed at us.
    vector<const opensaml::Assertion*> badtokens;

    // And also track "owned" tokens that we decrypt here.
    vector< boost::shared_ptr<saml2::Assertion> > ownedtokens;

    // With this flag on, we block unauthenticated ciphertext when decrypting,
    // unless the protocol was authenticated.
    pair<bool,bool> requireAuthenticatedEncryption = application.getBool("requireAuthenticatedEncryption");
    if (alreadySecured)
        requireAuthenticatedEncryption.second = false;

    // With this flag on, we ignore any unsigned assertions.
    const EntityDescriptor* entity = nullptr;
    pair<bool,bool> requireSignedAssertions = make_pair(false,false);
    if (alreadySecured && policy.getIssuerMetadata()) {
        entity = dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent());
        const PropertySet* rp = application.getRelyingParty(entity);
        requireSignedAssertions = rp->getBool("requireSignedAssertions");
    }

    // authnskew allows rejection of SSO if AuthnInstant is too old.
    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,unsigned int> authnskew = sessionProps ? sessionProps->getUnsignedInt("maxTimeSinceAuthn") : pair<bool,unsigned int>(false,0);

    // Saves off error messages potentially helpful for users.
    string contextualError;

    // Ensure the Bearer rule is in the policy set.
    if (find_if(policy.getRules(), _rulenamed(BEARER_POLICY_RULE)) == nullptr)
        policy.getRules().push_back(m_ssoRule.get());

    // Populate recipient as audience.
    policy.getAudiences().push_back(application.getRelyingParty(entity)->getXMLString("entityID").second);

    time_t now = time(nullptr);
    for (indirect_iterator<vector<saml2::Assertion*>::const_iterator> a = make_indirect_iterator(assertions.begin());
            a != make_indirect_iterator(assertions.end()); ++a) {
        try {
            // Skip unsigned assertion?
            if (!a->getSignature() && requireSignedAssertions.first && requireSignedAssertions.second)
                throw SecurityPolicyException("The incoming assertion was unsigned, violating local security policy.");

            // We clear the security flag, so we can tell whether the token was secured on its own.
            policy.setAuthenticated(false);
            policy.reset(true);

            // Extract message bits and re-verify Issuer information.
            extractMessageDetails(*a, samlconstants::SAML20P_NS, policy);

            // Run the policy over the assertion. Handles replay, freshness, and
            // signature verification, assuming the relevant rules are configured,
            // along with condition and profile enforcement.
            policy.evaluate(*a, &httpRequest);

            // If no security is in place now, we kick it.
            if (!alreadySecured && !policy.isAuthenticated())
                throw SecurityPolicyException("Unable to establish security of incoming assertion.");

            // If we hadn't established Issuer yet, redo the signedAssertions check.
            if (!entity && policy.getIssuerMetadata()) {
                entity = dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent());
                requireSignedAssertions = application.getRelyingParty(entity)->getBool("requireSignedAssertions");
                if (!a->getSignature() && requireSignedAssertions.first && requireSignedAssertions.second)
                    throw SecurityPolicyException("The incoming assertion was unsigned, violating local security policy.");
            }

            // Address checking.
            SubjectConfirmationData* subcondata = dynamic_cast<SubjectConfirmationData*>(
                dynamic_cast<SAML2AssertionPolicy&>(policy).getSubjectConfirmation()->getSubjectConfirmationData()
                );
            if (subcondata && subcondata->getAddress()) {
                auto_ptr_char boundip(subcondata->getAddress());
                checkAddress(application, httpRequest, boundip.get());
            }

            // Track it as a valid token.
            tokens.push_back(&(*a));

            // Save off the first valid SSO statement, but favor the "soonest" session expiration.
            const vector<AuthnStatement*>& statements = const_cast<const saml2::Assertion&>(*a).getAuthnStatements();
            for (indirect_iterator<vector<AuthnStatement*>::const_iterator> s = make_indirect_iterator(statements.begin());
                    s != make_indirect_iterator(statements.end()); ++s) {
                if (s->getAuthnInstant() && s->getAuthnInstantEpoch() - XMLToolingConfig::getConfig().clock_skew_secs > now) {
                    contextualError = "The login time at your identity provider was future-dated.";
                }
                else if (authnskew.first && authnskew.second && s->getAuthnInstant() &&
                        s->getAuthnInstantEpoch() <= now && (now - s->getAuthnInstantEpoch() > authnskew.second)) {
                    contextualError = "The gap between now and the time you logged into your identity provider exceeds the allowed limit.";
                }
                else if (authnskew.first && authnskew.second && s->getAuthnInstant() == nullptr) {
                    contextualError = "Your identity provider did not supply a time of login, violating local policy.";
                }
                else if (!ssoStatement || s->getSessionNotOnOrAfterEpoch() < ssoStatement->getSessionNotOnOrAfterEpoch()) {
                    ssoStatement = &(*s);
                }
            }

            // Save off the first valid Subject, but favor an unencrypted NameID over anything else.
            if (!ssoSubject || (!ssoSubject->getNameID() && a->getSubject()->getNameID()))
                ssoSubject = a->getSubject();
        }
        catch (std::exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            if (!ssoStatement)
                contextualError = ex.what();
            badtokens.push_back(&(*a));
        }
    }

    // In case we need decryption...
    CredentialResolver* cr = application.getCredentialResolver();
    if (!cr && !encassertions.empty())
        m_log.warn("found encrypted assertions, but no CredentialResolver was available");

    for (indirect_iterator<vector<saml2::EncryptedAssertion*>::const_iterator> ea = make_indirect_iterator(encassertions.begin());
            ea != make_indirect_iterator(encassertions.end()); ++ea) {
        // Attempt to decrypt it.
        boost::shared_ptr<saml2::Assertion> decrypted;
        try {
            Locker credlocker(cr);
            scoped_ptr<MetadataCredentialCriteria> mcc(
                policy.getIssuerMetadata() ? new MetadataCredentialCriteria(*policy.getIssuerMetadata()) : nullptr
                );
            boost::shared_ptr<XMLObject> wrapper(
                ea->decrypt(
                    *cr,
                    application.getRelyingParty(entity)->getXMLString("entityID").second,
                    mcc.get(),
                    requireAuthenticatedEncryption.first && requireAuthenticatedEncryption.second
                    )
                );
            decrypted = dynamic_pointer_cast<saml2::Assertion>(wrapper);
            if (decrypted) {
                ownedtokens.push_back(decrypted);
                if (m_log.isDebugEnabled())
                    m_log.debugStream() << "decrypted Assertion: " << *decrypted << logging::eol;
            }
        }
        catch (std::exception& ex) {
            m_log.error("failed to decrypt assertion: %s", ex.what());
        }
        if (!decrypted)
            continue;

        try {
            // Skip unsigned assertion?
            if (!decrypted->getSignature() && requireSignedAssertions.first && requireSignedAssertions.second)
                throw SecurityPolicyException("The incoming assertion was unsigned, violating local security policy.");

            // Run the schema validators against the assertion, since it was hidden by encryption.
            SchemaValidators.validate(decrypted.get());

            // We clear the security flag, so we can tell whether the token was secured on its own.
            policy.setAuthenticated(false);
            policy.reset(true);

            // Extract message bits and re-verify Issuer information.
            extractMessageDetails(*decrypted, samlconstants::SAML20P_NS, policy);

            // Run the policy over the assertion. Handles replay, freshness, and
            // signature verification, assuming the relevant rules are configured,
            // along with condition and profile enforcement.
            // We have to marshall the object first to ensure signatures can be checked.
            if (!decrypted->getDOM())
                decrypted->marshall();
            policy.evaluate(*decrypted, &httpRequest);

            // If no security is in place now, we kick it.
            if (!alreadySecured && !policy.isAuthenticated())
                throw SecurityPolicyException("Unable to establish security of incoming assertion.");

            // If we hadn't established Issuer yet, redo the signedAssertions check.
            if (!entity && policy.getIssuerMetadata()) {
                entity = dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent());
                requireSignedAssertions = application.getRelyingParty(entity)->getBool("requireSignedAssertions");
                if (!decrypted->getSignature() && requireSignedAssertions.first && requireSignedAssertions.second)
                    throw SecurityPolicyException("The decrypted assertion was unsigned, violating local security policy.");
            }

            // Address checking.
            SubjectConfirmationData* subcondata = dynamic_cast<SubjectConfirmationData*>(
                dynamic_cast<SAML2AssertionPolicy&>(policy).getSubjectConfirmation()->getSubjectConfirmationData()
                );
            if (subcondata && subcondata->getAddress()) {
                auto_ptr_char boundip(subcondata->getAddress());
                checkAddress(application, httpRequest, boundip.get());
            }

            // Track it as a valid token.
            tokens.push_back(decrypted.get());

            // Save off the first valid SSO statement, but favor the "soonest" session expiration.
            const vector<AuthnStatement*>& statements = const_cast<const saml2::Assertion*>(decrypted.get())->getAuthnStatements();
            for (indirect_iterator<vector<AuthnStatement*>::const_iterator> s = make_indirect_iterator(statements.begin());
                    s != make_indirect_iterator(statements.end()); ++s) {
                if (authnskew.first && authnskew.second && s->getAuthnInstant() && (now - s->getAuthnInstantEpoch() > authnskew.second))
                    contextualError = "The gap between now and the time you logged into your identity provider exceeds the limit.";
                else if (!ssoStatement || s->getSessionNotOnOrAfterEpoch() < ssoStatement->getSessionNotOnOrAfterEpoch())
                    ssoStatement = &(*s);
            }

            // Save off the first valid Subject, but favor an unencrypted NameID over anything else.
            if (!ssoSubject || (!ssoSubject->getNameID() && decrypted->getSubject()->getNameID()))
                ssoSubject = decrypted->getSubject();
        }
        catch (std::exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            if (!ssoStatement)
                contextualError = ex.what();
            badtokens.push_back(decrypted.get());
        }
    }

    if (!ssoStatement) {
        if (contextualError.empty())
            throw FatalProfileException("A valid authentication statement was not found in the incoming message.");
        throw FatalProfileException(contextualError.c_str());
    }

    // May need to decrypt NameID.
    scoped_ptr<XMLObject> decryptedID;
    NameID* ssoName = ssoSubject->getNameID();
    if (!ssoName) {
        EncryptedID* encname = ssoSubject->getEncryptedID();
        if (encname) {
            if (!cr)
                m_log.warn("found encrypted NameID, but no decryption credential was available");
            else {
                Locker credlocker(cr);
                scoped_ptr<MetadataCredentialCriteria> mcc(
                    policy.getIssuerMetadata() ? new MetadataCredentialCriteria(*policy.getIssuerMetadata()) : nullptr
                    );
                try {
                    decryptedID.reset(encname->decrypt(*cr, application.getRelyingParty(entity)->getXMLString("entityID").second, mcc.get()));
                    ssoName = dynamic_cast<NameID*>(decryptedID.get());
                    if (ssoName) {
                        if (m_log.isDebugEnabled())
                            m_log.debugStream() << "decrypted NameID: " << *ssoName << logging::eol;
                    }
                }
                catch (std::exception& ex) {
                    m_log.error("failed to decrypt NameID: %s", ex.what());
                }
            }
        }
    }

    m_log.debug("SSO profile processing completed successfully");

    // We've successfully "accepted" at least one SSO token, along with any additional valid tokens.
    // To complete processing, we need to extract and resolve attributes and then create the session.

    // Now we have to extract the authentication details for session setup.

    // Session expiration for SAML 2.0 is jointly IdP- and SP-driven.
    time_t sessionExp = ssoStatement->getSessionNotOnOrAfter() ?
        (ssoStatement->getSessionNotOnOrAfterEpoch() + XMLToolingConfig::getConfig().clock_skew_secs) : 0;
    pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
    if (!lifetime.first || lifetime.second == 0)
        lifetime.second = 28800;
    if (sessionExp == 0)
        sessionExp = now + lifetime.second;     // IdP says nothing, calulate based on SP.
    else
        sessionExp = min(sessionExp, now + lifetime.second);    // Use the lowest.

    const AuthnContext* authnContext = ssoStatement->getAuthnContext();

    // The context will handle deleting attributes and new tokens.
    scoped_ptr<ResolutionContext> ctx(
        resolveAttributes(
            application,
            &httpRequest,
            policy.getIssuerMetadata(),
            samlconstants::SAML20P_NS,
            response,
            nullptr,
            nullptr,
            ssoName,
            ssoStatement,
            (authnContext && authnContext->getAuthnContextClassRef()) ? authnContext->getAuthnContextClassRef()->getReference() : nullptr,
            (authnContext && authnContext->getAuthnContextDeclRef()) ? authnContext->getAuthnContextDeclRef()->getReference() : nullptr,
            &tokens
            )
        );

    if (ctx) {
        // Copy over any new tokens, but leave them in the context for cleanup.
        tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
    }

    // Now merge in bad tokens for caching.
    tokens.insert(tokens.end(), badtokens.begin(), badtokens.end());

    string session_id;
    application.getServiceProvider().getSessionCache()->insert(
        session_id,
        application,
        httpRequest,
        httpResponse,
        sessionExp,
        entity,
        samlconstants::SAML20P_NS,
        ssoName,
        ssoStatement->getAuthnInstant() ? ssoStatement->getAuthnInstant()->getRawData() : nullptr,
        ssoStatement->getSessionIndex(),
        (authnContext && authnContext->getAuthnContextClassRef()) ? authnContext->getAuthnContextClassRef()->getReference() : nullptr,
        (authnContext && authnContext->getAuthnContextDeclRef()) ? authnContext->getAuthnContextDeclRef()->getReference() : nullptr,
        &tokens,
        ctx ? &ctx->getResolvedAttributes() : nullptr
        );
}

#endif
