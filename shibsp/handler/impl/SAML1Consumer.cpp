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
 * SAML1Consumer.cpp
 *
 * SAML 1.x assertion consumer service.
 */

#include "internal.h"
#include "handler/AssertionConsumerService.h"

#ifndef SHIBSP_LITE
# include "Application.h"
# include "ServiceProvider.h"
# include "SessionCache.h"
# include "attribute/resolver/ResolutionContext.h"
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/binding/SecurityPolicy.h>
# include <saml/binding/SecurityPolicyRule.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml1/core/Protocols.h>
# include <saml/saml2/metadata/Metadata.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/io/HTTPRequest.h>
# include <xmltooling/util/DateTime.h>
using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml;
using saml2::NameID;
using saml2::NameIDBuilder;
using saml2md::EntityDescriptor;
using saml2md::SPSSODescriptor;
using saml2md::MetadataException;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML1Consumer : public AssertionConsumerService
    {
    public:
        SAML1Consumer(const DOMElement* e, const char* appId)
            : AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".SSO.SAML1")) {
#ifndef SHIBSP_LITE
            m_ssoRule = nullptr;
            m_post = XMLString::equals(getString("Binding").second, samlconstants::SAML1_PROFILE_BROWSER_POST);
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
                m_ssoRule = SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(SAML1BROWSERSSO_POLICY_RULE, e);
#endif
        }
        virtual ~SAML1Consumer() {
#ifndef SHIBSP_LITE
            delete m_ssoRule;
#endif
        }

#ifndef SHIBSP_LITE
        void generateMetadata(SPSSODescriptor& role, const char* handlerURL) const {
            AssertionConsumerService::generateMetadata(role, handlerURL);
            role.addSupport(samlconstants::SAML11_PROTOCOL_ENUM);
            role.addSupport(samlconstants::SAML10_PROTOCOL_ENUM);
        }

    private:
        void implementProtocol(
            const Application& application,
            const HTTPRequest& httpRequest,
            HTTPResponse& httpResponse,
            SecurityPolicy& policy,
            const PropertySet*,
            const XMLObject& xmlObject
            ) const;

        bool m_post;
        SecurityPolicyRule* m_ssoRule;
#else
        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML11_PROTOCOL_ENUM;
        }
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML1ConsumerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML1Consumer(p.first, p.second);
    }

#ifndef SHIBSP_LITE
    class SHIBSP_DLLLOCAL _rulenamed : std::unary_function<const SecurityPolicyRule*,bool>
    {
    public:
        _rulenamed(const char* name) : m_name(name) {}
        bool operator()(const SecurityPolicyRule* rule) const {
            return rule ? !strcmp(m_name, rule->getType()) : false;
        }
    private:
        const char* m_name;
    };
#endif
};

#ifndef SHIBSP_LITE

void SAML1Consumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    HTTPResponse& httpResponse,
    SecurityPolicy& policy,
    const PropertySet*,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of SAML 1.x SSO profile(s).
    m_log.debug("processing message against SAML 1.x SSO profile");

    // Check for errors...this will throw if it's not a successful message.
    checkError(&xmlObject);

    // With the binding aspects now moved out to the MessageDecoder,
    // the focus here is on the assertion content. For SAML 1.x POST,
    // all the security comes from the protocol layer, and signing
    // the assertion isn't sufficient. So we can check the policy
    // object now and bail if it's not a secured message.
    if (m_post && !policy.isAuthenticated()) {
        if (policy.getIssuer() && !policy.getIssuerMetadata())
            throw MetadataException("Security of SAML 1.x SSO POST response not established.");
        throw SecurityPolicyException("Security of SAML 1.x SSO POST response not established.");
    }

    // Remember whether we already established trust.
    bool alreadySecured = policy.isAuthenticated();

    const Response* response = dynamic_cast<const Response*>(&xmlObject);
    if (!response)
        throw FatalProfileException("Incoming message was not a samlp:Response.");

    const vector<saml1::Assertion*>& assertions = response->getAssertions();
    if (assertions.empty())
        throw FatalProfileException("Incoming message contained no SAML assertions.");

    pair<bool,int> minor = response->getMinorVersion();

    // Maintain list of "legit" tokens to feed to SP subsystems.
    const AuthenticationStatement* ssoStatement=nullptr;
    vector<const opensaml::Assertion*> tokens;

    // Also track "bad" tokens that we'll cache but not use.
    // This is necessary because there may be valid tokens not aimed at us.
    vector<const opensaml::Assertion*> badtokens;

    // With this flag on, we ignore any unsigned assertions.
    const EntityDescriptor* entity = policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : nullptr;
    pair<bool,bool> flag = application.getRelyingParty(entity)->getBool("requireSignedAssertions");

    // authnskew allows rejection of SSO if AuthnInstant is too old.
    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,unsigned int> authnskew = sessionProps ? sessionProps->getUnsignedInt("maxTimeSinceAuthn") : pair<bool,unsigned int>(false,0);

    // Saves off error messages potentially helpful for users.
    string contextualError;

    // Ensure the BrowserSSO rule is in the policy set.
    if (find_if(policy.getRules(), _rulenamed(SAML1BROWSERSSO_POLICY_RULE)) == nullptr)
        policy.getRules().push_back(m_ssoRule);

    // Populate recipient as audience.
    policy.getAudiences().push_back(application.getRelyingParty(entity)->getXMLString("entityID").second);

    time_t now = time(nullptr);
    for (vector<saml1::Assertion*>::const_iterator a = assertions.begin(); a!=assertions.end(); ++a) {
        try {
            // Skip unsigned assertion?
            if (!(*a)->getSignature() && flag.first && flag.second)
                throw SecurityPolicyException("The incoming assertion was unsigned, violating local security policy.");

            // We clear the security flag, so we can tell whether the token was secured on its own.
            policy.setAuthenticated(false);
            policy.reset(true);

            // Extract message bits and re-verify Issuer information.
            extractMessageDetails(
                *(*a),
                (minor.first && minor.second==0) ? samlconstants::SAML10_PROTOCOL_ENUM : samlconstants::SAML11_PROTOCOL_ENUM, policy
                );

            // Run the policy over the assertion. Handles replay, freshness, and
            // signature verification, assuming the relevant rules are configured,
            // along with condition and profile enforcement.
            policy.evaluate(*(*a), &httpRequest);

            // If no security is in place now, we kick it.
            if (!alreadySecured && !policy.isAuthenticated())
                throw SecurityPolicyException("Unable to establish security of incoming assertion.");

            // Track it as a valid token.
            tokens.push_back(*a);

            // Save off the first valid SSO statement.
            const vector<AuthenticationStatement*>& statements =
                    const_cast<const saml1::Assertion*>(*a)->getAuthenticationStatements();
            for (vector<AuthenticationStatement*>::const_iterator s = statements.begin(); s!=statements.end(); ++s) {
                if ((*s)->getAuthenticationInstant() &&
                        (*s)->getAuthenticationInstantEpoch() - XMLToolingConfig::getConfig().clock_skew_secs > now) {
                    contextualError = "The login time at your identity provider was future-dated.";
                }
                else if (authnskew.first && authnskew.second && (*s)->getAuthenticationInstant() &&
                        (*s)->getAuthenticationInstantEpoch() <= now && (now - (*s)->getAuthenticationInstantEpoch() > authnskew.second)) {
                    contextualError = "The gap between now and the time you logged into your identity provider exceeds the allowed limit.";
                }
                else if (authnskew.first && authnskew.second && (*s)->getAuthenticationInstant() == nullptr) {
                    contextualError = "Your identity provider did not supply a time of login, violating local policy.";
                }
                else if (!ssoStatement) {
                    ssoStatement = *s;
                    break;
                }
            }
        }
        catch (exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            if (!ssoStatement)
                contextualError = ex.what();
            badtokens.push_back(*a);
        }
    }

    if (!ssoStatement) {
        if (contextualError.empty())
            throw FatalProfileException("A valid authentication statement was not found in the incoming message.");
        throw FatalProfileException(contextualError.c_str());
    }

    // Address checking.
    SubjectLocality* locality = ssoStatement->getSubjectLocality();
    if (locality && locality->getIPAddress()) {
        auto_ptr_char ip(locality->getIPAddress());
        checkAddress(application, httpRequest, ip.get());
    }

    m_log.debug("SSO profile processing completed successfully");

    NameIdentifier* n = ssoStatement->getSubject()->getNameIdentifier();

    // Now we have to extract the authentication details for attribute and session setup.

    // Session expiration for SAML 1.x is purely SP-driven, and the method is mapped to a ctx class.
    pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
    if (!lifetime.first || lifetime.second == 0)
        lifetime.second = 28800;

    // We've successfully "accepted" at least one SSO token, along with any additional valid tokens.
    // To complete processing, we need to extract and resolve attributes and then create the session.

    // Normalize the SAML 1.x NameIdentifier...
    auto_ptr<NameID> nameid(n ? NameIDBuilder::buildNameID() : nullptr);
    if (n) {
        nameid->setName(n->getName());
        nameid->setFormat(n->getFormat());
        nameid->setNameQualifier(n->getNameQualifier());
    }

    // The context will handle deleting attributes and new tokens.
    auto_ptr<ResolutionContext> ctx(
        resolveAttributes(
            application,
            policy.getIssuerMetadata(),
            (!response->getMinorVersion().first || response->getMinorVersion().second==1) ?
                samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM,
            n,
            nameid.get(),
            ssoStatement->getAuthenticationMethod(),
            nullptr,
            &tokens
            )
        );

    if (ctx.get()) {
        // Copy over any new tokens, but leave them in the context for cleanup.
        tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
    }

    // Now merge in bad tokens for caching.
    tokens.insert(tokens.end(), badtokens.begin(), badtokens.end());

    application.getServiceProvider().getSessionCache()->insert(
        application,
        httpRequest,
        httpResponse,
        now + lifetime.second,
        entity,
        (!response->getMinorVersion().first || response->getMinorVersion().second==1) ?
            samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM,
        nameid.get(),
        ssoStatement->getAuthenticationInstant() ? ssoStatement->getAuthenticationInstant()->getRawData() : nullptr,
        nullptr,
        ssoStatement->getAuthenticationMethod(),
        nullptr,
        &tokens,
        ctx.get() ? &ctx->getResolvedAttributes() : nullptr
        );
}

#endif
