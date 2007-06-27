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
 * SAML1Consumer.cpp
 * 
 * SAML 1.x assertion consumer service 
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
# include <saml/saml1/core/Assertions.h>
# include <saml/saml1/core/Protocols.h>
# include <saml/saml1/profile/BrowserSSOProfileValidator.h>
# include <saml/saml2/metadata/Metadata.h>
using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml;
using saml2::NameID;
using saml2::NameIDBuilder;
using saml2md::EntityDescriptor;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace log4cpp;
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
                : AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".SAML1SSO")) {
#ifndef SHIBSP_LITE
            m_post = XMLString::equals(getString("Binding").second, samlconstants::SAML1_PROFILE_BROWSER_POST);
#endif
        }
        virtual ~SAML1Consumer() {}
        
    private:
#ifndef SHIBSP_LITE
        string implementProtocol(
            const Application& application,
            const HTTPRequest& httpRequest,
            SecurityPolicy& policy,
            const PropertySet* settings,
            const XMLObject& xmlObject
            ) const;
        bool m_post;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML1ConsumerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML1Consumer(p.first, p.second);
    }
    
};

#ifndef SHIBSP_LITE

string SAML1Consumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    SecurityPolicy& policy,
    const PropertySet* settings,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of SAML 1.x SSO profile(s).
    m_log.debug("processing message against SAML 1.x SSO profile");

    // With the binding aspects now moved out to the MessageDecoder,
    // the focus here is on the assertion content. For SAML 1.x POST,
    // all the security comes from the protocol layer, and signing
    // the assertion isn't sufficient. So we can check the policy
    // object now and bail if it's not a secure message.
    if (m_post && !policy.isSecure())
        throw SecurityPolicyException("Security of SAML 1.x SSO POST response not established.");
        
    // Remember whether we already established trust.
    bool alreadySecured = policy.isSecure();

    // Check for errors...this will throw if it's not a successful message.
    checkError(&xmlObject);

    const Response* response = dynamic_cast<const Response*>(&xmlObject);
    if (!response)
        throw FatalProfileException("Incoming message was not a samlp:Response.");

    const vector<saml1::Assertion*>& assertions = response->getAssertions();
    if (assertions.empty())
        throw FatalProfileException("Incoming message contained no SAML assertions.");

    // Maintain list of "legit" tokens to feed to SP subsystems.
    const AuthenticationStatement* ssoStatement=NULL;
    vector<const opensaml::Assertion*> tokens;

    // Also track "bad" tokens that we'll cache but not use.
    // This is necessary because there may be valid tokens not aimed at us.
    vector<const opensaml::Assertion*> badtokens;

    // Profile validator.
    time_t now = time(NULL);
    BrowserSSOProfileValidator ssoValidator(application.getAudiences(), now);

    // With this flag on, we ignore any unsigned assertions.
    pair<bool,bool> flag = settings->getBool("signedAssertions");

    for (vector<saml1::Assertion*>::const_iterator a = assertions.begin(); a!=assertions.end(); ++a) {
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

            // Track it as a valid token.
            tokens.push_back(*a);

            // Save off the first valid SSO statement.
            if (!ssoStatement && !(*a)->getAuthenticationStatements().empty())
                ssoStatement = (*a)->getAuthenticationStatements().front();
        }
        catch (exception& ex) {
            m_log.warn("detected a problem with assertion: %s", ex.what());
            badtokens.push_back(*a);
        }
    }

    if (!ssoStatement)
        throw FatalProfileException("A valid authentication statement was not found in the incoming message.");

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
    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
    if (!lifetime.first || lifetime.second == 0)
        lifetime.second = 28800;
    auto_ptr_char authnInstant(
        ssoStatement->getAuthenticationInstant() ? ssoStatement->getAuthenticationInstant()->getRawData() : NULL
        );
    auto_ptr_char authnMethod(ssoStatement->getAuthenticationMethod());

    // We've successfully "accepted" at least one SSO token, along with any additional valid tokens.
    // To complete processing, we need to extract and resolve attributes and then create the session.
    multimap<string,Attribute*> resolvedAttributes;
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        m_log.debug("extracting pushed attributes...");
        Locker extlocker(extractor);
        if (n) {
            try {
                extractor->extractAttributes(application, policy.getIssuerMetadata(), *n, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }
        for (vector<const opensaml::Assertion*>::const_iterator t = tokens.begin(); t!=tokens.end(); ++t) {
            try {
                extractor->extractAttributes(application, policy.getIssuerMetadata(), *(*t), resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter && !resolvedAttributes.empty()) {
            BasicFilteringContext fc(application, resolvedAttributes, policy.getIssuerMetadata(), authnMethod.get());
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
    }

    // Normalize the SAML 1.x NameIdentifier...
    auto_ptr<NameID> nameid(n ? NameIDBuilder::buildNameID() : NULL);
    if (n) {
        nameid->setName(n->getName());
        nameid->setFormat(n->getFormat());
        nameid->setNameQualifier(n->getNameQualifier());
    }

    const EntityDescriptor* issuerMetadata =
        policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;
    auto_ptr<ResolutionContext> ctx(
        resolveAttributes(application, issuerMetadata, nameid.get(), authnMethod.get(), NULL, &tokens, &resolvedAttributes)
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

    try {
        string key = application.getServiceProvider().getSessionCache()->insert(
            now + lifetime.second,
            application,
            httpRequest.getRemoteAddr().c_str(),
            issuerMetadata,
            nameid.get(),
            authnInstant.get(),
            NULL,
            authnMethod.get(),
            NULL,
            &tokens,
            &resolvedAttributes
            );
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        return key;
    }
    catch (exception&) {
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        throw;
    }
}

#endif
