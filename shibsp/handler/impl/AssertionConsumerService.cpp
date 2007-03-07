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
 * AssertionConsumerService.cpp
 * 
 * Base class for handlers that create sessions by consuming SSO protocol responses. 
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"
#include "handler/AssertionConsumerService.h"
#include "util/SPConstants.h"

#include <saml/SAMLConfig.h>
#include <saml/binding/URLEncoder.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/util/CommonDomainCookie.h>

using namespace shibspconstants;
using namespace samlconstants;
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

AssertionConsumerService::AssertionConsumerService(const DOMElement* e, Category& log)
    : AbstractHandler(e, log), m_configNS(SHIB2SPCONFIG_NS),
        m_role(samlconstants::SAML20MD_NS, opensaml::saml2md::IDPSSODescriptor::LOCAL_NAME)
{
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
        m_decoder = SAMLConfig::getConfig().MessageDecoderManager.newPlugin(getString("Binding").second,e);
}

AssertionConsumerService::~AssertionConsumerService()
{
    delete m_decoder;
}

pair<bool,long> AssertionConsumerService::run(SPRequest& request, bool isHandler) const
{
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        string relayState, providerId;
        string key = processMessage(request.getApplication(), request, providerId, relayState);
        return sendRedirect(request, key.c_str(), providerId.c_str(), relayState.c_str());
    }
    else {
        DDF in = wrap(request);
        DDFJanitor jin(in);
        in.addmember("application_id").string(request.getApplication().getId());
        DDF out=request.getServiceProvider().getListenerService()->send(in);
        DDFJanitor jout(out);
        if (!out["key"].isstring())
            throw FatalProfileException("Remote processing of SAML 1.x Browser profile did not return a usable session key.");
        return sendRedirect(request, out["key"].string(), out["provider_id"].string(), out["RelayState"].string());
    }
}

void AssertionConsumerService::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for new session", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }
    
    // Unpack the request.
    auto_ptr<HTTPRequest> http(getRequest(in));
    
    // Do the work.
    string relayState, providerId;
    string key = processMessage(*app, *http.get(), providerId, relayState);
    
    // Repack for return to caller.
    DDF ret=DDF(NULL).structure();
    DDFJanitor jret(ret);
    ret.addmember("key").string(key.c_str());
    if (!providerId.empty())
        ret.addmember("provider_id").string(providerId.c_str());
    if (!relayState.empty())
        ret.addmember("RelayState").string(relayState.c_str());
    out << ret;
}

string AssertionConsumerService::processMessage(
    const Application& application, const HTTPRequest& httpRequest, string& providerId, string& relayState
    ) const
{
    // Locate policy key.
    pair<bool,const char*> policyId = getString("policyId", m_configNS.get());  // namespace-qualified if inside handler element
    if (!policyId.first)
        policyId = application.getString("policyId");   // unqualified in Application(s) element
        
    // Access policy properties.
    const PropertySet* settings = application.getServiceProvider().getPolicySettings(policyId.second);
    pair<bool,bool> validate = settings->getBool("validate");

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    SecurityPolicy policy(
        application.getServiceProvider().getPolicyRules(policyId.second), 
        application.getMetadataProvider(),
        &m_role,
        application.getTrustEngine(),
        validate.first && validate.second
        );
    
    // Decode the message and process it in a protocol-specific way.
    auto_ptr<XMLObject> msg(m_decoder->decode(relayState, httpRequest, policy));
    string key = implementProtocol(application, httpRequest, policy, settings, *msg.get());

    auto_ptr_char issuer(policy.getIssuer() ? policy.getIssuer()->getName() : NULL);
    if (issuer.get())
        providerId = issuer.get();
    
    return key;
}

pair<bool,long> AssertionConsumerService::sendRedirect(
    SPRequest& request, const char* key, const char* providerId, const char* relayState
    ) const
{
    string s,k(key);
    
    if (relayState && !strcmp(relayState,"default")) {
        pair<bool,const char*> homeURL=request.getApplication().getString("homeURL");
        relayState=homeURL.first ? homeURL.second : "/";
    }
    else if (!relayState || !strcmp(relayState,"cookie")) {
        // Pull the value from the "relay state" cookie.
        pair<string,const char*> relay_cookie = request.getApplication().getCookieNameProps("_shibstate_");
        relayState = request.getCookie(relay_cookie.first.c_str());
        if (!relayState || !*relayState) {
            // No apparent relay state value to use, so fall back on the default.
            pair<bool,const char*> homeURL=request.getApplication().getString("homeURL");
            relayState=homeURL.first ? homeURL.second : "/";
        }
        else {
            char* rscopy=strdup(relayState);
            SAMLConfig::getConfig().getURLEncoder()->decode(rscopy);
            s=rscopy;
            free(rscopy);
            relayState=s.c_str();
        }
        request.setCookie(relay_cookie.first.c_str(),relay_cookie.second);
    }

    // We've got a good session, so set the session cookie.
    pair<string,const char*> shib_cookie=request.getApplication().getCookieNameProps("_shibsession_");
    k += shib_cookie.second;
    request.setCookie(shib_cookie.first.c_str(), k.c_str());

    // History cookie.
    maintainHistory(request, providerId, shib_cookie.second);

    // Now redirect to the target.
    return make_pair(true, request.sendRedirect(relayState));
}

void AssertionConsumerService::checkAddress(
    const Application& application, const HTTPRequest& httpRequest, const char* issuedTo
    ) const
{
    const PropertySet* props=application.getPropertySet("Sessions");
    pair<bool,bool> checkAddress = props ? props->getBool("checkAddress") : make_pair(false,true);
    if (!checkAddress.first)
        checkAddress.second=true;

    if (checkAddress.second) {
        m_log.debug("checking client address");
        if (httpRequest.getRemoteAddr() != issuedTo) {
            throw FatalProfileException(
               "Your client's current address ($client_addr) differs from the one used when you authenticated "
                "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                "Please contact your local support staff or help desk for assistance.",
                namedparams(1,"client_addr",httpRequest.getRemoteAddr().c_str())
                );
        }
    }
}

ResolutionContext* AssertionConsumerService::resolveAttributes(
    const Application& application,
    const HTTPRequest& httpRequest,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const vector<const Assertion*>* tokens
    ) const
{
    AttributeResolver* resolver = application.getAttributeResolver();
    if (!resolver) {
        m_log.info("no AttributeResolver available, skipping resolution");
        return NULL;
    }
    
    try {
        m_log.debug("resolving attributes...");
        auto_ptr<ResolutionContext> ctx(
            resolver->createResolutionContext(application, httpRequest.getRemoteAddr().c_str(), issuer, nameid, tokens)
            );
        resolver->resolveAttributes(*ctx.get());
        return ctx.release();
    }
    catch (exception& ex) {
        m_log.error("attribute resolution failed: %s", ex.what());
    }
    
    return NULL;
}

void AssertionConsumerService::maintainHistory(SPRequest& request, const char* providerId, const char* cookieProps) const
{
    if (!providerId)
        return;
        
    const PropertySet* sessionProps=request.getApplication().getPropertySet("Sessions");
    pair<bool,bool> idpHistory=sessionProps->getBool("idpHistory");
    if (!idpHistory.first || idpHistory.second) {
        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(request.getCookie(CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days=sessionProps->getUnsignedInt("idpHistoryDays");
        if (!days.first || days.second==0) {
            string c = string(cdc.set(providerId)) + cookieProps;
            request.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
        else {
            time_t now=time(NULL) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
            struct tm res;
            struct tm* ptime=gmtime_r(&now,&res);
#else
            struct tm* ptime=gmtime(&now);
#endif
            char timebuf[64];
            strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT",ptime);
            string c = string(cdc.set(providerId)) + cookieProps + "; expires=" + timebuf;
            request.setCookie(CommonDomainCookie::CDCName, c.c_str());
        }
    }
}
