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
 * Shib1SessionInitiator.cpp
 *
 * Shibboleth 1.x AuthnRequest support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include "metadata/MetadataProviderCriteria.h"
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/util/SAMLConstants.h>
#else
# include "lite/SAMLConstants.h"
#endif
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Shib1SessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        Shib1SessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Shib1"), nullptr, &m_remapper), m_appId(appId) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::Shib1SI";
                setAddress(address.c_str());
            }
        }
        virtual ~Shib1SessionInitiator() {}

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> unwrap(SPRequest& request, DDF& out) const;
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML11_PROTOCOL_ENUM;
        }

    private:
        pair<bool,long> doRequest(
            const Application& application,
            const HTTPRequest* httpRequest,
            HTTPResponse& httpResponse,
            const char* entityID,
            const char* acsLocation,
            bool artifact,
            string& relayState
            ) const;
        string m_appId;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL Shib1SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new Shib1SessionInitiator(p.first, p.second);
    }

};

void Shib1SessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::Shib1SI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Shib1 SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> Shib1SessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (entityID.empty() || !checkCompatibility(request, isHandler))
        return make_pair(false,0L);

    string target;
    pair<bool,const char*> prop;
    const Handler* ACS=nullptr;
    const Application& app = request.getApplication();

    if (isHandler) {
        prop.second = request.getParameter("acsIndex");
        if (prop.second && *prop.second) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(prop.second));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using acsIndex property");
        }

        prop = getString("target", request);
        if (prop.first)
            target = prop.second;

        // Since we're passing the ACS by value, we need to compute the return URL,
        // so we'll need the target resource for real.
        recoverRelayState(app, request, request, target, false);
        limitRelayState(m_log, app, request, target.c_str());
    }
    else {
        // Check for a hardwired target value in the map or handler.
        prop = getString("target", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (prop.first)
            target = prop.second;
        else
            target = request.getRequestURL();
    }

    if (!ACS) {
        // Try fixed index property.
        pair<bool,unsigned int> index = getUnsignedInt("acsIndex", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (index.first)
            ACS = app.getAssertionConsumerServiceByIndex(index.second);
    }

    // If we picked by index, validate the ACS for use with this protocol.
    if (!ACS || !XMLString::equals(getProtocolFamily(), ACS->getProtocolFamily())) {
        if (ACS)
            request.log(SPRequest::SPWarn, "invalid acsIndex property, or non-SAML 1.x ACS, using default SAML 1.x ACS");
        ACS = app.getAssertionConsumerServiceByProtocol(getProtocolFamily());
        if (!ACS)
            throw ConfigurationException("Unable to locate a SAML 1.x ACS endpoint to use for response.");
    }

    // Since we're not passing by index, we need to fully compute the return URL.
    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc = request.getHandlerURL(target.c_str());
    prop = ACS->getString("Location");
    if (prop.first)
        ACSloc += prop.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but we've turned it back into a resource by this point, so if there's
        // a target on the URL, reset to that value.
        prop.second = request.getParameter("target");
        if (prop.second && *prop.second)
            target = prop.second;
    }

    // Is the in-bound binding artifact?
    bool artifactInbound = XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT);

    m_log.debug("attempting to initiate session using Shibboleth with provider (%s)", entityID.c_str());

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Out of process means the POST data via the request can be exposed directly to the private method.
        // The method will handle POST preservation if necessary *before* issuing the response, but only if
        // it dispatches to an IdP.
        return doRequest(app, &request, request, entityID.c_str(), ACSloc.c_str(), artifactInbound, target);
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    in.addmember("entity_id").string(entityID.c_str());
    in.addmember("acsLocation").string(ACSloc.c_str());
    if (artifactInbound)
        in.addmember("artifact").integer(1);
    if (!target.empty())
        in.addmember("RelayState").unsafe_string(target.c_str());

    // Remote the processing. Our unwrap method will handle POST data if necessary.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

pair<bool,long> Shib1SessionInitiator::unwrap(SPRequest& request, DDF& out) const
{
    // See if there's any response to send back.
    if (!out["redirect"].isnull() || !out["response"].isnull()) {
        // If so, we're responsible for handling the POST data, probably by dropping a cookie.
        preservePostData(request.getApplication(), request, request, out["RelayState"].string());
    }
    return RemotedHandler::unwrap(request, out);
}

void Shib1SessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    const char* acsLocation = in["acsLocation"].string();
    if (!entityID || !acsLocation)
        throw ConfigurationException("No entityID or acsLocation parameter supplied to remoted SessionInitiator.");

    DDF ret(nullptr);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    auto_ptr<HTTPResponse> http(getResponse(ret));

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, nullptr, *http.get(), entityID, acsLocation, (in["artifact"].integer() != 0), relayState);
    if (!ret.isstruct())
        ret.structure();
    ret.addmember("RelayState").unsafe_string(relayState.c_str());
    out << ret;
}

pair<bool,long> Shib1SessionInitiator::doRequest(
    const Application& app,
    const HTTPRequest* httpRequest,
    HTTPResponse& httpResponse,
    const char* entityID,
    const char* acsLocation,
    bool artifact,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    // Use metadata to invoke the SSO service directly.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    MetadataProviderCriteria mc(app, entityID, &IDPSSODescriptor::ELEMENT_QNAME, shibspconstants::SHIB1_PROTOCOL_ENUM);
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
    if (!entity.first) {
        m_log.warn("unable to locate metadata for provider (%s)", entityID);
        throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    else if (!entity.second) {
        m_log.log(getParent() ? Priority::INFO : Priority::WARN, "unable to locate Shibboleth-aware identity provider role for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate Shibboleth-aware identity provider role for provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    else if (artifact && !SPConfig::getConfig().getArtifactResolver()->isSupported(dynamic_cast<const SSODescriptorType&>(*entity.second))) {
        m_log.warn("artifact profile selected for response, but identity provider lacks support");
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Identity provider ($entityID) lacks SAML artifact support.", namedparams(1, "entityID", entityID));
    }

    const EndpointType* ep=EndpointManager<SingleSignOnService>(
        dynamic_cast<const IDPSSODescriptor*>(entity.second)->getSingleSignOnServices()
        ).getByBinding(shibspconstants::SHIB1_AUTHNREQUEST_PROFILE_URI);
    if (!ep) {
        m_log.warn("unable to locate compatible SSO service for provider (%s)", entityID);
        if (getParent())
            return make_pair(false,0L);
        throw MetadataException("Unable to locate compatible SSO service for provider ($entityID)", namedparams(1, "entityID", entityID));
    }

    preserveRelayState(app, httpResponse, relayState);

    // Shib 1.x requires a target value.
    if (relayState.empty())
        relayState = "default";

    char timebuf[16];
    sprintf(timebuf,"%lu",time(nullptr));
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    auto_ptr_char dest(ep->getLocation());
    string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "shire=" + urlenc->encode(acsLocation) +
        "&time=" + timebuf + "&target=" + urlenc->encode(relayState.c_str()) +
        "&providerId=" + urlenc->encode(app.getRelyingParty(entity.first)->getString("entityID").second);

    if (httpRequest) {
        // If the request object is available, we're responsible for the POST data.
        preservePostData(app, *httpRequest, httpResponse, relayState.c_str());
    }

    return make_pair(true, httpResponse.sendRedirect(req.c_str()));
#else
    return make_pair(false,0L);
#endif
}
