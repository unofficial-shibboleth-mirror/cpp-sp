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
 * SAML2SessionInitiator.cpp
 * 
 * SAML 2.0 AuthnRequest support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2SessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        SAML2SessionInitiator(const DOMElement* e, const char* appId);
        virtual ~SAML2SessionInitiator() {
#ifndef SHIBSP_LITE
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
                XMLString::release(&m_outgoing);
                for_each(m_encoders.begin(), m_encoders.end(), cleanup_pair<const XMLCh*,MessageEncoder>());
                delete m_requestTemplate;
            }
#endif
        }
        
        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, const char* entityID=NULL, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application,
            HTTPResponse& httpResponse,
            const char* entityID,
            const XMLCh* acsIndex,
            const char* acsLocation,
            const XMLCh* acsBinding,
            bool isPassive,
            bool forceAuthn,
            const char* authnContextClassRef,
            const char* authnContextComparison,
            string& relayState
            ) const;

        string m_appId;
#ifndef SHIBSP_LITE
        XMLCh* m_outgoing;
        vector<const XMLCh*> m_bindings;
        map<const XMLCh*,MessageEncoder*> m_encoders;
        AuthnRequest* m_requestTemplate;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL SAML2SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2SessionInitiator(p.first, p.second);
    }

};

SAML2SessionInitiator::SAML2SessionInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.SAML2")), m_appId(appId)
{
#ifndef SHIBSP_LITE
    m_outgoing=NULL;
    m_requestTemplate=NULL;
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Check for a template AuthnRequest to build from.
        DOMElement* child = XMLHelper::getFirstChildElement(e, samlconstants::SAML20P_NS, AuthnRequest::LOCAL_NAME);
        if (child)
            m_requestTemplate = dynamic_cast<AuthnRequest*>(AuthnRequestBuilder::buildOneFromElement(child));

        // Handle outgoing binding setup.
        pair<bool,const XMLCh*> outgoing = getXMLString("outgoingBindings");
        if (outgoing.first) {
            m_outgoing = XMLString::replicate(outgoing.second);
            XMLString::trim(m_outgoing);
        }
        else {
            // No override, so we'll install a default binding precedence.
            string prec = string(samlconstants::SAML20_BINDING_HTTP_REDIRECT) + ' ' + samlconstants::SAML20_BINDING_HTTP_POST + ' ' +
                samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN + ' ' + samlconstants::SAML20_BINDING_HTTP_ARTIFACT;
            m_outgoing = XMLString::transcode(prec.c_str());
        }

        int pos;
        XMLCh* start = m_outgoing;
        while (start && *start) {
            pos = XMLString::indexOf(start,chSpace);
            if (pos != -1)
                *(start + pos)=chNull;
            m_bindings.push_back(start);
            try {
                auto_ptr_char b(start);
                MessageEncoder * encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                    b.get(),pair<const DOMElement*,const XMLCh*>(e,NULL)
                    );
                m_encoders[start] = encoder;
                m_log.debug("supporting outgoing binding (%s)", b.get());
            }
            catch (exception& ex) {
                m_log.error("error building MessageEncoder: %s", ex.what());
            }
            if (pos != -1)
                start = start + pos + 1;
            else
                break;
        }
    }
#endif

    // If Location isn't set, defer address registration until the setParent call.
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2SI";
        setAddress(address.c_str());
    }
}

void SAML2SessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::SAML2SI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in SAML2 SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> SAML2SessionInitiator::run(SPRequest& request, const char* entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (!entityID || !*entityID)
        return make_pair(false,0);

    string target;
    const Handler* ACS=NULL;
    const char* option;
    pair<bool,const char*> acClass;
    pair<bool,const char*> acComp;
    bool isPassive=false,forceAuthn=false;
    const Application& app=request.getApplication();
    pair<bool,bool> acsByIndex = getBool("acsByIndex");

    if (isHandler) {
        option=request.getParameter("acsIndex");
        if (option) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(option));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using default ACS location");
        }

        option = request.getParameter("target");
        if (option)
            target = option;
        if (acsByIndex.first && !acsByIndex.second) {
            // Since we're passing the ACS by value, we need to compute the return URL,
            // so we'll need the target resource for real.
            recoverRelayState(request.getApplication(), request, target, false);
        }

        option = request.getParameter("isPassive");
        isPassive = (option && (*option=='1' || *option=='t'));
        if (!isPassive) {
            option = request.getParameter("forceAuthn");
            forceAuthn = (option && (*option=='1' || *option=='t'));
        }

        acClass.second = request.getParameter("authnContextClassRef");
        acClass.first = (acClass.second!=NULL);
        acComp.second = request.getParameter("authnContextComparison");
        acComp.first = (acComp.second!=NULL);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
        const PropertySet* settings = request.getRequestSettings().first;

        pair<bool,bool> flag = settings->getBool("isPassive");
        isPassive = flag.first && flag.second;
        if (!isPassive) {
            flag = settings->getBool("forceAuthn");
            forceAuthn = flag.first && flag.second;
        }

        acClass = settings->getString("authnContextClassRef");
        acComp = settings->getString("authnContextComparison");
    }

    m_log.debug("attempting to initiate session using SAML 2.0 with provider (%s)", entityID);

    if (!ACS) {
        pair<bool,unsigned int> index = getUnsignedInt("defaultACSIndex");
        if (index.first) {
            ACS = app.getAssertionConsumerServiceByIndex(index.second);
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid defaultACSIndex, using default ACS location");
        }
        if (!ACS)
            ACS = app.getDefaultAssertionConsumerService();
    }

    // To invoke the request builder, the key requirement is to figure out how
    // to express the ACS, by index or value, and if by value, where.

    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        if (!acsByIndex.first || acsByIndex.second) {
            // Pass by Index.
            if (isHandler) {
                // We may already have RelayState set if we looped back here,
                // but just in case target is a resource, we reset it back.
                target.erase();
                option = request.getParameter("target");
                if (option)
                    target = option;
            }
            return doRequest(
                app, request, entityID,
                ACS ? ACS->getXMLString("index").second : NULL, NULL, NULL,
                isPassive, forceAuthn,
                acClass.first ? acClass.second : NULL,
                acComp.first ? acComp.second : NULL,
                target
                );
        }

        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
        string ACSloc=request.getHandlerURL(target.c_str());
        pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
        if (loc.first) ACSloc+=loc.second;

        if (isHandler) {
            // We may already have RelayState set if we looped back here,
            // but just in case target is a resource, we reset it back.
            target.erase();
            option = request.getParameter("target");
            if (option)
                target = option;
        }

        return doRequest(
            app, request, entityID,
            NULL, ACSloc.c_str(), ACS ? ACS->getXMLString("Binding").second : NULL,
            isPassive, forceAuthn,
            acClass.first ? acClass.second : NULL,
            acComp.first ? acComp.second : NULL,
            target
            );
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    in.addmember("entity_id").string(entityID);
    if (isPassive)
        in.addmember("isPassive").integer(1);
    else if (forceAuthn)
        in.addmember("forceAuthn").integer(1);
    if (acClass.first)
        in.addmember("authnContextClassRef").string(acClass.second);
    if (acComp.first)
        in.addmember("authnContextComparison").string(acComp.second);
    if (!acsByIndex.first || acsByIndex.second) {
        if (ACS)
            in.addmember("acsIndex").string(ACS->getString("index").second);
    }
    else {
        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
        string ACSloc=request.getHandlerURL(target.c_str());
        pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
        if (loc.first) ACSloc+=loc.second;
        in.addmember("acsLocation").string(ACSloc.c_str());
        if (ACS)
            in.addmember("acsBinding").string(ACS->getString("Binding").second);
    }

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        target.erase();
        option = request.getParameter("target");
        if (option)
            target = option;
    }
    if (!target.empty())
        in.addmember("RelayState").string(target.c_str());

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

void SAML2SessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    if (!entityID)
        throw ConfigurationException("No entityID parameter supplied to remoted SessionInitiator.");

    DDF ret(NULL);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    auto_ptr<HTTPResponse> http(getResponse(ret));

    auto_ptr_XMLCh index(in["acsIndex"].string());
    auto_ptr_XMLCh bind(in["acsBinding"].string());

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(
        *app, *http.get(), entityID,
        index.get(), in["acsLocation"].string(), bind.get(),
        in["isPassive"].integer()==1, in["forceAuthn"].integer()==1,
        in["authnContextClassRef"].string(), in["authnContextComparison"].string(),
        relayState
        );
    out << ret;
}

pair<bool,long> SAML2SessionInitiator::doRequest(
    const Application& app,
    HTTPResponse& httpResponse,
    const char* entityID,
    const XMLCh* acsIndex,
    const char* acsLocation,
    const XMLCh* acsBinding,
    bool isPassive,
    bool forceAuthn,
    const char* authnContextClassRef,
    const char* authnContextComparison,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    // Use metadata to locate the IdP's SSO service.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    MetadataProvider::Criteria mc(entityID, &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
    pair<const EntityDescriptor*,const RoleDescriptor*> entity=m->getEntityDescriptor(mc);
    if (!entity.first) {
        m_log.error("unable to locate metadata for provider (%s)", entityID);
        throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
    }
    else if (!entity.second) {
        m_log.error("unable to locate SAML 2.0 identity provider role for provider (%s)", entityID);
        return make_pair(false,0);
    }

    // Loop over the supportable outgoing bindings.
    const IDPSSODescriptor* role = dynamic_cast<const IDPSSODescriptor*>(entity.second);
    const EndpointType* ep=NULL;
    const MessageEncoder* encoder=NULL;
    vector<const XMLCh*>::const_iterator b;
    for (b = m_bindings.begin(); b!=m_bindings.end(); ++b) {
        if (ep=EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(*b)) {
            map<const XMLCh*,MessageEncoder*>::const_iterator enc = m_encoders.find(*b);
            if (enc!=m_encoders.end())
                encoder = enc->second;
            break;
        }
    }
    if (!ep || !encoder) {
        m_log.error("unable to locate compatible SSO service for provider (%s)", entityID);
        return make_pair(false,0);
    }

    preserveRelayState(app, httpResponse, relayState);

    auto_ptr<AuthnRequest> req(m_requestTemplate ? m_requestTemplate->cloneAuthnRequest() : AuthnRequestBuilder::buildAuthnRequest());
    if (m_requestTemplate) {
        // Freshen TS and ID.
        req->setID(NULL);
        req->setIssueInstant(time(NULL));
    }

    req->setDestination(ep->getLocation());
    if (acsIndex && *acsIndex)
        req->setAssertionConsumerServiceIndex(acsIndex);
    if (acsLocation) {
        auto_ptr_XMLCh wideloc(acsLocation);
        req->setAssertionConsumerServiceURL(wideloc.get());
    }
    if (acsBinding && *acsBinding)
        req->setProtocolBinding(acsBinding);
    if (isPassive)
        req->IsPassive(isPassive);
    else if (forceAuthn)
        req->ForceAuthn(forceAuthn);
    if (!req->getIssuer()) {
        Issuer* issuer = IssuerBuilder::buildIssuer();
        req->setIssuer(issuer);
        issuer->setName(app.getXMLString("entityID").second);
    }
    if (!req->getNameIDPolicy()) {
        NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
        req->setNameIDPolicy(namepol);
        namepol->AllowCreate(true);
    }
    if (authnContextClassRef || authnContextComparison) {
        RequestedAuthnContext* reqContext = req->getRequestedAuthnContext();
        if (!reqContext) {
            reqContext = RequestedAuthnContextBuilder::buildRequestedAuthnContext();
            req->setRequestedAuthnContext(reqContext);
        }
        if (authnContextClassRef) {
            reqContext->getAuthnContextDeclRefs().clear();
            auto_ptr_XMLCh wideclass(authnContextClassRef);
            AuthnContextClassRef* cref = AuthnContextClassRefBuilder::buildAuthnContextClassRef();
            cref->setReference(wideclass.get());
            reqContext->getAuthnContextClassRefs().push_back(cref);
        }
        if (authnContextComparison &&
                (!reqContext->getAuthnContextClassRefs().empty() || !reqContext->getAuthnContextDeclRefs().empty())) {
            auto_ptr_XMLCh widecomp(authnContextComparison);
            reqContext->setComparison(widecomp.get());
        }
    }

    auto_ptr_char dest(ep->getLocation());

    long ret = sendMessage(*encoder, req.get(), relayState.c_str(), dest.get(), role, app, httpResponse, role->WantAuthnRequestsSigned());
    req.release();  // freed by encoder
    return make_pair(true,ret);
#else
    return make_pair(false,0);
#endif
}
