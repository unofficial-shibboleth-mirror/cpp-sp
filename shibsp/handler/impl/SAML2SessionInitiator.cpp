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
 * SAML2SessionInitiator.cpp
 *
 * SAML 2.0 AuthnRequest support.
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
# include <boost/bind.hpp>
# include <boost/algorithm/string.hpp>
# include <boost/iterator/indirect_iterator.hpp>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
# include <saml/util/SAMLConstants.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
#else
# include "lite/SAMLConstants.h"
# include <xercesc/util/XMLUniDefs.hpp>
#endif

#include <boost/scoped_ptr.hpp>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
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
        virtual ~SAML2SessionInitiator() {}

        void init(const char* location);    // encapsulates actions that need to run either in the c'tor or setParent

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> unwrap(SPRequest& request, DDF& out) const;
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML20P_NS;
        }

#ifndef SHIBSP_LITE
        void generateMetadata(saml2md::SPSSODescriptor& role, const char* handlerURL) const {
            doGenerateMetadata(role, handlerURL);
        }
#endif

    private:
        pair<bool,long> doRequest(
            const Application& application,
            const HTTPRequest* httpRequest,
            HTTPResponse& httpResponse,
            const char* entityID,
            const XMLCh* acsIndex,
            bool artifactInbound,
            const char* acsLocation,
            const XMLCh* acsBinding,
            bool isPassive,
            bool forceAuthn,
            const char* authnContextClassRef,
            const char* authnContextComparison,
            const char* NameIDFormat,
            const char* SPNameQualifier,
            string& relayState
            ) const;

        string m_appId;
        auto_ptr_char m_paosNS,m_ecpNS;
        auto_ptr_XMLCh m_paosBinding;
#ifndef SHIBSP_LITE
        vector<string> m_bindings;
        map< string,boost::shared_ptr<MessageEncoder> > m_encoders;
        scoped_ptr<MessageEncoder> m_ecp;
        scoped_ptr<AuthnRequest> m_requestTemplate;
#else
        bool m_ecp;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    class SHIBSP_DLLLOCAL SessionInitiatorNodeFilter : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL SessionInitiatorNodeFilter g_SINFilter;

    SessionInitiator* SHIBSP_DLLLOCAL SAML2SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2SessionInitiator(p.first, p.second);
    }

};

SAML2SessionInitiator::SAML2SessionInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.SAML2"), &g_SINFilter, &m_remapper), m_appId(appId),
        m_paosNS(samlconstants::PAOS_NS), m_ecpNS(samlconstants::SAML20ECP_NS), m_paosBinding(samlconstants::SAML20_BINDING_PAOS)
#ifdef SHIBSP_LITE
        ,m_ecp(false)
#endif
{
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Check for a template AuthnRequest to build from.
        DOMElement* child = XMLHelper::getFirstChildElement(e, samlconstants::SAML20P_NS, AuthnRequest::LOCAL_NAME);
        if (child)
            m_requestTemplate.reset(dynamic_cast<AuthnRequest*>(AuthnRequestBuilder::buildOneFromElement(child)));
    }
#endif

    // If Location isn't set, defer initialization until the setParent call.
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        init(loc.second);
    }

    m_supportedOptions.insert("isPassive");
}

void SAML2SessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    init(loc.second);
}

void SAML2SessionInitiator::init(const char* location)
{
    if (location) {
        string address = m_appId + location + "::run::SAML2SI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in SAML2 SessionInitiator (or parent), can't register as remoted handler");
    }

    pair<bool,bool> flag = getBool("ECP");
#ifdef SHIBSP_LITE
    m_ecp = flag.first && flag.second;
#else

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // If directed, build an ECP encoder.
        if (flag.first && flag.second) {
            try {
                m_ecp.reset(
                    SAMLConfig::getConfig().MessageEncoderManager.newPlugin(
                        samlconstants::SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(getElement(), nullptr)
                        )
                    );
            }
            catch (std::exception& ex) {
                m_log.error("error building PAOS/ECP MessageEncoder: %s", ex.what());
            }
        }

        string dupBindings;
        pair<bool,const char*> outgoing = getString("outgoingBindings");
        if (outgoing.first) {
            dupBindings = outgoing.second;
        }
        else {
            // No override, so we'll install a default binding precedence.
            dupBindings = string(samlconstants::SAML20_BINDING_HTTP_REDIRECT) + ' ' + samlconstants::SAML20_BINDING_HTTP_POST + ' ' +
                samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN + ' ' + samlconstants::SAML20_BINDING_HTTP_ARTIFACT;
        }
        split(m_bindings, dupBindings, is_space(), algorithm::token_compress_on);
        for (vector<string>::const_iterator b = m_bindings.begin(); b != m_bindings.end(); ++b) {
            try {
                boost::shared_ptr<MessageEncoder> encoder(
                    SAMLConfig::getConfig().MessageEncoderManager.newPlugin(*b, pair<const DOMElement*,const XMLCh*>(getElement(),nullptr))
                    );
                if (encoder->isUserAgentPresent() && XMLString::equals(getProtocolFamily(), encoder->getProtocolFamily())) {
                    m_encoders[*b] = encoder;
                    m_log.debug("supporting outgoing binding (%s)", b->c_str());
                }
                else {
                    m_log.warn("skipping outgoing binding (%s), not a SAML 2.0 front-channel mechanism", b->c_str());
                }
            }
            catch (std::exception& ex) {
                m_log.error("error building MessageEncoder: %s", ex.what());
            }
        }
    }
#endif
}

pair<bool,long> SAML2SessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // First check for ECP support, since that doesn't require an IdP to be known.
    bool ECP = false;
    if (m_ecp && request.getHeader("Accept").find("application/vnd.paos+xml") != string::npos) {
        string PAOS = request.getHeader("PAOS");
        if (PAOS.find(m_paosNS.get()) != string::npos && PAOS.find(m_ecpNS.get()) != string::npos)
            ECP = true;
    }

    // We have to know the IdP to function unless this is ECP.
    if ((!ECP && entityID.empty()) || !checkCompatibility(request, isHandler))
        return make_pair(false, 0L);

    string target;
    pair<bool,const char*> prop;
    const Handler* ACS = nullptr;
    pair<bool,const char*> acClass, acComp, nidFormat, spQual;
    bool isPassive=false,forceAuthn=false;
    const Application& app = request.getApplication();

    // ECP means the ACS will be by value no matter what.
    pair<bool,bool> acsByIndex = ECP ? make_pair(true,false) : getBool("acsByIndex");

    if (isHandler) {
        prop.second = request.getParameter("acsIndex");
        if (prop.second && *prop.second) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(prop.second));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using acsIndex property");
            else if (ECP && !XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_PAOS)) {
                request.log(SPRequest::SPWarn, "acsIndex in request referenced a non-PAOS ACS, using default ACS location");
                ACS = nullptr;
            }
        }

        prop = getString("target", request);
        if (prop.first)
            target = prop.second;

        // Always need to recover target URL to compute handler below.
        recoverRelayState(app, request, request, target, false);
        app.limitRedirect(request, target.c_str());

        pair<bool,bool> flag = getBool("isPassive", request);
        isPassive = (flag.first && flag.second);

        if (!isPassive) {
            flag = getBool("forceAuthn", request);
            forceAuthn = (flag.first && flag.second);
        }

        // Populate via parameter, map, or property.
        acClass = getString("authnContextClassRef", request);
        acComp = getString("authnContextComparison", request);
        nidFormat = getString("NameIDFormat", request);
        spQual = getString("SPNameQualifier", request);
    }
    else {
        // Check for a hardwired target value in the map or handler.
        prop = getString("target", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (prop.first)
            target = prop.second;
        else
            target = request.getRequestURL();

        pair<bool,bool> flag = getBool("isPassive", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        isPassive = flag.first && flag.second;
        if (!isPassive) {
            flag = getBool("forceAuthn", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
            forceAuthn = flag.first && flag.second;
        }

        // Populate via map or property.
        acClass = getString("authnContextClassRef", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        acComp = getString("authnContextComparison", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        nidFormat = getString("NameIDFormat", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        spQual = getString("SPNameQualifier", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
    }

    if (ECP)
        m_log.debug("attempting to initiate session using SAML 2.0 Enhanced Client Profile");
    else
        m_log.debug("attempting to initiate session using SAML 2.0 with provider (%s)", entityID.c_str());

    if (!ACS) {
        if (ECP) {
            ACS = app.getAssertionConsumerServiceByProtocol(getProtocolFamily(), samlconstants::SAML20_BINDING_PAOS);
            if (!ACS)
                throw ConfigurationException("Unable to locate PAOS response endpoint.");
        }
        else {
            // Try fixed index property.
            pair<bool,unsigned int> index = getUnsignedInt("acsIndex", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
            if (index.first)
                ACS = app.getAssertionConsumerServiceByIndex(index.second);
        }
    }

    // If we picked by index, validate the ACS for use with this protocol.
    if (!ECP && (!ACS || !XMLString::equals(getProtocolFamily(), ACS->getProtocolFamily()))) {
        if (ACS)
            request.log(SPRequest::SPWarn, "invalid acsIndex property, or non-SAML 2.0 ACS, using default SAML 2.0 ACS");
        ACS = app.getAssertionConsumerServiceByProtocol(getProtocolFamily());
        if (!ACS)
            throw ConfigurationException("Unable to locate a SAML 2.0 ACS endpoint to use for response.");
    }

    // To invoke the request builder, the key requirement is to figure out how
    // to express the ACS, by index or value, and if by value, where.
    // We have to compute the handlerURL no matter what, because we may need to
    // flip the index to an SSL-version.
    string ACSloc = request.getHandlerURL(target.c_str());

    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
    	if (acsByIndex.first && acsByIndex.second) {
            // Pass by Index.
            if (isHandler) {
                // We may already have RelayState set if we looped back here,
                // but we've turned it back into a resource by this point, so if there's
                // a target on the URL, reset to that value.
                prop.second = request.getParameter("target");
                if (prop.second && *prop.second)
                    target = prop.second;
            }

            // Determine index to use.
            pair<bool,const XMLCh*> ix = pair<bool,const XMLCh*>(false,nullptr);
            if (!strncmp(ACSloc.c_str(), "https://", 8)) {
            	ix = ACS->getXMLString("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
            	if (!ix.first)
            		ix = ACS->getXMLString("index");
            }
            else {
            	ix = ACS->getXMLString("index");
            }

            return doRequest(
                app, &request, request, entityID.c_str(),
                ix.second,
                XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT),
                nullptr, nullptr,
                isPassive, forceAuthn,
                acClass.first ? acClass.second : nullptr,
                acComp.first ? acComp.second : nullptr,
                nidFormat.first ? nidFormat.second : nullptr,
                spQual.first ? spQual.second : nullptr,
                target
                );
        }

        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
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

        return doRequest(
            app, &request, request, entityID.c_str(),
            nullptr,
            XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT),
            ACSloc.c_str(), ACS->getXMLString("Binding").second,
            isPassive, forceAuthn,
            acClass.first ? acClass.second : nullptr,
            acComp.first ? acComp.second : nullptr,
            nidFormat.first ? nidFormat.second : nullptr,
            spQual.first ? spQual.second : nullptr,
            target
            );
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    if (!entityID.empty())
        in.addmember("entity_id").string(entityID.c_str());
    if (isPassive)
        in.addmember("isPassive").integer(1);
    else if (forceAuthn)
        in.addmember("forceAuthn").integer(1);
    if (acClass.first)
        in.addmember("authnContextClassRef").string(acClass.second);
    if (acComp.first)
        in.addmember("authnContextComparison").string(acComp.second);
    if (nidFormat.first)
        in.addmember("NameIDFormat").string(nidFormat.second);
    if (spQual.first)
        in.addmember("SPNameQualifier").string(spQual.second);
    if (acsByIndex.first && acsByIndex.second) {
        // Determine index to use.
        pair<bool,const char*> ix = pair<bool,const char*>(false,nullptr);
        if (!strncmp(ACSloc.c_str(), "https://", 8)) {
        	ix = ACS->getString("sslIndex", shibspconstants::ASCII_SHIB2SPCONFIG_NS);
        	if (!ix.first)
        		ix = ACS->getString("index");
        }
        else {
        	ix = ACS->getString("index");
        }
        in.addmember("acsIndex").string(ix.second);
        if (XMLString::equals(ACS->getString("Binding").second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT))
            in.addmember("artifact").integer(1);
    }
    else {
        // Since we're not passing by index, we need to fully compute the return URL and binding.
        // Compute the ACS URL. We add the ACS location to the base handlerURL.
        prop = ACS->getString("Location");
        if (prop.first)
            ACSloc += prop.second;
        in.addmember("acsLocation").string(ACSloc.c_str());
        prop = ACS->getString("Binding");
        in.addmember("acsBinding").string(prop.second);
        if (XMLString::equals(prop.second, samlconstants::SAML20_BINDING_HTTP_ARTIFACT))
            in.addmember("artifact").integer(1);
    }

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but we've turned it back into a resource by this point, so if there's
        // a target on the URL, reset to that value.
        prop.second = request.getParameter("target");
        if (prop.second && *prop.second)
            target = prop.second;
    }
    if (!target.empty())
        in.addmember("RelayState").unsafe_string(target.c_str());

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

pair<bool,long> SAML2SessionInitiator::unwrap(SPRequest& request, DDF& out) const
{
    // See if there's any response to send back.
    if (!out["redirect"].isnull() || !out["response"].isnull()) {
        // If so, we're responsible for handling the POST data, probably by dropping a cookie.
        preservePostData(request.getApplication(), request, request, out["RelayState"].string());
    }
    return RemotedHandler::unwrap(request, out);
}

void SAML2SessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    DDF ret(nullptr);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    scoped_ptr<HTTPResponse> http(getResponse(ret));

    auto_ptr_XMLCh index(in["acsIndex"].string());
    auto_ptr_XMLCh bind(in["acsBinding"].string());

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");
    string postData(in["PostData"].string() ? in["PostData"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(
        *app, nullptr, *http, in["entity_id"].string(),
        index.get(),
        (in["artifact"].integer() != 0),
        in["acsLocation"].string(), bind.get(),
        in["isPassive"].integer()==1, in["forceAuthn"].integer()==1,
        in["authnContextClassRef"].string(), in["authnContextComparison"].string(),
        in["NameIDFormat"].string(), in["SPNameQualifier"].string(),
        relayState
        );
    if (!ret.isstruct())
        ret.structure();
    ret.addmember("RelayState").unsafe_string(relayState.c_str());
    out << ret;
}

pair<bool,long> SAML2SessionInitiator::doRequest(
    const Application& app,
    const HTTPRequest* httpRequest,
    HTTPResponse& httpResponse,
    const char* entityID,
    const XMLCh* acsIndex,
    bool artifactInbound,
    const char* acsLocation,
    const XMLCh* acsBinding,
    bool isPassive,
    bool forceAuthn,
    const char* authnContextClassRef,
    const char* authnContextComparison,
    const char* NameIDFormat,
    const char* SPNameQualifier,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    bool ECP = XMLString::equals(acsBinding, m_paosBinding.get());

    pair<const EntityDescriptor*,const RoleDescriptor*> entity = pair<const EntityDescriptor*,const RoleDescriptor*>(nullptr,nullptr);
    const IDPSSODescriptor* role = nullptr;
    const EndpointType* ep = nullptr;
    const MessageEncoder* encoder = nullptr;

    // We won't need this for ECP, but safety dictates we get the lock here.
    MetadataProvider* m = app.getMetadataProvider();
    Locker locker(m);

    if (ECP) {
        encoder = m_ecp.get();
        if (!encoder) {
            m_log.error("MessageEncoder for PAOS binding not available");
            return make_pair(false, 0L);
        }
    }
    else {
        // Use metadata to locate the IdP's SSO service.
        MetadataProviderCriteria mc(app, entityID, &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
        entity = m->getEntityDescriptor(mc);
        if (!entity.first) {
            m_log.warn("unable to locate metadata for provider (%s)", entityID);
            throw MetadataException("Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", entityID));
        }
        else if (!entity.second) {
            m_log.log(getParent() ? Priority::INFO : Priority::WARN, "unable to locate SAML 2.0 identity provider role for provider (%s)", entityID);
            if (getParent())
                return make_pair(false, 0L);
            throw MetadataException("Unable to locate SAML 2.0 identity provider role for provider ($entityID)", namedparams(1, "entityID", entityID));
        }
        else if (artifactInbound && !SPConfig::getConfig().getArtifactResolver()->isSupported(dynamic_cast<const SSODescriptorType&>(*entity.second))) {
            m_log.warn("artifact binding selected for response, but identity provider lacks support");
            if (getParent())
                return make_pair(false, 0L);
            throw MetadataException("Identity provider ($entityID) lacks SAML 2.0 artifact support.", namedparams(1, "entityID", entityID));
        }

        // Loop over the supportable outgoing bindings.
        role = dynamic_cast<const IDPSSODescriptor*>(entity.second);
        for (vector<string>::const_iterator b = m_bindings.begin(); b != m_bindings.end(); ++b) {
            auto_ptr_XMLCh wideb(b->c_str());
            if (ep=EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(wideb.get())) {
                map< string,boost::shared_ptr<MessageEncoder> >::const_iterator enc = m_encoders.find(*b);
                if (enc != m_encoders.end())
                    encoder = enc->second.get();
                break;
            }
        }
        if (!ep || !encoder) {
            m_log.warn("unable to locate compatible SSO service for provider (%s)", entityID);
            if (getParent())
                return make_pair(false, 0L);
            throw MetadataException("Unable to locate compatible SSO service for provider ($entityID)", namedparams(1, "entityID", entityID));
        }
    }

    preserveRelayState(app, httpResponse, relayState);

    auto_ptr<AuthnRequest> req(m_requestTemplate ? m_requestTemplate->cloneAuthnRequest() : AuthnRequestBuilder::buildAuthnRequest());
    if (m_requestTemplate) {
        // Freshen TS and ID.
        req->setID(nullptr);
        req->setIssueInstant(time(nullptr));
    }

    if (ep)
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
        issuer->setName(app.getRelyingParty(entity.first)->getXMLString("entityID").second);
    }
    if (!req->getNameIDPolicy()) {
        NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
        req->setNameIDPolicy(namepol);
        namepol->AllowCreate(true);
    }
    if (NameIDFormat && *NameIDFormat) {
        auto_ptr_XMLCh wideform(NameIDFormat);
        req->getNameIDPolicy()->setFormat(wideform.get());
    }
    if (SPNameQualifier && *SPNameQualifier) {
        auto_ptr_XMLCh widequal(SPNameQualifier);
        req->getNameIDPolicy()->setSPNameQualifier(widequal.get());
    }
    if (authnContextClassRef || authnContextComparison) {
        RequestedAuthnContext* reqContext = req->getRequestedAuthnContext();
        if (!reqContext) {
            reqContext = RequestedAuthnContextBuilder::buildRequestedAuthnContext();
            req->setRequestedAuthnContext(reqContext);
        }
        if (authnContextClassRef) {
            reqContext->getAuthnContextDeclRefs().clear();
            string dup(authnContextClassRef);
            vector<string> contexts;
            split(contexts, dup, is_space(), algorithm::token_compress_on);
            for (vector<string>::const_iterator ac = contexts.begin(); ac != contexts.end(); ++ac) {
                auto_ptr_XMLCh wideac(ac->c_str());
                auto_ptr<AuthnContextClassRef> cref(AuthnContextClassRefBuilder::buildAuthnContextClassRef());
                cref->setReference(wideac.get());
                reqContext->getAuthnContextClassRefs().push_back(cref.get());
                cref.release();
            }
        }

        if (reqContext->getAuthnContextClassRefs().empty() && reqContext->getAuthnContextDeclRefs().empty()) {
        	req->setRequestedAuthnContext(nullptr);
        }
        else if (authnContextComparison) {
            auto_ptr_XMLCh widecomp(authnContextComparison);
            reqContext->setComparison(widecomp.get());
        }
    }

    pair<bool,bool> requestDelegation = getBool("requestDelegation");
    if (requestDelegation.first && requestDelegation.second) {
        if (entity.first) {
            // Request delegation by including the IdP as an Audience.
            // Also specify the expected session lifetime as the bound on the assertion lifetime.
            const PropertySet* sessionProps = app.getPropertySet("Sessions");
            pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
            if (!lifetime.first || lifetime.second == 0)
                lifetime.second = 28800;
            if (!req->getConditions())
                req->setConditions(ConditionsBuilder::buildConditions());
            req->getConditions()->setNotOnOrAfter(time(nullptr) + lifetime.second + 300);
            AudienceRestriction* audrest = AudienceRestrictionBuilder::buildAudienceRestriction();
            req->getConditions()->getConditions().push_back(audrest);
            Audience* aud = AudienceBuilder::buildAudience();
            audrest->getAudiences().push_back(aud);
            aud->setAudienceURI(entity.first->getEntityID());
        }
        else {
            m_log.warn("requestDelegation set, but IdP unknown at request time");
        }
    }

    if (ECP && entityID) {
        auto_ptr_XMLCh wideid(entityID);
        Scoping* scoping = req->getScoping();
        if (!scoping) {
            scoping = ScopingBuilder::buildScoping();
            req->setScoping(scoping);
        }
        IDPList* idplist = scoping->getIDPList();
        if (!idplist) {
            idplist = IDPListBuilder::buildIDPList();
            scoping->setIDPList(idplist);
        }
        VectorOf(IDPEntry) entries = idplist->getIDPEntrys();
        static bool (*wideequals)(const XMLCh*,const XMLCh*) = &XMLString::equals;
        if (find_if(entries, boost::bind(wideequals, boost::bind(&IDPEntry::getProviderID, _1), wideid.get())) == nullptr) {
            IDPEntry* entry = IDPEntryBuilder::buildIDPEntry();
            entry->setProviderID(wideid.get());
            entries.push_back(entry);
        }
    }

    XMLCh* genid = SAMLConfig::getConfig().generateIdentifier();
    req->setID(genid);
    XMLString::release(&genid);
    req->setIssueInstant(time(nullptr));

    scoped_ptr<AuthnRequestEvent> ar_event(newAuthnRequestEvent(app, httpRequest));
    if (ar_event) {
        auto_ptr_char b(ep ? ep->getBinding() : nullptr);
        ar_event->m_binding = b.get() ? b.get() : samlconstants::SAML20_BINDING_SOAP;
        auto_ptr_char prot(getProtocolFamily());
        ar_event->m_protocol = prot.get();
        ar_event->m_peer = entity.first;
        ar_event->m_saml2Request = req.get();
        app.getServiceProvider().getTransactionLog()->write(*ar_event);
    }

    auto_ptr_char dest(ep ? ep->getLocation() : nullptr);

    if (httpRequest) {
        // If the request object is available, we're responsible for the POST data.
        preservePostData(app, *httpRequest, httpResponse, relayState.c_str());
    }

    long ret = sendMessage(
        *encoder, req.get(), relayState.c_str(), dest.get(), role, app, httpResponse, role ? role->WantAuthnRequestsSigned() : false
        );
    req.release();  // freed by encoder
    return make_pair(true, ret);
#else
    return make_pair(false, 0L);
#endif
}
