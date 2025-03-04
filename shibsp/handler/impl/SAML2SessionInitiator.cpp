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
 * handler/impl/SAML2SessionInitiator.cpp
 *
 * SAML 2.0 AuthnRequest support.
 */

#include "internal.h"
#include "exceptions.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#include <boost/scoped_ptr.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace xercesc;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2SessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        SAML2SessionInitiator(const DOMElement* e, const char* appId, bool deprecationSupport);
        virtual ~SAML2SessionInitiator() {}

        void init(const char* location);    // encapsulates actions that need to run either in the c'tor or setParent

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> unwrap(SPRequest& request, DDF& out) const;
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;


    private:
        pair<bool,long> doRequest(
            SPRequest& request,
            const char* entityID,
            const XMLCh* acsIndex,
            const char* attributeIndex,
            bool artifactInbound,
            const char* acsLocation,
            const XMLCh* acsBinding,
            bool isPassive,
            bool forceAuthn,
            const char* authnContextClassRef,
            const char* authnContextComparison,
            const char* NameIDFormat,
            const char* SPNameQualifier,
            const char* requestTemplate,
            const char* outgoingBinding,
            string& relayState
            ) const;

        string m_appId;
        bool m_deprecationSupport;
        auto_ptr_char m_paosNS,m_ecpNS;
        auto_ptr_XMLCh m_paosBinding;
        bool m_ecp;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL SAML2SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p, bool deprecationSupport)
    {
        return new SAML2SessionInitiator(p.first, p.second, deprecationSupport);
    }

};

SAML2SessionInitiator::SAML2SessionInitiator(const DOMElement* e, const char* appId, bool deprecationSupport)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT ".SessionInitiator.SAML2"), nullptr, this),
        m_appId(appId), m_deprecationSupport(deprecationSupport), m_ecp(false)
{
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
                m_ecp.reset(SAMLConfig::getConfig().MessageEncoderManager.newPlugin(samlconstants::SAML20_BINDING_PAOS, getElement(), m_deprecationSupport));
            }
            catch (std::exception& ex) {
                m_log.error("error building PAOS/ECP MessageEncoder: %s", ex.what());
            }
        }

        string dupBindings;
        pair<bool,const char*> outgoing = getString("outgoingBindings");
        if (outgoing.first) {
            dupBindings = outgoing.second;
            trim(dupBindings);
        }
        else {
            // No override, so we'll install a default binding precedence.
            dupBindings = string(samlconstants::SAML20_BINDING_HTTP_REDIRECT) + ' ' + samlconstants::SAML20_BINDING_HTTP_POST + ' ' +
                samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN + ' ' + samlconstants::SAML20_BINDING_HTTP_ARTIFACT;
        }
        split(m_bindings, dupBindings, is_space(), algorithm::token_compress_on);
        for (vector<string>::const_iterator b = m_bindings.begin(); b != m_bindings.end(); ++b) {
            try {
                boost::shared_ptr<MessageEncoder> encoder(SAMLConfig::getConfig().MessageEncoderManager.newPlugin(*b, getElement(), m_deprecationSupport));
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
    pair<bool,const char*> acClass, acComp, nidFormat, spQual, attributeIndex;
    const char* requestTemplate = nullptr;
    const char* outgoingBinding = nullptr;
    bool isPassive=false,forceAuthn=false;

    // ECP means the ACS will be by value no matter what.
    pair<bool,bool> acsByIndex = ECP ? make_pair(true,false) : getBool("acsByIndex");

    if (isHandler) {
        prop.second = request.getParameter("acsIndex");
        if (prop.second && *prop.second) {
            //ACS = app.getAssertionConsumerServiceByIndex(atoi(prop.second));
            if (!ACS)
                request.log(Priority::SHIB_WARN, "invalid acsIndex specified in request, using acsIndex property");
            else if (ECP && !XMLString::equals(ACS->getString("Binding").second, nullptr)) {
                request.log(Priority::SHIB_WARN, "acsIndex in request referenced a non-PAOS ACS, using default ACS location");
                ACS = nullptr;
            }
        }

        prop = getString("target", request);
        if (prop.first)
            target = prop.second;

        // Always need to recover target URL to compute handler below.
        recoverRelayState(request, target, false);
        request.limitRedirect(target.c_str());

        // Default is to allow externally supplied settings.
        pair<bool,bool> externalInput = getBool("externalInput");
        unsigned int settingMask = HANDLER_PROPERTY_MAP | HANDLER_PROPERTY_FIXED;
        if (!externalInput.first || externalInput.second) {
            settingMask |= HANDLER_PROPERTY_REQUEST;
            requestTemplate = request.getParameter("template");
        }

        outgoingBinding = request.getParameter("outgoingBinding");

        pair<bool,bool> flag = getBool("isPassive", request, settingMask);
        isPassive = (flag.first && flag.second);

        if (!isPassive) {
            flag = getBool("forceAuthn", request, settingMask);
            forceAuthn = (flag.first && flag.second);
        }

        // Populate via parameter, map, or property.
        attributeIndex = getString("attributeIndex", request, settingMask);
        acClass = getString("authnContextClassRef", request, settingMask);
        acComp = getString("authnContextComparison", request, settingMask);
        nidFormat = getString("NameIDFormat", request, settingMask);
        spQual = getString("SPNameQualifier", request, settingMask);

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
        attributeIndex = getString("attributeIndex", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
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
            //ACS = app.getAssertionConsumerServiceByProtocol(getProtocolFamily(), nullptr);
            if (!ACS)
                throw ConfigurationException("Unable to locate PAOS response endpoint.");
        }
        else {
            // Try fixed index property.
            pair<bool,unsigned int> index = getUnsignedInt("acsIndex", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
            if (index.first) {
                //ACS = app.getAssertionConsumerServiceByIndex(index.second);
            }
        }
    }

    // To invoke the request builder, the key requirement is to figure out how
    // to express the ACS, by index or value, and if by value, where.
    // We have to compute the handlerURL no matter what, because we may need to
    // flip the index to an SSL-version.
    string ACSloc = request.getHandlerURL(target.c_str());

    if (false) {
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

            return doRequest(
                request, entityID.c_str(),
                nullptr,
                attributeIndex.first ? attributeIndex.second : nullptr,
                false,
                nullptr, nullptr,
                isPassive, forceAuthn,
                acClass.first ? acClass.second : nullptr,
                acComp.first ? acComp.second : nullptr,
                nidFormat.first ? nidFormat.second : nullptr,
                spQual.first ? spQual.second : nullptr,
                requestTemplate,
                outgoingBinding,
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
            request, entityID.c_str(),
            nullptr,
            attributeIndex.first ? attributeIndex.second : nullptr,
            false,
            ACSloc.c_str(), nullptr,
            isPassive, forceAuthn,
            acClass.first ? acClass.second : nullptr,
            acComp.first ? acComp.second : nullptr,
            nidFormat.first ? nidFormat.second : nullptr,
            spQual.first ? spQual.second : nullptr,
            requestTemplate,
            outgoingBinding,
            target
            );
    }

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    if (!entityID.empty())
        in.addmember("entity_id").string(entityID.c_str());
    if (isPassive)
        in.addmember("isPassive").integer(1);
    else if (forceAuthn)
        in.addmember("forceAuthn").integer(1);
    if (attributeIndex.first)
        in.addmember("attributeIndex").string(attributeIndex.second);
    if (acClass.first)
        in.addmember("authnContextClassRef").string(acClass.second);
    if (acComp.first)
        in.addmember("authnContextComparison").string(acComp.second);
    if (nidFormat.first)
        in.addmember("NameIDFormat").string(nidFormat.second);
    if (spQual.first)
        in.addmember("SPNameQualifier").string(spQual.second);
    if (requestTemplate)
        in.addmember("template").string(requestTemplate);
    if (outgoingBinding)
        in.addmember("outgoingBinding").string(outgoingBinding);
    if (acsByIndex.first && acsByIndex.second) {
        // Determine index to use.
        pair<bool,const char*> ix = pair<bool,const char*>(false,nullptr);
        if (!strncmp(ACSloc.c_str(), "https://", 8)) {
        	ix = ACS->getString("sslIndex");
        	if (!ix.first)
        		ix = ACS->getString("index");
        }
        else {
        	ix = ACS->getString("index");
        }
        in.addmember("acsIndex").string(ix.second);
        if (false)
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
        if (false)
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
    out = send(request, in);
    return unwrap(request, out);
}

pair<bool,long> SAML2SessionInitiator::unwrap(SPRequest& request, DDF& out) const
{
    // See if there's any response to send back.
    if (!out["redirect"].isnull() || !out["response"].isnull()) {
        // If so, we're responsible for handling the POST data, probably by dropping a cookie.
        preservePostData(request, out["RelayState"].string());
    }
    return RemotedHandler::unwrap(request, out);
}

void SAML2SessionInitiator::receive(DDF& in, ostream& out)
{
    /*
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
    scoped_ptr<HTTPResponse> http(getResponse(*app, ret));

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
        in["attributeIndex"].string(),
        (in["artifact"].integer() != 0),
        in["acsLocation"].string(), bind.get(),
        in["isPassive"].integer() == 1,
        in["forceAuthn"].integer() == 1,
        in["authnContextClassRef"].string(),
        in["authnContextComparison"].string(),
        in["NameIDFormat"].string(),
        in["SPNameQualifier"].string(),
        in["template"].string(),
        in["outgoingBinding"].string(),
        relayState
        );
    if (!ret.isstruct())
        ret.structure();
    ret.addmember("RelayState").unsafe_string(relayState.c_str());
    out << ret;
    */
}

pair<bool,long> SAML2SessionInitiator::doRequest(
    SPRequest& request,
    const char* entityID,
    const XMLCh* acsIndex,
    const char* attributeIndex,
    bool artifactInbound,
    const char* acsLocation,
    const XMLCh* acsBinding,
    bool isPassive,
    bool forceAuthn,
    const char* authnContextClassRef,
    const char* authnContextComparison,
    const char* NameIDFormat,
    const char* SPNameQualifier,
    const char* requestTemplate,
    const char* outgoingBinding,
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
            if (outgoingBinding && *b != outgoingBinding)
                continue;
            auto_ptr_XMLCh wideb(b->c_str());
            ep = EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(wideb.get());
            if (ep) {
                map< string,boost::shared_ptr<MessageEncoder> >::const_iterator enc = m_encoders.find(*b);
                if (enc != m_encoders.end()) {
                    encoder = enc->second.get();
                }
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

    const PropertySet* relyingParty = app.getRelyingParty(entity.first);

    auto_ptr<AuthnRequest> req;

    if (requestTemplate) {
        XMLSize_t x;
        XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(requestTemplate), &x);
        if (decoded) {
            istringstream is(reinterpret_cast<char*>(decoded));
            XMLString::release((char**)&decoded);
            DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(is);
            XercesJanitor<DOMDocument> docjanitor(doc);
            auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
            docjanitor.release();
            if (!dynamic_cast<AuthnRequest*>(xmlObject.get())) {
                throw FatalProfileException("Template parameter was not a SAML AuthnRequest");
            }
            req.reset(dynamic_cast<AuthnRequest*>(xmlObject.release()));
        }
        else {
            throw FatalProfileException("Unable to base64-eecode AuthnRequest template");
        }
    }
    else {
        req.reset(m_requestTemplate ? m_requestTemplate->cloneAuthnRequest() : AuthnRequestBuilder::buildAuthnRequest());
    }

    if (requestTemplate || m_requestTemplate) {
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
        issuer->setName(relyingParty->getXMLString("entityID").second);
    }
    if (!req->getNameIDPolicy()) {
        NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
        req->setNameIDPolicy(namepol);
        namepol->AllowCreate(true);
    }

    // Format may be specified, or inferred from RelyingParty.
    if (NameIDFormat && *NameIDFormat) {
        auto_ptr_XMLCh wideform(NameIDFormat);
        req->getNameIDPolicy()->setFormat(wideform.get());
    }
    else {
        pair<bool,const XMLCh*> rpFormat = relyingParty->getXMLString("NameIDFormat");
        if (rpFormat.first)
            req->getNameIDPolicy()->setFormat(rpFormat.second);
    }

    // SPNameQualifier may be specified, or inferred from RelyingParty.
    if (SPNameQualifier && *SPNameQualifier) {
        auto_ptr_XMLCh widequal(SPNameQualifier);
        req->getNameIDPolicy()->setSPNameQualifier(widequal.get());
    }
    else {
        pair<bool,const XMLCh*> rpQual = relyingParty->getXMLString("SPNameQualifier");
        if (rpQual.first)
            req->getNameIDPolicy()->setSPNameQualifier(rpQual.second);
    }

    // AttributeConsumingService may be specified, or inferred from RelyingParty.
    if (attributeIndex && *attributeIndex) {
        auto_ptr_XMLCh wideacs(attributeIndex);
        req->setAttributeConsumingServiceIndex(wideacs.get());
    }
    else {
        pair<bool,const XMLCh*> attrIndex = relyingParty->getXMLString("attributeIndex");
        if (attrIndex.first)
            req->setAttributeConsumingServiceIndex(attrIndex.second);
    }

    // If no specified AC class, infer from RelyingParty.
    if (!authnContextClassRef || !*authnContextClassRef) {
        pair<bool,const char*> rpContextClassRef = relyingParty->getString("authnContextClassRef");
        if (rpContextClassRef.first)
            authnContextClassRef = rpContextClassRef.second;
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
            trim(dup);
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
        } else {
            pair<bool,const XMLCh*> rpComp = relyingParty->getXMLString("authnContextComparison");
            if (rpComp.first)
                reqContext->setComparison(rpComp.second);
        }
    }

    pair<bool,bool> requestDelegation = getBool("requestDelegation");
    if (!requestDelegation.first)
        requestDelegation = relyingParty->getBool("requestDelegation");

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

    auto_ptr_char dest(ep ? ep->getLocation() : nullptr);

    if (httpRequest) {
        // If the request object is available, we're responsible for the POST data.
        preservePostData(app, *httpRequest, httpResponse, relayState.c_str());
    }

    long ret = sendMessage(
        *encoder,
        req.get(),
        relayState.c_str(),
        dest.get(),
        role,
        app,
        httpResponse,
        (role && role->WantAuthnRequestsSigned()) ? "true" : "false"
        );
    req.release();  // freed by encoder
    return make_pair(true, ret);
#else
    return make_pair(false, 0L);
#endif
}
