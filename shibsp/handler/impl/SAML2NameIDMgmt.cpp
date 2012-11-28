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
 * SAML2NameIDMgmt.cpp
 *
 * Handles SAML 2.0 NameID management protocol messages.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include "SessionCache.h"
# include "security/SecurityPolicy.h"
# include "security/SecurityPolicyProvider.h"
# include <fstream>
# include <boost/algorithm/string.hpp>
# include <boost/iterator/indirect_iterator.hpp>
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
# include <xmltooling/util/URLEncoder.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
#else
# include "lite/SAMLConstants.h"
#endif

#include <boost/scoped_ptr.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2NameIDMgmt : public AbstractHandler, public RemotedHandler
    {
    public:
        SAML2NameIDMgmt(const DOMElement* e, const char* appId);
        virtual ~SAML2NameIDMgmt() {}

        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        void generateMetadata(SPSSODescriptor& role, const char* handlerURL) const {
            const char* loc = getString("Location").second;
            string hurl(handlerURL);
            if (*loc != '/')
                hurl += '/';
            hurl += loc;
            auto_ptr_XMLCh widen(hurl.c_str());
            ManageNameIDService* ep = ManageNameIDServiceBuilder::buildManageNameIDService();
            ep->setLocation(widen.get());
            ep->setBinding(getXMLString("Binding").second);
            role.getManageNameIDServices().push_back(ep);
            role.addSupport(samlconstants::SAML20P_NS);
        }

        const char* getType() const {
            return "ManageNameIDService";
        }
#endif
        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML20P_NS;
        }

    private:
        pair<bool,long> doRequest(const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse) const;

#ifndef SHIBSP_LITE
        bool notifyBackChannel(const Application& application, const char* requestURL, const NameID& nameid, const NewID* newid) const;

        pair<bool,long> sendResponse(
            const XMLCh* requestID,
            const XMLCh* code,
            const XMLCh* subcode,
            const char* msg,
            const char* relayState,
            const RoleDescriptor* role,
            const Application& application,
            HTTPResponse& httpResponse,
            bool front
            ) const;

        scoped_ptr<MessageDecoder> m_decoder;
        vector<string> m_bindings;
        map< string,boost::shared_ptr<MessageEncoder> > m_encoders;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2NameIDMgmtFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2NameIDMgmt(p.first, p.second);
    }
};

SAML2NameIDMgmt::SAML2NameIDMgmt(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".NameIDMgmt.SAML2"))
{
#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        SAMLConfig& conf = SAMLConfig::getConfig();

        // Handle incoming binding.
        m_decoder.reset(
            conf.MessageDecoderManager.newPlugin(
                getString("Binding").second, pair<const DOMElement*,const XMLCh*>(e,shibspconstants::SHIB2SPCONFIG_NS)
                )
            );
        m_decoder->setArtifactResolver(SPConfig::getConfig().getArtifactResolver());

        if (m_decoder->isUserAgentPresent()) {
            // Handle front-channel binding setup.
            string dupBindings;
            pair<bool,const char*> outgoing = getString("outgoingBindings", m_configNS.get());
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
                        conf.MessageEncoderManager.newPlugin(*b, pair<const DOMElement*,const XMLCh*>(e,shibspconstants::SHIB2SPCONFIG_NS))
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
        else {
            pair<bool,const char*> b = getString("Binding");
            boost::shared_ptr<MessageEncoder> encoder(
                conf.MessageEncoderManager.newPlugin(b.second, pair<const DOMElement*,const XMLCh*>(e,shibspconstants::SHIB2SPCONFIG_NS))
                );
            m_encoders[b.second] = encoder;
        }
    }
#endif

    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());
}

pair<bool,long> SAML2NameIDMgmt::run(SPRequest& request, bool isHandler) const
{
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively and directly process the message.
        return doRequest(request.getApplication(), request, request);
    }
    else {
        // When not out of process, we remote all the message processing.
        vector<string> headers(1,"Cookie");
        headers.push_back("User-Agent");
        DDF out,in = wrap(request, &headers, true);
        DDFJanitor jin(in), jout(out);
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void SAML2NameIDMgmt::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for NameID mgmt", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for NameID mgmt, deleted?");
    }

    // Unpack the request.
    scoped_ptr<HTTPRequest> req(getRequest(in));

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, *req, *resp);
    out << ret;
}

pair<bool,long> SAML2NameIDMgmt::doRequest(const Application& application, const HTTPRequest& request, HTTPResponse& response) const
{
#ifndef SHIBSP_LITE
    SessionCache* cache = application.getServiceProvider().getSessionCache();

    // Locate policy key.
    pair<bool,const char*> policyId = getString("policyId", m_configNS.get());  // may be namespace-qualified inside handler element
    if (!policyId.first)
        policyId = getString("policyId");   // try unqualified
    if (!policyId.first)
        policyId = application.getString("policyId");   // unqualified in Application(s) element

    // Lock metadata for use by policy.
    Locker metadataLocker(application.getMetadataProvider());

    // Create the policy.
    scoped_ptr<SecurityPolicy> policy(
        application.getServiceProvider().getSecurityPolicyProvider()->createSecurityPolicy(application, &IDPSSODescriptor::ELEMENT_QNAME, policyId.second)
        );

    // Decode the message.
    string relayState;
    scoped_ptr<XMLObject> msg(m_decoder->decode(relayState, request, *policy));
    const ManageNameIDRequest* mgmtRequest = dynamic_cast<ManageNameIDRequest*>(msg.get());
    if (mgmtRequest) {
        if (!policy->isAuthenticated())
            throw SecurityPolicyException("Security of ManageNameIDRequest not established.");

        // Message from IdP to change or terminate a NameID.

        // If this is front-channel, we have to have a session_id to use already.
        string session_id = cache->active(application, request);
        if (m_decoder->isUserAgentPresent() && session_id.empty()) {
            m_log.error("no active session");
            return sendResponse(
                mgmtRequest->getID(),
                StatusCode::REQUESTER, StatusCode::UNKNOWN_PRINCIPAL, "No active session found in request.",
                relayState.c_str(),
                policy->getIssuerMetadata(),
                application,
                response,
                true
                );
        }

        EntityDescriptor* entity = policy->getIssuerMetadata() ? dynamic_cast<EntityDescriptor*>(policy->getIssuerMetadata()->getParent()) : nullptr;

        scoped_ptr<XMLObject> decryptedID;
        NameID* nameid = mgmtRequest->getNameID();
        if (!nameid) {
            // Check for EncryptedID.
            EncryptedID* encname = mgmtRequest->getEncryptedID();
            if (encname) {
                CredentialResolver* cr=application.getCredentialResolver();
                if (!cr)
                    m_log.warn("found encrypted NameID, but no decryption credential was available");
                else {
                    Locker credlocker(cr);
                    scoped_ptr<MetadataCredentialCriteria> mcc(
                        policy->getIssuerMetadata() ? new MetadataCredentialCriteria(*policy->getIssuerMetadata()) : nullptr
                        );
                    try {
                        decryptedID.reset(encname->decrypt(*cr, application.getRelyingParty(entity)->getXMLString("entityID").second, mcc.get()));
                        nameid = dynamic_cast<NameID*>(decryptedID.get());
                    }
                    catch (std::exception& ex) {
                        m_log.error(ex.what());
                    }
                }
            }
        }
        if (!nameid) {
            // No NameID, so must respond with an error.
            m_log.error("NameID not found in request");
            return sendResponse(
                mgmtRequest->getID(),
                StatusCode::REQUESTER, StatusCode::UNKNOWN_PRINCIPAL, "NameID not found in request.",
                relayState.c_str(),
                policy->getIssuerMetadata(),
                application,
                response,
                m_decoder->isUserAgentPresent()
                );
        }

        // For a front-channel request, we have to match the information in the request
        // against the current session.
        if (!session_id.empty()) {
            if (!cache->matches(application, request, entity, *nameid, nullptr)) {
                return sendResponse(
                    mgmtRequest->getID(),
                    StatusCode::REQUESTER, StatusCode::REQUEST_DENIED, "Active session did not match NameID mgmt request.",
                    relayState.c_str(),
                    policy->getIssuerMetadata(),
                    application,
                    response,
                    true
                    );
            }

        }

        // Determine what's happening...
        scoped_ptr<XMLObject> newDecryptedID;
        NewID* newid = nullptr;
        if (!mgmtRequest->getTerminate()) {
            // Better be a NewID in there.
            newid = mgmtRequest->getNewID();
            if (!newid) {
                // Check for NewEncryptedID.
                NewEncryptedID* encnewid = mgmtRequest->getNewEncryptedID();
                if (encnewid) {
                    CredentialResolver* cr=application.getCredentialResolver();
                    if (!cr)
                        m_log.warn("found encrypted NewID, but no decryption credential was available");
                    else {
                        Locker credlocker(cr);
                        scoped_ptr<MetadataCredentialCriteria> mcc(
                            policy->getIssuerMetadata() ? new MetadataCredentialCriteria(*policy->getIssuerMetadata()) : nullptr
                            );
                        try {
                            newDecryptedID.reset(encnewid->decrypt(*cr, application.getRelyingParty(entity)->getXMLString("entityID").second, mcc.get()));
                            newid = dynamic_cast<NewID*>(newDecryptedID.get());
                        }
                        catch (std::exception& ex) {
                            m_log.error(ex.what());
                        }
                    }
                }
            }

            if (!newid) {
                // No NewID, so must respond with an error.
                m_log.error("NewID not found in request");
                return sendResponse(
                    mgmtRequest->getID(),
                    StatusCode::REQUESTER, nullptr, "NewID not found in request.",
                    relayState.c_str(),
                    policy->getIssuerMetadata(),
                    application,
                    response,
                    m_decoder->isUserAgentPresent()
                    );
            }
        }

        // TODO: maybe support in-place modification of sessions?
        /*
        vector<string> sessions;
        try {
            time_t expires = logoutRequest->getNotOnOrAfter() ? logoutRequest->getNotOnOrAfterEpoch() : 0;
            cache->logout(entity, *nameid, &indexes, expires, application, sessions);

            // Now we actually terminate everything except for the active session,
            // if this is front-channel, for notification purposes.
            for (vector<string>::const_iterator sit = sessions.begin(); sit != sessions.end(); ++sit)
                if (session_id && strcmp(sit->c_str(), session_id))
                    cache->remove(sit->c_str(), application);
        }
        catch (exception& ex) {
            m_log.error("error while logging out matching sessions: %s", ex.what());
            return sendResponse(
                logoutRequest->getID(),
                StatusCode::RESPONDER, nullptr, ex.what(),
                relayState.c_str(),
                policy.getIssuerMetadata(),
                application,
                response,
                m_decoder->isUserAgentPresent()
                );
        }
        */

        // Do back-channel app notifications.
        // Not supporting front-channel due to privacy concerns.
        bool worked = notifyBackChannel(application, request.getRequestURL(), *nameid, newid);

        return sendResponse(
            mgmtRequest->getID(),
            worked ? StatusCode::SUCCESS : StatusCode::RESPONDER,
            nullptr,
            nullptr,
            relayState.c_str(),
            policy->getIssuerMetadata(),
            application,
            response,
            m_decoder->isUserAgentPresent()
            );
    }

    // A ManageNameIDResponse completes an SP-initiated sequence, currently not supported.
    /*
    const ManageNameIDResponse* mgmtResponse = dynamic_cast<ManageNameIDResponse*>(msg.get());
    if (mgmtResponse) {
        if (!policy.isAuthenticated()) {
            SecurityPolicyException ex("Security of ManageNameIDResponse not established.");
            if (policy.getIssuerMetadata())
                annotateException(&ex, policy.getIssuerMetadata()); // throws it
            ex.raise();
        }
        checkError(mgmtResponse, policy.getIssuerMetadata()); // throws if Status doesn't look good...

        // Return template for completion.
        return sendLogoutPage(application, response, false, "Global logout completed.");
    }
    */

    FatalProfileException ex("Incoming message was not a samlp:ManageNameIDRequest.");
    annotateException(&ex, policy->getIssuerMetadata()); // throws it
    return make_pair(false, 0L);  // never happen, satisfies compiler
#else
    throw ConfigurationException("Cannot process NameID mgmt message using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

pair<bool,long> SAML2NameIDMgmt::sendResponse(
    const XMLCh* requestID,
    const XMLCh* code,
    const XMLCh* subcode,
    const char* msg,
    const char* relayState,
    const RoleDescriptor* role,
    const Application& application,
    HTTPResponse& httpResponse,
    bool front
    ) const
{
    // Get endpoint and encoder to use.
    const EndpointType* ep = nullptr;
    const MessageEncoder* encoder = nullptr;
    if (front) {
        const IDPSSODescriptor* idp = dynamic_cast<const IDPSSODescriptor*>(role);
        for (vector<string>::const_iterator b = m_bindings.begin(); idp && b != m_bindings.end(); ++b) {
            auto_ptr_XMLCh wideb(b->c_str());
            if ((ep = EndpointManager<ManageNameIDService>(idp->getManageNameIDServices()).getByBinding(wideb.get()))) {
                map< string,boost::shared_ptr<MessageEncoder> >::const_iterator enc = m_encoders.find(*b);
                if (enc != m_encoders.end())
                    encoder = enc->second.get();
                break;
            }
        }
        if (!ep || !encoder) {
            auto_ptr_char id(dynamic_cast<EntityDescriptor*>(role->getParent())->getEntityID());
            m_log.error("unable to locate compatible NIM service for provider (%s)", id.get());
            MetadataException ex("Unable to locate endpoint at IdP ($entityID) to send ManageNameIDResponse.");
            annotateException(&ex, role);   // throws it
        }
    }
    else {
        encoder = m_encoders.begin()->second.get();
    }

    // Prepare response.
    auto_ptr<ManageNameIDResponse> nim(ManageNameIDResponseBuilder::buildManageNameIDResponse());
    nim->setInResponseTo(requestID);
    if (ep) {
        const XMLCh* loc = ep->getResponseLocation();
        if (!loc || !*loc)
            loc = ep->getLocation();
        nim->setDestination(loc);
    }
    Issuer* issuer = IssuerBuilder::buildIssuer();
    nim->setIssuer(issuer);
    issuer->setName(application.getRelyingParty(dynamic_cast<EntityDescriptor*>(role->getParent()))->getXMLString("entityID").second);
    fillStatus(*nim, code, subcode, msg);

    auto_ptr_char dest(nim->getDestination());

    long ret = sendMessage(*encoder, nim.get(), relayState, dest.get(), role, application, httpResponse);
    nim.release();  // freed by encoder
    return make_pair(true, ret);
}

#include "util/SPConstants.h"
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/soap/SOAPClient.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
using namespace soap11;
namespace {
    static const XMLCh NameIDNotification[] =   UNICODE_LITERAL_18(N,a,m,e,I,D,N,o,t,i,f,i,c,a,t,i,o,n);

    class SHIBSP_DLLLOCAL SOAPNotifier : public soap11::SOAPClient
    {
    public:
        SOAPNotifier() {}
        virtual ~SOAPNotifier() {}
    private:
        void prepareTransport(SOAPTransport& transport) {
            transport.setVerifyHost(false);
            HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(&transport);
            if (http) {
                http->useChunkedEncoding(false);
                http->setRequestHeader(PACKAGE_NAME, PACKAGE_VERSION);
            }
        }
    };
};

bool SAML2NameIDMgmt::notifyBackChannel(
    const Application& application, const char* requestURL, const NameID& nameid, const NewID* newid
    ) const
{
    unsigned int index = 0;
    string endpoint = application.getNotificationURL(requestURL, false, index++);
    if (endpoint.empty())
        return true;

    scoped_ptr<Envelope> env(EnvelopeBuilder::buildEnvelope());
    Body* body = BodyBuilder::buildBody();
    env->setBody(body);
    ElementProxy* msg = new AnyElementImpl(shibspconstants::SHIB2SPNOTIFY_NS, NameIDNotification);
    body->getUnknownXMLObjects().push_back(msg);
    msg->getUnknownXMLObjects().push_back(nameid.clone());
    if (newid)
        msg->getUnknownXMLObjects().push_back(newid->clone());
    else
        msg->getUnknownXMLObjects().push_back(TerminateBuilder::buildTerminate());

    bool result = true;
    SOAPNotifier soaper;
    while (!endpoint.empty()) {
        try {
            soaper.send(*env, SOAPTransport::Address(application.getId(), application.getId(), endpoint.c_str()));
            delete soaper.receive();
        }
        catch (std::exception& ex) {
            m_log.error("error notifying application of logout event: %s", ex.what());
            result = false;
        }
        soaper.reset();
        endpoint = application.getNotificationURL(requestURL, false, index++);
    }
    return result;
}

#endif
