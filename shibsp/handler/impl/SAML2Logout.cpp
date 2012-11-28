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
 * SAML2Logout.cpp
 *
 * Handles SAML 2.0 single logout protocol messages.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutHandler.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include "SessionCacheEx.h"
# include "security/SecurityPolicy.h"
# include "security/SecurityPolicyProvider.h"
# include "metadata/MetadataProviderCriteria.h"
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

    class SHIBSP_DLLLOCAL SAML2Logout : public AbstractHandler, public LogoutHandler
    {
    public:
        SAML2Logout(const DOMElement* e, const char* appId);
        virtual ~SAML2Logout() {}

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
            SingleLogoutService* ep = SingleLogoutServiceBuilder::buildSingleLogoutService();
            ep->setLocation(widen.get());
            ep->setBinding(getXMLString("Binding").second);
            role.getSingleLogoutServices().push_back(ep);
            role.addSupport(samlconstants::SAML20P_NS);
        }

        const char* getType() const {
            return "SingleLogoutService";
        }
#endif
        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML20P_NS;
        }

    private:
        pair<bool,long> doRequest(const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse) const;

#ifndef SHIBSP_LITE
        pair<bool,long> sendResponse(
            LogoutEvent* logoutEvent,
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

        LogoutEvent* newLogoutEvent(
            const Application& application, const HTTPRequest* request=nullptr, const Session* session=nullptr
            ) const {
            LogoutEvent* e = LogoutHandler::newLogoutEvent(application, request, session);
            if (e)
                e->m_protocol = m_protocol.get();
            return e;
        }

        scoped_ptr<MessageDecoder> m_decoder;
        vector<string> m_bindings;
        map< string,boost::shared_ptr<MessageEncoder> > m_encoders;
        auto_ptr_char m_protocol;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2LogoutFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2Logout(p.first, p.second);
    }
};

SAML2Logout::SAML2Logout(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".Logout.SAML2"))
#ifndef SHIBSP_LITE
        ,m_protocol(samlconstants::SAML20P_NS)
#endif
{
    m_initiator = false;
#ifndef SHIBSP_LITE
    m_preserve.push_back("ID");
    m_preserve.push_back("entityID");
    m_preserve.push_back("RelayState");

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

pair<bool,long> SAML2Logout::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first.
    // This won't initiate the loop, only continue/end it.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

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

void SAML2Logout::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
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

pair<bool,long> SAML2Logout::doRequest(const Application& application, const HTTPRequest& request, HTTPResponse& response) const
{
#ifndef SHIBSP_LITE
    // First capture the active session ID.
    SessionCache* cache = application.getServiceProvider().getSessionCache();
    SessionCacheEx* cacheex = dynamic_cast<SessionCacheEx*>(cache);
    string session_id = cache->active(application, request);

    scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(application, &request));
    if (logout_event.get() && !session_id.empty())
        logout_event->m_sessions.push_back(session_id);

    if (!strcmp(request.getMethod(),"GET") && request.getParameter("notifying")) {
        // This is returning from a front-channel notification, so we have to do the back-channel and then
        // respond. To do that, we need state from the original request.
        if (!request.getParameter("entityID")) {
            cache->remove(application, request, &response);
            throw FatalProfileException("Application notification loop did not return entityID for LogoutResponse.");
        }

        // Best effort on back channel and to remove the user agent's session.
        bool worked1 = false,worked2 = false;
        if (!session_id.empty()) {
            vector<string> sessions(1,session_id);
            worked1 = notifyBackChannel(application, request.getRequestURL(), sessions, false);
            try {
                cache->remove(application, request, &response);
                worked2 = true;
            }
            catch (std::exception& ex) {
                m_log.error("error removing session (%s): %s", session_id.c_str(), ex.what());
            }
        }
        else {
            worked1 = worked2 = true;
        }

        // We need metadata to issue a response.
        MetadataProvider* m = application.getMetadataProvider();
        Locker metadataLocker(m);
        MetadataProviderCriteria mc(
            application, request.getParameter("entityID"), &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS
            );
        pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
        if (!entity.first) {
            throw MetadataException(
                "Unable to locate metadata for identity provider ($entityID)",
                namedparams(1, "entityID", request.getParameter("entityID"))
                );
        }
        else if (!entity.second) {
            throw MetadataException(
                "Unable to locate SAML 2.0 IdP role for identity provider ($entityID).",
                namedparams(1, "entityID", request.getParameter("entityID"))
                );
        }

        auto_ptr_XMLCh reqid(request.getParameter("ID"));
        if (worked1 && worked2) {
            // Successful LogoutResponse. Has to be front-channel or we couldn't be here.
            if (logout_event.get())
                logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_GLOBAL;
            return sendResponse(
                logout_event.get(),
                reqid.get(),
                StatusCode::SUCCESS, nullptr, nullptr,
                request.getParameter("RelayState"),
                entity.second,
                application,
                response,
                true
                );
        }

        return sendResponse(
            logout_event.get(),
            reqid.get(),
            StatusCode::RESPONDER, nullptr, "Unable to fully destroy principal's session.",
            request.getParameter("RelayState"),
            entity.second,
            application,
            response,
            true
            );
    }

    // If we get here, it's an external protocol message to decode.

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
    const LogoutRequest* logoutRequest = dynamic_cast<LogoutRequest*>(msg.get());
    if (logoutRequest) {
        if (!policy->isAuthenticated())
            throw SecurityPolicyException("Security of LogoutRequest not established.");

        if (logout_event) {
            logout_event->m_saml2Request = logoutRequest;
            if (policy->getIssuerMetadata())
                logout_event->m_peer = dynamic_cast<const EntityDescriptor*>(policy->getIssuerMetadata()->getParent());
            application.getServiceProvider().getTransactionLog()->write(*logout_event);
            logout_event->m_saml2Request = nullptr;
        }

        // Message from IdP to logout one or more sessions.
        // Extract the NameID from the request, decrypting it if needed.

        scoped_ptr<XMLObject> decryptedID;
        NameID* nameid = logoutRequest->getNameID();
        if (!nameid) {
            // Check for EncryptedID.
            EncryptedID* encname = logoutRequest->getEncryptedID();
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
                        decryptedID.reset(
                            encname->decrypt(
                                *cr,
                                application.getRelyingParty(
                                    policy->getIssuerMetadata() ?
                                        dynamic_cast<EntityDescriptor*>(policy->getIssuerMetadata()->getParent()) :
                                            nullptr)->getXMLString("entityID").second,
                                mcc.get()
                                )
                            );
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
                logout_event.get(),
                logoutRequest->getID(),
                StatusCode::REQUESTER, StatusCode::UNKNOWN_PRINCIPAL, "NameID not found in request.",
                relayState.c_str(),
                policy->getIssuerMetadata(),
                application,
                response,
                m_decoder->isUserAgentPresent()
                );
        }

        // Suck indexes out of the request for next steps.
        set<string> indexes;
        EntityDescriptor* entity =
            policy->getIssuerMetadata() ? dynamic_cast<EntityDescriptor*>(policy->getIssuerMetadata()->getParent()) : nullptr;
        const vector<SessionIndex*> sindexes = logoutRequest->getSessionIndexs();
        for (indirect_iterator<vector<SessionIndex*>::const_iterator> i = make_indirect_iterator(sindexes.begin());
                i != make_indirect_iterator(sindexes.end()); ++i) {
            auto_ptr_char sindex(i->getSessionIndex());
            indexes.insert(sindex.get());
        }

        // For a front-channel LogoutRequest, we have to match the information in the request
        // against the current session, if one is known/available.
        if (!session_id.empty()) {
            if (!cache->matches(application, request, entity, *nameid, &indexes)) {
                return sendResponse(
                    logout_event.get(),
                    logoutRequest->getID(),
                    StatusCode::REQUESTER, StatusCode::REQUEST_DENIED, "Active session did not match logout request.",
                    relayState.c_str(),
                    policy->getIssuerMetadata(),
                    application,
                    response,
                    true
                    );
            }
        }
        else if (m_decoder->isUserAgentPresent()) {
            m_log.info("processing front channel logout request with no active session");
        }

        // Now we perform "logout" by finding the matching sessions.
        vector<string> sessions;
        try {
            if (cacheex) {
                time_t expires = logoutRequest->getNotOnOrAfter() ? logoutRequest->getNotOnOrAfterEpoch() : 0;
                cacheex->logout(application, entity, *nameid, &indexes, expires, sessions);
                m_log.debug("session cache returned %d sessions bound to NameID in logout request", sessions.size());

                // Now we actually terminate everything except for the active session,
                // if this is front-channel, for notification purposes.
                for (vector<string>::const_iterator sit = sessions.begin(); sit != sessions.end(); ++sit)
                    if (*sit != session_id)
                        cacheex->remove(application, sit->c_str()); // using the ID-based removal operation
            }
            else {
                m_log.warn("session cache does not support extended API, can't implement indirect logout of sessions");
                if (!session_id.empty())
                    sessions.push_back(session_id);
            }
        }
        catch (std::exception& ex) {
            m_log.error("error while logging out matching sessions: %s", ex.what());
            if (logout_event) {
                logout_event->m_nameID = nameid;
                logout_event->m_sessions = sessions;
                logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_PARTIAL;
            }
            return sendResponse(
                logout_event.get(),
                logoutRequest->getID(),
                StatusCode::RESPONDER, nullptr, ex.what(),
                relayState.c_str(),
                policy->getIssuerMetadata(),
                application,
                response,
                m_decoder->isUserAgentPresent()
                );
        }

        if (m_decoder->isUserAgentPresent()) {
            if (!session_id.empty()) {
                // Pass control to the first front channel notification point, if any.
                map<string,string> parammap;
                if (!relayState.empty())
                    parammap["RelayState"] = relayState;
                auto_ptr_char entityID(entity ? entity->getEntityID() : nullptr);
                if (entityID.get())
                    parammap["entityID"] = entityID.get();
                auto_ptr_char reqID(logoutRequest->getID());
                if (reqID.get())
                    parammap["ID"] = reqID.get();
                pair<bool,long> result = notifyFrontChannel(application, request, response, &parammap);
                if (result.first)
                    return result;
            }
            else {
                m_log.info("client's session isn't available, skipping front-channel notifications");
            }
        }

        // For back-channel requests, or if no front-channel notification is needed or possible...
        bool worked1 = notifyBackChannel(application, request.getRequestURL(), sessions, false);
        bool worked2 = true;
        if (!session_id.empty()) {
            // One last session to yoink...
            try {
                cache->remove(application, request, &response);
            }
            catch (std::exception& ex) {
                worked2 = false;
                m_log.error("error removing active session (%s): %s", session_id.c_str(), ex.what());
            }
        }

        if (logout_event) {
            logout_event->m_nameID = nameid;
            logout_event->m_sessions = sessions;
            logout_event->m_logoutType = (worked1 && worked2) ? LogoutEvent::LOGOUT_EVENT_PARTIAL : LogoutEvent::LOGOUT_EVENT_GLOBAL;
        }
        return sendResponse(
            logout_event.get(),
            logoutRequest->getID(),
            (worked1 && worked2) ? StatusCode::SUCCESS : StatusCode::RESPONDER,
            (worked1 && worked2) ? nullptr : StatusCode::PARTIAL_LOGOUT,
            nullptr,
            relayState.c_str(),
            policy->getIssuerMetadata(),
            application,
            response,
            m_decoder->isUserAgentPresent()
            );
    }

    // A LogoutResponse completes an SP-initiated logout sequence.
    const LogoutResponse* logoutResponse = dynamic_cast<LogoutResponse*>(msg.get());
    if (logoutResponse) {
        if (!policy->isAuthenticated()) {
            SecurityPolicyException ex("Security of LogoutResponse not established.");
            annotateException(&ex, policy->getIssuerMetadata()); // throws it
        }
 
        if (logout_event) {
            logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_PARTIAL;
            logout_event->m_saml2Response = logoutResponse;
            if (policy->getIssuerMetadata())
                logout_event->m_peer = dynamic_cast<const EntityDescriptor*>(policy->getIssuerMetadata()->getParent());
        }

        try {
            checkError(logoutResponse, policy->getIssuerMetadata()); // throws if Status doesn't look good...
        }
        catch (std::exception& ex) {
            if (logout_event) {
                logout_event->m_exception = &ex;
                application.getServiceProvider().getTransactionLog()->write(*logout_event);
            }
            throw;
        }

        // If relay state is set, recover the original return URL.
        if (!relayState.empty())
            recoverRelayState(application, request, response, relayState);

        // Check for partial logout.
        const StatusCode* sc = logoutResponse->getStatus() ? logoutResponse->getStatus()->getStatusCode() : nullptr;
        sc = sc ? sc->getStatusCode() : nullptr;
        if (sc && XMLString::equals(sc->getValue(), StatusCode::PARTIAL_LOGOUT)) {
            if (logout_event)
                application.getServiceProvider().getTransactionLog()->write(*logout_event);
            return sendLogoutPage(application, request, response, "partial");
        }

        if (logout_event) {
            logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_GLOBAL;
            application.getServiceProvider().getTransactionLog()->write(*logout_event);
        }

        if (!relayState.empty()) {
            application.limitRedirect(request, relayState.c_str());
            return make_pair(true, response.sendRedirect(relayState.c_str()));
        }

        // Return template for completion of logout.
        return sendLogoutPage(application, request, response, "global");
    }

    FatalProfileException ex("Incoming message was not a samlp:LogoutRequest or samlp:LogoutResponse.");
    if (policy->getIssuerMetadata())
        annotateException(&ex, policy->getIssuerMetadata()); // throws it
    ex.raise();
    return make_pair(false,0L);  // never happen, satisfies compiler
#else
    throw ConfigurationException("Cannot process logout message using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

pair<bool,long> SAML2Logout::sendResponse(
    LogoutEvent* logoutEvent,
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
            if ((ep = EndpointManager<SingleLogoutService>(idp->getSingleLogoutServices()).getByBinding(wideb.get()))) {
                map< string,boost::shared_ptr<MessageEncoder> >::const_iterator enc = m_encoders.find(*b);
                if (enc != m_encoders.end())
                    encoder = enc->second.get();
                break;
            }
        }
        if (!ep || !encoder) {
            auto_ptr_char id(dynamic_cast<EntityDescriptor*>(role->getParent())->getEntityID());
            m_log.error("unable to locate compatible SLO service for provider (%s)", id.get());
            MetadataException ex("Unable to locate endpoint at IdP ($entityID) to send LogoutResponse.");
            annotateException(&ex, role);   // throws it
        }
    }
    else {
        encoder = m_encoders.begin()->second.get();
    }

    // Prepare response.
    auto_ptr<LogoutResponse> logout(LogoutResponseBuilder::buildLogoutResponse());
    logout->setInResponseTo(requestID);
    if (ep) {
        const XMLCh* loc = ep->getResponseLocation();
        if (!loc || !*loc)
            loc = ep->getLocation();
        logout->setDestination(loc);
    }
    Issuer* issuer = IssuerBuilder::buildIssuer();
    logout->setIssuer(issuer);
    issuer->setName(application.getRelyingParty(dynamic_cast<EntityDescriptor*>(role->getParent()))->getXMLString("entityID").second);
    fillStatus(*logout, code, subcode, msg);
    XMLCh* msgid = SAMLConfig::getConfig().generateIdentifier();
    logout->setID(msgid);
    XMLString::release(&msgid);
    logout->setIssueInstant(time(nullptr));

    if (logoutEvent) {
        logoutEvent->m_peer = dynamic_cast<EntityDescriptor*>(role->getParent());
        logoutEvent->m_saml2Response = logout.get();
        application.getServiceProvider().getTransactionLog()->write(*logoutEvent);
    }

    auto_ptr_char dest(logout->getDestination());
    long ret = sendMessage(*encoder, logout.get(), relayState, dest.get(), role, application, httpResponse, front);
    logout.release();  // freed by encoder
    return make_pair(true, ret);
}

#endif
