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
 * SAML2LogoutInitiator.cpp
 *
 * Triggers SP-initiated logout for SAML 2.0 sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutInitiator.h"

#ifndef SHIBSP_LITE
# include "binding/SOAPClient.h"
# include "metadata/MetadataProviderCriteria.h"
# include "security/SecurityPolicy.h"
# include <boost/algorithm/string.hpp>
# include <boost/iterator/indirect_iterator.hpp>
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Protocols.h>
# include <saml/saml2/binding/SAML2SOAPClient.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataCredentialCriteria.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAML2LogoutInitiator : public AbstractHandler, public LogoutInitiator
    {
    public:
        SAML2LogoutInitiator(const DOMElement* e, const char* appId);
        virtual ~SAML2LogoutInitiator() {}

        void init(const char* location);    // encapsulates actions that need to run either in the c'tor or setParent

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML20P_NS;
        }

    private:
        pair<bool,long> doRequest(
            const Application& application, const HTTPRequest& request, HTTPResponse& httpResponse, Session* session
            ) const;

        string m_appId;
        auto_ptr_char m_protocol;
#ifndef SHIBSP_LITE
        auto_ptr<LogoutRequest> buildRequest(
            const Application& application, const Session& session, const RoleDescriptor& role, const MessageEncoder* encoder=nullptr
            ) const;

        LogoutEvent* newLogoutEvent(
            const Application& application, const HTTPRequest* request=nullptr, const Session* session=nullptr
            ) const {
            LogoutEvent* e = LogoutHandler::newLogoutEvent(application, request, session);
            if (e)
                e->m_protocol = m_protocol.get();
            return e;
        }

        bool m_async;
        vector<string> m_bindings;
        map< string,boost::shared_ptr<MessageEncoder> > m_encoders;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SAML2LogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAML2LogoutInitiator(p.first, p.second);
    }
};

SAML2LogoutInitiator::SAML2LogoutInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.SAML2")), m_appId(appId), m_protocol(samlconstants::SAML20P_NS)
#ifndef SHIBSP_LITE
        ,m_async(true)
#endif
{
    // If Location isn't set, defer initialization until the setParent call.
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        init(loc.second);
    }
}

void SAML2LogoutInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    init(loc.second);
}

void SAML2LogoutInitiator::init(const char* location)
{
    if (location) {
        string address = m_appId + location + "::run::SAML2LI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in SAML2 LogoutInitiator (or parent), can't register as remoted handler");
    }

#ifndef SHIBSP_LITE
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        pair<bool,bool> async = getBool("asynchronous");
        m_async = !async.first || async.second;

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


pair<bool,long> SAML2LogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    // At this point we know the front-channel is handled.
    // We need the session to do any other work.

    Session* session = nullptr;
    try {
        session = request.getSession(false, true, false);  // don't cache it and ignore all checks
        if (!session)
            return make_pair(false, 0L);

        // We only handle SAML 2.0 sessions.
        if (!XMLString::equals(session->getProtocol(), m_protocol.get())) {
            session->unlock();
            return make_pair(false, 0L);
        }
    }
    catch (std::exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
        return make_pair(false, 0L);
    }

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively.
        return doRequest(request.getApplication(), request, request, session);
    }
    else {
        // When not out of process, we remote the request.
        session->unlock();
        vector<string> headers(1,"Cookie");
        DDF out,in = wrap(request,&headers);
        DDFJanitor jin(in), jout(out);
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void SAML2LogoutInitiator::receive(DDF& in, ostream& out)
{
#ifndef SHIBSP_LITE
    // Defer to base class for notifications
    if (in["notify"].integer() == 1)
        return LogoutHandler::receive(in, out);

    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
    }

    // Unpack the request.
    scoped_ptr<HTTPRequest> req(getRequest(in));

    // Set up a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    Session* session = nullptr;
    try {
         session = app->getServiceProvider().getSessionCache()->find(*app, *req, nullptr, nullptr);
    }
    catch (std::exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
    }

    // With no session, we just skip the request and let it fall through to an empty struct return.
    if (session) {
        if (session->getNameID() && session->getEntityID()) {
            // Since we're remoted, the result should either be a throw, which we pass on,
            // a false/0 return, which we just return as an empty structure, or a response/redirect,
            // which we capture in the facade and send back.
            doRequest(*app, *req, *resp, session);
        }
        else {
            session->unlock();
            m_log.log(getParent() ? Priority::WARN : Priority::ERROR, "bypassing SAML 2.0 logout, no NameID or issuing entityID found in session");
            app->getServiceProvider().getSessionCache()->remove(*app, *req, resp.get());
        }
    }
    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> SAML2LogoutInitiator::doRequest(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, Session* session
    ) const
{
    Locker sessionLocker(session, false);
#ifndef SHIBSP_LITE
    scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(application, &httpRequest, session));
#endif

    // Do back channel notification.
    vector<string> sessions(1, session->getID());
    if (!notifyBackChannel(application, httpRequest.getRequestURL(), sessions, false)) {
#ifndef SHIBSP_LITE
        if (logout_event) {
            logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_PARTIAL;
            application.getServiceProvider().getTransactionLog()->write(*logout_event);
        }
#endif
        sessionLocker.assign();
        session = nullptr;
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
        return sendLogoutPage(application, httpRequest, httpResponse, "partial");
    }

#ifndef SHIBSP_LITE
    pair<bool,long> ret = make_pair(false, 0L);
    try {
        // With a session in hand, we can create a LogoutRequest message, if we can find a compatible endpoint.
        MetadataProvider* m = application.getMetadataProvider();
        Locker metadataLocker(m);
        MetadataProviderCriteria mc(application, session->getEntityID(), &IDPSSODescriptor::ELEMENT_QNAME, samlconstants::SAML20P_NS);
        pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
        if (!entity.first) {
            throw MetadataException(
                "Unable to locate metadata for identity provider ($entityID)", namedparams(1, "entityID", session->getEntityID())
                );
        }
        else if (!entity.second) {
            throw MetadataException(
                "Unable to locate SAML 2.0 IdP role for identity provider ($entityID).", namedparams(1, "entityID", session->getEntityID())
                );
        }

        const IDPSSODescriptor* role = dynamic_cast<const IDPSSODescriptor*>(entity.second);
        if (role->getSingleLogoutServices().empty()) {
            throw MetadataException(
                "No SingleLogoutService endpoints in metadata for identity provider ($entityID).", namedparams(1, "entityID", session->getEntityID())
                );
        }

        const EndpointType* ep = nullptr;
        const MessageEncoder* encoder = nullptr;
        for (vector<string>::const_iterator b = m_bindings.begin(); b != m_bindings.end(); ++b) {
            auto_ptr_XMLCh wideb(b->c_str());
            if (ep = EndpointManager<SingleLogoutService>(role->getSingleLogoutServices()).getByBinding(wideb.get())) {
                map< string,boost::shared_ptr<MessageEncoder> >::const_iterator enc = m_encoders.find(*b);
                if (enc != m_encoders.end())
                    encoder = enc->second.get();
                break;
            }
        }
        if (!ep || !encoder) {
            m_log.debug("no compatible front channel SingleLogoutService, trying back channel...");
            shibsp::SecurityPolicy policy(application);
            shibsp::SOAPClient soaper(policy);
            MetadataCredentialCriteria mcc(*role);

            LogoutResponse* logoutResponse = nullptr;
            scoped_ptr<StatusResponseType> srt;
            auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
            const vector<SingleLogoutService*>& endpoints = role->getSingleLogoutServices();
            for (indirect_iterator<vector<SingleLogoutService*>::const_iterator> epit = make_indirect_iterator(endpoints.begin());
                    !logoutResponse && epit != make_indirect_iterator(endpoints.end()); ++epit) {
                try {
                    if (!XMLString::equals(epit->getBinding(), binding.get()))
                        continue;
                    auto_ptr<LogoutRequest> msg(buildRequest(application, *session, *role));

                    // Log the request.
                    if (logout_event) {
                        logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_UNKNOWN;
                        logout_event->m_saml2Request = msg.get();
                        application.getServiceProvider().getTransactionLog()->write(*logout_event);
                        logout_event->m_saml2Request = nullptr;
                    }

                    auto_ptr_char dest(epit->getLocation());
                    SAML2SOAPClient client(soaper, false);
                    client.sendSAML(msg.release(), application.getId(), mcc, dest.get());
                    srt.reset(client.receiveSAML());
                    if (!(logoutResponse = dynamic_cast<LogoutResponse*>(srt.get()))) {
                        break;
                    }
                }
                catch (std::exception& ex) {
                    m_log.error("error sending LogoutRequest message: %s", ex.what());
                    soaper.reset();
                }
            }

            // No answer at all?
            if (!logoutResponse) {
                if (endpoints.empty())
                    m_log.info("IdP doesn't support single logout protocol over a compatible binding");
                else
                    m_log.warn("IdP didn't respond to logout request");

                // Log the end result.
                if (logout_event) {
                    logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_PARTIAL;
                    application.getServiceProvider().getTransactionLog()->write(*logout_event);
                }

                ret = sendLogoutPage(application, httpRequest, httpResponse, "partial");
            }
            else {
                // Check the status, looking for non-success or a partial logout code.
                const StatusCode* sc = logoutResponse->getStatus() ? logoutResponse->getStatus()->getStatusCode() : nullptr;
                bool partial = (!sc || !XMLString::equals(sc->getValue(), StatusCode::SUCCESS));
                if (!partial && sc->getStatusCode()) {
                    // Success, but still need to check for partial.
                    partial = XMLString::equals(sc->getStatusCode()->getValue(), StatusCode::PARTIAL_LOGOUT);
                }

                // Log the end result.
                if (logout_event) {
                    logout_event->m_logoutType = partial ? LogoutEvent::LOGOUT_EVENT_PARTIAL : LogoutEvent::LOGOUT_EVENT_GLOBAL;
                    logout_event->m_saml2Response = logoutResponse;
                    application.getServiceProvider().getTransactionLog()->write(*logout_event);
                }

                if (partial)
                    ret = sendLogoutPage(application, httpRequest, httpResponse, "partial");
                else {
                    const char* returnloc = httpRequest.getParameter("return");
                    if (returnloc) {
                        // Relative URLs get promoted, absolutes get validated.
                        if (*returnloc == '/') {
                            string loc(returnloc);
                            httpRequest.absolutize(loc);
                            ret.second = httpResponse.sendRedirect(loc.c_str());
                        }
                        else {
                            application.limitRedirect(httpRequest, returnloc);
                            ret.second = httpResponse.sendRedirect(returnloc);
                        }
                        ret.first = true;
                    }
                    else {
                        ret = sendLogoutPage(application, httpRequest, httpResponse, "global");
                    }
                }
            }

            if (session) {
                sessionLocker.assign();
                session = nullptr;
                application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
            }

            return ret;
        }

        // Save off return location as RelayState.
        string relayState;
        const char* returnloc = httpRequest.getParameter("return");
        if (returnloc) {
            application.limitRedirect(httpRequest, returnloc);
            relayState = returnloc;
            httpRequest.absolutize(relayState);
            cleanRelayState(application, httpRequest, httpResponse);
            preserveRelayState(application, httpResponse, relayState);
        }

        auto_ptr<LogoutRequest> msg(buildRequest(application, *session, *role, encoder));
        msg->setDestination(ep->getLocation());

        // Log the request.
        if (logout_event) {
            logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_UNKNOWN;
            logout_event->m_saml2Request = msg.get();
            application.getServiceProvider().getTransactionLog()->write(*logout_event);
        }

        auto_ptr_char dest(ep->getLocation());
        ret.second = sendMessage(*encoder, msg.get(), relayState.c_str(), dest.get(), role, application, httpResponse, true);
        ret.first = true;
        msg.release();  // freed by encoder

        if (session) {
            sessionLocker.assign();
            session = nullptr;
            application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
        }
    }
    catch (MetadataException& mex) {
        // Less noise for IdPs that don't support logout (i.e. most)
        m_log.info("unable to issue SAML 2.0 logout request: %s", mex.what());
    }
    catch (std::exception& ex) {
        m_log.error("error issuing SAML 2.0 logout request: %s", ex.what());
    }

    return ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

auto_ptr<LogoutRequest> SAML2LogoutInitiator::buildRequest(
    const Application& application, const Session& session, const RoleDescriptor& role, const MessageEncoder* encoder
    ) const
{
    const PropertySet* relyingParty = application.getRelyingParty(dynamic_cast<EntityDescriptor*>(role.getParent()));

    auto_ptr<LogoutRequest> msg(LogoutRequestBuilder::buildLogoutRequest());
    Issuer* issuer = IssuerBuilder::buildIssuer();
    msg->setIssuer(issuer);
    issuer->setName(relyingParty->getXMLString("entityID").second);
    auto_ptr_XMLCh index(session.getSessionIndex());
    if (index.get() && *index.get()) {
        SessionIndex* si = SessionIndexBuilder::buildSessionIndex();
        msg->getSessionIndexs().push_back(si);
        si->setSessionIndex(index.get());
    }

    const NameID* nameid = session.getNameID();
    pair<bool,const char*> flag = relyingParty->getString("encryption");
    if (flag.first &&
        (!strcmp(flag.second, "true") || (encoder && !strcmp(flag.second, "front")) || (!encoder && !strcmp(flag.second, "back")))) {
        auto_ptr<EncryptedID> encrypted(EncryptedIDBuilder::buildEncryptedID());
        MetadataCredentialCriteria mcc(role);
        encrypted->encrypt(
            *nameid,
            *(application.getMetadataProvider()),
            mcc,
            encoder ? encoder->isCompact() : false,
            relyingParty->getXMLString("encryptionAlg").second
            );
        msg->setEncryptedID(encrypted.get());
        encrypted.release();
    }
    else {
        msg->setNameID(nameid->cloneNameID());
    }

    XMLCh* msgid = SAMLConfig::getConfig().generateIdentifier();
    msg->setID(msgid);
    XMLString::release(&msgid);
    msg->setIssueInstant(time(nullptr));

    if (m_async && encoder) {
        msg->setExtensions(saml2p::ExtensionsBuilder::buildExtensions());
        msg->getExtensions()->getUnknownXMLObjects().push_back(AsynchronousBuilder::buildAsynchronous());
    }

    return msg;
}

#endif
