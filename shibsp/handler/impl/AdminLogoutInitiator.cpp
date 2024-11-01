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
 * AdminLogoutInitiator.cpp
 *
 * Triggers administrative logout of a session.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "handler/SecuredHandler.h"
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

    class SHIBSP_DLLLOCAL AdminLogoutInitiator : public SecuredHandler, public LogoutInitiator
    {
    public:
        AdminLogoutInitiator(const DOMElement* e, const char* appId);
        virtual ~AdminLogoutInitiator() {}

        void init(const char* location);    // encapsulates actions that need to run either in the c'tor or setParent

        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(const Application& application, const HTTPRequest& request, HTTPResponse& httpResponse) const;

        string m_appId;
#ifndef SHIBSP_LITE
        auto_ptr_char m_protocol;
        auto_ptr<LogoutRequest> buildRequest(
            const Application& application,
            const Session& session,
            const RoleDescriptor& role,
            const XMLCh* endpoint
            ) const;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AdminLogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p, bool)
    {
        return new AdminLogoutInitiator(p.first, p.second);
    }
};

AdminLogoutInitiator::AdminLogoutInitiator(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT ".LogoutInitiator.Admin")), m_appId(appId)
#ifndef SHIBSP_LITE
        ,m_protocol(samlconstants::SAML20P_NS)
#endif
{
    // If Location isn't set, defer initialization until the setParent call.
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        init(loc.second);
    }
}

void AdminLogoutInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    init(loc.second);
}

void AdminLogoutInitiator::init(const char* location)
{
    if (location) {
        string address = m_appId + location + "::run::AdminLI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Admin LogoutInitiator (or parent), can't register as remoted handler");
    }
}


pair<bool,long> AdminLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // No front-channel notifications, so skip calling logout base class.

    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively.
        return doRequest(request.getApplication(), request, request);
    }
    else {
        // When not out of process, we remote the request.
        vector<string> headers(1, "User-Agent");
        DDF out, in = wrap(request, &headers);
        DDFJanitor jin(in), jout(out);
        out = send(request, in);
        return unwrap(request, out);
    }
}

void AdminLogoutInitiator::receive(DDF& in, ostream& out)
{
#ifndef SHIBSP_LITE
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
    }

    // Unpack the request.
    scoped_ptr<HTTPRequest> req(getRequest(*app, in));

    // Set up a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(*app, ret));

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, *req, *resp);

    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> AdminLogoutInitiator::doRequest(const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse) const
{
    const char* sessionId = httpRequest.getParameter("session");
    if (!sessionId || !*sessionId) {
        // Something's horribly wrong.
        m_log.error("no session parameter supplied for request");
        istringstream msg("NO SESSION PARAMETER");
        return make_pair(true, httpResponse.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_BADREQUEST));
    }

    Session* session = nullptr;
    try {
        session = application.getServiceProvider().getSessionCache()->find(application, sessionId);
    }
    catch (const std::exception& ex) {
        m_log.error("error accessing designated session: %s", ex.what());
    }

    // With no session, we return a 404 after "revoking" the session just to be safe.
    if (!session) {
        application.getServiceProvider().getSessionCache()->remove(application, sessionId);
        istringstream msg("NOT FOUND");
        return make_pair(true, httpResponse.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTFOUND));
    }

    time_t revocationExp = session->getExpiration();

    Locker sessionLocker(session, false);

    bool doSAML = false;

#ifndef SHIBSP_LITE
    if (XMLString::equals(session->getProtocol(), m_protocol.get())) {
        if (!session->getEntityID() || !session->getNameID()) {
            m_log.info("skipping SAML 2.0 logout attempt, no NameID or issuing entityID found in session");
        }
        else {
            doSAML = true;
        }
    }
    else {
        m_log.info("skipping global logout for non-SAML2 session");
    }
#endif

    // Do back channel notification.
    vector<string> sessions(1, session->getID());
    if (!notifyBackChannel(application, httpRequest.getRequestURL(), sessions, true)) {
        sessionLocker.assign();
        session = nullptr;
        application.getServiceProvider().getSessionCache()->remove(application, sessionId, revocationExp);
        
        istringstream msg("PARTIAL");
        return make_pair(true, httpResponse.sendResponse(msg, 206)); // misuse of an HTTP code, but whatever
    }

    if (!doSAML) {
        sessionLocker.assign();
        session = nullptr;
        application.getServiceProvider().getSessionCache()->remove(application, sessionId, revocationExp);

        istringstream msg("OK");
        return make_pair(true, httpResponse.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_OK));
    }

#ifndef SHIBSP_LITE
    pair<bool,long> ret = make_pair(false, 0L);
    try {
        // With a session in hand, we can create a LogoutRequest message, if we can find a compatible SOAP endpoint.
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

        shibsp::SecurityPolicy policy(application);
        shibsp::SOAPClient soaper(policy);
        MetadataCredentialCriteria mcc(*role);

        bool requestSent = false;
        LogoutResponse* logoutResponse = nullptr;
        scoped_ptr<StatusResponseType> srt;
        auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
        const vector<SingleLogoutService*>& endpoints = role->getSingleLogoutServices();
        for (indirect_iterator<vector<SingleLogoutService*>::const_iterator> epit = make_indirect_iterator(endpoints.begin());
                !logoutResponse && epit != make_indirect_iterator(endpoints.end()); ++epit) {
            try {
                if (!XMLString::equals(epit->getBinding(), binding.get()))
                    continue;

                requestSent = true;
                auto_ptr<LogoutRequest> msg(buildRequest(application, *session, *role, epit->getLocation()));

                SAML2SOAPClient client(soaper, false);
                auto_ptr_char dest(epit->getLocation());
                client.sendSAML(msg.release(), application.getId(), mcc, dest.get());
                srt.reset(client.receiveSAML());
                if (!(logoutResponse = dynamic_cast<LogoutResponse*>(srt.get()))) {
                    break;
                }
            }
            catch (const std::exception& ex) {
                m_log.error("error sending LogoutRequest message: %s", ex.what());
                soaper.reset();
            }
        }

        // No answer at all?
        if (!logoutResponse) {
            if (!requestSent)
                m_log.info("IdP (%s) doesn't support SOAP-based single logout protocol", session->getEntityID());
        }
        else {
            // Check the status, looking for non-success or a partial logout code.
            const StatusCode* sc = logoutResponse->getStatus() ? logoutResponse->getStatus()->getStatusCode() : nullptr;
            bool partial = (!sc || !XMLString::equals(sc->getValue(), StatusCode::SUCCESS));
            if (!partial && sc->getStatusCode()) {
                // Success, but still need to check for partial.
                partial = XMLString::equals(sc->getStatusCode()->getValue(), StatusCode::PARTIAL_LOGOUT);
            }

            if (!partial) {
                sessionLocker.assign();
                session = nullptr;
                application.getServiceProvider().getSessionCache()->remove(application, sessionId, revocationExp);
                istringstream msg("OK");
                ret = make_pair(true, httpResponse.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_OK));
            }
        }
    }
    catch (const MetadataException& mex) {
        // Less noise for IdPs that don't support logout (i.e. most)
        m_log.info("unable to attempt SAML 2.0 logout: %s", mex.what());
    }
    catch (const std::exception& ex) {
        m_log.error("error issuing SAML 2.0 logout request: %s", ex.what());
    }

    if (session) {
        sessionLocker.assign();
        session = nullptr;
        application.getServiceProvider().getSessionCache()->remove(application, sessionId, revocationExp);
    }

    if (ret.first)
        return ret;

    istringstream msg("PARTIAL");
    return make_pair(true, httpResponse.sendResponse(msg, 206)); // misuse of an HTTP code, but whatever

#else
    throw ConfigurationException("Cannot perform SAML logout using lite version of shibsp library.");
#endif
}

#ifndef SHIBSP_LITE

auto_ptr<LogoutRequest> AdminLogoutInitiator::buildRequest(
    const Application& application,
    const Session& session,
    const RoleDescriptor& role,
    const XMLCh* endpoint) const
{
    const PropertySet* relyingParty = application.getRelyingParty(dynamic_cast<EntityDescriptor*>(role.getParent()));

    auto_ptr<LogoutRequest> msg(LogoutRequestBuilder::buildLogoutRequest());
    msg->setReason(LogoutRequest::REASON_ADMIN);
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
    pair<bool, const char*> flag = getString("encryption");
    if (!flag.first)
        flag = relyingParty->getString("encryption");
    auto_ptr_char dest(endpoint);
    if (SPConfig::shouldSignOrEncrypt(flag.first ? flag.second : "conditional", dest.get(), false)) {
        try {
            auto_ptr<EncryptedID> encrypted(EncryptedIDBuilder::buildEncryptedID());
            MetadataCredentialCriteria mcc(role);
            encrypted->encrypt(
                *nameid,
                *(application.getMetadataProvider()),
                mcc,
                false,
                relyingParty->getXMLString("encryptionAlg").second
            );
            msg->setEncryptedID(encrypted.get());
            encrypted.release();
        }
        catch (const std::exception& ex) {
            // If we're encrypting deliberately, failure should be fatal.
            if (flag.first && strcmp(flag.second, "conditional")) {
                throw;
            }
            // If opportunistically, just log and move on.
            m_log.info("Conditional encryption of NameID in LogoutRequest failed: %s", ex.what());
            auto_ptr<NameID> namewrapper(nameid->cloneNameID());
            msg->setNameID(namewrapper.get());
            namewrapper.release();
        }
    }
    else {
        auto_ptr<NameID> namewrapper(nameid->cloneNameID());
        msg->setNameID(namewrapper.get());
        namewrapper.release();
    }

    XMLCh* msgid = SAMLConfig::getConfig().generateIdentifier();
    msg->setID(msgid);
    XMLString::release(&msgid);
    msg->setIssueInstant(time(nullptr));

    return msg;
}

#endif
