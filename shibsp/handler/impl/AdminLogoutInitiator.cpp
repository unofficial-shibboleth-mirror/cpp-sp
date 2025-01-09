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
 * handler/impl/AdminLogoutInitiator.cpp
 *
 * Triggers administrative logout of a session.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "handler/SecuredHandler.h"
#include "handler/LogoutInitiator.h"
#include "logging/Category.h"
#include "session/SessionCache.h"

#include <sstream>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL AdminLogoutInitiator : public SecuredHandler, public LogoutInitiator
    {
    public:
        AdminLogoutInitiator(const ptree& pt);
        virtual ~AdminLogoutInitiator() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AdminLogoutInitiatorFactory(const pair<ptree&,const char*> p, bool)
    {
        return new AdminLogoutInitiator(p.first);
    }
};

AdminLogoutInitiator::AdminLogoutInitiator(const ptree& pt)
    : SecuredHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".LogoutInitiator.Admin"))
{
}

pair<bool,long> AdminLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // No front-channel notifications, so skip calling logout base class.

    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    const char* sessionId = request.getParameter("session");
    if (!sessionId || !*sessionId) {
        // Something's horribly wrong.
        m_log.error("no session parameter supplied for request");
        istringstream msg("NO SESSION PARAMETER");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_BADREQUEST));
    }

    Session* session = nullptr;
    try {
        session = AgentConfig::getConfig().getAgent().getSessionCache()->find(request, sessionId);
    }
    catch (const std::exception& ex) {
        m_log.error("error accessing designated session: %s", ex.what());
    }

    // With no session, we return a 404 after "revoking" the session just to be safe.
    if (!session) {
        AgentConfig::getConfig().getAgent().getSessionCache()->remove(
            request.getRequestSettings().first->getString("sessionBucket", "default"), sessionId);
        istringstream msg("NOT FOUND");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_NOTFOUND));
    }

    time_t revocationExp = session->getExpiration();

    unique_lock<Session> sessionLocker(*session, adopt_lock);

    bool doSAML = false;

    // Do back channel notification.
    vector<string> sessions(1, session->getID());
    if (!notifyBackChannel(request, sessions, true)) {
        sessionLocker.unlock();
        session = nullptr;
        AgentConfig::getConfig().getAgent().getSessionCache()->remove(
            request.getRequestSettings().first->getString("sessionBucket", "default"), sessionId, revocationExp);
        
        istringstream msg("PARTIAL");
        return make_pair(true, request.sendResponse(msg, 206)); // misuse of an HTTP code, but whatever
    }

    if (!doSAML) {
        sessionLocker.unlock();
        session = nullptr;
        AgentConfig::getConfig().getAgent().getSessionCache()->remove(
            request.getRequestSettings().first->getString("sessionBucket", "default"), sessionId, revocationExp);

        istringstream msg("OK");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_OK));
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

