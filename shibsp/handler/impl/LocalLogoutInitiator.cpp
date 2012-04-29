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
 * LocalLogoutInitiator.cpp
 * 
 * Logs out a session locally.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutInitiator.h"

#ifndef SHIBSP_LITE
using namespace boost;
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL LocalLogoutInitiator : public AbstractHandler, public LogoutInitiator
    {
    public:
        LocalLogoutInitiator(const DOMElement* e, const char* appId);
        virtual ~LocalLogoutInitiator() {}
        
        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application, const HTTPRequest& request, HTTPResponse& httpResponse, Session* session
            ) const;

        string m_appId;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL LocalLogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new LocalLogoutInitiator(p.first, p.second);
    }
};

LocalLogoutInitiator::LocalLogoutInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.Local")), m_appId(appId)
{
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = string(appId) + loc.second + "::run::LocalLI";
        setAddress(address.c_str());
    }
}

void LocalLogoutInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::LocalLI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Local LogoutInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> LocalLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class first.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively.
        Session* session = nullptr;
        try {
            session = request.getSession(false, true, false);  // don't cache it and ignore all checks
        }
        catch (std::exception& ex) {
            m_log.error("error accessing current session: %s", ex.what());
        }
        return doRequest(request.getApplication(), request, request, session);
    }
    else {
        // When not out of process, we remote the request.
        vector<string> headers(1,"Cookie");
        headers.push_back("User-Agent");
        DDF out,in = wrap(request,&headers);
        DDFJanitor jin(in), jout(out);
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void LocalLogoutInitiator::receive(DDF& in, ostream& out)
{
#ifndef SHIBSP_LITE
    // Defer to base class for back channel notifications
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

    // This is the "last chance" handler so even without a session, we "complete" the logout.
    doRequest(*app, *req, *resp, session);

    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> LocalLogoutInitiator::doRequest(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse, Session* session
    ) const
{
    if (session) {
        // Guard the session in case of exception.
        Locker locker(session, false);

        // Do back channel notification.
        bool result;
        vector<string> sessions(1, session->getID());
        result = notifyBackChannel(application, httpRequest.getRequestURL(), sessions, true);
#ifndef SHIBSP_LITE
        scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(application, &httpRequest, session));
        if (logout_event) {
            logout_event->m_logoutType = result ? LogoutEvent::LOGOUT_EVENT_LOCAL : LogoutEvent::LOGOUT_EVENT_PARTIAL;
            application.getServiceProvider().getTransactionLog()->write(*logout_event);
        }
#endif
        locker.assign();    // unlock the session
        application.getServiceProvider().getSessionCache()->remove(application, httpRequest, &httpResponse);
        if (!result)
            return sendLogoutPage(application, httpRequest, httpResponse, "partial");
    }

    // Route back to return location specified, or use the local template.
    const char* dest = httpRequest.getParameter("return");
    if (dest) {
        // Relative URLs get promoted, absolutes get validated.
        if (*dest == '/') {
            string d(dest);
            httpRequest.absolutize(d);
            return make_pair(true, httpResponse.sendRedirect(d.c_str()));
        }
        application.limitRedirect(httpRequest, dest);
        return make_pair(true, httpResponse.sendRedirect(dest));
    }
    return sendLogoutPage(application, httpRequest, httpResponse, "local");
}
