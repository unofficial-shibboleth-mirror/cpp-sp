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
 * AssertionLookup.cpp
 *
 * Handler for looking up assertions in the SessionCache.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCacheEx.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"
#include "handler/SecuredHandler.h"

#include <boost/scoped_ptr.hpp>

#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
# include <saml/Assertion.h>
# include <xmltooling/util/XMLHelper.h>
using namespace opensaml;
#endif

using namespace shibspconstants;
using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API AssertionLookup : public SecuredHandler, public RemotedHandler
    {
    public:
        AssertionLookup(const DOMElement* e, const char* appId);
        virtual ~AssertionLookup() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

        const char* getType() const {
            return "AssertionLookup";
        }

    private:
        pair<bool,long> processMessage(const Application& application, HTTPRequest& httpRequest, HTTPResponse& httpResponse) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AssertionLookupFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new AssertionLookup(p.first, p.second);
    }

};

AssertionLookup::AssertionLookup(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".AssertionLookup"), "exportACL", "127.0.0.1 ::1")
{
    setAddress("run::AssertionLookup");
}

pair<bool,long> AssertionLookup::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    try {
        if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request, request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = wrap(request);
            DDFJanitor jin(in), jout(out);

            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        istringstream msg("Assertion Lookup Failed");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void AssertionLookup::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for assertion lookup", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for assertion lookup, deleted?");
    }

    // Unpack the request.
    scoped_ptr<HTTPRequest> req(getRequest(in));
    //m_log.debug("found %d client certificates", req->getClientCertificates().size());

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    processMessage(*app, *req, *resp);
    out << ret;
}

pair<bool,long> AssertionLookup::processMessage(const Application& application, HTTPRequest& httpRequest, HTTPResponse& httpResponse) const
{
#ifndef SHIBSP_LITE
    const char* key = httpRequest.getParameter("key");
    const char* ID = httpRequest.getParameter("ID");
    if (!key || !*key || !ID || !*ID) {
        m_log.error("assertion lookup request failed, missing required parameters");
        throw FatalProfileException("Missing key or ID parameters.");
    }

    m_log.debug("processing assertion lookup request (session: %s, assertion: %s)", key, ID);

    SessionCacheEx* cache = dynamic_cast<SessionCacheEx*>(application.getServiceProvider().getSessionCache());
    if (!cache) {
        m_log.error("session cache does not support extended API");
        throw FatalProfileException("Session cache does not support assertion lookup.");
    }

    // The cache will either silently pass a session or nullptr back, or throw an exception out.
    Session* session = cache->find(application, key);
    if (!session) {
        m_log.error("valid session (%s) not found for assertion lookup", key);
        throw FatalProfileException("Session key not found.");
    }

    Locker locker(session, false);

    const Assertion* assertion = session->getAssertion(ID);
    if (!assertion) {
        m_log.error("assertion (%s) not found in session (%s)", ID, key);
        throw FatalProfileException("Assertion not found.");
    }

    stringstream s;
    s << *assertion;
    httpResponse.setContentType("application/samlassertion+xml");
    return make_pair(true, httpResponse.sendResponse(s));
#else
    return make_pair(false, 0L);
#endif
}
