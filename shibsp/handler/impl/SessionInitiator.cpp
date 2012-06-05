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
 * SessionInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/SessionInitiator.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
using namespace opensaml::saml2md;
#endif

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory ChainingSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory Shib1SessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory SAML2SessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory WAYFSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory SAMLDSSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory TransformSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory FormSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory CookieSessionInitiatorFactory;
};

map<string,string> SessionInitiator::m_remapper;

void SHIBSP_API shibsp::registerSessionInitiators()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.registerFactory(CHAINING_SESSION_INITIATOR, ChainingSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SHIB1_SESSION_INITIATOR, Shib1SessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SAML2_SESSION_INITIATOR, SAML2SessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(WAYF_SESSION_INITIATOR, WAYFSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SAMLDS_SESSION_INITIATOR, SAMLDSSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(TRANSFORM_SESSION_INITIATOR, TransformSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(FORM_SESSION_INITIATOR, FormSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(COOKIE_SESSION_INITIATOR, CookieSessionInitiatorFactory);

    SessionInitiator::m_remapper["defaultACSIndex"] = "acsIndex";
}

SessionInitiator::SessionInitiator()
{
}

SessionInitiator::~SessionInitiator()
{
}

#ifndef SHIBSP_LITE
const char* SessionInitiator::getType() const
{
    return "SessionInitiator";
}

void SessionInitiator::generateMetadata(SPSSODescriptor& role, const char* handlerURL) const
{
    // In case any plugins were directly calling this before, we stub it out.
}

void SessionInitiator::doGenerateMetadata(SPSSODescriptor& role, const char* handlerURL) const
{
    if (getParent())
        return;
    const char* loc = getString("Location").second;
    string hurl(handlerURL);
    if (*loc != '/')
        hurl += '/';
    hurl += loc;
    auto_ptr_XMLCh widen(hurl.c_str());

    RequestInitiator* ep = RequestInitiatorBuilder::buildRequestInitiator();
    ep->setLocation(widen.get());
    ep->setBinding(samlconstants::SP_REQUEST_INIT_NS);
    Extensions* ext = role.getExtensions();
    if (!ext) {
        ext = ExtensionsBuilder::buildExtensions();
        role.setExtensions(ext);
    }
    ext->getUnknownXMLObjects().push_back(ep);
}
#endif

const set<string>& SessionInitiator::getSupportedOptions() const
{
    return m_supportedOptions;
}

bool SessionInitiator::checkCompatibility(SPRequest& request, bool isHandler) const
{
    bool isPassive = false;
    if (isHandler) {
        const char* flag = request.getParameter("isPassive");
        if (flag) {
            isPassive = (*flag=='1' || *flag=='t');
        }
        else {
            pair<bool,bool> flagprop = getBool("isPassive");
            isPassive = (flagprop.first && flagprop.second);
        }
    }
    else {
        // It doesn't really make sense to use isPassive with automated sessions, but...
        pair<bool,bool> flagprop = request.getRequestSettings().first->getBool("isPassive");
        if (!flagprop.first)
            flagprop = getBool("isPassive");
        isPassive = (flagprop.first && flagprop.second);
    }

    // Check for support of isPassive if it's used.
    if (isPassive && getSupportedOptions().count("isPassive") == 0) {
        if (getParent()) {
            log(SPRequest::SPInfo, "handler does not support isPassive option");
            return false;
        }
        throw ConfigurationException("Unsupported option (isPassive) supplied to SessionInitiator.");
    }

    return true;
}

pair<bool,long> SessionInitiator::run(SPRequest& request, bool isHandler) const
{
    cleanRelayState(request.getApplication(), request, request);

    const char* entityID = nullptr;
    pair<bool,const char*> param = getString("entityIDParam");
    if (isHandler) {
        entityID = request.getParameter(param.first ? param.second : "entityID");
        if (!param.first && (!entityID || !*entityID))
            entityID=request.getParameter("providerId");
    }
    if (!entityID || !*entityID) {
        param = request.getRequestSettings().first->getString("entityID");
        if (param.first)
            entityID = param.second;
    }
    if (!entityID || !*entityID)
        entityID = getString("entityID").second;

    string copy(entityID ? entityID : "");

    try {
        return run(request, copy, isHandler);
    }
    catch (exception& ex) {
        // If it's a handler operation, and isPassive is used or returnOnError is set, we trap the error.
        if (isHandler) {
            bool returnOnError = false;
            const char* flag = request.getParameter("isPassive");
            if (flag && (*flag == 't' || *flag == '1')) {
                returnOnError = true;
            }
            else {
                pair<bool,bool> flagprop = getBool("isPassive");
                if (flagprop.first && flagprop.second) {
                    returnOnError = true;
                }
                else {
                    flag = request.getParameter("returnOnError");
                    if (flag) {
                        returnOnError = (*flag=='1' || *flag=='t');
                    }
                    else {
                        flagprop = getBool("returnOnError");
                        returnOnError = (flagprop.first && flagprop.second);
                    }
                }
            }

            if (returnOnError) {
                // Log it and attempt to recover relay state so we can get back.
                log(SPRequest::SPError, ex.what());
                log(SPRequest::SPInfo, "trapping SessionInitiator error condition and returning to target location");
                flag = request.getParameter("target");
                string target(flag ? flag : "");
                recoverRelayState(request.getApplication(), request, request, target, false);
                return make_pair(true, request.sendRedirect(target.c_str()));
            }
        }
        throw;
    }
}

#ifndef SHIBSP_LITE

AuthnRequestEvent* SessionInitiator::newAuthnRequestEvent(const Application& application, const xmltooling::HTTPRequest* request) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::Logging))
        return nullptr;
    try {
        auto_ptr<TransactionLog::Event> event(SPConfig::getConfig().EventManager.newPlugin(AUTHNREQUEST_EVENT, nullptr));
        AuthnRequestEvent* ar_event = dynamic_cast<AuthnRequestEvent*>(event.get());
        if (ar_event) {
            ar_event->m_request = request;
            ar_event->m_app = &application;
            event.release();
            return ar_event;
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".SessionInitiator").warn("unable to audit event, log event object was of an incorrect type");
        }
    }
    catch (exception& ex) {
        Category::getInstance(SHIBSP_LOGCAT".SessionInitiator").warn("exception auditing event: %s", ex.what());
    }
    return nullptr;
}

#endif
