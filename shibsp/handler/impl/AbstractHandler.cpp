/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AbstractHandler.cpp
 * 
 * Base class for handlers based on a DOMPropertySet. 
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"

#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace samlconstants;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<Handler,const DOMElement*>::Factory SAML1ConsumerFactory;
};

void SHIBSP_API shibsp::registerHandlers()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.AssertionConsumerServiceManager.registerFactory(SAML1_PROFILE_BROWSER_ARTIFACT, SAML1ConsumerFactory);
    conf.AssertionConsumerServiceManager.registerFactory(SAML1_PROFILE_BROWSER_POST, SAML1ConsumerFactory);
}

AbstractHandler::AbstractHandler(
    const DOMElement* e, log4cpp::Category& log, DOMNodeFilter* filter, const map<string,string>* remapper
    ) : m_log(log) {
    load(e,log,filter,remapper);
}

void AbstractHandler::checkError(const XMLObject* response) const
{
    const saml2p::StatusResponseType* r2 = dynamic_cast<const saml2p::StatusResponseType*>(response);
    if (r2) {
        const saml2p::Status* status = r2->getStatus();
        if (status) {
            const saml2p::StatusCode* sc = status->getStatusCode();
            const XMLCh* code = sc ? sc->getValue() : NULL;
            if (code && !XMLString::equals(code,saml2p::StatusCode::SUCCESS)) {
                FatalProfileException ex("SAML Response message contained an error.");
                auto_ptr_char c1(code);
                ex.addProperty("code", c1.get());
                if (sc->getStatusCode()) {
                    code = sc->getStatusCode()->getValue();
                    auto_ptr_char c2(code);
                    ex.addProperty("code2", c2.get());
                }
                if (status->getStatusMessage()) {
                    auto_ptr_char msg(status->getStatusMessage()->getMessage());
                    ex.addProperty("message", msg.get());
                }
            }
        }
    }

    const saml1p::Response* r1 = dynamic_cast<const saml1p::Response*>(response);
    if (r1) {
        const saml1p::Status* status = r1->getStatus();
        if (status) {
            const saml1p::StatusCode* sc = status->getStatusCode();
            const QName* code = sc ? sc->getValue() : NULL;
            if (code && *code != saml1p::StatusCode::SUCCESS) {
                FatalProfileException ex("SAML Response message contained an error.");
                ex.addProperty("code", code->toString().c_str());
                if (sc->getStatusCode()) {
                    code = sc->getStatusCode()->getValue();
                    if (code)
                        ex.addProperty("code2", code->toString().c_str());
                }
                if (status->getStatusMessage()) {
                    auto_ptr_char msg(status->getStatusMessage()->getMessage());
                    ex.addProperty("message", msg.get());
                }
            }
        }
    }
}

void AbstractHandler::recoverRelayState(HTTPRequest& httpRequest, string& relayState) const
{
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        // Out of process, we look for StorageService-backed state.
        // TODO: something like ss:SSID:key?
    }
    
    if (conf.isEnabled(SPConfig::InProcess)) {
        // In process, we should be able to cast down to a full SPRequest.
        SPRequest& request = dynamic_cast<SPRequest&>(httpRequest);
        if (relayState.empty() || relayState == "cookie") {
            // Pull the value from the "relay state" cookie.
            pair<string,const char*> relay_cookie = request.getApplication().getCookieNameProps("_shibstate_");
            const char* state = request.getCookie(relay_cookie.first.c_str());
            if (state && *state) {
                // URL-decode the value.
                char* rscopy=strdup(state);
                XMLToolingConfig::getConfig().getURLEncoder()->decode(rscopy);
                relayState = rscopy;
                free(rscopy);
                
                // Clear the cookie.
                request.setCookie(relay_cookie.first.c_str(),relay_cookie.second);
            }
            else
                relayState = "default"; // fall through...
        }
        
        // Check for "default" value.
        if (relayState == "default") {
            pair<bool,const char*> homeURL=request.getApplication().getString("homeURL");
            relayState=homeURL.first ? homeURL.second : "/";
        }
    }
}
