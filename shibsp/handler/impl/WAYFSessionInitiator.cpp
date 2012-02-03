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
 * WAYFSessionInitiator.cpp
 * 
 * Shibboleth WAYF support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"

#ifndef SHIBSP_LITE
# include <saml/util/SAMLConstants.h>
#else
# include "lite/SAMLConstants.h"
#endif

#include <ctime>
#include <boost/lexical_cast.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL WAYFSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        WAYFSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.WAYF"), nullptr, &m_remapper), m_url(nullptr) {
            pair<bool,const char*> url = getString("URL");
            if (!url.first)
                throw ConfigurationException("WAYF SessionInitiator requires a URL property.");
            m_url = url.second;
        }
        virtual ~WAYFSessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

        const XMLCh* getProtocolFamily() const {
            return samlconstants::SAML11_PROTOCOL_ENUM;
        }

    private:
        const char* m_url;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL WAYFSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new WAYFSessionInitiator(p.first, p.second);
    }

};

pair<bool,long> WAYFSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // The IdP CANNOT be specified for us to run. Otherwise, we'd be redirecting to a WAYF
    // anytime the IdP's metadata was wrong.
    if (!entityID.empty() || !checkCompatibility(request, isHandler))
        return make_pair(false, 0L);

    string target;
    pair<bool,const char*> prop;
    const Handler* ACS = nullptr;
    const Application& app = request.getApplication();
    pair<bool,const char*> discoveryURL = pair<bool,const char*>(true, m_url);

    if (isHandler) {
        prop.second = request.getParameter("acsIndex");
        if (prop.second && *prop.second) {
            ACS = app.getAssertionConsumerServiceByIndex(atoi(prop.second));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using acsIndex property");
        }

        prop = getString("target", request);
        if (prop.first)
            target = prop.second;

        // Since we're passing the ACS by value, we need to compute the return URL,
        // so we'll need the target resource for real.
        recoverRelayState(request.getApplication(), request, request, target, false);
        request.getApplication().limitRedirect(request, target.c_str());

        prop.second = request.getParameter("discoveryURL");
        if (prop.second && *prop.second)
            discoveryURL.second = prop.second;
    }
    else {
        // Check for a hardwired target value in the map or handler.
        prop = getString("target", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (prop.first)
            target = prop.second;
        else
            target = request.getRequestURL();

        discoveryURL = request.getRequestSettings().first->getString("discoveryURL");
    }
    
    if (!ACS) {
        // Try fixed index property.
        pair<bool,unsigned int> index = getUnsignedInt("acsIndex", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (index.first)
            ACS = app.getAssertionConsumerServiceByIndex(index.second);
    }

    // If we picked by index, validate the ACS for use with this protocol.
    if (!ACS || !XMLString::equals(samlconstants::SAML11_PROTOCOL_ENUM, ACS->getProtocolFamily())) {
        if (ACS)
            request.log(SPRequest::SPWarn, "invalid acsIndex property, or non-SAML 1.x ACS, using default SAML 1.x ACS");
        ACS = app.getAssertionConsumerServiceByProtocol(getProtocolFamily());
        if (!ACS)
            throw ConfigurationException("Unable to locate a SAML 1.x ACS endpoint to use for response.");
    }

    if (!discoveryURL.first)
        discoveryURL.second = m_url;
    m_log.debug("sending request to WAYF (%s)", discoveryURL.second);

    // Since we're not passing by index, we need to fully compute the return URL.
    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc = request.getHandlerURL(target.c_str());
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

    preserveRelayState(app, request, target);
    if (!isHandler)
        preservePostData(app, request, request, target.c_str());

    // WAYF requires a target value.
    if (target.empty())
        target = "default";

    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    string req=string(discoveryURL.second) + (strchr(discoveryURL.second,'?') ? '&' : '?') + "shire=" + urlenc->encode(ACSloc.c_str()) +
        "&time=" + lexical_cast<string>(time(nullptr)) + "&target=" + urlenc->encode(target.c_str()) +
        "&providerId=" + urlenc->encode(app.getString("entityID").second);

    return make_pair(true, request.sendRedirect(req.c_str()));
}
