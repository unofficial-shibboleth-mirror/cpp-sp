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
 * Shib1SessionInitiator.cpp
 * 
 * Shibboleth 1.x AuthnRequest support.
 */

#include "internal.h"
#include "Application.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/EndpointManager.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Shib1SessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        Shib1SessionInitiator(const DOMElement* e, const char* appId)
            : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator")) {}
        virtual ~Shib1SessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, const char* entityID=NULL, bool isHandler=true) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL Shib1SessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new Shib1SessionInitiator(p.first, p.second);
    }

};

pair<bool,long> Shib1SessionInitiator::run(SPRequest& request, const char* entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (!entityID || !*entityID)
        return make_pair(false,0);

    string target;
    const char* option;
    const Handler* ACS=NULL;
    const Application& app=request.getApplication();

    if (isHandler) {
        option=request.getParameter("acsIndex");
        if (option)
            ACS=app.getAssertionConsumerServiceByIndex(atoi(option));

        option = request.getParameter("target");
        if (option)
            target = option;
        recoverRelayState(request, target, false);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
    }
        
    m_log.debug("attempting to initiate session using SAML 1.x with provider (%s)", entityID);

    // Use metadata to invoke the SSO service directly.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    const EntityDescriptor* entity=m->getEntityDescriptor(entityID);
    if (!entity) {
        m_log.error("unable to locate metadata for provider (%s)", entityID);
        return make_pair(false,0);
    }
    const IDPSSODescriptor* role=entity->getIDPSSODescriptor(shibspconstants::SHIB1_PROTOCOL_ENUM);
    if (!role) {
        m_log.error("unable to locate Shibboleth-aware identity provider role for provider (%s)", entityID);
        return make_pair(false,0);
    }
    const EndpointType* ep=EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(
        shibspconstants::SHIB1_AUTHNREQUEST_PROFILE_URI
        );
    if (!ep) {
        m_log.error("unable to locate compatible SSO service for provider (%s)", entityID);
        return make_pair(false,0);
    }
    auto_ptr_char dest(ep->getLocation());

    if (!ACS)
        ACS = app.getDefaultAssertionConsumerService();

    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc=request.getHandlerURL(target.c_str());
    pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
    if (loc.first) ACSloc+=loc.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        option = request.getParameter("target");
        if (option)
            target = option;
    }
    preserveRelayState(request, target);

    // Shib 1.x requires a target value.
    if (target.empty())
        target = "default";

    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "shire=" + urlenc->encode(ACSloc.c_str()) +
        "&time=" + timebuf + "&target=" + urlenc->encode(target.c_str()) +
        "&providerId=" + urlenc->encode(app.getString("entityID").second);

    return make_pair(true, request.sendRedirect(req.c_str()));
}
