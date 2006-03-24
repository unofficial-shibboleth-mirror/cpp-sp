/*
 *  Copyright 2001-2005 Internet2
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

/*
 * handlers.cpp -- ADFS-aware profile handlers that plug into SP
 *
 * Scott Cantor
 * 10/10/2005
 */

#include "internal.h"

#ifndef HAVE_STRCASECMP
# define strcasecmp stricmp
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace adfs;
using namespace log4cpp;

namespace {
  
  // TODO: Refactor/extend API so I don't have to cut/paste this code out of libshib-target
  class SessionInitiator : virtual public IHandler
  {
  public:
    SessionInitiator(const DOMElement* e) {}
    ~SessionInitiator() {}
    pair<bool,void*> run(ShibTarget* st, const IPropertySet* handler, bool isHandler=true);
  
  private:
    const IPropertySet* getCompatibleACS(const IApplication* app, const vector<ShibProfile>& profiles);
    pair<bool,void*> ShibAuthnRequest(
        ShibTarget* st,
        const IPropertySet* shire,
        const char* dest,
        const char* target,
        const char* providerId
        );
    pair<bool,void*> ADFSAuthnRequest(
        ShibTarget* st,
        const IPropertySet* shire,
        const char* dest,
        const char* target,
        const char* providerId
        );
  };

  class ADFSHandler : virtual public IHandler
  {
  public:
    ADFSHandler(const DOMElement* e) {}
    ~ADFSHandler() {}
    pair<bool,void*> run(ShibTarget* st, const IPropertySet* handler, bool isHandler=true);
  };
}


IPlugIn* ADFSSessionInitiatorFactory(const DOMElement* e)
{
    return new SessionInitiator(e);
}

IPlugIn* ADFSHandlerFactory(const DOMElement* e)
{
    return new ADFSHandler(e);
}

pair<bool,void*> SessionInitiator::run(ShibTarget* st, const IPropertySet* handler, bool isHandler)
{
    string dupresource;
    const char* resource=NULL;
    const IPropertySet* ACS=NULL;
    const IApplication* app=st->getApplication();
    
    if (isHandler) {
        /* 
         * Binding is CGI query string with:
         *  target      the resource to direct back to later
         *  acsIndex    optional index of an ACS to use on the way back in
         *  providerId  optional direct invocation of a specific IdP
         */
        string query=st->getArgs();
        CgiParse parser(query.c_str(),query.length());

        const char* option=parser.get_value("acsIndex");
        if (option)
            ACS=app->getAssertionConsumerServiceByIndex(atoi(option));
        option=parser.get_value("providerId");
        
        resource=parser.get_value("target");
        if (!resource || !*resource) {
            pair<bool,const char*> home=app->getString("homeURL");
            if (home.first)
                resource=home.second;
            else
                throw FatalProfileException("Session initiator requires a target parameter or a homeURL application property.");
        }
        else if (!option) {
            dupresource=resource;
            resource=dupresource.c_str();
        }
        
        if (option) {
            // Here we actually use metadata to invoke the SSO service directly.
            Metadata m(app->getMetadataProviders());
            const IEntityDescriptor* entity=m.lookup(option);
            if (!entity)
                throw MetadataException("Session initiator unable to locate metadata for provider ($1).", params(1,option));

            // Look for an IdP role with Shib support.
            const IIDPSSODescriptor* role=entity->getIDPSSODescriptor(Constants::SHIB_NS);
            if (role) {
                // Look for a SSO endpoint with Shib support.
                const IEndpointManager* SSO=role->getSingleSignOnServiceManager();
                const IEndpoint* ep=SSO->getEndpointByBinding(Constants::SHIB_AUTHNREQUEST_PROFILE_URI);
                if (ep) {
                    if (!ACS) {
                        // Look for an ACS with SAML support.
                        vector<ShibProfile> v;
                        v.push_back(SAML11_POST);
                        v.push_back(SAML11_ARTIFACT);
                        v.push_back(SAML10_ARTIFACT);
                        v.push_back(SAML10_POST);
                        ACS=getCompatibleACS(app,v);
                    }
                    auto_ptr_char dest(ep->getLocation());
                    return ShibAuthnRequest(
                        st,ACS ? ACS : app->getDefaultAssertionConsumerService(),dest.get(),resource,app->getString("providerId").second
                        );
                }
            }
            // Look for an IdP role with ADFS support.
            role=entity->getIDPSSODescriptor(adfs::XML::WSFED_NS);
            if (role) {
                // Finally, look for a SSO endpoint with ADFS support.
                const IEndpointManager* SSO=role->getSingleSignOnServiceManager();
                const IEndpoint* ep=SSO->getEndpointByBinding(adfs::XML::WSFED_NS);
                if (ep) {
                    if (!ACS) {
                        // Look for an ACS with ADFS support.
                        vector<ShibProfile> v;
                        v.push_back(ADFS_SSO);
                        ACS=getCompatibleACS(app,v);
                    }
                    auto_ptr_char dest(ep->getLocation());
                    return ADFSAuthnRequest(
                        st,ACS ? ACS : app->getDefaultAssertionConsumerService(),dest.get(),resource,app->getString("providerId").second
                        );
                }
            }

            throw MetadataException(
                "Session initiator unable to locate a compatible identity provider SSO endpoint for provider ($1).",
                params(1,option)
                );
        }
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        resource=st->getRequestURL();
    }
    
    // For now, we only support external session initiation via a wayfURL
    pair<bool,const char*> wayfURL=handler->getString("wayfURL");
    if (!wayfURL.first)
        throw ConfigurationException("Session initiator is missing wayfURL property.");

    pair<bool,const XMLCh*> wayfBinding=handler->getXMLString("wayfBinding");
    if (!wayfBinding.first || !XMLString::compareString(wayfBinding.second,Constants::SHIB_AUTHNREQUEST_PROFILE_URI))
        // Standard Shib 1.x
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,app->getString("providerId").second);
    else if (!XMLString::compareString(wayfBinding.second,Constants::SHIB_LEGACY_AUTHNREQUEST_PROFILE_URI))
        // Shib pre-1.2
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,NULL);
    else if (!strcmp(handler->getString("wayfBinding").second,"urn:mace:shibboleth:1.0:profiles:EAuth")) {
        pair<bool,bool> localRelayState=st->getConfig()->getPropertySet("Local")->getBool("localRelayState");
        if (!localRelayState.first || !localRelayState.second)
            throw ConfigurationException("E-Authn requests cannot include relay state, so localRelayState must be enabled.");

        // Here we store the state in a cookie.
        pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(resource) + shib_cookie.second);
        return make_pair(true, st->sendRedirect(wayfURL.second));
    }
    else if (!XMLString::compareString(wayfBinding.second,adfs::XML::WSFED_NS))
        return ADFSAuthnRequest(st,ACS,wayfURL.second,resource,app->getString("providerId").second);
   
    throw UnsupportedProfileException("Unsupported WAYF binding ($1).", params(1,handler->getString("wayfBinding").second));
}

// Get an ACS that can handle one of the desired profiles
const IPropertySet* SessionInitiator::getCompatibleACS(const IApplication* app, const vector<ShibProfile>& profiles)
{
    // This isn't going to be very efficient until I can revise the IApplication API to
    // support ACS lookup by profile.
    
    int mask=0;
    for (vector<ShibProfile>::const_iterator p=profiles.begin(); p!=profiles.end(); p++)
        mask+=*p;
    
    // See if the default is acceptable.
    const IPropertySet* ACS=app->getDefaultAssertionConsumerService();
    pair<bool,const XMLCh*> binding=ACS ? ACS->getXMLString("Binding") : pair<bool,const XMLCh*>(false,NULL);
    if (!ACS || !binding.first || !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_POST)) {
        pair<bool,unsigned int> version =
            ACS ? ACS->getUnsignedInt("MinorVersion","urn:oasis:names:tc:SAML:1.0:protocol") : pair<bool,unsigned int>(false,1);
        if (!version.first)
            version.second=1;
        if (mask & (version.second==1 ? SAML11_POST : SAML10_POST))
            return ACS;
    }
    else if (!XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_ARTIFACT)) {
        pair<bool,unsigned int> version=ACS->getUnsignedInt("MinorVersion","urn:oasis:names:tc:SAML:1.0:protocol");
        if (!version.first)
            version.second=1;
        if (mask & (version.second==1 ? SAML11_ARTIFACT : SAML10_ARTIFACT))
            return ACS;
    }
    else if (!XMLString::compareString(binding.second,adfs::XML::WSFED_NS)) {
        if (mask & ADFS_SSO)
            return ACS;
    }
    
    // If not, iterate by profile.
    for (vector<ShibProfile>::const_iterator i=profiles.begin(); i!=profiles.end(); i++) {
        for (unsigned int j=0; j<=65535; j++) {
            ACS=app->getAssertionConsumerServiceByIndex(j);
            if (!ACS && j)
                break;  // we're past 0 and didn't get a hit, so we'll bail
            else if (ACS) {
                binding=ACS->getXMLString("Binding");
                pair<bool,unsigned int> version=ACS->getUnsignedInt("MinorVersion","urn:oasis:names:tc:SAML:1.0:protocol");
                if (!version.first)
                    version.second=1;
                switch (*i) {
                    case SAML11_POST:
                        if (version.second==1 && (!binding.first || !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_POST)))
                            return ACS;
                        break;
                    case SAML11_ARTIFACT:
                        if (version.second==1 && !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_ARTIFACT))
                            return ACS;
                        break;
                    case ADFS_SSO:
                        if (!XMLString::compareString(binding.second,adfs::XML::WSFED_NS))
                            return ACS;
                        break;
                    case SAML10_POST:
                        if (version.second==0 && (!binding.first || !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_POST)))
                            return ACS;
                        break;
                    case SAML10_ARTIFACT:
                        if (version.second==0 && !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_ARTIFACT))
                            return ACS;
                        break;
                    default:
                        break;
                }
            }
        }
    }
    
    return NULL;
}

// Handles Shib 1.x AuthnRequest profile.
pair<bool,void*> SessionInitiator::ShibAuthnRequest(
    ShibTarget* st,
    const IPropertySet* shire,
    const char* dest,
    const char* target,
    const char* providerId
    )
{
    if (!shire) {
        // Look for an ACS with SAML support.
        vector<ShibProfile> v;
        v.push_back(SAML11_POST);
        v.push_back(SAML11_ARTIFACT);
        v.push_back(SAML10_ARTIFACT);
        v.push_back(SAML10_POST);
        shire=getCompatibleACS(st->getApplication(),v);
    }
    if (!shire)
        shire=st->getApplication()->getDefaultAssertionConsumerService();
    
    // Compute the ACS URL. We add the ACS location to the handler baseURL.
    // Legacy configs will not have an ACS specified, so no suffix will be added.
    string ACSloc=st->getHandlerURL(target);
    if (shire) ACSloc+=shire->getString("Location").second;
    
    char timebuf[16];
    sprintf(timebuf,"%lu",time(NULL));
    string req=string(dest) + "?shire=" + CgiParse::url_encode(ACSloc.c_str()) + "&time=" + timebuf;

    // How should the resource value be preserved?
    pair<bool,bool> localRelayState=st->getConfig()->getPropertySet("Local")->getBool("localRelayState");
    if (!localRelayState.first || !localRelayState.second) {
        // The old way, just send it along.
        req+="&target=" + CgiParse::url_encode(target);
    }
    else {
        // Here we store the state in a cookie and send a fixed
        // value to the IdP so we can recognize it on the way back.
        pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(target) + shib_cookie.second);
        req+="&target=cookie";
    }
    
    // Only omitted for 1.1 style requests.
    if (providerId)
        req+="&providerId=" + CgiParse::url_encode(providerId);

    return make_pair(true, st->sendRedirect(req));
}

// Handles ADFS token request profile.
pair<bool,void*> SessionInitiator::ADFSAuthnRequest(
    ShibTarget* st,
    const IPropertySet* shire,
    const char* dest,
    const char* target,
    const char* providerId
    )
{
    if (!shire) {
        // Look for an ACS with ADFS support.
        vector<ShibProfile> v;
        v.push_back(ADFS_SSO);
        shire=getCompatibleACS(st->getApplication(),v);
    }
    if (!shire)
        shire=st->getApplication()->getDefaultAssertionConsumerService();

    // Compute the ACS URL. We add the ACS location to the handler baseURL.
    // Legacy configs will not have an ACS specified, so no suffix will be added.
    string ACSloc=st->getHandlerURL(target);
    if (shire) ACSloc+=shire->getString("Location").second;
    
    // UTC timestamp
#ifndef HAVE_GMTIME_R
    time_t epoch=time(NULL);
    struct tm* ptime=gmtime(&epoch);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&epoch,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);

    string req=string(dest) + "?wa=wsignin1.0&wreply=" + CgiParse::url_encode(ACSloc.c_str()) + "&wct=" + CgiParse::url_encode(timebuf);

    // How should the resource value be preserved?
    pair<bool,bool> localRelayState=st->getConfig()->getPropertySet("Local")->getBool("localRelayState");
    if (!localRelayState.first || !localRelayState.second) {
        // The old way, just send it along.
        req+="&wctx=" + CgiParse::url_encode(target);
    }
    else {
        // Here we store the state in a cookie and send a fixed
        // value to the IdP so we can recognize it on the way back.
        pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(target) + shib_cookie.second);
        req+="&wctx=cookie";
    }
    
    req+="&wtrealm=" + CgiParse::url_encode(providerId);

    return make_pair(true, st->sendRedirect(req));
}

pair<bool,void*> ADFSHandler::run(ShibTarget* st, const IPropertySet* handler, bool isHandler)
{
    const IApplication* app=st->getApplication();
    
    // Check for logout/GET first.
    if (!strcasecmp(st->getRequestMethod(), "GET")) {
        /* 
         * Only legal GET is a signoutcleanup request...
         *  wa=wsignoutcleanup1.0
         */
        string query=st->getArgs();
        CgiParse parser(query.c_str(),query.length());
        const char* wa=parser.get_value("wa");
        if (!wa || strcmp(wa,"wsignoutcleanup1.0"))
            throw FatalProfileException("ADFS protocol handler received invalid action request ($1)", params(1,wa ? wa : "none"));
        
        // Recover the session key.
        pair<string,const char*> shib_cookie = st->getCookieNameProps("_shibsession_");
        const char* session_id = st->getCookie(shib_cookie.first);
        
        // Logout is best effort.
        if (session_id && *session_id) {
            try {
                st->getConfig()->getListener()->sessionEnd(st->getApplication(),session_id);
            }
            catch (SAMLException& e) {
                st->log(ShibTarget::LogLevelError, string("logout processing failed with exception: ") + e.what());
            }
#ifndef _DEBUG
            catch (...) {
                st->log(ShibTarget::LogLevelError, "logout processing failed with unknown exception");
            }
#endif
            // We send the cookie property alone, which acts as an empty value.
            st->setCookie(shib_cookie.first,shib_cookie.second);
        }
        
        const char* ret=parser.get_value("wreply");
        if (!ret)
            ret=handler->getString("ResponseLocation").second;
        if (!ret)
            ret=st->getApplication()->getString("homeURL").second;
        if (!ret)
            ret="/";
        return make_pair(true, st->sendRedirect(ret));
    }
    
    if (strcasecmp(st->getRequestMethod(), "POST"))
        throw FatalProfileException(
            "ADFS protocol handler does not support HTTP method ($1)", params(1,st->getRequestMethod())
            );
    
    if (!st->getContentType() || strcasecmp(st->getContentType(),"application/x-www-form-urlencoded"))
        throw FatalProfileException(
            "Blocked invalid content-type ($1) submitted to ADFS protocol handler", params(1,st->getContentType())
            );

    string input=st->getPostData();
    if (input.empty())
        throw FatalProfileException("ADFS protocol handler received no data from browser");

    ShibProfile profile=ADFS_SSO;
    string cookie,target,providerId;
    
    string hURL=st->getHandlerURL(st->getRequestURL());
    pair<bool,const char*> loc=handler->getString("Location");
    string recipient=loc.first ? hURL + loc.second : hURL;
    st->getConfig()->getListener()->sessionNew(
        app,
        profile,
        recipient.c_str(),
        input.c_str(),
        st->getRemoteAddr(),
        target,
        cookie,
        providerId
        );

    st->log(ShibTarget::LogLevelDebug, string("profile processing succeeded, new session created (") + cookie + ")");

    if (target=="default") {
        pair<bool,const char*> homeURL=app->getString("homeURL");
        target=homeURL.first ? homeURL.second : "/";
    }
    else if (target=="cookie" || target.empty()) {
        // Pull the target value from the "relay state" cookie.
        pair<string,const char*> relay_cookie = st->getCookieNameProps("_shibstate_");
        const char* relay_state = st->getCookie(relay_cookie.first);
        if (!relay_state || !*relay_state) {
            // No apparent relay state value to use, so fall back on the default.
            pair<bool,const char*> homeURL=app->getString("homeURL");
            target=homeURL.first ? homeURL.second : "/";
        }
        else {
            char* rscopy=strdup(relay_state);
            CgiParse::url_decode(rscopy);
            target=rscopy;
            free(rscopy);
        }
    }

    // We've got a good session, set the session cookie.
    pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibsession_");
    st->setCookie(shib_cookie.first, cookie + shib_cookie.second);

    const IPropertySet* sessionProps=app->getPropertySet("Sessions");
    pair<bool,bool> idpHistory=sessionProps->getBool("idpHistory");
    if (!idpHistory.first || idpHistory.second) {
        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(st->getCookie(CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days=sessionProps->getUnsignedInt("idpHistoryDays");
            if (!days.first || days.second==0)
                st->setCookie(CommonDomainCookie::CDCName,string(cdc.set(providerId.c_str())) + shib_cookie.second);
            else {
                time_t now=time(NULL) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
                struct tm res;
                struct tm* ptime=gmtime_r(&now,&res);
#else
                struct tm* ptime=gmtime(&now);
#endif
                char timebuf[64];
                strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT",ptime);
                st->setCookie(
                    CommonDomainCookie::CDCName,
                    string(cdc.set(providerId.c_str())) + shib_cookie.second + "; expires=" + timebuf
                    );
        }
    }

    // Now redirect to the target.
    return make_pair(true, st->sendRedirect(target));
}
