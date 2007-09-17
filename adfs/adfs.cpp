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

/**
 * adfs.cpp
 *
 * ADFSv1 extension library
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define ADFS_EXPORTS __declspec(dllexport)
#else
# define ADFS_EXPORTS
#endif

#include <shibsp/base.h>
#include <shibsp/exceptions.h>
#include <shibsp/Application.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/SessionCache.h>
#include <shibsp/SPConfig.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/handler/LogoutHandler.h>
#include <shibsp/handler/SessionInitiator.h>
#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <shibsp/attribute/resolver/ResolutionContext.h>
# include <saml/SAMLConfig.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml1/profile/AssertionValidator.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/EndpointManager.h>
# include <xmltooling/impl/AnyElement.h>
# include <xmltooling/validation/ValidatorSuite.h>
using namespace opensaml::saml2md;
#endif
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#define WSFED_NS "http://schemas.xmlsoap.org/ws/2003/07/secext"
#define WSTRUST_NS "http://schemas.xmlsoap.org/ws/2005/02/trust"

namespace {

#ifndef SHIBSP_LITE
    class SHIBSP_DLLLOCAL ADFSDecoder : public MessageDecoder
    {
        auto_ptr_XMLCh m_ns;
    public:
        ADFSDecoder() : m_ns(WSTRUST_NS) {}
        virtual ~ADFSDecoder() {}
        
        XMLObject* decode(string& relayState, const GenericRequest& genericRequest, SecurityPolicy& policy) const;

    protected:
        void extractMessageDetails(
            const XMLObject& message, const GenericRequest& req, const XMLCh* protocol, SecurityPolicy& policy
            ) const {
        }
    };

    MessageDecoder* ADFSDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
    {
        return new ADFSDecoder();
    }
#endif

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL ADFSSessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        ADFSSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.ADFS")), m_appId(appId), m_binding(WSFED_NS) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSSI";
                setAddress(address.c_str());
            }
        }
        virtual ~ADFSSessionInitiator() {}
        
        void setParent(const PropertySet* parent) {
            DOMPropertySet::setParent(parent);
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSSI";
                setAddress(address.c_str());
            }
            else {
                m_log.warn("no Location property in ADFS SessionInitiator (or parent), can't register as remoted handler");
            }
        }

        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, const char* entityID=NULL, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application,
            HTTPResponse& httpResponse,
            const char* entityID,
            const char* acsLocation,
            string& relayState
            ) const;
        string m_appId;
        auto_ptr_XMLCh m_binding;
    };

    class SHIBSP_DLLLOCAL ADFSConsumer : public shibsp::AssertionConsumerService
    {
    public:
        ADFSConsumer(const DOMElement* e, const char* appId)
            : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".SSO.ADFS"))
#ifndef SHIBSP_LITE
                ,m_protocol(WSFED_NS)
#endif
            {}
        virtual ~ADFSConsumer() {}

    private:
#ifndef SHIBSP_LITE
        string implementProtocol(
            const Application& application,
            const HTTPRequest& httpRequest,
            SecurityPolicy& policy,
            const PropertySet* settings,
            const XMLObject& xmlObject
            ) const;
        auto_ptr_XMLCh m_protocol;
#endif
    };

    class SHIBSP_DLLLOCAL ADFSLogoutInitiator : public AbstractHandler, public RemotedHandler
    {
    public:
        ADFSLogoutInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.ADFS")), m_appId(appId), m_binding(WSFED_NS) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSLI";
                setAddress(address.c_str());
            }
        }
        virtual ~ADFSLogoutInitiator() {}
        
        void setParent(const PropertySet* parent) {
            DOMPropertySet::setParent(parent);
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSLI";
                setAddress(address.c_str());
            }
            else {
                m_log.warn("no Location property in ADFS LogoutInitiator (or parent), can't register as remoted handler");
            }
        }

        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        pair<bool,long> doRequest(
            const Application& application, const char* requestURL, const char* entityID, HTTPResponse& httpResponse
            ) const;

        string m_appId;
        auto_ptr_XMLCh m_binding;
    };

    class SHIBSP_DLLLOCAL ADFSLogout : public AbstractHandler, public LogoutHandler
    {
    public:
        ADFSLogout(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".Logout.ADFS")), m_login(e, appId) {
#ifndef SHIBSP_LITE
            m_initiator = false;
            m_preserve.push_back("wreply");
            string address = string(appId) + getString("Location").second + "::run::ADFSLO";
            setAddress(address.c_str());
#endif
        }
        virtual ~ADFSLogout() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        ADFSConsumer m_login;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* ADFSSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSSessionInitiator(p.first, p.second);
    }

    Handler* ADFSLogoutFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSLogout(p.first, p.second);
    }

    Handler* ADFSLogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSLogoutInitiator(p.first, p.second);
    }

    const XMLCh RequestedSecurityToken[] =      UNICODE_LITERAL_22(R,e,q,u,e,s,t,e,d,S,e,c,u,r,i,t,y,T,o,k,e,n);
    const XMLCh RequestSecurityTokenResponse[] =UNICODE_LITERAL_28(R,e,q,u,e,s,t,S,e,c,u,r,i,t,y,T,o,k,e,n,R,e,s,p,o,n,s,e);
};

extern "C" int ADFS_EXPORTS xmltooling_extension_init(void*)
{
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.registerFactory("ADFS", ADFSSessionInitiatorFactory);
    conf.LogoutInitiatorManager.registerFactory("ADFS", ADFSLogoutInitiatorFactory);
    conf.AssertionConsumerServiceManager.registerFactory("ADFS", ADFSLogoutFactory);
    conf.AssertionConsumerServiceManager.registerFactory(WSFED_NS, ADFSLogoutFactory);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.registerFactory(WSFED_NS, ADFSDecoderFactory);
    XMLObjectBuilder::registerBuilder(QName(WSTRUST_NS,"RequestedSecurityToken"), new AnyElementBuilder());
    XMLObjectBuilder::registerBuilder(QName(WSTRUST_NS,"RequestSecurityTokenResponse"), new AnyElementBuilder());
#endif
    return 0;
}

extern "C" void ADFS_EXPORTS xmltooling_extension_term()
{
    /* should get unregistered during normal shutdown...
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.deregisterFactory("ADFS");
    conf.LogoutInitiatorManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory(WSFED_NS);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.deregisterFactory(WSFED_NS);
#endif
    */
}

pair<bool,long> ADFSSessionInitiator::run(SPRequest& request, const char* entityID, bool isHandler) const
{
    // We have to know the IdP to function.
    if (!entityID || !*entityID)
        return make_pair(false,0);

    string target;
    const Handler* ACS=NULL;
    const char* option;
    const Application& app=request.getApplication();

    if (isHandler) {
        option = request.getParameter("target");
        if (option)
            target = option;

        // Since we're passing the ACS by value, we need to compute the return URL,
        // so we'll need the target resource for real.
        recoverRelayState(request.getApplication(), request, target, false);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
    }

    // Since we're not passing by index, we need to fully compute the return URL.
    if (!ACS) {
        // Get all the ADFS endpoints.
        const vector<const Handler*>& handlers = app.getAssertionConsumerServicesByBinding(m_binding.get());

        // Index comes from request, or default set in the handler, or we just pick the first endpoint.
        pair<bool,unsigned int> index = make_pair(false,0);
        if (isHandler) {
            option = request.getParameter("acsIndex");
            if (option)
                index = make_pair(true, atoi(option));
        }
        if (!index.first)
            index = getUnsignedInt("defaultACSIndex");
        if (index.first) {
            for (vector<const Handler*>::const_iterator h = handlers.begin(); !ACS && h!=handlers.end(); ++h) {
                if (index.second == (*h)->getUnsignedInt("index").second)
                    ACS = *h;
            }
        }
        else if (!handlers.empty()) {
            ACS = handlers.front();
        }
    }
    if (!ACS)
        throw ConfigurationException("Unable to locate ADFS response endpoint.");

    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc=request.getHandlerURL(target.c_str());
    pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
    if (loc.first) ACSloc+=loc.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        target.erase();
        option = request.getParameter("target");
        if (option)
            target = option;
    }

    m_log.debug("attempting to initiate session using ADFS with provider (%s)", entityID);

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
        return doRequest(app, request, entityID, ACSloc.c_str(), target);

    // Remote the call.
    DDF out,in = DDF(m_address.c_str()).structure();
    DDFJanitor jin(in), jout(out);
    in.addmember("application_id").string(app.getId());
    in.addmember("entity_id").string(entityID);
    in.addmember("acsLocation").string(ACSloc.c_str());
    if (!target.empty())
        in.addmember("RelayState").string(target.c_str());

    // Remote the processing.
    out = request.getServiceProvider().getListenerService()->send(in);
    return unwrap(request, out);
}

void ADFSSessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate ADFS request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    const char* acsLocation = in["acsLocation"].string();
    if (!entityID || !acsLocation)
        throw ConfigurationException("No entityID or acsLocation parameter supplied to remoted SessionInitiator.");

    DDF ret(NULL);
    DDFJanitor jout(ret);

    // Wrap the outgoing object with a Response facade.
    auto_ptr<HTTPResponse> http(getResponse(ret));

    string relayState(in["RelayState"].string() ? in["RelayState"].string() : "");

    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, *http.get(), entityID, acsLocation, relayState);
    out << ret;
}

pair<bool,long> ADFSSessionInitiator::doRequest(
    const Application& app,
    HTTPResponse& httpResponse,
    const char* entityID,
    const char* acsLocation,
    string& relayState
    ) const
{
#ifndef SHIBSP_LITE
    // Use metadata to invoke the SSO service directly.
    MetadataProvider* m=app.getMetadataProvider();
    Locker locker(m);
    const EntityDescriptor* entity=m->getEntityDescriptor(entityID);
    if (!entity) {
        m_log.error("unable to locate metadata for provider (%s)", entityID);
        throw MetadataException("Unable to locate metadata for identity provider ($entityID)",
            namedparams(1, "entityID", entityID));
    }
    const IDPSSODescriptor* role=entity->getIDPSSODescriptor(m_binding.get());
    if (!role) {
        m_log.error("unable to locate ADFS-aware identity provider role for provider (%s)", entityID);
        return make_pair(false,0);
    }
    const EndpointType* ep=EndpointManager<SingleSignOnService>(role->getSingleSignOnServices()).getByBinding(m_binding.get());
    if (!ep) {
        m_log.error("unable to locate compatible SSO service for provider (%s)", entityID);
        return make_pair(false,0);
    }

    preserveRelayState(app, httpResponse, relayState);

    // UTC timestamp
    time_t epoch=time(NULL);
#ifndef HAVE_GMTIME_R
    struct tm* ptime=gmtime(&epoch);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&epoch,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);

    auto_ptr_char dest(ep->getLocation());
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();

    string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "wa=wsignin1.0&wreply=" + urlenc->encode(acsLocation) +
        "&wct=" + urlenc->encode(timebuf) + "&wtrealm=" + urlenc->encode(app.getString("entityID").second);
    if (!relayState.empty())
        req += "&wctx=" + urlenc->encode(relayState.c_str());

    return make_pair(true, httpResponse.sendRedirect(req.c_str()));
#else
    return make_pair(false,0);
#endif
}

#ifndef SHIBSP_LITE

XMLObject* ADFSDecoder::decode(string& relayState, const GenericRequest& genericRequest, SecurityPolicy& policy) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("decode");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT".MessageDecoder.ADFS");

    log.debug("validating input");
    const HTTPRequest* httpRequest=dynamic_cast<const HTTPRequest*>(&genericRequest);
    if (!httpRequest)
        throw BindingException("Unable to cast request object to HTTPRequest type.");
    if (strcmp(httpRequest->getMethod(),"POST"))
        throw BindingException("Invalid HTTP method ($1).", params(1, httpRequest->getMethod()));
    const char* param = httpRequest->getParameter("wa");
    if (!param || strcmp(param, "wsignin1.0"))
        throw BindingException("Missing or invalid wa parameter (should be wsignin1.0).");
    param = httpRequest->getParameter("wctx");
    if (param)
        relayState = param;

    param = httpRequest->getParameter("wresult");
    if (!param)
        throw BindingException("Request missing wresult parameter.");

    log.debug("decoded ADFS response:\n%s", param);

    // Parse and bind the document into an XMLObject.
    istringstream is(param);
    DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser()
        : XMLToolingConfig::getConfig().getParser()).parse(is); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    if (!XMLHelper::isNodeNamed(xmlObject->getDOM(), m_ns.get(), RequestSecurityTokenResponse))
        throw BindingException("Decoded message was not of the appropriate type.");

    if (!policy.getValidating())
        SchemaValidators.validate(xmlObject.get());

    // Skip policy step here, there's no security in the wrapper.
    // policy.evaluate(*xmlObject.get(), &genericRequest);
    
    return xmlObject.release();
}

string ADFSConsumer::implementProtocol(
    const Application& application,
    const HTTPRequest& httpRequest,
    SecurityPolicy& policy,
    const PropertySet* settings,
    const XMLObject& xmlObject
    ) const
{
    // Implementation of ADFS profile.
    m_log.debug("processing message against ADFS Passive Requester profile");

    // With ADFS, all the security comes from the assertion, which is two levels down in the message.

    const ElementProxy* response = dynamic_cast<const ElementProxy*>(&xmlObject);
    if (!response || !response->hasChildren())
        throw FatalProfileException("Incoming message was not of the proper type or contains no security token.");
    response = dynamic_cast<const ElementProxy*>(response->getUnknownXMLObjects().front());
    if (!response || !response->hasChildren())
        throw FatalProfileException("Token wrapper element did not contain a security token.");
    const saml1::Assertion* token = dynamic_cast<const saml1::Assertion*>(response->getUnknownXMLObjects().front());
    if (!token || !token->getSignature())
        throw FatalProfileException("Incoming message did not contain a signed SAML 1.1 assertion.");

    // Extract message and issuer details from assertion.
    extractMessageDetails(*token, m_protocol.get(), policy);

    // Run the policy over the assertion. Handles replay, freshness, and
    // signature verification, assuming the relevant rules are configured.
    policy.evaluate(*token);
    
    // If no security is in place now, we kick it.
    if (!policy.isAuthenticated())
        throw SecurityPolicyException("Unable to establish security of incoming assertion.");

    // Now do profile and core semantic validation to ensure we can use it for SSO.
    // Profile validator.
    time_t now = time(NULL);
    saml1::AssertionValidator ssoValidator(application.getAudiences(), now);
    ssoValidator.validateAssertion(*token);
    if (!token->getConditions() || !token->getConditions()->getNotBefore() || !token->getConditions()->getNotOnOrAfter())
        throw FatalProfileException("Assertion did not contain time conditions.");
    else if (token->getAuthenticationStatements().empty())
        throw FatalProfileException("Assertion did not contain an authentication statement.");

    // With ADFS, we only have one token, but we need to put it in a vector.
    vector<const Assertion*> tokens(1,token);
    const saml1::AuthenticationStatement* ssoStatement=token->getAuthenticationStatements().front();

    // Address checking.
    saml1::SubjectLocality* locality = ssoStatement->getSubjectLocality();
    if (locality && locality->getIPAddress()) {
        auto_ptr_char ip(locality->getIPAddress());
        checkAddress(application, httpRequest, ip.get());
    }

    m_log.debug("ADFS profile processing completed successfully");

    saml1::NameIdentifier* n = ssoStatement->getSubject()->getNameIdentifier();

    // Now we have to extract the authentication details for attribute and session setup.

    // Session expiration for ADFS is purely SP-driven, and the method is mapped to a ctx class.
    const PropertySet* sessionProps = application.getPropertySet("Sessions");
    pair<bool,unsigned int> lifetime = sessionProps ? sessionProps->getUnsignedInt("lifetime") : pair<bool,unsigned int>(true,28800);
    if (!lifetime.first || lifetime.second == 0)
        lifetime.second = 28800;

    // We've successfully "accepted" the SSO token.
    // To complete processing, we need to extract and resolve attributes and then create the session.

    // Normalize the SAML 1.x NameIdentifier...
    auto_ptr<saml2::NameID> nameid(n ? saml2::NameIDBuilder::buildNameID() : NULL);
    if (n) {
        nameid->setName(n->getName());
        nameid->setFormat(n->getFormat());
        nameid->setNameQualifier(n->getNameQualifier());
    }

    // The context will handle deleting attributes and new tokens.
        auto_ptr<ResolutionContext> ctx(
        resolveAttributes(
            application,
            policy.getIssuerMetadata(),
            m_protocol.get(),
            n,
            nameid.get(),
            ssoStatement->getAuthenticationMethod(),
            NULL,
            &tokens
            )
        );

    if (ctx.get()) {
        // Copy over any new tokens, but leave them in the context for cleanup.
        tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());
    }

    return application.getServiceProvider().getSessionCache()->insert(
        now + lifetime.second,
        application,
        httpRequest.getRemoteAddr().c_str(),
        policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL,
        m_protocol.get(),
        nameid.get(),
        ssoStatement->getAuthenticationInstant() ? ssoStatement->getAuthenticationInstant()->getRawData() : NULL,
        NULL,
        ssoStatement->getAuthenticationMethod(),
        NULL,
        &tokens,
        ctx.get() ? &ctx->getResolvedAttributes() : NULL
        );
}

#endif

pair<bool,long> ADFSLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Normally we'd do notifications and session clearage here, but ADFS logout
    // is missing the needed request/response features, so we have to rely on
    // the IdP half to notify us back about the logout and do the work there.
    // Basically we have no way to tell in the Logout receiving handler whether
    // we initiated the logout or not.

    Session* session = NULL;
    try {
        session = request.getSession(false, true, false);  // don't cache it and ignore all checks
        if (!session)
            return make_pair(false,0);

        // We only handle ADFS sessions.
        if (!XMLString::equals(session->getProtocol(), WSFED_NS) || !session->getEntityID()) {
            session->unlock();
            return make_pair(false,0);
        }
    }
    catch (exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
        return make_pair(false,0);
    }

    string entityID(session->getEntityID());
    session->unlock();

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // When out of process, we run natively.
        return doRequest(request.getApplication(), request.getRequestURL(), entityID.c_str(), request);
    }
    else {
        // When not out of process, we remote the request.
        Locker locker(session, false);
        DDF out,in(m_address.c_str());
        DDFJanitor jin(in), jout(out);
        in.addmember("application_id").string(request.getApplication().getId());
        in.addmember("url").string(request.getRequestURL());
        in.addmember("entity_id").string(entityID.c_str());
        out=request.getServiceProvider().getListenerService()->send(in);
        return unwrap(request, out);
    }
}

void ADFSLogoutInitiator::receive(DDF& in, ostream& out)
{
#ifndef SHIBSP_LITE
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for logout", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for logout, deleted?");
    }
    
    // Set up a response shim.
    DDF ret(NULL);
    DDFJanitor jout(ret);
    auto_ptr<HTTPResponse> resp(getResponse(ret));
    
    // Since we're remoted, the result should either be a throw, which we pass on,
    // a false/0 return, which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    doRequest(*app, in["url"].string(), in["entity_id"].string(), *resp.get());

    out << ret;
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> ADFSLogoutInitiator::doRequest(
    const Application& application, const char* requestURL, const char* entityID, HTTPResponse& response
    ) const
{
#ifndef SHIBSP_LITE
    try {
        if (!entityID)
            throw ConfigurationException("Missing entityID parameter.");

        // With a session in hand, we can create a request message, if we can find a compatible endpoint.
        Locker metadataLocker(application.getMetadataProvider());
        const EntityDescriptor* entity = application.getMetadataProvider()->getEntityDescriptor(entityID);
        if (!entity) {
            throw MetadataException(
                "Unable to locate metadata for identity provider ($entityID)",
                namedparams(1, "entityID", entityID)
                );
        }
        const IDPSSODescriptor* role = entity->getIDPSSODescriptor(m_binding.get());
        if (!role) {
            throw MetadataException(
                "Unable to locate ADFS IdP role for identity provider ($entityID).",
                namedparams(1, "entityID", entityID)
                );
        }

        const EndpointType* ep = EndpointManager<SingleLogoutService>(role->getSingleLogoutServices()).getByBinding(m_binding.get());
        if (!ep) {
            throw MetadataException(
                "Unable to locate ADFS single logout service for identity provider ($entityID).",
                namedparams(1, "entityID", entityID)
                );
        }

        auto_ptr_char dest(ep->getLocation());

        string req=string(dest.get()) + (strchr(dest.get(),'?') ? '&' : '?') + "wa=wsignout1.0";
        return make_pair(true,response.sendRedirect(req.c_str()));
    }
    catch (exception& ex) {
        m_log.error("error issuing ADFS logout request: %s", ex.what());
    }

    return make_pair(false,0);
#else
    throw ConfigurationException("Cannot perform logout using lite version of shibsp library.");
#endif
}

pair<bool,long> ADFSLogout::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class for front-channel loop first.
    // This won't initiate the loop, only continue/end it.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    // wa parameter indicates the "action" to perform
    bool returning = false;
    const char* param = request.getParameter("wa");
    if (param) {
        if (!strcmp(param, "wsignin1.0"))
            return m_login.run(request, isHandler);
        else if (strcmp(param, "wsignout1.0") && strcmp(param, "wsignoutcleanup1.0"))
            throw FatalProfileException("Unsupported WS-Federation action paremeter ($1).", params(1, param));
    }
    else if (strcmp(request.getMethod(),"GET") || !request.getParameter("notifying"))
        throw FatalProfileException("Unsupported request to ADFS protocol endpoint.");
    else
        returning = true;

    param = request.getParameter("wreply");
    const Application& app = request.getApplication();

    // Get the session_id.
    pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");
    const char* session_id = request.getCookie(shib_cookie.first.c_str());

    if (!returning) {
        // Pass control to the first front channel notification point, if any.
        map<string,string> parammap;
        if (param)
            parammap["wreply"] = param;
        pair<bool,long> result = notifyFrontChannel(app, request, request, &parammap);
        if (result.first)
            return result;
    }

    // Best effort on back channel and to remove the user agent's session.
    if (session_id) {
        vector<string> sessions(1,session_id);
        notifyBackChannel(app, request.getRequestURL(), sessions, false);
        try {
            app.getServiceProvider().getSessionCache()->remove(session_id, app);
        }
        catch (exception& ex) {
            m_log.error("error removing session (%s): %s", session_id, ex.what());
        }
        request.setCookie(shib_cookie.first.c_str(), shib_cookie.second);
    }

    if (param)
        return make_pair(true, request.sendRedirect(param));
    return sendLogoutPage(app, request, false, "Logout complete.");
}
