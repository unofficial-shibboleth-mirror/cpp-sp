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
#include <shibsp/SPConfig.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/handler/LogoutHandler.h>
#include <shibsp/handler/SessionInitiator.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <log4cpp/Category.hh>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <shibsp/SessionCache.h>
# include <shibsp/attribute/Attribute.h>
# include <shibsp/attribute/filtering/AttributeFilter.h>
# include <shibsp/attribute/filtering/BasicFilteringContext.h>
# include <shibsp/attribute/resolver/AttributeExtractor.h>
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
using namespace opensaml;
#endif
using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace log4cpp;
using namespace std;

#define WSFED_NS "http://schemas.xmlsoap.org/ws/2003/07/secext"
#define WSTRUST_NS "http://schemas.xmlsoap.org/ws/2005/02/trust"

namespace {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL ADFSSessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        ADFSSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator")), m_appId(appId), m_binding(WSFED_NS) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::ADFSSI";
                setAddress(address.c_str());
            }
        }
        virtual ~ADFSSessionInitiator() {}
        
        void setParent(const PropertySet* parent);
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
            : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".ADFSSSO"))
#ifndef SHIBSP_LITE
                ,m_binding(WSFED_NS)
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
        auto_ptr_XMLCh m_binding;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

#ifndef SHIBSP_LITE
    class ADFSDecoder : public MessageDecoder
    {
        auto_ptr_XMLCh m_ns;
    public:
        ADFSDecoder() : m_ns(WSTRUST_NS) {}
        virtual ~ADFSDecoder() {}
        
        XMLObject* decode(string& relayState, const GenericRequest& genericRequest, SecurityPolicy& policy) const;
    };

    MessageDecoder* ADFSDecoderFactory(const pair<const DOMElement*,const XMLCh*>& p)
    {
        return new ADFSDecoder();
    }
#endif

    SessionInitiator* ADFSSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSSessionInitiator(p.first, p.second);
    }

    Handler* ADFSConsumerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ADFSConsumer(p.first, p.second);
    }

    const XMLCh RequestedSecurityToken[] =      UNICODE_LITERAL_22(R,e,q,u,e,s,t,e,d,S,e,c,u,r,i,t,y,T,o,k,e,n);
    const XMLCh RequestSecurityTokenResponse[] =UNICODE_LITERAL_28(R,e,q,u,e,s,t,S,e,c,u,r,i,t,y,T,o,k,e,n,R,e,s,p,o,n,s,e);
};

extern "C" int ADFS_EXPORTS xmltooling_extension_init(void*)
{
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.registerFactory("ADFS", ADFSSessionInitiatorFactory);
    conf.AssertionConsumerServiceManager.registerFactory("ADFS", ADFSConsumerFactory);
    conf.AssertionConsumerServiceManager.registerFactory(WSFED_NS, ADFSConsumerFactory);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.registerFactory(WSFED_NS, ADFSDecoderFactory);
    XMLObjectBuilder::registerBuilder(QName(WSTRUST_NS,"RequestedSecurityToken"), new AnyElementBuilder());
    XMLObjectBuilder::registerBuilder(QName(WSTRUST_NS,"RequestedSecurityTokenResponse"), new AnyElementBuilder());
#endif
    return 0;
}

extern "C" void ADFS_EXPORTS xmltooling_extension_term()
{
    /* should get unregistered during normal shutdown...
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory("ADFS");
    conf.AssertionConsumerServiceManager.deregisterFactory(WSFED_NS);
#ifndef SHIBSP_LITE
    SAMLConfig::getConfig().MessageDecoderManager.deregisterFactory(WSFED_NS);
#endif
    */
}

void ADFSSessionInitiator::setParent(const PropertySet* parent)
{
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
#ifndef HAVE_GMTIME_R
    time_t epoch=time(NULL);
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

    // Run through the policy.
    policy.evaluate(*xmlObject.get(), &genericRequest);
    
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

    // Run the policy over the assertion. Handles issuer consistency, replay, freshness,
    // and signature verification, assuming the relevant rules are configured.
    policy.evaluate(*token);
    
    // If no security is in place now, we kick it.
    if (!policy.isSecure())
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
    multimap<string,Attribute*> resolvedAttributes;
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        m_log.debug("extracting pushed attributes...");
        Locker extlocker(extractor);
        if (n) {
            try {
                extractor->extractAttributes(application, policy.getIssuerMetadata(), *n, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }
        try {
            extractor->extractAttributes(application, policy.getIssuerMetadata(), *token, resolvedAttributes);
        }
        catch (exception& ex) {
            m_log.error("caught exception extracting attributes: %s", ex.what());
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter && !resolvedAttributes.empty()) {
            BasicFilteringContext fc(application, resolvedAttributes, policy.getIssuerMetadata(), ssoStatement->getAuthenticationMethod());
            Locker filtlocker(filter);
            try {
                filter->filterAttributes(fc, resolvedAttributes);
            }
            catch (exception& ex) {
                m_log.error("caught exception filtering attributes: %s", ex.what());
                m_log.error("dumping extracted attributes due to filtering exception");
                for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,shibsp::Attribute>());
                resolvedAttributes.clear();
            }
        }
    }

    // Normalize the SAML 1.x NameIdentifier...
    auto_ptr<saml2::NameID> nameid(n ? saml2::NameIDBuilder::buildNameID() : NULL);
    if (n) {
        nameid->setName(n->getName());
        nameid->setFormat(n->getFormat());
        nameid->setNameQualifier(n->getNameQualifier());
    }

    const EntityDescriptor* issuerMetadata =
        policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : NULL;
    auto_ptr<ResolutionContext> ctx(
        resolveAttributes(
            application,
            issuerMetadata,
            m_binding.get(),
            nameid.get(),
            ssoStatement->getAuthenticationMethod(),
            NULL,
            &tokens,
            &resolvedAttributes
            )
        );

    if (ctx.get()) {
        // Copy over any new tokens, but leave them in the context for cleanup.
        tokens.insert(tokens.end(), ctx->getResolvedAssertions().begin(), ctx->getResolvedAssertions().end());

        // Copy over new attributes, and transfer ownership.
        resolvedAttributes.insert(ctx->getResolvedAttributes().begin(), ctx->getResolvedAttributes().end());
        ctx->getResolvedAttributes().clear();
    }

    try {
        string key = application.getServiceProvider().getSessionCache()->insert(
            now + lifetime.second,
            application,
            httpRequest.getRemoteAddr().c_str(),
            issuerMetadata,
            m_binding.get(),
            nameid.get(),
            ssoStatement->getAuthenticationInstant() ? ssoStatement->getAuthenticationInstant()->getRawData() : NULL,
            NULL,
            ssoStatement->getAuthenticationMethod(),
            NULL,
            &tokens,
            &resolvedAttributes
            );
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        return key;
    }
    catch (exception&) {
        for_each(resolvedAttributes.begin(), resolvedAttributes.end(), cleanup_pair<string,Attribute>());
        throw;
    }
}

#endif
