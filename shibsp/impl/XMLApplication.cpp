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
 * XMLServiceProvider.cpp
 *
 * XML-based SP configuration and mgmt.
 */

#include "internal.h"
#include "ServiceProvider.h"
#include "SPConfig.h"
#include "binding/ProtocolProvider.h"
#include "handler/LogoutInitiator.h"
#include "handler/SessionInitiator.h"
#include "impl/XMLApplication.h"

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLHelper.h>

#ifndef SHIBSP_LITE
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "security/PKIXTrustEngine.h"
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/binding/SAMLArtifact.h>
# include <saml/saml2/binding/SAML2ArtifactType0004.h>
# include <saml/saml2/metadata/EntityMatcher.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <xmltooling/security/ChainingTrustEngine.h>
# include <xmltooling/security/CredentialResolver.h>
# include <xmltooling/security/SecurityHelper.h>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace {

    static vector<const Handler*> g_noHandlers;

    static const XMLCh applicationId[] =        UNICODE_LITERAL_13(a,p,p,l,i,c,a,t,i,o,n,I,d);
    static const XMLCh ApplicationOverride[] =  UNICODE_LITERAL_19(A,p,p,l,i,c,a,t,i,o,n,O,v,e,r,r,i,d,e);
    static const XMLCh _AttributeExtractor[] =  UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,E,x,t,r,a,c,t,o,r);
    static const XMLCh _AttributeFilter[] =     UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh _AssertionConsumerService[] = UNICODE_LITERAL_24(A,s,s,e,r,t,i,o,n,C,o,n,s,u,m,e,r,S,e,r,v,i,c,e);
    static const XMLCh _ArtifactResolutionService[] =UNICODE_LITERAL_25(A,r,t,i,f,a,c,t,R,e,s,o,l,u,t,i,o,n,S,e,r,v,i,c,e);
    static const XMLCh _Audience[] =            UNICODE_LITERAL_8(A,u,d,i,e,n,c,e);
    static const XMLCh Binding[] =              UNICODE_LITERAL_7(B,i,n,d,i,n,g);
    static const XMLCh Channel[]=               UNICODE_LITERAL_7(C,h,a,n,n,e,l);
    static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh _default[] =             UNICODE_LITERAL_7(d,e,f,a,u,l,t);
    static const XMLCh ExternalApplicationOverrides[] = UNICODE_LITERAL_28(E,x,t,e,r,n,a,l,A,p,p,l,i,c,a,t,i,o,n,O,v,e,r,r,i,d,e,s);
    static const XMLCh _Handler[] =             UNICODE_LITERAL_7(H,a,n,d,l,e,r);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _index[] =               UNICODE_LITERAL_5(i,n,d,e,x);
    static const XMLCh Location[] =             UNICODE_LITERAL_8(L,o,c,a,t,i,o,n);
    static const XMLCh Logout[] =               UNICODE_LITERAL_6(L,o,g,o,u,t);
    static const XMLCh _LogoutInitiator[] =     UNICODE_LITERAL_15(L,o,g,o,u,t,I,n,i,t,i,a,t,o,r);
    static const XMLCh _ManageNameIDService[] = UNICODE_LITERAL_19(M,a,n,a,g,e,N,a,m,e,I,D,S,e,r,v,i,c,e);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh NameIDMgmt[] =           UNICODE_LITERAL_10(N,a,m,e,I,D,M,g,m,t);
    static const XMLCh Notify[] =               UNICODE_LITERAL_6(N,o,t,i,f,y);
    static const XMLCh _policyId[] =            UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
    static const XMLCh RelyingParty[] =         UNICODE_LITERAL_12(R,e,l,y,i,n,g,P,a,r,t,y);
    static const XMLCh _SessionInitiator[] =    UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _SingleLogoutService[] = UNICODE_LITERAL_19(S,i,n,g,l,e,L,o,g,o,u,t,S,e,r,v,i,c,e);
    static const XMLCh SSO[] =                  UNICODE_LITERAL_3(S,S,O);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
};

XMLApplication::XMLApplication(
    const ServiceProvider* sp,
    const ProtocolProvider* pp,
    DOMElement* e,
    bool deprecationSupport,
    const XMLApplication* base,
    DOMDocument* doc
    ) : Application(sp), m_base(base), m_acsDefault(nullptr), m_sessionInitDefault(nullptr), m_artifactResolutionDefault(nullptr),
        m_deprecationSupport(deprecationSupport), m_doc(doc)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLApplication");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".Application");

    // First load any property sets.
    map<string,string> remapperMap;
    remapperMap[shibspconstants::ASCII_SHIB2SPCONFIG_NS] = shibspconstants::ASCII_SHIB3SPCONFIG_NS;
    remapperMap["relayStateLimit"] = "redirectLimit";
    remapperMap["relayStateWhitelist"] = "redirectWhitelist";
    DOMPropertySet::STLRemapper remapper(remapperMap);
    load(e, nullptr, this, &remapper);

    // Process redirect limit policy. Do this before assigning the parent pointer
    // to ensure we get only our Sessions element.
    const PropertySet* sessionProps = getPropertySet("Sessions");
    if (sessionProps) {
        pair<bool,const char*> prop = sessionProps->getString("redirectLimit");
        if (prop.first) {
            if (!strcmp(prop.second, "none"))
                m_redirectLimit = REDIRECT_LIMIT_NONE;
            else if (!strcmp(prop.second, "exact"))
                m_redirectLimit = REDIRECT_LIMIT_EXACT;
            else if (!strcmp(prop.second, "host"))
                m_redirectLimit = REDIRECT_LIMIT_HOST;
            else {
                if (!strcmp(prop.second, "exact+whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_EXACT_WHITELIST;
                else if (!strcmp(prop.second, "host+whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_HOST_WHITELIST;
                else if (!strcmp(prop.second, "whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_WHITELIST;
                else
                    throw ConfigurationException("Unrecognized redirectLimit setting ($1)", params(1, prop.second));
                prop = sessionProps->getString("redirectWhitelist");
                if (prop.first) {
                    string dup(prop.second);
                    trim(dup);
                    split(m_redirectWhitelist, dup, is_space(), algorithm::token_compress_on);
                }
            }
        }
        else {
            m_redirectLimit = base ? REDIRECT_LIMIT_INHERIT : REDIRECT_LIMIT_NONE;
        }

        // Audit some additional settings for logging purposes.
        prop = sessionProps->getString("cookieProps");
        if (!prop.first) {
            log.warn("empty/missing cookieProps setting, set to \"https\" for SSL/TLS-only usage");
        }
        else if (!strcmp(prop.second, "http")) {
            log.warn("insecure cookieProps setting, set to \"https\" for SSL/TLS-only usage");
        }
        else if (strcmp(prop.second, "https")) {
            if (!strstr(prop.second, "secure"))
                log.warn("custom cookieProps setting should include \"; secure\" for SSL/TLS-only usage");
            else if (!strstr(prop.second, "HttpOnly"))
                log.warn("custom cookieProps setting should include \"; HttpOnly\", site is vulnerable to client-side cookie theft");

            while (*prop.second && isspace(*prop.second))
                ++prop.second;
            if (*prop.second != ';')
                log.warn("custom cookieProps setting must begin with a semicolon (;) as a delimiter");
        }

        pair<bool,bool> handlerSSL = sessionProps->getBool("handlerSSL");
        if (handlerSSL.first && !handlerSSL.second)
            log.warn("handlerSSL should be enabled for SSL/TLS-enabled web sites");
    }
    else {
        m_redirectLimit = base ? REDIRECT_LIMIT_INHERIT : REDIRECT_LIMIT_NONE;
    }

    // Assign parent.
    if (base)
        setParent(base);

    SPConfig& conf=SPConfig::getConfig();
#ifndef SHIBSP_LITE
    XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
#endif

    // This used to be an actual hash, but now it's just a hex-encode to avoid xmlsec dependency.
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    string tohash=getId();
    tohash+=getString("entityID").second;
    for (const char* ch = tohash.c_str(); *ch; ++ch) {
        m_hash += (DIGITS[((unsigned char)(0xF0 & *ch)) >> 4 ]);
        m_hash += (DIGITS[0x0F & *ch]);
    }

    doAttributeInfo();

    if (conf.isEnabled(SPConfig::Handlers))
        doHandlers(pp, e, log);

    // Notification.
    const DOMNodeList* nlist = e->getElementsByTagNameNS(e->getNamespaceURI(), Notify);
    for (XMLSize_t i = 0; nlist && i < nlist->getLength(); ++i) {
        if (nlist->item(i)->getParentNode()->isSameNode(e)) {
            const XMLCh* channel = static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(nullptr, Channel);
            string loc(XMLHelper::getAttrString(static_cast<DOMElement*>(nlist->item(i)), nullptr, Location));
            if (!loc.empty()) {
                if (channel && *channel == chLatin_f)
                    m_frontLogout.push_back(loc);
                else
                    m_backLogout.push_back(loc);
            }
        }
    }

#ifndef SHIBSP_LITE
    nlist = e->getElementsByTagNameNS(samlconstants::SAML20_NS, Audience::LOCAL_NAME);
    if (nlist && nlist->getLength()) {
        log.warn("DEPRECATED: use of <saml:Audience> elements outside of a Security Policy Rule");
        for (XMLSize_t i = 0; i < nlist->getLength(); ++i)
            if (nlist->item(i)->getParentNode()->isSameNode(e) && nlist->item(i)->hasChildNodes())
                m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());
    }

    if (conf.isEnabled(SPConfig::Metadata)) {
        m_metadata.reset(
            doChainedPlugins(
                SAMLConfig::getConfig().MetadataProviderManager, "MetadataProvider", CHAINING_METADATA_PROVIDER, _MetadataProvider, e, log
                )
            );
        try {
            if (m_metadata)
                m_metadata->init();
            else if (!m_base)
                log.warn("no MetadataProvider available, configure at least one for standard SSO usage");
        }
        catch (const std::exception& ex) {
            log.crit("error initializing MetadataProvider: %s", ex.what());
        }
    }

    if (conf.isEnabled(SPConfig::Trust)) {
        m_trust.reset(doChainedPlugins(xmlConf.TrustEngineManager, "TrustEngine", CHAINING_TRUSTENGINE, _TrustEngine, e, log));
        if (!m_trust && !m_base) {
            if (XMLString::equals(e->getNamespaceURI(), shibspconstants::SHIB2SPCONFIG_NS)) {
                log.info(
                    "no TrustEngine specified or installed in legacy config, using default chain {%s, %s}",
                    EXPLICIT_KEY_TRUSTENGINE, SHIBBOLETH_PKIX_TRUSTENGINE
                    );
                m_trust.reset(xmlConf.TrustEngineManager.newPlugin(CHAINING_TRUSTENGINE, nullptr, m_deprecationSupport));
                ChainingTrustEngine* trustchain = dynamic_cast<ChainingTrustEngine*>(m_trust.get());
                if (trustchain) {
                    trustchain->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE, nullptr, m_deprecationSupport));
                    trustchain->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(SHIBBOLETH_PKIX_TRUSTENGINE, nullptr, m_deprecationSupport));
                }
            }
            else {
                log.info("no TrustEngine specified or installed, using default of %s", EXPLICIT_KEY_TRUSTENGINE);
                m_trust.reset(xmlConf.TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE, nullptr, m_deprecationSupport));
            }
        }
    }

    if (conf.isEnabled(SPConfig::AttributeResolution)) {
        doAttributePlugins(e, log);
    }

    if (conf.isEnabled(SPConfig::Credentials)) {
        m_credResolver.reset(
            doChainedPlugins(xmlConf.CredentialResolverManager, "CredentialResolver", CHAINING_CREDENTIAL_RESOLVER, _CredentialResolver, e, log)
            );
    }

    // Finally, load relying parties.
    const DOMElement* child = XMLHelper::getFirstChildElement(e, RelyingParty);
    while (child) {
        if (child->hasAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)) {
            boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
            rp->load(child, nullptr, this);
            rp->setParent(this);
            m_partyMap[child->getAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)] = rp;
        }
        else if (child->hasAttributeNS(nullptr, _type)) {
            string emtype(XMLHelper::getAttrString(child, nullptr, _type));
            boost::shared_ptr<EntityMatcher> em(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(emtype, child, m_deprecationSupport));
            boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
            rp->load(child, nullptr, this);
            rp->setParent(this);
            m_partyVec.push_back(make_pair(em, rp));
        }
        child = XMLHelper::getNextSiblingElement(child, RelyingParty);
    }
    if (base && m_partyMap.empty() && m_partyVec.empty() && (!base->m_partyMap.empty() || !base->m_partyVec.empty())) {
        // For inheritance of RPs to work, we have to pull them in to the override by cloning the DOM.
        child = XMLHelper::getFirstChildElement(base->getElement(), RelyingParty);
        while (child) {
            if (child->hasAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)) {
                DOMElement* rpclone = static_cast<DOMElement*>(child->cloneNode(true));
                boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
                rp->load(rpclone, nullptr, this);
                rp->setParent(this);
                m_partyMap[rpclone->getAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)] = rp;
            }
            else if (child->hasAttributeNS(nullptr, _type)) {
                DOMElement* rpclone = static_cast<DOMElement*>(child->cloneNode(true));
                string emtype(XMLHelper::getAttrString(rpclone, nullptr, _type));
                boost::shared_ptr<EntityMatcher> em(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(emtype, rpclone, m_deprecationSupport));
                boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
                rp->load(rpclone, nullptr, this);
                rp->setParent(this);
                m_partyVec.push_back(make_pair(em, rp));
            }
            child = XMLHelper::getNextSiblingElement(child, RelyingParty);
        }
    }
#endif

    // Out of process only, we register a listener endpoint.
    if (!conf.isEnabled(SPConfig::InProcess)) {
        string addr=string(getId()) + "::getHeaders::Application";
        const_cast<ServiceProvider*>(sp)->regListener(addr.c_str(), this);
    }
}

XMLApplication::~XMLApplication()
{
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess) && !SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        string addr=string(getId()) + "::getHeaders::Application";
        const_cast<ServiceProvider&>(getServiceProvider()).unregListener(addr.c_str(), this);
    }
    if (m_doc)
        m_doc->release();
}

template <class T> T* XMLApplication::doChainedPlugins(
    const PluginManager<T,string,const DOMElement*>& pluginMgr,
    const char* pluginType,
    const char* chainingType,
    const XMLCh* localName,
    DOMElement* e,
    Category& log,
    const char* dummyType
    )
{
    string t;
    DOMElement* child = XMLHelper::getFirstChildElement(e, localName);
    if (child) {
        // Check for multiple.
        if (XMLHelper::getNextSiblingElement(child, localName)) {
            log.info("multiple %s plugins, wrapping in a chain", pluginType);
            DOMElement* chain = child->getOwnerDocument()->createElementNS(nullptr, localName);
            while (child) {
                chain->appendChild(child);
                child = XMLHelper::getFirstChildElement(e, localName);
            }
            t = chainingType;
            child = chain;
            e->appendChild(chain);
        }
        else {
            // Only a single one.
            t = XMLHelper::getAttrString(child, nullptr, _type);
        }

        try {
            if (!t.empty()) {
                log.info("building %s of type %s...", pluginType, t.c_str());
                return pluginMgr.newPlugin(t.c_str(), child, m_deprecationSupport);
            }
            else {
                throw ConfigurationException("$1 element had no type attribute.", params(1, pluginType));
            }
        }
        catch (const std::exception& ex) {
            log.crit("error building %s: %s", pluginType, ex.what());
            if (dummyType) {
                // Install a dummy version as a safety valve.
                log.crit("installing safe %s in place of failed version", pluginType);
                return pluginMgr.newPlugin(dummyType, nullptr, m_deprecationSupport);
            }
        }
    }

    return nullptr;
}

void XMLApplication::doAttributeInfo()
{
    // Populate prefix pair.
    m_attributePrefix.second = "HTTP_";
    pair<bool,const char*> prefix = getString("attributePrefix");
    if (prefix.first) {
        m_attributePrefix.first = prefix.second;
        const char* pch = prefix.second;
        while (*pch) {
            m_attributePrefix.second += (isalnum(*pch) ? toupper(*pch) : '_');
            pch++;
        }
    }

    pair<bool,const char*> attributes = getString("REMOTE_USER");
    if (attributes.first) {
        string dup(attributes.second);
        trim(dup);
        split(m_remoteUsers, dup, is_space(), algorithm::token_compress_on);
    }

    // Load attribute ID lists for REMOTE_USER and header clearing.
    if (SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        attributes = getString("unsetHeaders");
        if (attributes.first) {
            string transformedprefix(m_attributePrefix.second);
            const char* pch;
            prefix = getString("metadataAttributePrefix");
            if (prefix.first) {
                pch = prefix.second;
                while (*pch) {
                    transformedprefix += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
            }

            string dup(attributes.second);
            trim(dup);
            vector<string> headerNames;
            split(headerNames, dup, is_space(), algorithm::token_compress_on);
            for (vector<string>::const_iterator h = headerNames.begin(); h != headerNames.end(); ++h) {
                string transformed;
                const char* pch = h->c_str();
                while (*pch) {
                    transformed += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
                m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + *h, m_attributePrefix.second + transformed));
                if (prefix.first)
                    m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + prefix.second + *h, transformedprefix + transformed));
            }
            m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + "Shib-Application-ID", m_attributePrefix.second + "SHIB_APPLICATION_ID"));
        }
    }
}

void XMLApplication::doHandlers(const ProtocolProvider* pp, const DOMElement* e, Category& log)
{
    SPConfig& conf = SPConfig::getConfig();

    const PropertySet* sessions = getPropertySet("Sessions");

    // Process assertion export handler.
    pair<bool,const char*> location = sessions ? sessions->getString("exportLocation") : pair<bool,const char*>(false,nullptr);
    if (location.first) {
        try {
            DOMElement* exportElement = e->getOwnerDocument()->createElementNS(e->getNamespaceURI(), _Handler);
            exportElement->setAttributeNS(nullptr,Location,sessions->getXMLString("exportLocation").second);
            pair<bool,const XMLCh*> exportACL = sessions->getXMLString("exportACL");
            if (exportACL.first) {
                static const XMLCh _acl[] = UNICODE_LITERAL_9(e,x,p,o,r,t,A,C,L);
                exportElement->setAttributeNS(nullptr,_acl,exportACL.second);
            }
            boost::shared_ptr<Handler> exportHandler(
                conf.HandlerManager.newPlugin(
                    samlconstants::SAML20_BINDING_URI, pair<const DOMElement*,const char*>(exportElement, getId()), m_deprecationSupport
                    )
                );
            m_handlers.push_back(exportHandler);

            // Insert into location map. If it contains the handlerURL, we skip past that part.
            const char* hurl = sessions->getString("handlerURL").second;
            if (!hurl)
                hurl = "/Shibboleth.sso";
            const char* pch = strstr(location.second, hurl);
            if (pch)
                location.second = pch + strlen(hurl);
            if (*location.second == '/')
                m_handlerMap[location.second] = exportHandler.get();
            else
                m_handlerMap[string("/") + location.second] = exportHandler.get();
        }
        catch (const std::exception& ex) {
            log.error("caught exception installing assertion lookup handler: %s", ex.what());
        }
    }

    // Look for "shorthand" elements first.
    set<string> protocols;
    DOMElement* child = sessions ? XMLHelper::getFirstChildElement(sessions->getElement()) : nullptr;
    while (child) {
        if (XMLHelper::isNodeNamed(child, sessions->getElement()->getNamespaceURI(), SSO)) {
            if (pp)
                doSSO(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, SSO auto-configure unsupported");
        }
        else if (XMLHelper::isNodeNamed(child, sessions->getElement()->getNamespaceURI(), Logout)) {
            if (pp)
                doLogout(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, Logout auto-configure unsupported");
        }
        else if (XMLHelper::isNodeNamed(child, sessions->getElement()->getNamespaceURI(), NameIDMgmt)) {
            if (pp)
                doNameIDMgmt(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, NameIDMgmt auto-configure unsupported");
        }
        else {
            break;  // drop into next while loop
        }
        child = XMLHelper::getNextSiblingElement(child);
    }

    // Process other handlers.
    bool hardACS=false, hardSessionInit=false, hardArt=false;
    while (child) {
        if (!child->hasAttributeNS(nullptr, Location)) {
            auto_ptr_char hclass(child->getLocalName());
            log.error("%s handler with no Location property cannot be processed for application (%s)",
                hclass.get(), getId());
            child = XMLHelper::getNextSiblingElement(child);
            continue;
        }

        auto_ptr_char dupcheck(child->getAttributeNS(nullptr, Location));
        if (dupcheck.get() && *dupcheck.get()) {
            string _dupcheck(dupcheck.get());
            if (*_dupcheck.begin() != '/')
                _dupcheck.insert(_dupcheck.begin(), '/');
            if (m_handlerMap.find(_dupcheck) != m_handlerMap.end()) {
                auto_ptr_char hclass(child->getLocalName());
                log.error("%s handler at duplicate Location (%s) will not be processed for application (%s)",
                    hclass.get(), _dupcheck.c_str(), getId());
                child = XMLHelper::getNextSiblingElement(child);
                continue;
            }
        }

        try {
            boost::shared_ptr<Handler> handler;
            if (XMLString::equals(child->getLocalName(), _AssertionConsumerService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("AssertionConsumerService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(
                    conf.AssertionConsumerServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );
                // Map by protocol.
                const XMLCh* protfamily = handler->getProtocolFamily();
                if (protfamily)
                    m_acsProtocolMap[protfamily].push_back(handler.get());
                m_acsIndexMap[handler->getUnsignedInt("index").second] = handler.get();

                if (!hardACS) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardACS = true;
                            m_acsDefault = handler.get();
                        }
                    }
                    else if (!m_acsDefault)
                        m_acsDefault = handler.get();
                }
            }
            else if (XMLString::equals(child->getLocalName(), _SessionInitiator)) {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("SessionInitiator element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                boost::shared_ptr<SessionInitiator> sihandler(
                    conf.SessionInitiatorManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );
                handler = sihandler;
                pair<bool,const char*> si_id = handler->getString("id");
                if (si_id.first && si_id.second)
                    m_sessionInitMap[si_id.second] = sihandler.get();
                if (!hardSessionInit) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardSessionInit = true;
                            m_sessionInitDefault = sihandler.get();
                        }
                    }
                    else if (!m_sessionInitDefault) {
                        m_sessionInitDefault = sihandler.get();
                    }
                }
            }
            else if (XMLString::equals(child->getLocalName(), _LogoutInitiator)) {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("LogoutInitiator element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(
                    conf.LogoutInitiatorManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );
            }
            else if (XMLString::equals(child->getLocalName(), _ArtifactResolutionService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("ArtifactResolutionService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(
                    conf.ArtifactResolutionServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );

                if (!hardArt) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardArt = true;
                            m_artifactResolutionDefault = handler.get();
                        }
                    }
                    else if (!m_artifactResolutionDefault)
                        m_artifactResolutionDefault = handler.get();
                }
            }
            else if (XMLString::equals(child->getLocalName(), _SingleLogoutService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("SingleLogoutService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(
                    conf.SingleLogoutServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );
            }
            else if (XMLString::equals(child->getLocalName(), _ManageNameIDService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("ManageNameIDService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(
                    conf.ManageNameIDServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport)
                    );
            }
            else {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("Handler element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.HandlerManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId()), m_deprecationSupport));
            }

            m_handlers.push_back(handler);

            // Insert into location map.
            location = handler->getString("Location");
            if (location.first && *location.second == '/')
                m_handlerMap[location.second] = handler.get();
            else if (location.first)
                m_handlerMap[string("/") + location.second] = handler.get();
        }
        catch (const std::exception& ex) {
            log.error("caught exception processing handler element: %s", ex.what());
        }

        child = XMLHelper::getNextSiblingElement(child);
    }
}

void XMLApplication::doSSO(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;

    // This denotes whether the SSO element has been processed before or is specific to an override.
    bool hasChildElements = e->getFirstElementChild() != nullptr;

    const DOMNamedNodeMap* ssoprops = e->getAttributes();
    XMLSize_t ssopropslen = ssoprops ? ssoprops->getLength() : 0;

    const SPConfig& conf = SPConfig::getConfig();

    int index = 0; // track ACS indexes globally across all protocols

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(XMLHelper::getTextContent(e));
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for initiator.
        const PropertySet* initiator = pp.getInitiator(prot.get(), "SSO");
        if (initiator) {
            log.info("auto-configuring SSO initiation for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> inittype = initiator->getXMLString("id");
            if (inittype.first) {
                if (!hasChildElements) {
                    // Append a session initiator element of the designated type to the root element.
                    DOMElement* sidom = e->getOwnerDocument()->createElementNS(e->getNamespaceURI(), _SessionInitiator);

                    // Copy in any attributes from the <SSO> element so they can be accessed as properties in the SI handler
                    // but more importantly the MessageEncoders, which are DOM-aware only, not SP property-aware.
                    // The property-based lookups will walk up the DOM tree but the DOM-only code won't.
                    for (XMLSize_t p = 0; p < ssopropslen; ++p) {
                        DOMNode* ssoprop = ssoprops->item(p);
                        if (ssoprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            sidom->setAttributeNS(
                                ((DOMAttr*)ssoprop)->getNamespaceURI(),
                                ((DOMAttr*)ssoprop)->getLocalName(),
                                ((DOMAttr*)ssoprop)->getValue()
                            );
                        }
                    }

                    sidom->setAttributeNS(nullptr, _type, inittype.second);
                    e->appendChild(sidom);
                    log.info("adding SessionInitiator of type (%s) to chain (/Login)", initiator->getString("id").second);
                }

                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
            else {
                log.error("missing id property on Initiator element, check config for protocol (%s)", prot.get());
            }
        }

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "SSO");
        if (!bindings.empty()) {
            log.info("auto-configuring SSO endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b, ++index) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* acsdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _AssertionConsumerService);

                    // Copy in any attributes from the <SSO> element so they can be accessed as properties in the ACS handler,
                    // since the handlers aren't attached to the SSO element.
                    for (XMLSize_t p = 0; p < ssopropslen; ++p) {
                        DOMNode* ssoprop = ssoprops->item(p);
                        if (ssoprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            acsdom->setAttributeNS(
                                ((DOMAttr*)ssoprop)->getNamespaceURI(),
                                ((DOMAttr*)ssoprop)->getLocalName(),
                                ((DOMAttr*)ssoprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    acsdom->setAttributeNS(nullptr, Binding, idprop.second);
                    acsdom->setAttributeNS(nullptr, Location, pathprop.second);
                    xstring indexbuf(1, chDigit_1 + (index % 10));
                    if (index / 10)
                        indexbuf = (XMLCh)(chDigit_1 + (index / 10)) + indexbuf;
                    acsdom->setAttributeNS(nullptr, _index, indexbuf.c_str());

                    log.info("adding AssertionConsumerService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.AssertionConsumerServiceManager.newPlugin(
                            (*b)->getString("id").second, pair<const DOMElement*,const char*>(acsdom, getId()), m_deprecationSupport
                            )
                        );
                    m_handlers.push_back(handler);

                    // Setup maps and defaults.
                    const XMLCh* protfamily = handler->getProtocolFamily();
                    if (protfamily)
                        m_acsProtocolMap[protfamily].push_back(handler.get());
                    m_acsIndexMap[handler->getUnsignedInt("index").second] = handler.get();
                    if (!m_acsDefault)
                        m_acsDefault = handler.get();

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }
        }

        if (!initiator && bindings.empty()) {
            log.error("no SSO Initiator or Binding config for protocol (%s)", prot.get());
        }
    }

    // Handle discovery.
    static const XMLCh discoveryProtocol[] = UNICODE_LITERAL_17(d,i,s,c,o,v,e,r,y,P,r,o,t,o,c,o,l);
    static const XMLCh discoveryURL[] = UNICODE_LITERAL_12(d,i,s,c,o,v,e,r,y,U,R,L);
    static const XMLCh _URL[] = UNICODE_LITERAL_3(U,R,L);

    if (!hasChildElements) {
        const XMLCh* discop = e->getAttributeNS(nullptr, discoveryProtocol);
        if (discop && *discop) {
            const XMLCh* discou = e->getAttributeNS(nullptr, discoveryURL);
            if (discou && *discou) {
                // Append a session initiator element of the designated type to the root element.
                DOMElement* sidom = e->getOwnerDocument()->createElementNS(e->getNamespaceURI(), _SessionInitiator);

                // Copy in any attributes from the <SSO> element so they can be accessed as properties in the SI handler
                // but more importantly the MessageEncoders, which are DOM-aware only, not SP property-aware.
                // The property-based lookups will walk up the DOM tree but the DOM-only code won't.
                for (XMLSize_t p = 0; p < ssopropslen; ++p) {
                    DOMNode* ssoprop = ssoprops->item(p);
                    if (ssoprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                        sidom->setAttributeNS(
                            ((DOMAttr*)ssoprop)->getNamespaceURI(),
                            ((DOMAttr*)ssoprop)->getLocalName(),
                            ((DOMAttr*)ssoprop)->getValue()
                        );
                    }
                }

                sidom->setAttributeNS(nullptr, _type, discop);
                sidom->setAttributeNS(nullptr, _URL, discou);
                e->appendChild(sidom);
                if (log.isInfoEnabled()) {
                    auto_ptr_char dp(discop);
                    log.info("adding SessionInitiator of type (%s) to chain (/Login)", dp.get());
                }
            }
            else {
                log.error("SSO discoveryProtocol specified without discoveryURL");
            }
        }
    }

    if (!hasChildElements) {
        // Attach default Location to SSO element.
        static const XMLCh _loc[] = { chForwardSlash, chLatin_L, chLatin_o, chLatin_g, chLatin_i, chLatin_n, chNull };
        e->setAttributeNS(nullptr, Location, _loc);
    }

    // Instantiate Chaining initiator around the SSO element.
    boost::shared_ptr<SessionInitiator> chain(
        conf.SessionInitiatorManager.newPlugin(CHAINING_SESSION_INITIATOR, pair<const DOMElement*,const char*>(e, getId()), m_deprecationSupport)
        );
    m_handlers.push_back(chain);
    m_sessionInitDefault = chain.get();
    m_handlerMap["/Login"] = chain.get();
}

void XMLApplication::doLogout(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;

    // This denotes whether the Logout element has been processed before or is specific to an override.
    bool hasChildElements = e->getFirstElementChild() != nullptr;

    const DOMNamedNodeMap* sloprops = e->getAttributes();
    XMLSize_t slopropslen = sloprops ? sloprops->getLength() : 0;

    const SPConfig& conf = SPConfig::getConfig();

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(XMLHelper::getTextContent(e));
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for initiator.
        const PropertySet* initiator = pp.getInitiator(prot.get(), "Logout");
        if (initiator) {
            log.info("auto-configuring Logout initiation for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> inittype = initiator->getXMLString("id");
            if (inittype.first) {
                if (!hasChildElements) {
                    // Append a logout initiator element of the designated type to the root element.
                    DOMElement* lidom = e->getOwnerDocument()->createElementNS(e->getNamespaceURI(), _LogoutInitiator);

                    // Copy in any attributes from the <Logout> element so they can be accessed as properties in the LI handler
                    // but more importantly the MessageEncoders, which are DOM-aware only, not SP property-aware.
                    // The property-based lookups will walk up the DOM tree but the DOM-only code won't.
                    for (XMLSize_t p = 0; p < slopropslen; ++p) {
                        DOMNode* sloprop = sloprops->item(p);
                        if (sloprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            lidom->setAttributeNS(
                                ((DOMAttr*)sloprop)->getNamespaceURI(),
                                ((DOMAttr*)sloprop)->getLocalName(),
                                ((DOMAttr*)sloprop)->getValue()
                            );
                        }
                    }

                    lidom->setAttributeNS(nullptr, _type, inittype.second);
                    e->appendChild(lidom);
                    log.info("adding LogoutInitiator of type (%s) to chain (/Logout)", initiator->getString("id").second);
                }

                if (protocols.count(prot.get()) == 0) {
                    doArtifactResolution(pp, prot.get(), e, log);
                    protocols.insert(prot.get());
                }
            }
            else {
                log.error("missing id property on Initiator element, check config for protocol (%s)", prot.get());
            }
        }

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "Logout");
        if (!bindings.empty()) {
            log.info("auto-configuring Logout endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* slodom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _SingleLogoutService);

                    // Copy in any attributes from the <Logout> element so they can be accessed as properties in the SLO handler.
                    for (XMLSize_t p = 0; p < slopropslen; ++p) {
                        DOMNode* sloprop = sloprops->item(p);
                        if (sloprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            slodom->setAttributeNS(
                                ((DOMAttr*)sloprop)->getNamespaceURI(),
                                ((DOMAttr*)sloprop)->getLocalName(),
                                ((DOMAttr*)sloprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    slodom->setAttributeNS(nullptr, Binding, idprop.second);
                    slodom->setAttributeNS(nullptr, Location, pathprop.second);
                    if (e->hasAttributeNS(nullptr, _policyId))
                        slodom->setAttributeNS(e->getNamespaceURI(), _policyId, e->getAttributeNS(nullptr, _policyId));

                    log.info("adding SingleLogoutService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.SingleLogoutServiceManager.newPlugin((*b)->getString("id").second, pair<const DOMElement*,const char*>(slodom, getId()), m_deprecationSupport)
                        );
                    m_handlers.push_back(handler);

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }

            if (protocols.count(prot.get()) == 0) {
                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
        }

        if (!initiator && bindings.empty()) {
            log.error("no Logout Initiator or Binding config for protocol (%s)", prot.get());
        }
    }

    // Attach default Location to Logout element.
    static const XMLCh _loc[] = { chForwardSlash, chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chNull };
    e->setAttributeNS(nullptr, Location, _loc);

    // Instantiate Chaining initiator around the SSO element.
    boost::shared_ptr<Handler> chain(
        conf.LogoutInitiatorManager.newPlugin(CHAINING_LOGOUT_INITIATOR, pair<const DOMElement*,const char*>(e, getId()), m_deprecationSupport)
        );
    m_handlers.push_back(chain);
    m_handlerMap["/Logout"] = chain.get();
}

void XMLApplication::doNameIDMgmt(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;
    const DOMNamedNodeMap* nimprops = e->getAttributes();
    XMLSize_t nimpropslen = nimprops ? nimprops->getLength() : 0;

    const SPConfig& conf = SPConfig::getConfig();

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(XMLHelper::getTextContent(e));
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "NameIDMgmt");
        if (!bindings.empty()) {
            log.info("auto-configuring NameIDMgmt endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* nimdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _ManageNameIDService);

                    // Copy in any attributes from the <NameIDMgmt> element so they can be accessed as properties in the NIM handler.
                    for (XMLSize_t p = 0; p < nimpropslen; ++p) {
                        DOMNode* nimprop = nimprops->item(p);
                        if (nimprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            nimdom->setAttributeNS(
                                ((DOMAttr*)nimprop)->getNamespaceURI(),
                                ((DOMAttr*)nimprop)->getLocalName(),
                                ((DOMAttr*)nimprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    nimdom->setAttributeNS(nullptr, Binding, idprop.second);
                    nimdom->setAttributeNS(nullptr, Location, pathprop.second);
                    if (e->hasAttributeNS(nullptr, _policyId))
                        nimdom->setAttributeNS(e->getNamespaceURI(), _policyId, e->getAttributeNS(nullptr, _policyId));

                    log.info("adding ManageNameIDService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.ManageNameIDServiceManager.newPlugin(
                            (*b)->getString("id").second, pair<const DOMElement*,const char*>(nimdom, getId()), m_deprecationSupport
                            )
                        );
                    m_handlers.push_back(handler);

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }

            if (protocols.count(prot.get()) == 0) {
                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
        }
        else {
            log.error("no NameIDMgmt Binding config for protocol (%s)", prot.get());
        }
    }
}

void XMLApplication::doArtifactResolution(const ProtocolProvider& pp, const char* protocol, DOMElement* e, Category& log)
{
    const SPConfig& conf = SPConfig::getConfig();

    int index = 0; // track indexes globally across all protocols

    // Look for incoming bindings.
    const vector<const PropertySet*>& bindings = pp.getBindings(protocol, "ArtifactResolution");
    if (!bindings.empty()) {
        log.info("auto-configuring ArtifactResolution endpoints for protocol (%s)", protocol);
        pair<bool,const XMLCh*> idprop,pathprop;
        for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b, ++index) {
            idprop = (*b)->getXMLString("id");
            pathprop = (*b)->getXMLString("path");
            if (idprop.first && pathprop.first) {
                DOMElement* artdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _ArtifactResolutionService);
                artdom->setAttributeNS(nullptr, Binding, idprop.second);
                artdom->setAttributeNS(nullptr, Location, pathprop.second);
                xstring indexbuf(1, chDigit_1 + (index % 10));
                if (index / 10)
                    indexbuf = (XMLCh)(chDigit_1 + (index / 10)) + indexbuf;
                artdom->setAttributeNS(nullptr, _index, indexbuf.c_str());

                log.info("adding ArtifactResolutionService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                boost::shared_ptr<Handler> handler(
                    conf.ArtifactResolutionServiceManager.newPlugin(
                        (*b)->getString("id").second, pair<const DOMElement*,const char*>(artdom, getId()), m_deprecationSupport
                        )
                    );
                m_handlers.push_back(handler);

                if (!m_artifactResolutionDefault)
                    m_artifactResolutionDefault = handler.get();

                // Insert into location map.
                pair<bool,const char*> location = handler->getString("Location");
                if (location.first && *location.second == '/')
                    m_handlerMap[location.second] = handler.get();
                else if (location.first)
                    m_handlerMap[string("/") + location.second] = handler.get();
            }
            else {
                log.error("missing id or path property on Binding element, check config for protocol (%s)", protocol);
            }
        }
    }
}

#ifndef SHIBSP_LITE

void XMLApplication::doAttributePlugins(DOMElement* e, Category& log)
{
    const SPConfig& conf = SPConfig::getConfig();

    m_attrExtractor.reset(
        doChainedPlugins(conf.AttributeExtractorManager, "AttributeExtractor", CHAINING_ATTRIBUTE_EXTRACTOR, _AttributeExtractor, e, log)
        );

    m_attrFilter.reset(
        doChainedPlugins(conf.AttributeFilterManager, "AttributeFilter", CHAINING_ATTRIBUTE_FILTER, _AttributeFilter, e, log, DUMMY_ATTRIBUTE_FILTER)
        );

    m_attrResolver.reset(
        doChainedPlugins(conf.AttributeResolverManager, "AttributeResolver", CHAINING_ATTRIBUTE_RESOLVER, _AttributeResolver, e, log)
        );

    if (m_unsetHeaders.empty()) {
        vector<string> unsetHeaders;
        if (m_attrExtractor) {
            Locker extlock(m_attrExtractor.get());
            m_attrExtractor->getAttributeIds(unsetHeaders);
        }
        else if (m_base && m_base->m_attrExtractor) {
            Locker extlock(m_base->m_attrExtractor.get());
            m_base->m_attrExtractor->getAttributeIds(unsetHeaders);
        }
        if (m_attrResolver) {
            Locker reslock(m_attrResolver.get());
            m_attrResolver->getAttributeIds(unsetHeaders);
        }
        else if (m_base && m_base->m_attrResolver) {
            Locker extlock(m_base->m_attrResolver.get());
            m_base->m_attrResolver->getAttributeIds(unsetHeaders);
        }
        if (!unsetHeaders.empty()) {
            string transformedprefix(m_attributePrefix.second);
            const char* pch;
            pair<bool,const char*> prefix = getString("metadataAttributePrefix");
            if (prefix.first) {
                pch = prefix.second;
                while (*pch) {
                    transformedprefix += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
            }
            for (vector<string>::const_iterator hdr = unsetHeaders.begin(); hdr!=unsetHeaders.end(); ++hdr) {
                string transformed;
                pch = hdr->c_str();
                while (*pch) {
                    transformed += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
                m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + *hdr, m_attributePrefix.second + transformed));
                if (prefix.first)
                    m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + prefix.second + *hdr, transformedprefix + transformed));
            }
        }
        m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + "Shib-Application-ID", m_attributePrefix.second + "SHIB_APPLICATION_ID"));
    }
}

SAMLArtifact* XMLApplication::generateSAML1Artifact(const opensaml::saml2md::EntityDescriptor* relyingParty) const
{
    throw ConfigurationException("No support for SAML 1.x artifact generation.");
}

SAML2Artifact* XMLApplication::generateSAML2Artifact(const opensaml::saml2md::EntityDescriptor* relyingParty) const
{
    pair<bool, int> index = make_pair(false, 0);
    const PropertySet* props = getRelyingParty(relyingParty);
    index = props->getInt("artifactEndpointIndex");
    if (!index.first)
        index = getArtifactEndpointIndex();
    pair<bool, const char*> entityID = props->getString("entityID");
    return new SAML2ArtifactType0004(
        SecurityHelper::doHash("SHA1", entityID.second, strlen(entityID.second), false),
        index.first ? index.second : 1
    );
}

#endif

void XMLApplication::receive(DDF& in, ostream& out)
{
    // Only current function is to return the headers to clear.
    DDF header;
    DDF ret = DDF(nullptr).list();
    DDFJanitor jret(ret);
    for (vector< pair<string, string> >::const_iterator i = m_unsetHeaders.begin(); i != m_unsetHeaders.end(); ++i) {
        header = DDF(i->first.c_str()).string(i->second.c_str());
        ret.add(header);
    }
    out << ret;
}

DOMNodeFilter::FilterAction XMLApplication::acceptNode(const DOMNode* node) const
{
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name, ApplicationOverride) ||
        XMLString::equals(name, _Audience) ||
        XMLString::equals(name, Notify) ||
        XMLString::equals(name, _Handler) ||
        XMLString::equals(name, _AssertionConsumerService) ||
        XMLString::equals(name, _ArtifactResolutionService) ||
        XMLString::equals(name, Logout) ||
        XMLString::equals(name, _LogoutInitiator) ||
        XMLString::equals(name, _ManageNameIDService) ||
        XMLString::equals(name, NameIDMgmt) ||
        XMLString::equals(name, _SessionInitiator) ||
        XMLString::equals(name, _SingleLogoutService) ||
        XMLString::equals(name, SSO) ||
        XMLString::equals(name, RelyingParty) ||
        XMLString::equals(name, _MetadataProvider) ||
        XMLString::equals(name, _TrustEngine) ||
        XMLString::equals(name, _CredentialResolver) ||
        XMLString::equals(name, _AttributeFilter) ||
        XMLString::equals(name, _AttributeExtractor) ||
        XMLString::equals(name, _AttributeResolver) ||
        XMLString::equals(name, ExternalApplicationOverrides)) {
        return FILTER_REJECT;
    }

    const XMLCh _cookieProps[] = UNICODE_LITERAL_11(c,o,o,k,i,e,P,r,o,p,s);
    const XMLCh _http[] = UNICODE_LITERAL_4(h,t,t,p);
    const XMLCh _https[] = UNICODE_LITERAL_5(h,t,t,p,s);
    const XMLCh _Sessions[] = UNICODE_LITERAL_8(S,e,s,s,i,o,n,s);

    if (XMLString::equals(name, _Sessions)) {
        // This is a hack, but it's a fairly clean way to mutate a setting.
        DOMNode* cookieProps = node->getAttributes()->getNamedItemNS(nullptr, _cookieProps);
        if (cookieProps) {
            const XMLCh* val = cookieProps->getNodeValue();
            if (!val || (*val != chSemiColon && !XMLString::equals(val, _http) && !XMLString::equals(val, _https))) {
                xstring newval(1, chSemiColon);
                newval += chSpace;
                newval += val;
                cookieProps->setNodeValue(newval.c_str());
            }
        }
    }

    return FILTER_ACCEPT;
}

#ifndef SHIBSP_LITE

pair<bool, const char*> XMLApplication::getString(const char* name, const char* ns) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        if (!ns && !strcmp(name, "entityID")) {
            const ListenerService* listener = getServiceProvider().getListenerService(false);
            DDF* in = listener ? listener->getInput() : nullptr;
            if (in) {
                const char* entityID = in->getmember("_mapped")["entityID"].string();
                if (entityID)
                    return make_pair(true, entityID);
            }
        }
    }

    return DOMPropertySet::getString(name, ns);
}

pair<bool, const XMLCh*> XMLApplication::getXMLString(const char* name, const char* ns) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        if (!ns && !strcmp(name, "entityID")) {
            const ListenerService* listener = getServiceProvider().getListenerService(false);
            DDF* in = listener ? listener->getInput() : nullptr;
            if (in) {
                void* entityID = in->getmember("_mapped")["entityID-16"].pointer();
                if (entityID)
                    return make_pair(true, reinterpret_cast<const XMLCh*>(entityID));
            }
        }
    }

    return DOMPropertySet::getXMLString(name, ns);
}

const PropertySet* XMLApplication::getRelyingParty(const EntityDescriptor* provider) const
{
    if (!provider)
        return this;

    // Check for exact match on name.
    map< xstring,boost::shared_ptr<PropertySet> >::const_iterator i = m_partyMap.find(provider->getEntityID());
    if (i != m_partyMap.end())
        return i->second.get();

    // Check for extensible matching.
    vector < pair< boost::shared_ptr<EntityMatcher>,boost::shared_ptr<PropertySet> > >::const_iterator j;
    for (j = m_partyVec.begin(); j != m_partyVec.end(); ++j) {
        if (j->first->matches(*provider))
            return j->second.get();
    }

    // Check for group match.
    const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(provider->getParent());
    while (group) {
        if (group->getName()) {
            i = m_partyMap.find(group->getName());
            if (i != m_partyMap.end())
                return i->second.get();
        }
        group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
    }
    return this;
}

const PropertySet* XMLApplication::getRelyingParty(const XMLCh* entityID) const
{
    if (!entityID)
        return this;
    map< xstring,boost::shared_ptr<PropertySet> >::const_iterator i = m_partyMap.find(entityID);
    return (i != m_partyMap.end()) ? i->second.get() : this;
}

#endif

string XMLApplication::getNotificationURL(const char* resource, bool front, unsigned int index) const
{
    const vector<string>& locs = front ? m_frontLogout : m_backLogout;
    if (locs.empty())
        return m_base ? m_base->getNotificationURL(resource, front, index) : string();
    else if (index >= locs.size())
        return string();

#ifdef HAVE_STRCASECMP
    if (!resource || (strncasecmp(resource,"http://",7) && strncasecmp(resource,"https://",8)))
#else
    if (!resource || (strnicmp(resource,"http://",7) && strnicmp(resource,"https://",8)))
#endif
        throw ConfigurationException("Request URL was not absolute.");

    const char* handler = locs[index].c_str();

    // Should never happen...
    if (!handler || (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)))
        throw ConfigurationException(
            "Invalid Location property ($1) in Notify element for Application ($2)",
            params(2, handler ? handler : "null", getId())
            );

    // The "Location" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler

    const char* path = nullptr;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store.
    string notifyURL(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the URL
    notifyURL += host + path;
    return notifyURL;
}

void XMLApplication::clearHeader(SPRequest& request, const char* rawname, const char* cginame) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + rawname;
        string temp2 = m_attributePrefix.second + (cginame + 5);
        request.clearHeader(temp.c_str(), temp2.c_str());
    }
    else if (m_base) {
        m_base->clearHeader(request, rawname, cginame);
    }
    else {
        request.clearHeader(rawname, cginame);
    }
}

void XMLApplication::setHeader(SPRequest& request, const char* name, const char* value) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + name;
        request.setHeader(temp.c_str(), value);
    }
    else if (m_base) {
        m_base->setHeader(request, name, value);
    }
    else {
        request.setHeader(name, value);
    }
}

string XMLApplication::getSecureHeader(const SPRequest& request, const char* name) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + name;
        return request.getSecureHeader(temp.c_str());
    }
    else if (m_base) {
        return m_base->getSecureHeader(request,name);
    }
    else {
        return request.getSecureHeader(name);
    }
}

const SessionInitiator* XMLApplication::getDefaultSessionInitiator() const
{
    if (m_sessionInitDefault) return m_sessionInitDefault;
    return m_base ? m_base->getDefaultSessionInitiator() : nullptr;
}

const SessionInitiator* XMLApplication::getSessionInitiatorById(const char* id) const
{
    map<string,const SessionInitiator*>::const_iterator i = m_sessionInitMap.find(id);
    if (i != m_sessionInitMap.end()) return i->second;
    return m_base ? m_base->getSessionInitiatorById(id) : nullptr;
}

const Handler* XMLApplication::getDefaultAssertionConsumerService() const
{
    if (m_acsDefault) return m_acsDefault;
    return m_base ? m_base->getDefaultAssertionConsumerService() : nullptr;
}

const Handler* XMLApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
{
    map<unsigned int,const Handler*>::const_iterator i = m_acsIndexMap.find(index);
    if (i != m_acsIndexMap.end()) return i->second;
    return m_base ? m_base->getAssertionConsumerServiceByIndex(index) : nullptr;
}

const Handler* XMLApplication::getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding) const
{
    ACSProtocolMap::const_iterator i = m_acsProtocolMap.find(protocol);
    if (i != m_acsProtocolMap.end() && !i->second.empty()) {
        if (!binding || !*binding)
            return i->second.front();
        for (ACSProtocolMap::value_type::second_type::const_iterator j = i->second.begin(); j != i->second.end(); ++j) {
            if (!strcmp(binding, (*j)->getString("Binding").second))
                return *j;
        }
    }
    return m_base ? m_base->getAssertionConsumerServiceByProtocol(protocol, binding) : nullptr;
}

const Handler* XMLApplication::getHandler(const char* path) const
{
    string wrap(path);
    wrap = wrap.substr(0, wrap.find(';'));
    map<string,const Handler*>::const_iterator i = m_handlerMap.find(wrap.substr(0, wrap.find('?')));
    if (i != m_handlerMap.end())
        return i->second;
    return m_base ? m_base->getHandler(path) : nullptr;
}

void XMLApplication::getHandlers(vector<const Handler*>& handlers) const
{
    static void (vector<const Handler*>::* pb)(const Handler* const&) = &vector<const Handler*>::push_back;
    // Copy all of the override's handlers.
    for_each(m_handlers.begin(), m_handlers.end(), boost::bind(pb, boost::ref(handlers), boost::bind(&boost::shared_ptr<Handler>::get, _1)));
    if (m_base) {
        if (handlers.empty()) {
            // If the override doesn't supply any handlers, copy the parent's in normal order.
            for_each(m_base->m_handlers.begin(), m_base->m_handlers.end(), boost::bind(pb, boost::ref(handlers), boost::bind(&boost::shared_ptr<Handler>::get, _1)));
        }
        else {
            // This unfortunately distorts the usual ordering when it comes to metadata generation, but avoiding that would be a lot of code.
            for (map<string, const Handler*>::const_iterator h = m_base->m_handlerMap.begin(); h != m_base->m_handlerMap.end(); ++h) {
                if (m_handlerMap.count(h->first) == 0)
                    handlers.push_back(h->second);
            }
        }
    }
}

void XMLApplication::limitRedirect(const GenericRequest& request, const char* url) const
{
    if (!url || *url == '/')
        return;
    if (m_redirectLimit == REDIRECT_LIMIT_INHERIT)
        return m_base->limitRedirect(request, url);
    if (m_redirectLimit != REDIRECT_LIMIT_NONE) {
        vector<string> whitelist;
        if (m_redirectLimit == REDIRECT_LIMIT_EXACT || m_redirectLimit == REDIRECT_LIMIT_EXACT_WHITELIST) {
            // Scheme and hostname have to match.
            if (request.isDefaultPort()) {
                whitelist.push_back(string(request.getScheme()) + "://" + request.getHostname() + '/');
            }
            whitelist.push_back(string(request.getScheme()) + "://" + request.getHostname() + ':' + lexical_cast<string>(request.getPort()) + '/');
        }
        else if (m_redirectLimit == REDIRECT_LIMIT_HOST || m_redirectLimit == REDIRECT_LIMIT_HOST_WHITELIST) {
            // Allow any scheme or port.
            whitelist.push_back(string("https://") + request.getHostname() + '/');
            whitelist.push_back(string("http://") + request.getHostname() + '/');
            whitelist.push_back(string("https://") + request.getHostname() + ':');
            whitelist.push_back(string("http://") + request.getHostname() + ':');
        }

        static bool (*startsWithI)(const char*,const char*) = XMLString::startsWithI;
        if (!whitelist.empty() && find_if(whitelist.begin(), whitelist.end(),
                boost::bind(startsWithI, url, boost::bind(&string::c_str, _1))) != whitelist.end()) {
            return;
        }
        else if (!m_redirectWhitelist.empty() && find_if(m_redirectWhitelist.begin(), m_redirectWhitelist.end(),
                boost::bind(startsWithI, url, boost::bind(&string::c_str, _1))) != m_redirectWhitelist.end()) {
            return;
        }
        Category::getInstance(SHIBSP_LOGCAT ".Application").warn("redirectLimit policy enforced, blocked redirect to (%s)", url);
        throw opensaml::SecurityPolicyException("Blocked unacceptable redirect location.");
    }
}
