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
 * DynamicMetadataProvider.cpp
 *
 * Advanced implementation of a dynamic caching MetadataProvider.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "metadata/MetadataProviderCriteria.h"

#include <boost/algorithm/string.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/framework/XSECDefs.hpp>

#include <saml/version.h>
#include <saml/binding/SAMLArtifact.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/DynamicMetadataProvider.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL DynamicMetadataProvider : public saml2md::DynamicMetadataProvider
    {
    public:
        DynamicMetadataProvider(const xercesc::DOMElement* e=nullptr);

        virtual ~DynamicMetadataProvider() {}

    protected:
        saml2md::EntityDescriptor* resolve(const saml2md::MetadataProvider::Criteria& criteria) const;

    private:
        bool m_verifyHost,m_ignoreTransport,m_encoded;
        string m_subst, m_match, m_regex;
        boost::scoped_ptr<X509TrustEngine> m_trust;
        boost::scoped_ptr<CredentialResolver> m_dummyCR;
    };

    saml2md::MetadataProvider* SHIBSP_DLLLOCAL DynamicMetadataProviderFactory(const DOMElement* const & e)
    {
        return new DynamicMetadataProvider(e);
    }

    static const XMLCh encoded[] =          UNICODE_LITERAL_7(e,n,c,o,d,e,d);
    static const XMLCh ignoreTransport[] =  UNICODE_LITERAL_15(i,g,n,o,r,e,T,r,a,n,s,p,o,r,t);
    static const XMLCh match[] =            UNICODE_LITERAL_5(m,a,t,c,h);
    static const XMLCh Regex[] =            UNICODE_LITERAL_5(R,e,g,e,x);
    static const XMLCh Subst[] =            UNICODE_LITERAL_5(S,u,b,s,t);
    static const XMLCh _TrustEngine[] =     UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh verifyHost[] =       UNICODE_LITERAL_10(v,e,r,i,f,y,H,o,s,t);
};

DynamicMetadataProvider::DynamicMetadataProvider(const DOMElement* e)
    : saml2md::DynamicMetadataProvider(e),
        m_verifyHost(XMLHelper::getAttrBool(e, true, verifyHost)),
        m_ignoreTransport(XMLHelper::getAttrBool(e, false, ignoreTransport)),
        m_encoded(true), m_trust(nullptr)
{
    const DOMElement* child = XMLHelper::getFirstChildElement(e, Subst);
    if (child && child->hasChildNodes()) {
        auto_ptr_char s(child->getFirstChild()->getNodeValue());
        if (s.get() && *s.get()) {
            m_subst = s.get();
            m_encoded = XMLHelper::getAttrBool(child, true, encoded);
        }
    }

    if (m_subst.empty()) {
        child = XMLHelper::getFirstChildElement(e, Regex);
        if (child && child->hasChildNodes() && child->hasAttributeNS(nullptr, match)) {
            m_match = XMLHelper::getAttrString(child, nullptr, match);
            auto_ptr_char repl(child->getFirstChild()->getNodeValue());
            if (repl.get() && *repl.get())
                m_regex = repl.get();
        }
    }

    if (!m_ignoreTransport) {
        child = XMLHelper::getFirstChildElement(e, _TrustEngine);
        string t = XMLHelper::getAttrString(child, nullptr, _type);
        if (!t.empty()) {
            TrustEngine* trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t.c_str(), child);
            if (!dynamic_cast<X509TrustEngine*>(trust)) {
                delete trust;
                throw ConfigurationException("DynamicMetadataProvider requires an X509TrustEngine plugin.");
            }
            m_trust.reset(dynamic_cast<X509TrustEngine*>(trust));
            m_dummyCR.reset(XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(DUMMY_CREDENTIAL_RESOLVER, nullptr));
        }

        if (!m_trust.get() || !m_dummyCR.get())
            throw ConfigurationException("DynamicMetadataProvider requires an X509TrustEngine plugin unless ignoreTransport is true.");
    }
}

saml2md::EntityDescriptor* DynamicMetadataProvider::resolve(const saml2md::MetadataProvider::Criteria& criteria) const
{
#ifdef _DEBUG
    xmltooling::NDC("resolve");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".MetadataProvider.Dynamic");

    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        if (m_subst.empty() && (m_regex.empty() || m_match.empty()))
            throw saml2md::MetadataException("Unable to resolve metadata dynamically from an artifact.");
        name = "{sha1}" + criteria.artifact->getSource();
    }

    // Possibly transform the input into a different URL to use.
    if (!m_subst.empty()) {
        string name2 = boost::replace_first_copy(m_subst, "$entityID",
            m_encoded ? XMLToolingConfig::getConfig().getURLEncoder()->encode(name.c_str()) : name);
        log.info("transformed location from (%s) to (%s)", name.c_str(), name2.c_str());
        name = name2;
    }
    else if (!m_match.empty() && !m_regex.empty()) {
        try {
            RegularExpression exp(m_match.c_str());
            XMLCh* temp = exp.replace(name.c_str(), m_regex.c_str());
            if (temp) {
                auto_ptr_char narrow(temp);
                XMLString::release(&temp);

                // For some reason it returns the match string if it doesn't match the expression.
                if (name != narrow.get()) {
                    log.info("transformed location from (%s) to (%s)", name.c_str(), narrow.get());
                    name = narrow.get();
                }
            }
        }
        catch (XMLException& ex) {
            auto_ptr_char msg(ex.getMessage());
            log.error("caught error applying regular expression: %s", msg.get());
        }
    }

    // Establish networking properties based on calling application.
    const MetadataProviderCriteria* mpc = dynamic_cast<const MetadataProviderCriteria*>(&criteria);
    if (!mpc)
        throw saml2md::MetadataException("Dynamic MetadataProvider requires Shibboleth-aware lookup criteria, check calling code.");
    const PropertySet* relyingParty;
    if (criteria.artifact)
        relyingParty = mpc->application.getRelyingParty((XMLCh*)nullptr);
    else if (criteria.entityID_unicode)
        relyingParty = mpc->application.getRelyingParty(criteria.entityID_unicode);
    else {
        auto_ptr_XMLCh temp2(name.c_str());
        relyingParty = mpc->application.getRelyingParty(temp2.get());
    }

    // Prepare a transport object addressed appropriately.
    SOAPTransport::Address addr(relyingParty->getString("entityID").second, name.c_str(), name.c_str());
    const char* pch = strchr(addr.m_endpoint,':');
    if (!pch)
        throw IOException("location was not a URL.");
    string scheme(addr.m_endpoint, pch-addr.m_endpoint);
    boost::scoped_ptr<SOAPTransport> transport;
    try {
        transport.reset(XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr));
    }
    catch (exception& ex) {
        log.error("exception while building transport object to resolve URL: %s", ex.what());
        throw IOException("Unable to resolve entityID with a known transport protocol.");
    }

    // Apply properties as directed.
    transport->setVerifyHost(m_verifyHost);
    if (m_trust.get() && m_dummyCR.get() && !transport->setTrustEngine(m_trust.get(), m_dummyCR.get()))
        throw IOException("Unable to install X509TrustEngine into transport object.");

    Locker credlocker(nullptr, false);
    CredentialResolver* credResolver = nullptr;
    pair<bool,const char*> authType=relyingParty->getString("authType");
    if (!authType.first || !strcmp(authType.second,"TLS")) {
        credResolver = mpc->application.getCredentialResolver();
        if (credResolver)
            credlocker.assign(credResolver);
        if (credResolver) {
            CredentialCriteria cc;
            cc.setUsage(Credential::TLS_CREDENTIAL);
            authType = relyingParty->getString("keyName");
            if (authType.first)
                cc.getKeyNames().insert(authType.second);
            const Credential* cred = credResolver->resolve(&cc);
            cc.getKeyNames().clear();
            if (cred) {
                if (!transport->setCredential(cred))
                    log.error("failed to load Credential into metadata resolver");
            }
            else {
                log.error("no TLS credential supplied");
            }
        }
        else {
            log.error("no CredentialResolver available for TLS");
        }
    }
    else {
        SOAPTransport::transport_auth_t type=SOAPTransport::transport_auth_none;
        pair<bool,const char*> username=relyingParty->getString("authUsername");
        pair<bool,const char*> password=relyingParty->getString("authPassword");
        if (!username.first || !password.first)
            log.error("transport authType (%s) specified but authUsername or authPassword was missing", authType.second);
        else if (!strcmp(authType.second,"basic"))
            type = SOAPTransport::transport_auth_basic;
        else if (!strcmp(authType.second,"digest"))
            type = SOAPTransport::transport_auth_digest;
        else if (!strcmp(authType.second,"ntlm"))
            type = SOAPTransport::transport_auth_ntlm;
        else if (!strcmp(authType.second,"gss"))
            type = SOAPTransport::transport_auth_gss;
        else if (strcmp(authType.second,"none"))
            log.error("unknown authType (%s) specified for RelyingParty", authType.second);
        if (type > SOAPTransport::transport_auth_none) {
            if (transport->setAuth(type,username.second,password.second))
                log.debug("configured for transport authentication (method=%s, username=%s)", authType.second, username.second);
            else
                log.error("failed to configure transport authentication (method=%s)", authType.second);
        }
    }

    pair<bool,unsigned int> timeout = relyingParty->getUnsignedInt("connectTimeout");
    transport->setConnectTimeout(timeout.first ? timeout.second : 10);
    timeout = relyingParty->getUnsignedInt("timeout");
    transport->setTimeout(timeout.first ? timeout.second : 20);
    mpc->application.getServiceProvider().setTransportOptions(*transport);

    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(transport.get());
    if (http) {
        pair<bool,bool> flag = relyingParty->getBool("chunkedEncoding");
        http->useChunkedEncoding(flag.first && flag.second);
        http->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
        http->setRequestHeader("XML-Security-C", XSEC_FULLVERSIONDOT);
        http->setRequestHeader("OpenSAML-C", gOpenSAMLDotVersionStr);
        http->setRequestHeader(PACKAGE_NAME, PACKAGE_VERSION);
    }

    try {
        // Use a nullptr stream to trigger a body-less "GET" operation.
        transport->send();
        istream& msg = transport->receive();

        DOMDocument* doc=nullptr;
        StreamInputSource src(msg, "DynamicMetadataProvider");
        Wrapper4InputSource dsrc(&src,false);
        if (m_validate)
            doc=XMLToolingConfig::getConfig().getValidatingParser().parse(dsrc);
        else
            doc=XMLToolingConfig::getConfig().getParser().parse(dsrc);

        // Wrap the document for now.
        XercesJanitor<DOMDocument> docjanitor(doc);

        // Unmarshall objects, binding the document.
        auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjanitor.release();

        // Make sure it's metadata.
        saml2md::EntityDescriptor* entity = dynamic_cast<saml2md::EntityDescriptor*>(xmlObject.get());
        if (!entity) {
            throw saml2md::MetadataException(
                "Root of metadata instance not recognized: $1", params(1,xmlObject->getElementQName().toString().c_str())
                );
        }
        xmlObject.release();
        return entity;
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        log.error("Xerces error while resolving location (%s): %s", name.c_str(), msg.get());
        throw saml2md::MetadataException(msg.get());
    }
}
