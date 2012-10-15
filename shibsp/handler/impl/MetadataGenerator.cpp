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
 * MetadataGenerator.cpp
 *
 * Handler for generating "approximate" metadata based on SP configuration.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"
#include "handler/SecuredHandler.h"

#include <boost/scoped_ptr.hpp>
#include <boost/iterator/indirect_iterator.hpp>

#ifndef SHIBSP_LITE
# include "attribute/resolver/AttributeExtractor.h"
# include "metadata/MetadataProviderCriteria.h"
# include <boost/ptr_container/ptr_vector.hpp>
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/signature/ContentReference.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/encryption/Encryption.h>
# include <xmltooling/security/Credential.h>
# include <xmltooling/security/CredentialCriteria.h>
# include <xmltooling/security/SecurityHelper.h>
# include <xmltooling/signature/Signature.h>
# include <xmltooling/util/ParserPool.h>
# include <xmltooling/util/PathResolver.h>
# include <xsec/dsig/DSIGConstants.hpp>
# include <xercesc/framework/LocalFileInputSource.hpp>
# include <xercesc/framework/Wrapper4InputSource.hpp>
#endif


using namespace shibsp;
#ifndef SHIBSP_LITE
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmlencryption;
#endif
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API MetadataGenerator : public SecuredHandler, public RemotedHandler
    {
    public:
        MetadataGenerator(const DOMElement* e, const char* appId);
        virtual ~MetadataGenerator() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

    private:
        pair<bool,long> processMessage(
            const Application& application,
            const char* handlerURL,
            const char* entityID,
            HTTPResponse& httpResponse
            ) const;

#ifndef SHIBSP_LITE
        void registerEncryptionMethod(const XMLCh* alg) {
            if (XMLToolingConfig::getConfig().isXMLAlgorithmSupported(alg, XMLToolingConfig::ALGTYPE_ENCRYPT) ||
                XMLToolingConfig::getConfig().isXMLAlgorithmSupported(alg, XMLToolingConfig::ALGTYPE_KEYENCRYPT) ||
                XMLToolingConfig::getConfig().isXMLAlgorithmSupported(alg, XMLToolingConfig::ALGTYPE_KEYAGREE)) {
                // Non-default builder needed to override namespace/prefix.
                if (!m_encryptionBuilder)
                    m_encryptionBuilder = XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_NS, EncryptionMethod::LOCAL_NAME));
                EncryptionMethod* em = dynamic_cast<EncryptionMethod*>(
                    m_encryptionBuilder->buildObject(
                        samlconstants::SAML20MD_NS, EncryptionMethod::LOCAL_NAME, samlconstants::SAML20MD_PREFIX
                        )
                    );
                em->setAlgorithm(alg);
                m_encryptions.push_back(em);

                if (
#ifdef URI_ID_RSA_OAEP
                    XMLString::equals(alg, DSIGConstants::s_unicodeStrURIRSA_OAEP) ||
#endif
                    XMLString::equals(alg, DSIGConstants::s_unicodeStrURIRSA_OAEP_MGFP1)) {
                    // Check for non-support of SHA-256. This is a reasonable guess as to whether
                    // "all" standard digests and MGF variants will be supported or not, and if not, we
                    // explicitly advertise only SHA-1.
                    if (!XMLToolingConfig::getConfig().isXMLAlgorithmSupported(DSIGConstants::s_unicodeStrURISHA256, XMLToolingConfig::ALGTYPE_DIGEST)) {
                        if (!m_digestBuilder)
                            m_digestBuilder = XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML20MD_ALGSUPPORT_NS, DigestMethod::LOCAL_NAME));
                        
#ifdef URI_ID_RSA_OAEP
                        // Add MGF for new OAEP variant.
                        if (XMLString::equals(alg, DSIGConstants::s_unicodeStrURIRSA_OAEP)) {
                            MGF* mgf = MGFBuilder::buildMGF();
                            mgf->setAlgorithm(DSIGConstants::s_unicodeStrURIMGF1_SHA1);
                            em->getUnknownXMLObjects().push_back(mgf);
                        }
#endif

                        DigestMethod* dm = dynamic_cast<DigestMethod*>(
                            m_digestBuilder->buildObject(xmlconstants::XMLSIG_NS, DigestMethod::LOCAL_NAME, xmlconstants::XMLSIG_PREFIX)
                            );
                        dm->setAlgorithm(DSIGConstants::s_unicodeStrURISHA1);
                        em->getUnknownXMLObjects().push_back(dm);
                    }
                }
            }
        }

        void registerDigestMethod(const XMLCh* alg) {
            if (XMLToolingConfig::getConfig().isXMLAlgorithmSupported(alg, XMLToolingConfig::ALGTYPE_DIGEST)) {
                DigestMethod* dm = DigestMethodBuilder::buildDigestMethod();
                dm->setAlgorithm(alg);
                m_digests.push_back(dm);
            }
        }

        void registerSigningMethod(const XMLCh* alg) {
            if (XMLToolingConfig::getConfig().isXMLAlgorithmSupported(alg, XMLToolingConfig::ALGTYPE_SIGN)) {
                SigningMethod* sm = SigningMethodBuilder::buildSigningMethod();
                sm->setAlgorithm(alg);
                m_signings.push_back(sm);
            }
        }

        string m_salt;
        short m_http,m_https;
        vector<string> m_bases;
        scoped_ptr<UIInfo> m_uiinfo;
        scoped_ptr<Organization> m_org;
        scoped_ptr<EntityAttributes> m_entityAttrs;
        ptr_vector<ContactPerson> m_contacts;
        ptr_vector<NameIDFormat> m_formats;
        ptr_vector<RequestedAttribute> m_reqAttrs;
        ptr_vector<AttributeConsumingService> m_attrConsumers;
        ptr_vector<EncryptionMethod> m_encryptions;
        ptr_vector<DigestMethod> m_digests;
        ptr_vector<SigningMethod> m_signings;
        const XMLObjectBuilder* m_encryptionBuilder;
        const XMLObjectBuilder* m_digestBuilder;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL MetadataGeneratorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new MetadataGenerator(p.first, p.second);
    }

};

MetadataGenerator::MetadataGenerator(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".MetadataGenerator"))
#ifndef SHIBSP_LITE
        ,m_http(0), m_https(0), m_encryptionBuilder(nullptr), m_digestBuilder(nullptr)
#endif
{
    string address(appId);
    address += getString("Location").second;
    setAddress(address.c_str());

#ifndef SHIBSP_LITE
    static XMLCh EndpointBase[] =           UNICODE_LITERAL_12(E,n,d,p,o,i,n,t,B,a,s,e);

    pair<bool,const char*> salt = getString("salt");
    if (salt.first)
        m_salt = salt.second;

    pair<bool,bool> flag = getBool("http");
    if (flag.first)
        m_http = flag.second ? 1 : -1;
    flag = getBool("https");
    if (flag.first)
        m_https = flag.second ? 1 : -1;

    e = XMLHelper::getFirstChildElement(e);
    while (e) {
        if (XMLString::equals(e->getLocalName(), EndpointBase) && e->hasChildNodes()) {
            auto_ptr_char base(e->getFirstChild()->getNodeValue());
            if (base.get() && *base.get())
                m_bases.push_back(base.get());
        }
        else {
            // Try and parse the object.
            auto_ptr<XMLObject> child(XMLObjectBuilder::buildOneFromElement(const_cast<DOMElement*>(e)));
            ContactPerson* cp = dynamic_cast<ContactPerson*>(child.get());
            if (cp) {
                m_contacts.push_back(cp);
                child.release();
            }
            else {
                NameIDFormat* nif = dynamic_cast<NameIDFormat*>(child.get());
                if (nif) {
                    m_formats.push_back(nif);
                    child.release();
                }
                else {
                    RequestedAttribute* req = dynamic_cast<RequestedAttribute*>(child.get());
                    if (req) {
                        m_reqAttrs.push_back(req);
                        child.release();
                    }
                    else {
                        AttributeConsumingService* acs = dynamic_cast<AttributeConsumingService*>(child.get());
                        if (acs) {
                            m_attrConsumers.push_back(acs);
                            child.release();
                        }
                        else {
                            UIInfo* info = dynamic_cast<UIInfo*>(child.get());
                            if (info) {
                                if (!m_uiinfo) {
                                    m_uiinfo.reset(info);
                                    child.release();
                                }
                                else {
                                    m_log.warn("skipping duplicate UIInfo element");
                                }
                            }
                            else {
                                Organization* org = dynamic_cast<Organization*>(child.get());
                                if (org) {
                                    if (!m_org) {
                                        m_org.reset(org);
                                        child.release();
                                    }
                                    else {
                                        m_log.warn("skipping duplicate Organization element");
                                    }
                                }
                                else {
                                    EntityAttributes* ea = dynamic_cast<EntityAttributes*>(child.get());
                                    if (ea) {
                                        if (!m_entityAttrs) {
                                            m_entityAttrs.reset(ea);
                                            child.release();
                                        }
                                        else {
                                            m_log.warn("skipping duplicate EntityAttributes element");
                                        }
                                    }
                                    else {
                                        EncryptionMethod* em = dynamic_cast<EncryptionMethod*>(child.get());
                                        if (em) {
                                            m_encryptions.push_back(em);
                                            child.release();
                                        }
                                        else {
                                            DigestMethod* dm = dynamic_cast<DigestMethod*>(child.get());
                                            if (dm) {
                                                m_digests.push_back(dm);
                                                child.release();
                                            }
                                            else {
                                                SigningMethod* sm = dynamic_cast<SigningMethod*>(child.get());
                                                if (sm) {
                                                    m_signings.push_back(sm);
                                                    child.release();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        e = XMLHelper::getNextSiblingElement(e);
    }

    // Default in precedence rules for various algorithms.
    if (m_encryptions.empty()) {
#ifdef XSEC_OPENSSL_HAVE_GCM
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES128_GCM);
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES192_GCM);
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES256_GCM);
#endif
#ifdef XSEC_OPENSSL_HAVE_AES
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES128_CBC);
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES192_CBC);
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIAES256_CBC);
#endif
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURI3DES_CBC);
#ifdef URI_ID_RSA_OAEP
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIRSA_OAEP);
#endif
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIRSA_OAEP_MGFP1);
        registerEncryptionMethod(DSIGConstants::s_unicodeStrURIRSA_1_5);
    }

    if (m_digests.empty()) {
        registerDigestMethod(DSIGConstants::s_unicodeStrURISHA512);
        registerDigestMethod(DSIGConstants::s_unicodeStrURISHA384);
        registerDigestMethod(DSIGConstants::s_unicodeStrURISHA256);
        registerDigestMethod(DSIGConstants::s_unicodeStrURISHA224);
        registerDigestMethod(DSIGConstants::s_unicodeStrURISHA1);
    }

    if (m_signings.empty()) {
#ifdef XSEC_OPENSSL_HAVE_EC
        registerSigningMethod(DSIGConstants::s_unicodeStrURIECDSA_SHA512);
        registerSigningMethod(DSIGConstants::s_unicodeStrURIECDSA_SHA384);
        registerSigningMethod(DSIGConstants::s_unicodeStrURIECDSA_SHA256);
# ifdef URI_ID_ECDSA_SHA224
        registerSigningMethod(DSIGConstants::s_unicodeStrURIECDSA_SHA224);
# endif
#endif
        registerSigningMethod(DSIGConstants::s_unicodeStrURIRSA_SHA512);
        registerSigningMethod(DSIGConstants::s_unicodeStrURIRSA_SHA384);
        registerSigningMethod(DSIGConstants::s_unicodeStrURIRSA_SHA256);

#ifdef URI_ID_DSA_SHA256
        registerSigningMethod(DSIGConstants::s_unicodeStrURIDSA_SHA256);
#endif

#ifdef XSEC_OPENSSL_HAVE_EC
        registerSigningMethod(DSIGConstants::s_unicodeStrURIECDSA_SHA1);
#endif
        registerSigningMethod(DSIGConstants::s_unicodeStrURIRSA_SHA1);
        registerSigningMethod(DSIGConstants::s_unicodeStrURIDSA_SHA1);
    }
#endif
}

pair<bool,long> MetadataGenerator::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    try {
        if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request.getHandlerURL(), request.getParameter("entityID"), request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out,in = DDF(m_address.c_str());
            in.addmember("application_id").string(request.getApplication().getId());
            in.addmember("handler_url").string(request.getHandlerURL());
            if (request.getParameter("entityID"))
                in.addmember("entity_id").string(request.getParameter("entityID"));
            DDFJanitor jin(in), jout(out);

            out = request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        istringstream msg("Metadata Request Failed");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_ERROR));
    }
}

void MetadataGenerator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const char* hurl = in["handler_url"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for metadata request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for metadata request, deleted?");
    }
    else if (!hurl) {
        throw ConfigurationException("Missing handler_url parameter in remoted method call.");
    }

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    processMessage(*app, hurl, in["entity_id"].string(), *resp);
    out << ret;
}

pair<bool,long> MetadataGenerator::processMessage(
    const Application& application, const char* handlerURL, const char* entityID, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    m_log.debug("processing metadata request");

    const PropertySet* relyingParty = nullptr;
    if (entityID) {
        MetadataProvider* m = application.getMetadataProvider();
        Locker locker(m);
        MetadataProviderCriteria mc(application, entityID);
        relyingParty = application.getRelyingParty(m->getEntityDescriptor(mc).first);
    }
    else {
        relyingParty = &application;
    }

    scoped_ptr<EntityDescriptor> entity;
    pair<bool,const char*> prop = getString("template");
    if (prop.first) {
        // Load a template to use for our metadata.
        string templ(prop.second);
        XMLToolingConfig::getConfig().getPathResolver()->resolve(templ, PathResolver::XMLTOOLING_CFG_FILE);
        auto_ptr_XMLCh widenit(templ.c_str());
        LocalFileInputSource src(widenit.get());
        Wrapper4InputSource dsrc(&src,false);
        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(dsrc);
        XercesJanitor<DOMDocument> docjan(doc);
        auto_ptr<XMLObject> xmlobj(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
        docjan.release();
        entity.reset(dynamic_cast<EntityDescriptor*>(xmlobj.get()));
        xmlobj.release();
        if (!entity)
            throw ConfigurationException("Template file ($1) did not contain an EntityDescriptor", params(1, templ.c_str()));
    }
    else {
        entity.reset(EntityDescriptorBuilder::buildEntityDescriptor());
    }

    // We always have extensions for algorithm support.
    if (!entity->getExtensions()) {
        entity->setExtensions(ExtensionsBuilder::buildExtensions());
        entity->getExtensions()->addNamespace(Namespace(samlconstants::SAML20MD_ALGSUPPORT_NS, samlconstants::SAML20MD_ALGSUPPORT_PREFIX));
    }

    if (!entity->getID()) {
        string hashinput = m_salt + relyingParty->getString("entityID").second;
        string hashed = '_' + SecurityHelper::doHash("SHA1", hashinput.c_str(), hashinput.length());
        auto_ptr_XMLCh widenit(hashed.c_str());
        entity->setID(widenit.get());
    }

    pair<bool,unsigned int> cache = getUnsignedInt("cacheDuration");
    if (cache.first) {
        entity->setCacheDuration(cache.second);
    }
    cache = getUnsignedInt("validUntil");
    if (cache.first)
        entity->setValidUntil(time(nullptr) + cache.second);
    entity->setEntityID(relyingParty->getXMLString("entityID").second);

    if (m_org && !entity->getOrganization())
        entity->setOrganization(m_org->cloneOrganization());

    for (ptr_vector<ContactPerson>::const_iterator cp = m_contacts.begin(); cp != m_contacts.end(); ++cp)
        entity->getContactPersons().push_back(cp->cloneContactPerson());

    if (m_entityAttrs) {
        entity->getExtensions()->getUnknownXMLObjects().push_back(m_entityAttrs->cloneEntityAttributes());
    }

    SPSSODescriptor* role;
    if (entity->getSPSSODescriptors().empty()) {
        role = SPSSODescriptorBuilder::buildSPSSODescriptor();
        entity->getSPSSODescriptors().push_back(role);
    }
    else {
        role = entity->getSPSSODescriptors().front();
    }

    for (ptr_vector<NameIDFormat>::const_iterator nif = m_formats.begin(); nif != m_formats.end(); ++nif)
        role->getNameIDFormats().push_back(nif->cloneNameIDFormat());

    if (m_uiinfo) {
        if (!role->getExtensions())
            role->setExtensions(ExtensionsBuilder::buildExtensions());
        role->getExtensions()->getUnknownXMLObjects().push_back(m_uiinfo->cloneUIInfo());
    }

    if (!m_digests.empty() || !m_signings.empty()) {
        for (ptr_vector<DigestMethod>::const_iterator dm = m_digests.begin(); dm != m_digests.end(); ++dm)
            entity->getExtensions()->getUnknownXMLObjects().push_back(dm->cloneDigestMethod());
        for (ptr_vector<SigningMethod>::const_iterator sm = m_signings.begin(); sm != m_signings.end(); ++sm)
            entity->getExtensions()->getUnknownXMLObjects().push_back(sm->cloneSigningMethod());
    }

    for (ptr_vector<AttributeConsumingService>::const_iterator acs = m_attrConsumers.begin(); acs != m_attrConsumers.end(); ++acs)
        role->getAttributeConsumingServices().push_back(acs->cloneAttributeConsumingService());

    if (!m_reqAttrs.empty()) {
        int index = 1;
        const vector<AttributeConsumingService*>& svcs = const_cast<const SPSSODescriptor*>(role)->getAttributeConsumingServices();
        for (indirect_iterator<vector<AttributeConsumingService*>::const_iterator> s = make_indirect_iterator(svcs.begin());
                s != make_indirect_iterator(svcs.end()); ++s) {
            pair<bool,int> i = s->getIndex();
            if (i.first && index == i.second)
                index = i.second + 1;
        }
        AttributeConsumingService* svc = AttributeConsumingServiceBuilder::buildAttributeConsumingService();
        role->getAttributeConsumingServices().push_back(svc);
        svc->setIndex(index);
        ServiceName* sn = ServiceNameBuilder::buildServiceName();
        svc->getServiceNames().push_back(sn);
        sn->setName(entity->getEntityID());
        static const XMLCh english[] = UNICODE_LITERAL_2(e,n);
        sn->setLang(english);
        for (ptr_vector<RequestedAttribute>::const_iterator req = m_reqAttrs.begin(); req != m_reqAttrs.end(); ++req)
            svc->getRequestedAttributes().push_back(req->cloneRequestedAttribute());
    }

    // Policy flags.
    prop = relyingParty->getString("signing");
    if (prop.first && (!strcmp(prop.second,"true") || !strcmp(prop.second,"front")))
        role->AuthnRequestsSigned(true);
    pair<bool,bool> flagprop = relyingParty->getBool("requireSignedAssertions");
    if (flagprop.first && flagprop.second)
        role->WantAssertionsSigned(true);

    // Ask each handler to generate itself.
    vector<const Handler*> handlers;
    application.getHandlers(handlers);
    for (indirect_iterator<vector<const Handler*>::const_iterator> h = make_indirect_iterator(handlers.begin());
            h != make_indirect_iterator(handlers.end()); ++h) {
        if (m_bases.empty()) {
            if (strncmp(handlerURL, "https", 5) == 0) {
                if (m_https >= 0)
                    h->generateMetadata(*role, handlerURL);
                if (m_http == 1) {
                    string temp(handlerURL);
                    temp.erase(4, 1);
                    h->generateMetadata(*role, temp.c_str());
                }
            }
            else {
                if (m_http >= 0)
                    h->generateMetadata(*role, handlerURL);
                if (m_https == 1) {
                    string temp(handlerURL);
                    temp.insert(temp.begin() + 4, 's');
                    h->generateMetadata(*role, temp.c_str());
                }
            }
        }
        else {
            for (vector<string>::const_iterator b = m_bases.begin(); b != m_bases.end(); ++b)
                h->generateMetadata(*role, b->c_str());
        }
    }

    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        Locker extlocker(extractor);
        extractor->generateMetadata(*role);
    }

    CredentialResolver* credResolver = application.getCredentialResolver();
    if (credResolver) {
        Locker credLocker(credResolver);
        CredentialCriteria cc;
        prop = relyingParty->getString("keyName");
        if (prop.first)
            cc.getKeyNames().insert(prop.second);
        vector<const Credential*> signingcreds,enccreds;
        cc.setUsage(Credential::SIGNING_CREDENTIAL);
        credResolver->resolve(signingcreds, &cc);
        cc.setUsage(Credential::ENCRYPTION_CREDENTIAL);
        credResolver->resolve(enccreds, &cc);

        for (vector<const Credential*>::const_iterator c = signingcreds.begin(); c != signingcreds.end(); ++c) {
            KeyInfo* kinfo = (*c)->getKeyInfo();
            if (kinfo) {
                KeyDescriptor* kd = KeyDescriptorBuilder::buildKeyDescriptor();
                kd->setKeyInfo(kinfo);
                const XMLCh* use = KeyDescriptor::KEYTYPE_SIGNING;
                for (vector<const Credential*>::iterator match = enccreds.begin(); match != enccreds.end(); ++match) {
                    if (*match == *c) {
                        use = nullptr;
                        enccreds.erase(match);
                        break;
                    }
                }
                kd->setUse(use);
                if (!use) {
                    for (ptr_vector<EncryptionMethod>::const_iterator em = m_encryptions.begin(); em != m_encryptions.end(); ++em)
                        kd->getEncryptionMethods().push_back(em->cloneEncryptionMethod());
                }
                role->getKeyDescriptors().push_back(kd);
            }
        }

        for (vector<const Credential*>::const_iterator c = enccreds.begin(); c != enccreds.end(); ++c) {
            KeyInfo* kinfo = (*c)->getKeyInfo();
            if (kinfo) {
                KeyDescriptor* kd = KeyDescriptorBuilder::buildKeyDescriptor();
                kd->setUse(KeyDescriptor::KEYTYPE_ENCRYPTION);
                kd->setKeyInfo(kinfo);
                for (ptr_vector<EncryptionMethod>::const_iterator em = m_encryptions.begin(); em != m_encryptions.end(); ++em)
                    kd->getEncryptionMethods().push_back(em->cloneEncryptionMethod());
                role->getKeyDescriptors().push_back(kd);
            }
        }
    }

    // Stream for response.
    stringstream s;

    // Self-sign it?
    pair<bool,bool> flag = getBool("signing");
    if (flag.first && flag.second) {
        if (credResolver) {
            Locker credLocker(credResolver);
            // Fill in criteria to use.
            CredentialCriteria cc;
            cc.setUsage(Credential::SIGNING_CREDENTIAL);
            prop = getString("keyName");
            if (prop.first)
                cc.getKeyNames().insert(prop.second);
            pair<bool,const XMLCh*> sigalg = getXMLString("signingAlg");
            pair<bool,const XMLCh*> digalg = getXMLString("digestAlg");
            if (sigalg.first)
                cc.setXMLAlgorithm(sigalg.second);
            const Credential* cred = credResolver->resolve(&cc);
            if (!cred)
                throw XMLSecurityException("Unable to obtain signing credential to use.");

            // Pretty-print it first and then read it back in.
            stringstream pretty;
            XMLHelper::serialize(entity->marshall(), pretty, true);
            DOMDocument* prettydoc = XMLToolingConfig::getConfig().getParser().parse(pretty);
            scoped_ptr<XMLObject> prettyentity(XMLObjectBuilder::buildOneFromElement(prettydoc->getDocumentElement(), true));

            Signature* sig = SignatureBuilder::buildSignature();
            dynamic_cast<EntityDescriptor*>(prettyentity.get())->setSignature(sig);
            if (sigalg.first)
                sig->setSignatureAlgorithm(sigalg.second);
            if (digalg.first) {
                opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                if (cr)
                    cr->setDigestAlgorithm(digalg.second);
            }

            // Sign while marshalling.
            vector<Signature*> sigs(1,sig);
            prettyentity->marshall(prettydoc,&sigs,cred);
            s << "<!--" << endl << "This is example metadata only. Do *NOT* supply it as is without review,"
                << endl << "and do *NOT* provide it in real time to your partners." << endl << " -->" << endl;
            s << *prettyentity;
        }
        else {
            throw FatalProfileException("Can't self-sign metadata, no credential resolver found.");
        }
    }
    else {
        // Pretty-print it directly to client.
        s << "<!--" << endl << "This is example metadata only. Do *NOT* supply it as is without review,"
            << endl << "and do *NOT* provide it in real time to your partners." << endl << " -->";
        XMLHelper::serialize(entity->marshall(), s, true);
    }

    prop = getString("mimeType");
    httpResponse.setContentType(prop.first ? prop.second : "application/samlmetadata+xml");
    return make_pair(true, httpResponse.sendResponse(s));
#else
    return make_pair(false, 0L);
#endif
}
