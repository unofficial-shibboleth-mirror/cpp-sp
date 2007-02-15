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
 * SOAPClient.cpp
 * 
 * Specialized SOAPClient for SP environment.
 */

#include "internal.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "binding/SOAPClient.h"

#include <log4cpp/Category.hh>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
#include <xmltooling/util/NDC.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL _addcert : public binary_function<X509Data*,XSECCryptoX509*,void> {
    public:
        void operator()(X509Data* bag, XSECCryptoX509* cert) const {
            safeBuffer& buf=cert->getDEREncodingSB();
            X509Certificate* x=X509CertificateBuilder::buildX509Certificate();
            x->setValue(buf.sbStrToXMLCh());
            bag->getX509Certificates().push_back(x);
        }
    };
};

SOAPClient::SOAPClient(const Application& application, opensaml::SecurityPolicy& policy)
    : opensaml::SOAPClient(policy), m_app(application), m_settings(NULL), m_credUse(NULL), m_credResolver(NULL)
{
    SPConfig& conf = SPConfig::getConfig();
    pair<bool,const char*> policyId = m_app.getString("policyId");
    m_settings = conf.getServiceProvider()->getPolicySettings(policyId.second);
    const vector<const opensaml::SecurityPolicyRule*>& rules = conf.getServiceProvider()->getPolicyRules(policyId.second);
    for (vector<const opensaml::SecurityPolicyRule*>::const_iterator rule=rules.begin(); rule!=rules.end(); ++rule)
        policy.addRule(*rule);
    policy.setMetadataProvider(application.getMetadataProvider());
    policy.setTrustEngine(application.getTrustEngine());
}

void SOAPClient::send(const soap11::Envelope& env, const KeyInfoSource& peer, const char* endpoint)
{
    if (!m_peer)
        m_peer = dynamic_cast<const RoleDescriptor*>(&peer);
 
    if (m_peer) {
        const EntityDescriptor* entity = m_peer ? dynamic_cast<const EntityDescriptor*>(m_peer->getParent()) : NULL;
        m_credUse = entity ? m_app.getCredentialUse(entity) : NULL;
    }
    
    // Check for message signing requirements.   
    if (m_credUse) {
        pair<bool,bool> flag = m_credUse->getBool("signRequests");
        if (flag.first && flag.second) {
            CredentialResolver* cr=NULL;
            pair<bool,const char*> cred = m_credUse->getString("Signing");
            if (cred.first && (cr=SPConfig::getConfig().getServiceProvider()->getCredentialResolver(cred.second))) {
                // Looks like we're supposed to sign, so check for message.
                const vector<XMLObject*>& bodies=const_cast<const soap11::Body*>(env.getBody())->getUnknownXMLObjects();
                if (!bodies.empty()) {
                    opensaml::SignableObject* msg = dynamic_cast<opensaml::SignableObject*>(bodies.front());
                    if (msg) {
                        // Build a Signature.
                        Signature* sig = SignatureBuilder::buildSignature();
                        msg->setSignature(sig);
                        pair<bool,const XMLCh*> alg = m_credUse->getXMLString("sigAlgorithm");
                        if (alg.first)
                            sig->setSignatureAlgorithm(alg.second);
                        Locker locker(cr);
                        sig->setSigningKey(cr->getKey());
                    
                        // Build KeyInfo.
                        const vector<XSECCryptoX509*>& certs = cr->getCertificates();
                        if (!certs.empty()) {
                            KeyInfo* keyInfo=KeyInfoBuilder::buildKeyInfo();
                            sig->setKeyInfo(keyInfo);
                            X509Data* x509Data=X509DataBuilder::buildX509Data();
                            keyInfo->getX509Datas().push_back(x509Data);
                            for_each(certs.begin(),certs.end(),bind1st(_addcert(),x509Data));
                        }

                        // Sign it. The marshalling step in the base class should be a no-op.
                        vector<Signature*> sigs(1,sig);
                        env.marshall((DOMDocument*)NULL,&sigs);
                    }
                }
            }
        }
    }
    
    opensaml::SOAPClient::send(env, peer, endpoint);
}

void SOAPClient::prepareTransport(SOAPTransport& transport)
{
#ifdef _DEBUG
    xmltooling::NDC("prepareTransport");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".SOAPClient");
    log.debug("prepping SOAP transport for use by application (%s)", m_app.getId());

    pair<bool,bool> flag = m_settings->getBool("requireConfidentiality");
    if ((!flag.first || flag.second) && !transport.isConfidential())
        throw opensaml::BindingException("Transport confidentiality required, but not available."); 

    flag = m_settings->getBool("validate");
    setValidating(flag.first && flag.second);
    flag = m_settings->getBool("requireTransportAuth");
    forceTransportAuthentication(!flag.first || flag.second);

    opensaml::SOAPClient::prepareTransport(transport);

    if (!m_credUse) {
        const EntityDescriptor* entity = m_peer ? dynamic_cast<const EntityDescriptor*>(m_peer->getParent()) : NULL;
        m_credUse = entity ? m_app.getCredentialUse(entity) : NULL;
    }
    if (m_credUse) {
        pair<bool,const char*> authType=m_credUse->getString("authType");
        if (authType.first) {
            SOAPTransport::transport_auth_t type=SOAPTransport::transport_auth_none;
            pair<bool,const char*> username=m_credUse->getString("authUsername");
            pair<bool,const char*> password=m_credUse->getString("authPassword");
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
            else
                log.error("unknown authType (%s) specified in CredentialUse element", authType.second);
            if (type > SOAPTransport::transport_auth_none) {
                if (transport.setAuth(type,username.second,password.second))
                    log.debug("configured for transport authentication (method=%s, username=%s)", authType.second, username.second);
                else
                    log.error("failed to configure transport authentication (method=%s)", authType.second);
            }
        }
        
        authType = m_credUse->getString("TLS");
        if (authType.first) {
            m_credResolver = SPConfig::getConfig().getServiceProvider()->getCredentialResolver(authType.second);
            if (m_credResolver) {
                m_credResolver->lock();
                if (!transport.setCredentialResolver(m_credResolver)) {
                    m_credResolver->unlock();
                    m_credResolver = NULL;
                    log.error("failed to load CredentialResolver into SOAPTransport");
                }
            }
            else {
                log.error("unable to access CredentialResolver (%s)", authType.second);
            }
        }
    } 

    transport.setConnectTimeout(m_settings->getUnsignedInt("connectTimeout").second);
    transport.setTimeout(m_settings->getUnsignedInt("timeout").second);

    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(&transport);
    if (http) {
        flag = m_settings->getBool("chunkedEncoding");
        http->useChunkedEncoding(!flag.first || flag.second);
        http->setRequestHeader("Shibboleth", PACKAGE_VERSION);
    }
}

void SOAPClient::reset()
{
    m_credUse = NULL;
    if (m_credResolver)
        m_credResolver->unlock();
    m_credResolver = NULL;
    opensaml::SOAPClient::reset();
}