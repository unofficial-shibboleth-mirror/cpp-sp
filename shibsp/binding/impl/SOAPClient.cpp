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
 * SOAPClient.cpp
 * 
 * Specialized SOAPClient for SP environment.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "binding/SOAPClient.h"
#include "security/SecurityPolicy.h"

#include <saml/exceptions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/signature/ContentReference.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
#include <xmltooling/util/NDC.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

SOAPClient::SOAPClient(SecurityPolicy& policy)
    : opensaml::SOAPClient(policy), m_app(policy.getApplication()), m_relyingParty(nullptr), m_credResolver(nullptr)
{
}

SOAPClient::~SOAPClient()
{
    if (m_credResolver)
        m_credResolver->unlock();
}

void SOAPClient::send(const soap11::Envelope& env, const char* from, MetadataCredentialCriteria& to, const char* endpoint)
{
    // Check for message signing requirements.   
    m_relyingParty = m_app.getRelyingParty(dynamic_cast<const EntityDescriptor*>(to.getRole().getParent()));
    pair<bool,const char*> flag = m_relyingParty->getString("signing");
    if (flag.first && (!strcmp(flag.second, "true") || !strcmp(flag.second, "back"))) {
        m_credResolver=m_app.getCredentialResolver();
        if (m_credResolver) {
            m_credResolver->lock();
            const Credential* cred = nullptr;

            // Fill in criteria to use.
            to.setUsage(Credential::SIGNING_CREDENTIAL);
            pair<bool,const char*> keyName = m_relyingParty->getString("keyName");
            if (keyName.first)
                to.getKeyNames().insert(keyName.second);

            // Check for an explicit algorithm, in which case resolve a credential directly.
            pair<bool,const XMLCh*> sigalg = m_relyingParty->getXMLString("signingAlg");
            if (sigalg.first) {
                to.setXMLAlgorithm(sigalg.second);
                cred = m_credResolver->resolve(&to);
            }
            else {
                // Prefer credential based on peer's requirements.
                pair<const SigningMethod*,const Credential*> p = to.getRole().getSigningMethod(*m_credResolver, to);
                if (p.first)
                    sigalg = make_pair(true, p.first->getAlgorithm());
                if (p.second)
                    cred = p.second;
            }

            // Reset criteria back.
            to.reset();

            if (cred) {
                // Check for message.
                const vector<XMLObject*>& bodies=const_cast<const soap11::Body*>(env.getBody())->getUnknownXMLObjects();
                if (!bodies.empty()) {
                    opensaml::SignableObject* msg = dynamic_cast<opensaml::SignableObject*>(bodies.front());
                    if (msg) {
                        // Build a Signature.
                        Signature* sig = SignatureBuilder::buildSignature();
                        msg->setSignature(sig);
                        if (sigalg.first)
                            sig->setSignatureAlgorithm(sigalg.second);
                        sigalg = m_relyingParty->getXMLString("digestAlg");
                        if (!sigalg.first) {
                            const DigestMethod* dm = to.getRole().getDigestMethod();
                            if (dm)
                                sigalg = make_pair(true, dm->getAlgorithm());
                        }
                        if (sigalg.first)
                            dynamic_cast<opensaml::ContentReference*>(sig->getContentReference())->setDigestAlgorithm(sigalg.second);

                        // Sign it. The marshalling step in the base class should be a no-op.
                        vector<Signature*> sigs(1,sig);
                        env.marshall((DOMDocument*)nullptr,&sigs,cred);
                    }
                }
            }
            else {
                Category::getInstance(SHIBSP_LOGCAT".SOAPClient").warn("no signing credential resolved, leaving message unsigned");
            }
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".SOAPClient").warn("no CredentialResolver available, leaving unsigned");
        }
    }
    
    opensaml::SOAPClient::send(env, from, to, endpoint);
}

void SOAPClient::prepareTransport(SOAPTransport& transport)
{
#ifdef _DEBUG
    xmltooling::NDC("prepareTransport");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".SOAPClient");
    log.debug("prepping SOAP transport for use by application (%s)", m_app.getId());

    pair<bool,bool> flag = m_relyingParty->getBool("requireConfidentiality");
    if ((!flag.first || flag.second) && !transport.isConfidential())
        throw opensaml::BindingException("Transport confidentiality required, but not available."); 

    setValidating(getPolicy().getValidating());
    flag = m_relyingParty->getBool("requireTransportAuth");
    forceTransportAuthentication(!flag.first || flag.second);

    opensaml::SOAPClient::prepareTransport(transport);

    pair<bool,const char*> authType=m_relyingParty->getString("authType");
    if (!authType.first || !strcmp(authType.second,"TLS")) {
        if (!m_credResolver) {
            m_credResolver = m_app.getCredentialResolver();
            if (m_credResolver)
                m_credResolver->lock();
        }
        if (m_credResolver) {
            m_criteria->setUsage(Credential::TLS_CREDENTIAL);
            authType = m_relyingParty->getString("keyName");
            if (authType.first)
                m_criteria->getKeyNames().insert(authType.second);
            const Credential* cred = m_credResolver->resolve(m_criteria);
            m_criteria->getKeyNames().clear();
            if (cred) {
                if (!transport.setCredential(cred))
                    log.error("failed to load Credential into SOAPTransport");
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
        pair<bool,const char*> username=m_relyingParty->getString("authUsername");
        pair<bool,const char*> password=m_relyingParty->getString("authPassword");
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
            if (transport.setAuth(type,username.second,password.second))
                log.debug("configured for transport authentication (method=%s, username=%s)", authType.second, username.second);
            else
                log.error("failed to configure transport authentication (method=%s)", authType.second);
        }
    }
    
    pair<bool,unsigned int> timeout = m_relyingParty->getUnsignedInt("connectTimeout"); 
    transport.setConnectTimeout(timeout.first ? timeout.second : 10);
    timeout = m_relyingParty->getUnsignedInt("timeout");
    transport.setTimeout(timeout.first ? timeout.second : 20);
    m_app.getServiceProvider().setTransportOptions(transport);

    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(&transport);
    if (http) {
        flag = m_relyingParty->getBool("chunkedEncoding");
        http->useChunkedEncoding(flag.first && flag.second);
        http->setRequestHeader(PACKAGE_NAME, PACKAGE_VERSION);
    }
}

void SOAPClient::reset()
{
    m_relyingParty = nullptr;
    if (m_credResolver)
        m_credResolver->unlock();
    m_credResolver = nullptr;
    opensaml::SOAPClient::reset();
}

