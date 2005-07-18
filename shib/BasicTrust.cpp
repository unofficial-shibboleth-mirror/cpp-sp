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

/* BasicTrust.cpp - a trust implementation that relies solely on standard SAML metadata

   Scott Cantor
   4/9/05

   $History:$
*/

#include "internal.h"

#include <openssl/x509.h>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

IPlugIn* BasicTrustFactory(const DOMElement* e)
{
    return new BasicTrust(e);
}

static const XMLCh resolver[] =
{ chLatin_K, chLatin_e, chLatin_y, chLatin_I, chLatin_n, chLatin_f, chLatin_o,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull
};
static const XMLCh type[] =
{ chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };

BasicTrust::BasicTrust(const DOMElement* e)
{
    // Find any KeyResolver plugins.
    e=saml::XML::getFirstChildElement(e);
    while (e) {
        if (!XMLString::compareString(resolver,e->getLocalName()) && e->hasAttributeNS(NULL,type)) {
            try {
                auto_ptr_char temp(e->getAttributeNS(NULL,type));
                m_resolvers.push_back(KeyInfoResolver::getInstance(temp.get(),e));
            }
            catch (SAMLException& ex) {
                Category::getInstance(SHIB_LOGCAT".Trust.Basic").error(
                    "caught SAML exception building KeyInfoResolver plugin: %s",ex.what()
                    );
            }
#ifndef _DEBUG
            catch (...) {
                Category::getInstance(SHIB_LOGCAT".Trust.Basic").error("caught unknown exception building KeyInfoResolver plugin");
            }
#endif
        }
        e=saml::XML::getNextSiblingElement(e);
    }
    m_resolvers.push_back(KeyInfoResolver::getInstance(e));
}

BasicTrust::~BasicTrust()
{
    for (vector<KeyInfoResolver*>::iterator i=m_resolvers.begin(); i!=m_resolvers.end(); i++)
        delete *i;
}

bool BasicTrust::validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName)
{
#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Basic");

    if (!certEE) {
        log.error("no certificate provided for comparison");
        return false;
    }

    // The new "basic" trust implementation relies solely on certificates living within the
    // role interface to verify the EE certificate.

    log.debug("comparing certificate to KeyDescriptors");
    Iterator<const IKeyDescriptor*> kd_i=role->getKeyDescriptors();
    while (kd_i.hasNext()) {
        const IKeyDescriptor* kd=kd_i.next();
        if (kd->getUse()==IKeyDescriptor::encryption)
            continue;
        DSIGKeyInfoList* KIL=kd->getKeyInfo();
        if (!KIL)
            continue;
        Iterator<KeyInfoResolver*> resolvers(m_resolvers);
        while (resolvers.hasNext()) {
            XSECCryptoX509* cert=resolvers.next()->resolveCert(KIL);
            if (cert) {
                log.debug("KeyDescriptor resolved into a certificate, comparing it...");
                if (cert->getProviderName()!=DSIGConstants::s_unicodeStrPROVOpenSSL) {
                    log.warn("only the OpenSSL XSEC provider is supported");
                    continue;
                }
                else if (!X509_cmp(reinterpret_cast<X509*>(certEE),static_cast<OpenSSLCryptoX509*>(cert)->getOpenSSLX509())) {
                    log.info("certificate match found in KeyDescriptor");
                    return true;
                }
                else
                    log.debug("certificate did not match");
            }
        }
    }
    
    log.debug("failed to find an exact match for certificate in KeyDescriptors");
    return false;
}

bool BasicTrust::validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator)
{
#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Basic");

    // The new "basic" trust implementation relies solely on keys living within the
    // role interface to verify the token. No indirection of any sort is allowed,
    // unless an alternate key resolver is involved.
 
    log.debug("validating signature with KeyDescriptors");
    Iterator<const IKeyDescriptor*> kd_i=role->getKeyDescriptors();
    while (kd_i.hasNext()) {
        const IKeyDescriptor* kd=kd_i.next();
        if (kd->getUse()!=IKeyDescriptor::signing)
            continue;
        DSIGKeyInfoList* KIL=kd->getKeyInfo();
        if (!KIL)
            continue;
        Iterator<KeyInfoResolver*> resolvers(m_resolvers);
        while (resolvers.hasNext()) {
            XSECCryptoKey* key=((XSECKeyInfoResolver*)*resolvers.next())->resolveKey(KIL);
            if (key) {
                log.debug("KeyDescriptor resolved into a key, trying it...");
                try {
                    token.verify(key);
                    log.info("signature verified with KeyDescriptor");
                    return true;
                }
                catch (SAMLException& e) {
                    log.debug("verification with KeyDescriptor failed: %s", e.what());
                }
            }
        }
    }
    
    log.debug("failed to validate signature with KeyDescriptors");
    return false;
}
