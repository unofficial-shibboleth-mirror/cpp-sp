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
 * KeyInfoAttributeDecoder.cpp
 *
 * Decodes KeyInfo information into a SimpleAttribute.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/SimpleAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/KeyInfoResolver.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/signature/KeyInfo.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL KeyInfoAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        KeyInfoAttributeDecoder(const DOMElement* e);
        ~KeyInfoAttributeDecoder() {
            delete m_keyInfoResolver;
        }

        Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const;

    private:
        void extract(const KeyInfo* k, vector<string>& dest) const {
            auto_ptr<Credential> cred (getKeyInfoResolver()->resolve(k, Credential::RESOLVE_KEYS));
            if (cred.get()) {
                dest.push_back(string());
                dest.back() = SecurityHelper::getDEREncoding(*cred.get(), m_hash ? m_keyInfoHashAlg.c_str() : nullptr);
                if (dest.back().empty())
                    dest.pop_back();
            }
        }

        const KeyInfoResolver* getKeyInfoResolver() const {
            return m_keyInfoResolver ? m_keyInfoResolver : XMLToolingConfig::getConfig().getKeyInfoResolver();
        }

        bool m_hash;
        string m_keyInfoHashAlg;
        KeyInfoResolver* m_keyInfoResolver;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL KeyInfoAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new KeyInfoAttributeDecoder(e);
    }

    static const XMLCh _KeyInfoResolver[] = UNICODE_LITERAL_15(K,e,y,I,n,f,o,R,e,s,o,l,v,e,r);
    static const XMLCh _hash[] =            UNICODE_LITERAL_4(h,a,s,h);
    static const XMLCh keyInfoHashAlg[] =   UNICODE_LITERAL_14(k,e,y,I,n,f,o,H,a,s,h,A,l,g);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
};

KeyInfoAttributeDecoder::KeyInfoAttributeDecoder(const DOMElement* e)
    : AttributeDecoder(e),
        m_hash(XMLHelper::getAttrBool(e, false, _hash)),
        m_keyInfoHashAlg(XMLHelper::getAttrString(e, "SHA1", keyInfoHashAlg)),
        m_keyInfoResolver(nullptr) {
    e = XMLHelper::getFirstChildElement(e,_KeyInfoResolver);
    if (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (t.empty())
            throw UnknownExtensionException("<KeyInfoResolver> element found with no type attribute");
        m_keyInfoResolver = XMLToolingConfig::getConfig().KeyInfoResolverManager.newPlugin(t.c_str(), e);
    }
}

Attribute* KeyInfoAttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.KeyInfo");

    if (!xmlObject || !XMLString::equals(saml1::Attribute::LOCAL_NAME, xmlObject->getElementQName().getLocalPart())) {
        log.warn("XMLObject type not recognized by KeyInfoAttributeDecoder, no values returned");
        return nullptr;
    }

    auto_ptr<SimpleAttribute> attr(new SimpleAttribute(ids));
    vector<string>& dest = attr->getValues();
    vector<XMLObject*>::const_iterator v,stop;

    const saml2::Attribute* saml2attr = dynamic_cast<const saml2::Attribute*>(xmlObject);
    if (saml2attr) {
        const vector<XMLObject*>& values = saml2attr->getAttributeValues();
        v = values.begin();
        stop = values.end();
        if (log.isDebugEnabled()) {
            auto_ptr_char n(saml2attr->getName());
            log.debug(
                "decoding KeyInfo information (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                );
        }
    }
    else {
        const saml1::Attribute* saml1attr = dynamic_cast<const saml1::Attribute*>(xmlObject);
        if (saml1attr) {
            const vector<XMLObject*>& values = saml1attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml1attr->getAttributeName());
                log.debug(
                    "decoding KeyInfo information (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            log.warn("XMLObject type not recognized by KeyInfoAttributeDecoder, no values returned");
            return nullptr;
        }
    }

    for (; v!=stop; ++v) {
        const KeyInfo* k = dynamic_cast<const KeyInfo*>(*v);
        if (k)
            extract(k, dest);
        else if ((*v)->hasChildren()) {
            const list<XMLObject*>& children = (*v)->getOrderedChildren();
            for (list<XMLObject*>::const_iterator vv = children.begin(); vv!=children.end(); ++vv) {
                if (k=dynamic_cast<const KeyInfo*>(*vv))
                    extract(k, dest);
                else
                    log.warn("skipping AttributeValue without a recognizable KeyInfo");
            }
        }
    }

    return dest.empty() ? nullptr : _decode(attr.release());
}
