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
 * Base64AttributeDecoder.cpp
 *
 * Decodes SAML containing base64-encoded values into SimpleAttributes.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/SimpleAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

#include <xercesc/util/Base64.hpp>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL Base64AttributeDecoder : virtual public AttributeDecoder
    {
    public:
        Base64AttributeDecoder(const DOMElement* e) : AttributeDecoder(e) {}
        ~Base64AttributeDecoder() {}

        shibsp::Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL Base64AttributeDecoderFactory(const DOMElement* const & e)
    {
        return new Base64AttributeDecoder(e);
    }
};

shibsp::Attribute* Base64AttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    auto_ptr<SimpleAttribute> simple(new SimpleAttribute(ids));
    vector<string>& dest = simple->getValues();
    vector<XMLObject*>::const_iterator v,stop;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.Base64");

    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                    "decoding SimpleAttribute (%s) from SAML 2 Attribute (%s) with %lu base64-encoded value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            const opensaml::saml1::Attribute* saml1attr = dynamic_cast<const opensaml::saml1::Attribute*>(xmlObject);
            if (saml1attr) {
                const vector<XMLObject*>& values = saml1attr->getAttributeValues();
                v = values.begin();
                stop = values.end();
                if (log.isDebugEnabled()) {
                    auto_ptr_char n(saml1attr->getAttributeName());
                log.debug(
                    "decoding SimpleAttribute (%s) from SAML 1 Attribute (%s) with %lu base64-encoded value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
                }
            }
            else {
                log.warn("XMLObject type not recognized by Base64AttributeDecoder, no values returned");
                return nullptr;
            }
        }

        for (; v!=stop; ++v) {
            if (!(*v)->hasChildren()) {
                auto_ptr_char val((*v)->getTextContent());
                if (val.get() && *val.get()) {
                    xsecsize_t x;
                    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(val.get()),&x);
                    if (decoded) {
                        dest.push_back(reinterpret_cast<char*>(decoded));
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                        XMLString::release(&decoded);
#else
                        XMLString::release((char**)&decoded);
#endif
                    }
                    else {
                        log.warn("skipping AttributeValue, unable to base64-decode");
                    }
                }
                else
                    log.warn("skipping empty AttributeValue");
            }
            else {
                log.warn("skipping complex AttributeValue");
            }
        }

        return dest.empty() ? nullptr : _decode(simple.release());
    }

    const NameID* saml2name = dynamic_cast<const NameID*>(xmlObject);
    if (saml2name) {
        if (log.isDebugEnabled()) {
            auto_ptr_char f(saml2name->getFormat());
            log.debug("decoding SimpleAttribute (%s) from SAML 2 NameID with Format (%s)", ids.front().c_str(), f.get() ? f.get() : "unspecified");
        }
        auto_ptr_char val(saml2name->getName());
        if (val.get() && *val.get()) {
            xsecsize_t x;
            XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(val.get()),&x);
            if (decoded) {
                dest.push_back(reinterpret_cast<char*>(decoded));
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                XMLString::release(&decoded);
#else
                XMLString::release((char**)&decoded);
#endif
            }
            else {
                log.warn("ignoring NameID, unable to base64-decode");
            }
        }
        else
            log.warn("ignoring empty NameID");
    }
    else {
        const NameIdentifier* saml1name = dynamic_cast<const NameIdentifier*>(xmlObject);
        if (saml1name) {
            if (log.isDebugEnabled()) {
                auto_ptr_char f(saml1name->getFormat());
                log.debug(
                    "decoding SimpleAttribute (%s) from SAML 1 NameIdentifier with Format (%s)",
                    ids.front().c_str(), f.get() ? f.get() : "unspecified"
                    );
            }
            auto_ptr_char val(saml1name->getName());
            if (val.get() && *val.get()) {
                xsecsize_t x;
                XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(val.get()),&x);
                if (decoded) {
                    dest.push_back(reinterpret_cast<char*>(decoded));
    #ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                    XMLString::release(&decoded);
    #else
                    XMLString::release((char**)&decoded);
    #endif
                }
                else {
                    log.warn("ignoring NameIdentifier, unable to base64-decode");
                }
            }
            else
                log.warn("ignoring empty NameIdentifier");
        }
        else {
            log.warn("XMLObject type not recognized by Base64AttributeDecoder, no values returned");
            return nullptr;
        }
    }

    return dest.empty() ? nullptr : _decode(simple.release());
}
