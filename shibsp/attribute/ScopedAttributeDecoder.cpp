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
 * ScopedAttributeDecoder.cpp
 *
 * Decodes SAML into ScopedAttributes.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/ScopedAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    static const XMLCh Scope[] =            UNICODE_LITERAL_5(S,c,o,p,e);
    static const XMLCh scopeDelimiter[] =   UNICODE_LITERAL_14(s,c,o,p,e,D,e,l,i,m,i,t,e,r);

    class SHIBSP_DLLLOCAL ScopedAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        ScopedAttributeDecoder(const DOMElement* e) : AttributeDecoder(e), m_delimiter('@') {
            if (e && e->hasAttributeNS(nullptr,scopeDelimiter)) {
                auto_ptr_char d(e->getAttributeNS(nullptr,scopeDelimiter));
                m_delimiter = *(d.get());
            }
        }
        ~ScopedAttributeDecoder() {}

        // deprecated method
        shibsp::Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const {
            return decode(nullptr, ids, xmlObject, assertingParty, relyingParty);
        }

        shibsp::Attribute* decode(
            const GenericRequest*, const vector<string>&, const XMLObject*, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const;

    private:
        char m_delimiter;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL ScopedAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new ScopedAttributeDecoder(e);
    }
};

shibsp::Attribute* ScopedAttributeDecoder::decode(
    const GenericRequest* request, const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    char* val;
    char* scope;
    const XMLCh* xmlscope;
    xmltooling::QName scopeqname(nullptr,Scope);
    auto_ptr<ScopedAttribute> scoped(new ScopedAttribute(ids, m_delimiter));
    vector< pair<string,string> >& dest = scoped->getValues();
    pair<vector<XMLObject*>::const_iterator,vector<XMLObject*>::const_iterator> valrange;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.Scoped");

    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            valrange = valueRange(request, values);
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                    "decoding ScopedAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            const opensaml::saml1::Attribute* saml1attr = dynamic_cast<const opensaml::saml1::Attribute*>(xmlObject);
            if (saml1attr) {
                const vector<XMLObject*>& values = saml1attr->getAttributeValues();
                valrange = valueRange(request, values);
                if (log.isDebugEnabled()) {
                    auto_ptr_char n(saml1attr->getAttributeName());
                    log.debug(
                        "decoding ScopedAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                        ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                        );
                }
            }
            else {
                log.warn("XMLObject type not recognized by ScopedAttributeDecoder, no values returned");
                return nullptr;
            }
        }

        for (; valrange.first != valrange.second; ++valrange.first) {
            if (!(*valrange.first)->hasChildren()) {
                val = toUTF8((*valrange.first)->getTextContent());
                if (val && *val) {
                    const AttributeExtensibleXMLObject* aexo=dynamic_cast<const AttributeExtensibleXMLObject*>(*valrange.first);
                    xmlscope = aexo ? aexo->getAttribute(scopeqname) : nullptr;
                    if (xmlscope && *xmlscope) {
                        auto_arrayptr<char> noninlinescope(toUTF8(xmlscope));
                        dest.push_back(pair<string,string>(val,noninlinescope.get()));
                    }
                    else {
                        scope = strchr(val, m_delimiter);
                        if (scope) {
                            *scope++ = 0;
                            if (*scope)
                                dest.push_back(pair<string,string>(val,scope));
                            else
                                log.warn("ignoring unscoped AttributeValue");
                        }
                        else {
                            log.warn("ignoring unscoped AttributeValue");
                        }
                    }
                }
                else {
                    log.warn("skipping empty AttributeValue");
                }
                delete[] val;
            }
            else {
                log.warn("skipping complex AttributeValue");
            }
        }

        return dest.empty() ? nullptr : _decode(scoped.release());
    }

    const NameID* saml2name = dynamic_cast<const NameID*>(xmlObject);
    if (saml2name) {
        if (log.isDebugEnabled()) {
            auto_ptr_char f(saml2name->getFormat());
            log.debug("decoding ScopedAttribute (%s) from SAML 2 NameID with Format (%s)", ids.front().c_str(), f.get() ? f.get() : "unspecified");
        }
        val = toUTF8(saml2name->getName());
    }
    else {
        const NameIdentifier* saml1name = dynamic_cast<const NameIdentifier*>(xmlObject);
        if (saml1name) {
            if (log.isDebugEnabled()) {
                auto_ptr_char f(saml1name->getFormat());
                log.debug(
                    "decoding ScopedAttribute (%s) from SAML 1 NameIdentifier with Format (%s)",
                    ids.front().c_str(), f.get() ? f.get() : "unspecified"
                    );
            }
            val = toUTF8(saml1name->getName());
        }
        else {
            log.warn("XMLObject type not recognized by ScopedAttributeDecoder, no values returned");
            return nullptr;
        }
    }

    if (val && *val && *val != m_delimiter) {
        scope = strchr(val, m_delimiter);
        if (scope) {
            *scope++ = 0;
            if (*scope)
                dest.push_back(pair<string,string>(val,scope));
            else
                log.warn("ignoring NameID with no scope");
        }
        else {
            log.warn("ignoring NameID with no scope delimiter (%c)", m_delimiter);
        }
    }
    else {
        log.warn("ignoring empty NameID");
    }
    delete[] val;
    return dest.empty() ? nullptr : _decode(scoped.release());
}
