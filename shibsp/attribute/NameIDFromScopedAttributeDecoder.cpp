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
 * NameIDFromNameIDFromScopedAttributeDecoder.cpp
 *
 * Decodes SAML "scoped" attributes into NameIDAttributes.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/NameIDAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    static const XMLCh defaultQualifiers[] =UNICODE_LITERAL_17(d,e,f,a,u,l,t,Q,u,a,l,i,f,i,e,r,s);
    static const XMLCh format[] =           UNICODE_LITERAL_6(f,o,r,m,a,t);
    static const XMLCh formatter[] =        UNICODE_LITERAL_9(f,o,r,m,a,t,t,e,r);
    static const XMLCh Scope[] =            UNICODE_LITERAL_5(S,c,o,p,e);
    static const XMLCh scopeDelimeter[] =   UNICODE_LITERAL_14(s,c,o,p,e,D,e,l,i,m,e,t,e,r);

    class SHIBSP_DLLLOCAL NameIDFromScopedAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        NameIDFromScopedAttributeDecoder(const DOMElement* e)
            : AttributeDecoder(e),
                m_delimeter('@'),
                m_format(XMLHelper::getAttrString(e, nullptr, format)),
                m_formatter(XMLHelper::getAttrString(e, nullptr, formatter)),
                m_defaultQualifiers(XMLHelper::getAttrBool(e, false, defaultQualifiers)) {
            if (e && e->hasAttributeNS(nullptr,scopeDelimeter)) {
                auto_ptr_char d(e->getAttributeNS(nullptr,scopeDelimeter));
                m_delimeter = *(d.get());
            }
        }
        ~NameIDFromScopedAttributeDecoder() {}

        shibsp::Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const;

    private:
        char m_delimeter;
        string m_format,m_formatter;
        bool m_defaultQualifiers;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL NameIDFromScopedAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new NameIDFromScopedAttributeDecoder(e);
    }
};

shibsp::Attribute* NameIDFromScopedAttributeDecoder::decode(
    const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{

    char* val;
    char* scope;
    const XMLCh* xmlscope;
    xmltooling::QName scopeqname(nullptr,Scope);
    auto_ptr<NameIDAttribute> nameid(
        new NameIDAttribute(ids, (!m_formatter.empty()) ? m_formatter.c_str() : DEFAULT_NAMEID_FORMATTER)
        );
    vector<NameIDAttribute::Value>& dest = nameid->getValues();
    vector<XMLObject*>::const_iterator v,stop;

    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.NameIDFromScoped");

    if (xmlObject && XMLString::equals(opensaml::saml1::Attribute::LOCAL_NAME,xmlObject->getElementQName().getLocalPart())) {
        const opensaml::saml2::Attribute* saml2attr = dynamic_cast<const opensaml::saml2::Attribute*>(xmlObject);
        if (saml2attr) {
            const vector<XMLObject*>& values = saml2attr->getAttributeValues();
            v = values.begin();
            stop = values.end();
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml2attr->getName());
                log.debug(
                    "decoding NameIDAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
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
                        "decoding NameIDAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                        ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                        );
                }
            }
            else {
                log.warn("XMLObject type not recognized by NameIDFromScopedAttributeDecoder, no values returned");
                return nullptr;
            }
        }

        for (; v!=stop; ++v) {
            if (!(*v)->hasChildren()) {
                val = toUTF8((*v)->getTextContent());
                if (val && *val) {
                    dest.push_back(NameIDAttribute::Value());
                    NameIDAttribute::Value& destval = dest.back();
                    const AttributeExtensibleXMLObject* aexo=dynamic_cast<const AttributeExtensibleXMLObject*>(*v);
                    xmlscope = aexo ? aexo->getAttribute(scopeqname) : nullptr;
                    if (!xmlscope || !*xmlscope) {
                        // Terminate the value at the scope delimiter.
                        if (scope = strchr(val, m_delimeter))
                            *scope++ = 0;
                    }
                    destval.m_Name = val;
                    destval.m_Format = m_format;
                    if (m_defaultQualifiers && assertingParty)
                        destval.m_NameQualifier = assertingParty;
                    if (m_defaultQualifiers && relyingParty)
                        destval.m_SPNameQualifier = relyingParty;
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

        return dest.empty() ? nullptr : _decode(nameid.release());
    }

    log.warn("XMLObject type not recognized by NameIDFromScopedAttributeDecoder, no values returned");
    return nullptr;
}
