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
 * DOMAttributeDecoder.cpp
 *
 * Decodes a DOM into an ExtensibleAttribute.
 */

#include "internal.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/ExtensibleAttribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL DOMAttributeDecoder : virtual public AttributeDecoder
    {
    public:
        DOMAttributeDecoder(const DOMElement* e);
        ~DOMAttributeDecoder() {}

        // deprecated method
        Attribute* decode(
            const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const {
            return decode(nullptr, ids, xmlObject, assertingParty, relyingParty);
        }

        Attribute* decode(
            const GenericRequest*, const vector<string>&, const XMLObject*, const char* assertingParty=nullptr, const char* relyingParty=nullptr
            ) const;

    private:
        DDF convert(DOMElement* e, bool nameit=true) const;
        string m_formatter;
        map<pair<xstring,xstring>,string> m_tagMap;
    };

    AttributeDecoder* SHIBSP_DLLLOCAL DOMAttributeDecoderFactory(const DOMElement* const & e)
    {
        return new DOMAttributeDecoder(e);
    }

    static const XMLCh Mapping[] =  UNICODE_LITERAL_7(M,a,p,p,i,n,g);
    static const XMLCh _from[] =    UNICODE_LITERAL_4(f,r,o,m);
    static const XMLCh _to[] =      UNICODE_LITERAL_2(t,o);
    static const XMLCh formatter[] =UNICODE_LITERAL_9(f,o,r,m,a,t,t,e,r);
};

DOMAttributeDecoder::DOMAttributeDecoder(const DOMElement* e)
    : AttributeDecoder(e), m_formatter(XMLHelper::getAttrString(e, nullptr, formatter))
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.DOM");

    e = XMLHelper::getFirstChildElement(e, Mapping);
    while (e) {
        if (e->hasAttributeNS(nullptr, _from) && e->hasAttributeNS(nullptr, _to)) {
            auto_ptr<xmltooling::QName> f(XMLHelper::getNodeValueAsQName(e->getAttributeNodeNS(nullptr, _from)));
            auto_ptr_char t(e->getAttributeNS(nullptr, _to));
            if (f.get() && t.get() && *t.get()) {
                if (log.isDebugEnabled())
                    log.debug("mapping (%s) to (%s)", f->toString().c_str(), t.get());
                m_tagMap.insert(
                    pair< const pair<xstring,xstring>,string>(
                        pair<xstring,xstring>(f->getLocalPart(), f->hasNamespaceURI() ? f->getNamespaceURI() : &chNull),
                        t.get()
                        )
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, Mapping);
    }
}

Attribute* DOMAttributeDecoder::decode(
    const GenericRequest* request, const vector<string>& ids, const XMLObject* xmlObject, const char* assertingParty, const char* relyingParty
    ) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT".AttributeDecoder.DOM");

    if (!xmlObject)
        return nullptr;

    auto_ptr<ExtensibleAttribute> attr(new ExtensibleAttribute(ids, m_formatter.c_str()));
    DDF dest = attr->getValues();
    vector<XMLObject*> genericObjectWrapper;    // used to support stand-alone object decoding
    pair<vector<XMLObject*>::const_iterator,vector<XMLObject*>::const_iterator> valrange;

    const saml2::Attribute* saml2attr = dynamic_cast<const saml2::Attribute*>(xmlObject);
    if (saml2attr) {
        const vector<XMLObject*>& values = saml2attr->getAttributeValues();
        valrange = valueRange(request, values);
        if (log.isDebugEnabled()) {
            auto_ptr_char n(saml2attr->getName());
            log.debug(
                "decoding ExtensibleAttribute (%s) from SAML 2 Attribute (%s) with %lu value(s)",
                ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                );
        }
    }
    else {
        const saml1::Attribute* saml1attr = dynamic_cast<const saml1::Attribute*>(xmlObject);
        if (saml1attr) {
            const vector<XMLObject*>& values = saml1attr->getAttributeValues();
            valrange = valueRange(request, values);
            if (log.isDebugEnabled()) {
                auto_ptr_char n(saml1attr->getAttributeName());
                log.debug(
                    "decoding ExtensibleAttribute (%s) from SAML 1 Attribute (%s) with %lu value(s)",
                    ids.front().c_str(), n.get() ? n.get() : "unnamed", values.size()
                    );
            }
        }
        else {
            log.debug("decoding arbitrary XMLObject type (%s)", xmlObject->getElementQName().toString().c_str());
            genericObjectWrapper.push_back(const_cast<XMLObject*>(xmlObject));
            valrange.first = genericObjectWrapper.begin();
            valrange.second = genericObjectWrapper.end();
        }
    }

    for (; valrange.first != valrange.second; ++valrange.first) {
        DOMElement* e = (*valrange.first)->getDOM();
        if (e) {
            DDF converted = convert(e, false);
            if (!converted.isnull())
                dest.add(converted);
        }
        else
            log.warn("skipping XMLObject without a backing DOM");
    }

    return dest.integer() ? _decode(attr.release()) : nullptr;
}

DDF DOMAttributeDecoder::convert(DOMElement* e, bool nameit) const
{
    const XMLCh* nsURI;
    const XMLCh* local;
    map<pair<xstring,xstring>,string>::const_iterator mapping;
    DDF obj = DDF(nullptr).structure();

    if (nameit) {
        // Name this structure.
        nsURI = e->getNamespaceURI();
        local = e->getLocalName();
        mapping = m_tagMap.find(pair<xstring,xstring>(local,nsURI));
        if (mapping == m_tagMap.end()) {
            auto_ptr_char temp(local);
            obj.name(temp.get());
        }
        else {
            obj.name(mapping->second.c_str());
        }
    }

    // Process non-xmlns attributes.
    DOMNamedNodeMap* attrs = e->getAttributes();
    for (XMLSize_t a = attrs->getLength(); a > 0; --a) {
        DOMNode* attr = attrs->item(a-1);
        nsURI = attr->getNamespaceURI();
        if (XMLString::equals(nsURI, xmlconstants::XMLNS_NS))
            continue;
        local = attr->getLocalName();
        mapping = m_tagMap.find(pair<xstring,xstring>(local, nsURI ? nsURI : &chNull));
        if (mapping == m_tagMap.end()) {
            auto_ptr_char temp(local);
            obj.addmember(temp.get()).string(toUTF8(attr->getNodeValue(), true), false);
        }
        else {
            obj.addmember(mapping->second.c_str()).string(toUTF8(attr->getNodeValue(), true), false);
        }
    }

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    if (!child && e->hasChildNodes() && e->getFirstChild()->getNodeType() == DOMNode::TEXT_NODE) {
        // Attach a _text member if a text node is present.
        obj.addmember("_string").string(toUTF8(e->getFirstChild()->getTextContent(), true), false);
    }
    else {
        while (child) {
            // Convert the child element.
            DDF converted = convert(child);
            if (!converted.isnull()) {
                // Now identify it and attach it.
                if (obj[converted.name()].isnull()) {
                    // We're a new child, so just attach as a structure member.
                    obj.add(converted);
                }
                else if (obj[converted.name()].islist()) {
                    // We're already a repeating child, so add it to the list.
                    obj[converted.name()].add(converted);
                }
                else if (obj[converted.name()].isstruct()) {
                    // This is the complex case where we see a child for the second
                    // time and have to convert a structure member into a named list.
                    DDF newlist = DDF(converted.name()).list();
                    newlist.add(obj[converted.name()].remove());
                    newlist.add(converted);
                    obj.add(newlist);
                }
            }
            child = XMLHelper::getNextSiblingElement(child);
        }
    }

    // If we're empty, just delete.
    if (obj.integer() == 0)
        obj.destroy();
    return obj;
}
