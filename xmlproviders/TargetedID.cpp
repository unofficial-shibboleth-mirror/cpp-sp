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

/* TargetedID.cpp - eduPersonTargetedID custom attribute handling

   Scott Cantor
   4/30/05

   $History:$
*/

#include "internal.h"
#include <saml/saml2/core/Assertions.h>
#include <xercesc/util/Base64.hpp>

using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml2;
using namespace std;

namespace {
    class TargetedID : public SAMLAttribute
    {
    public:
        TargetedID(
            const XMLCh* name=NULL,
            const XMLCh* ns=NULL,
            const saml::QName* type=NULL,
            long lifetime=0,
            const Iterator<const XMLCh*>& values=EMPTY(const XMLCh*),
            const Iterator<const XMLCh*>& nameQualifiers=EMPTY(const XMLCh*),
            const Iterator<const XMLCh*>& spNameQualifiers=EMPTY(const XMLCh*)
            );
        TargetedID(DOMElement* e);
        TargetedID(istream& in);
        ~TargetedID();
    
        saml::SAMLObject* clone() const;
        
        saml::Iterator<const XMLCh*> getValues() const;
        saml::Iterator<std::string> getSingleByteValues() const;

        void setValues(const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*)) {
            throw SAMLException("unsupported operation");
        }
        void addValue(const XMLCh* value) {
            throw SAMLException("unsupported operation");
        }
        void removeValue(unsigned long index);
        
        static const XMLCh NameID[];
        static const XMLCh SPNameQualifier[];
        static const XMLCh FORMAT_PERSISTENT[];
    protected:
        void valueToDOM(unsigned int index, DOMElement* e) const;
        void valueFromDOM(DOMElement* e);
        void ownStrings();
    
    private:
        vector<const XMLCh*> m_nameQualifiers;
        vector<const XMLCh*> m_spNameQualifiers;
        mutable vector<const XMLCh*> m_encodedValues;
    };

    struct TargetedIDBuilder : public virtual IAttributeFactory
    {
        TargetedIDBuilder(const DOMElement* e) {}
        SAMLAttribute* build(DOMElement* e) const {
            return new TargetedID(e);
        }
    };
}

IPlugIn* TargetedIDFactory(const DOMElement* e)
{
    return new TargetedIDBuilder(e);
}

TargetedID::TargetedID(
    const XMLCh* name,
    const XMLCh* ns,
    const saml::QName* type,
    long lifetime,
    const Iterator<const XMLCh*>& values,
    const Iterator<const XMLCh*>& nameQualifiers,
    const Iterator<const XMLCh*>& spNameQualifiers
    ) : SAMLAttribute(name,ns,NULL,lifetime,values)
{
    RTTI(TargetedID);
    if (values.size()!=nameQualifiers.size() || values.size()!=spNameQualifiers.size())
        throw MalformedException("TargetedID() requires the number of qualifiers to equal the number of values");

    while (nameQualifiers.hasNext())
        m_nameQualifiers.push_back(saml::XML::assign(nameQualifiers.next()));
    while (spNameQualifiers.hasNext())
        m_spNameQualifiers.push_back(saml::XML::assign(spNameQualifiers.next()));
}

TargetedID::TargetedID(DOMElement* e) : SAMLAttribute(e,false)
{
    RTTI(TargetedID);
    fromDOM(e);
}

TargetedID::TargetedID(istream& in) : SAMLAttribute(in,false)
{
    RTTI(TargetedID);
    fromDOM(m_document->getDocumentElement());
}

TargetedID::~TargetedID()
{
    if (m_bOwnStrings) {
        for (vector<const XMLCh*>::iterator i=m_nameQualifiers.begin(); i!=m_nameQualifiers.end(); i++) {
            XMLCh* p = const_cast<XMLCh*>(*i);
            XMLString::release(&p);
        }
        for (vector<const XMLCh*>::iterator j=m_spNameQualifiers.begin(); j!=m_spNameQualifiers.end(); j++) {
            XMLCh* p = const_cast<XMLCh*>(*j);
            XMLString::release(&p);
        }
    }

    // We always own any encoded values we've built.
    for (vector<const XMLCh*>::iterator i=m_encodedValues.begin(); i!=m_encodedValues.end(); i++) {
        XMLCh* p = const_cast<XMLCh*>(*i);
        XMLString::release(&p);
    }
}

void TargetedID::ownStrings()
{
    if (!m_bOwnStrings) {
        for (vector<const XMLCh*>::iterator i=m_nameQualifiers.begin(); i!=m_nameQualifiers.end(); i++)
            (*i)=saml::XML::assign(*i);
        for (vector<const XMLCh*>::iterator j=m_spNameQualifiers.begin(); j!=m_spNameQualifiers.end(); j++)
            (*j)=saml::XML::assign(*j);
        SAMLAttribute::ownStrings();
    }
}

Iterator<const XMLCh*> TargetedID::getValues() const
{
    if (m_encodedValues.empty()) {
        getSingleByteValues();
        for (vector<string>::const_iterator i=m_sbValues.begin(); i!=m_sbValues.end(); i++)
            m_encodedValues.push_back(XMLString::transcode(i->c_str()));
    }
    return m_encodedValues;
}

Iterator<string> TargetedID::getSingleByteValues() const
{
    if (m_sbValues.empty()) {
        for (unsigned long i=0; i<m_values.size(); i++) {
            auto_ptr_char a(m_nameQualifiers[i]);
            auto_ptr_char b(m_spNameQualifiers[i]);
            auto_ptr_char c(m_values[i]);
            if (a.get() && *(a.get()) && b.get() && *(b.get()) && c.get() && *(c.get())) {
                string cat(a.get()); cat+="!"; cat+=b.get(); cat+="!"; cat+=c.get();
                m_sbValues.push_back(cat);
            }
            else
                m_sbValues.push_back("");
        }
    }
    return m_sbValues;
}

void TargetedID::removeValue(unsigned long index)
{
    if (m_bOwnStrings) {
        XMLCh* p=const_cast<XMLCh*>(m_nameQualifiers[index]);
        XMLString::release(&p);
        p=const_cast<XMLCh*>(m_spNameQualifiers[index]);
        XMLString::release(&p);
    }
    m_nameQualifiers.erase(m_nameQualifiers.begin()+index);
    m_spNameQualifiers.erase(m_spNameQualifiers.begin()+index);

    if (!m_encodedValues.empty()) {
        XMLCh* p=const_cast<XMLCh*>(m_encodedValues[index]);
        XMLString::release(&p);
        m_encodedValues.erase(m_encodedValues.begin()+index);
    }
    
    SAMLAttribute::removeValue(index);
}

void TargetedID::valueFromDOM(DOMElement* e)
{
    // Look for a SAML2 NameID.
    e=saml::XML::getFirstChildElement(e,samlconstants::SAML20_NS,NameID::LOCAL_NAME);
    if (e && !XMLString::compareString(NameIDType::PERSISTENT,e->getAttributeNS(NULL,NameIDType::FORMAT_ATTRIB_NAME))) {
        m_nameQualifiers.push_back(e->getAttributeNS(NULL,NameIDType::NAMEQUALIFIER_ATTRIB_NAME));
        m_spNameQualifiers.push_back(e->getAttributeNS(NULL,NameIDType::SPNAMEQUALIFIER_ATTRIB_NAME));
        if (e->hasChildNodes() && e->getFirstChild()->getNodeType()==DOMNode::TEXT_NODE)
            m_values.push_back(e->getFirstChild()->getNodeValue());
        else
            m_values.push_back(&chNull);
        return;
    }

    // Insert a null value placeholder.
    m_nameQualifiers.push_back(&chNull);    
    m_spNameQualifiers.push_back(&chNull);    
    m_values.push_back(&chNull);
}

void TargetedID::valueToDOM(unsigned int index, DOMElement* e) const
{
    const XMLCh* nq=m_nameQualifiers[index];
    const XMLCh* spnq=m_spNameQualifiers[index];
    const XMLCh* val=m_values[index];
    if (!saml::XML::isEmpty(nq) && !saml::XML::isEmpty(spnq) && !saml::XML::isEmpty(val)) {
        // Build a SAML2 NameID.
        DOMElement* nameid=e->getOwnerDocument()->createElementNS(samlconstants::SAML20_NS,NameID::LOCAL_NAME);
        nameid->setAttributeNS(NULL,NameIDType::FORMAT_ATTRIB_NAME,NameIDType::PERSISTENT);    
        nameid->setAttributeNS(NULL,NameIDType::NAMEQUALIFIER_ATTRIB_NAME,nq);
        nameid->setAttributeNS(NULL,NameIDType::SPNAMEQUALIFIER_ATTRIB_NAME,spnq);
        nameid->appendChild(e->getOwnerDocument()->createTextNode(val));
        e->appendChild(nameid);
    }
}

SAMLObject* TargetedID::clone() const
{
    return new TargetedID(m_name,m_namespace,m_type,m_lifetime,m_values,m_nameQualifiers,m_spNameQualifiers);
}
