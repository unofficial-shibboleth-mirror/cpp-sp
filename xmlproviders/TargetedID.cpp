/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* TargetedID.cpp - eduPersonTargetedID custom attribute handling

   Scott Cantor
   4/30/05

   $History:$
*/

#include "internal.h"
#include <xercesc/util/Base64.hpp>

using namespace shibboleth;
using namespace saml;
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
        void removeValue(unsigned int index);
        
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
                string cat(a.get()); cat+="!!"; cat+=b.get(); cat+="!!"; cat+=c.get();
                unsigned int outlen;
                XMLByte* encoded = Base64::encode(reinterpret_cast<XMLByte*>((char*)cat.c_str()), cat.length(), &outlen);
                XMLByte *pos, *pos2;
                for (pos=encoded, pos2=encoded; *pos2; pos2++)
                    if (isgraph(*pos2))
                        *pos++=*pos2;
                *pos=0;
                m_sbValues.push_back(reinterpret_cast<char*>(encoded));
                XMLString::release(&encoded);
            }
            else
                m_sbValues.push_back("");
        }
    }
    return m_sbValues;
}

void TargetedID::removeValue(unsigned int index)
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
    e=saml::XML::getFirstChildElement(e,::XML::SAML2ASSERT_NS,NameID);
    if (e && !XMLString::compareString(FORMAT_PERSISTENT,e->getAttributeNS(NULL,L(Format)))) {
        m_nameQualifiers.push_back(e->getAttributeNS(NULL,L(NameQualifier)));
        m_spNameQualifiers.push_back(e->getAttributeNS(NULL,SPNameQualifier));
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
        DOMElement* nameid=e->getOwnerDocument()->createElementNS(::XML::SAML2ASSERT_NS,NameID);
        nameid->setAttributeNS(NULL,L(Format),FORMAT_PERSISTENT);    
        nameid->setAttributeNS(NULL,L(NameQualifier),nq);
        nameid->setAttributeNS(NULL,SPNameQualifier,spnq);
        nameid->appendChild(e->getOwnerDocument()->createTextNode(val));
        e->appendChild(nameid);
    }
}

SAMLObject* TargetedID::clone() const
{
    return new TargetedID(m_name,m_namespace,m_type,m_lifetime,m_values,m_nameQualifiers,m_spNameQualifiers);
}

const XMLCh TargetedID::NameID[] =
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_I, chLatin_D, chNull };

const XMLCh TargetedID::SPNameQualifier[] =
{ chLatin_S, chLatin_P, chLatin_N, chLatin_a, chLatin_m, chLatin_e,
  chLatin_Q, chLatin_u, chLatin_a, chLatin_l, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_r, chNull
};

const XMLCh TargetedID::FORMAT_PERSISTENT[] =
{
    chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
    chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
    chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
    chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_i, chLatin_d, chDash,
    chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chColon,
    chLatin_p, chLatin_e, chLatin_r, chLatin_s, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_t, chNull
};
