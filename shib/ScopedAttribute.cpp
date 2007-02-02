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

/* ScopedAttribute.cpp - eduPerson scoped attribute base class

   Scott Cantor
   6/4/02

   $History:$
*/

#include "internal.h"
#include <xercesc/util/regx/RegularExpression.hpp>
#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

const XMLCh ScopedAttribute::Scope[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chNull };

ScopedAttribute::ScopedAttribute(
    const XMLCh* name,
    const XMLCh* ns,
    const saml::QName* type,
    long lifetime,
    const saml::Iterator<const XMLCh*>& scopes,
    const saml::Iterator<const XMLCh*>& values
    ) : SAMLAttribute(name,ns,type,lifetime,values)
{
    RTTI(ScopedAttribute);
    if (scopes.size()!=values.size())
        throw MalformedException("ScopedAttribute() requires the number of scopes to equal the number of values");

    while (scopes.hasNext())
        m_scopes.push_back(saml::XML::assign(scopes.next()));
}

ScopedAttribute::ScopedAttribute(DOMElement* e) : SAMLAttribute(e,false)
{
    RTTI(ScopedAttribute);
    fromDOM(e);
}

ScopedAttribute::ScopedAttribute(istream& in) : SAMLAttribute(in,false)
{
    RTTI(ScopedAttribute);
    fromDOM(m_document->getDocumentElement());
}

ScopedAttribute::~ScopedAttribute()
{
    if (m_bOwnStrings) {
        for (vector<const XMLCh*>::iterator i=m_scopes.begin(); i!=m_scopes.end(); i++) {
            XMLCh* p = const_cast<XMLCh*>(*i);
            XMLString::release(&p);
        }
    }

    // We always own any scoped values we've built.
    for (vector<const XMLCh*>::iterator i=m_scopedValues.begin(); i!=m_scopedValues.end(); i++) {
        XMLCh* p = const_cast<XMLCh*>(*i);
        XMLString::release(&p);
    }
}

void ScopedAttribute::ownStrings()
{
    if (!m_bOwnStrings) {
        for (vector<const XMLCh*>::iterator i=m_scopes.begin(); i!=m_scopes.end(); i++)
            (*i)=saml::XML::assign(*i);
        SAMLAttribute::ownStrings();
    }
}

Iterator<const XMLCh*> ScopedAttribute::getValues() const
{
    static XMLCh at[]={chAt, chNull};

    if (m_scopedValues.empty()) {
        vector<const XMLCh*>::const_iterator j=m_scopes.begin();
        for (vector<const XMLCh*>::const_iterator i=m_values.begin(); i!=m_values.end(); i++, j++) {
            XMLCh* temp=new XMLCh[XMLString::stringLen(*i) + XMLString::stringLen(*j) + 2];
            temp[0]=chNull;
            XMLString::catString(temp,*i);
            XMLString::catString(temp,at);
            XMLString::catString(temp,*j);
            m_scopedValues.push_back(temp);
        }
    }
    return m_scopedValues;
}

Iterator<string> ScopedAttribute::getSingleByteValues() const
{
    getValues();
    if (m_sbValues.empty()) {
        for (vector<const XMLCh*>::const_iterator i=m_scopedValues.begin(); i!=m_scopedValues.end(); i++) {
            auto_ptr<char> temp(toUTF8(*i));
            if (temp.get())
                m_sbValues.push_back(temp.get());
        }
    }
    return m_sbValues;
}

void ScopedAttribute::setValues(const Iterator<const XMLCh*>& values)
{
    throw SAMLException("unsupported operation");
}

void ScopedAttribute::addValue(const XMLCh* value)
{
    throw SAMLException("unsupported operation");
}

void ScopedAttribute::removeValue(unsigned long index)
{
    if (m_bOwnStrings) {
        XMLCh* p=const_cast<XMLCh*>(m_scopes[index]);
        XMLString::release(&p);
    }
    m_scopes.erase(m_scopes.begin()+index);
    
    if (!m_scopedValues.empty()) {
        XMLCh* p=const_cast<XMLCh*>(m_scopedValues[index]);
        XMLString::release(&p);
        m_scopedValues.erase(m_scopedValues.begin()+index);
    }

    SAMLAttribute::removeValue(index);
}

void ScopedAttribute::valueFromDOM(DOMElement* e)
{
    SAMLAttribute::valueFromDOM(e);
    m_scopes.push_back(e->getAttributeNS(NULL,Scope));
}

void ScopedAttribute::valueToDOM(unsigned int index, DOMElement* e) const
{
    SAMLAttribute::valueToDOM(index,e);
    const XMLCh* scope=m_scopes[index];
    if (!saml::XML::isEmpty(scope))
        e->setAttributeNS(NULL,Scope,m_scopes[index]);
}

SAMLObject* ScopedAttribute::clone() const
{
    return new ScopedAttribute(m_name,m_namespace,m_type,m_lifetime,m_scopes,m_values);
}
