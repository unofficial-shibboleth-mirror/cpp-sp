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
