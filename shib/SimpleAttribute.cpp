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


/* SimpleAttribute.cpp - simple attribute implementation with AAP-support

   Scott Cantor
   12/19/02

   $History:$
*/

#include "internal.h"

using namespace shibboleth;

SimpleAttribute::SimpleAttribute(const XMLCh* name, const XMLCh* ns, long lifetime, const saml::Iterator<const XMLCh*>& values)
    : SAMLAttribute(name,ns,&Constants::SHIB_ATTRIBUTE_VALUE_TYPE,lifetime,values) {}

SimpleAttribute::SimpleAttribute(DOMElement* e) : SAMLAttribute(e)
{
    // Default scope comes from subject.
    DOMNodeList* nlist=
        static_cast<DOMElement*>(e->getParentNode())->getElementsByTagNameNS(saml::XML::SAML_NS,L(NameIdentifier));
    if (!nlist || nlist->getLength() != 1)
        throw saml::MalformedException(saml::SAMLException::RESPONDER,"SimpleAttribute() can't find saml:NameIdentifier in enclosing statement");
    m_originSite=static_cast<DOMElement*>(nlist->item(0))->getAttributeNS(NULL,L(NameQualifier));
}

SimpleAttribute::~SimpleAttribute() {}

saml::SAMLObject* SimpleAttribute::clone() const
{
    SimpleAttribute* dest=new SimpleAttribute(m_name,m_namespace,m_lifetime);
    dest->m_originSite=m_originSite;
    dest->m_values.assign(m_values.begin(),m_values.end());
    return dest;
}

bool SimpleAttribute::accept(DOMElement* e) const
{
    ShibInternalConfig& conf=dynamic_cast<ShibInternalConfig&>(ShibConfig::getConfig());
    return conf.m_AAP ? conf.m_AAP->accept(m_name,m_originSite.c_str(),e) : true;
}
