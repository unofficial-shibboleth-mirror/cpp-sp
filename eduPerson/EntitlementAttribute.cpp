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


/* EntitlementAttribute.cpp - eduPersonEntitlement implementation

   Scott Cantor
   6/21/02

   $History:$
*/

#ifdef WIN32
# define EDUPERSON_EXPORTS __declspec(dllexport)
#endif

#include <eduPerson.h>
#include <shib.h>
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;
using namespace std;

static XMLCh anyURI[]={ chLatin_a, chLatin_n, chLatin_y, chLatin_U, chLatin_R, chLatin_I, chNull };

EntitlementAttribute::EntitlementAttribute(long lifetime, const XMLCh* values[])
    : SAMLAttribute(eduPerson::Constants::EDUPERSON_ENTITLEMENT,
		    shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
		    NULL,lifetime,values)
{
    m_type=new saml::QName(saml::XML::XSD_NS,anyURI);
}

EntitlementAttribute::EntitlementAttribute(IDOM_Element* e) : SAMLAttribute(e) {}

EntitlementAttribute::~EntitlementAttribute() {}

void EntitlementAttribute::addValues(IDOM_Element* e)
{
    // Our only special job is to check the type.
    IDOM_NodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeValue));
    for (int i=0; nlist && i<nlist->getLength(); i++)
    {
        auto_ptr<saml::QName> type(saml::QName::getQNameAttribute(static_cast<IDOM_Element*>(nlist->item(0)),saml::XML::XSI_NS,L(type)));
	if (!type.get() || XMLString::compareString(type->getNamespaceURI(),saml::XML::XSD_NS) ||
	    XMLString::compareString(type->getLocalName(),anyURI))
	    throw InvalidAssertionException(SAMLException::RESPONDER,"EntitlementAttribute() found an invalid attribute value type");
	if (!m_type)
	    m_type=type.release();
	addValue(static_cast<IDOM_Element*>(nlist->item(i)));
    }
}

SAMLObject* EntitlementAttribute::clone() const
{
    EntitlementAttribute* dest=new EntitlementAttribute(m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    return dest;
}
