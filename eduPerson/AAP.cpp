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


/* AAP.cpp - XML AAP implementation

   Scott Cantor
   12/21/02

   $History:$
*/

#include "internal.h"

#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

AAP::AAP(const char* uri)
{
    NDC ndc("AAP");
    Category& log=Category::getInstance("eduPerson.AAP");

    saml::XML::Parser p;
    DOMDocument* doc=NULL;
	try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,uri);
        Wrapper4InputSource dsrc(&src,false);
		doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed AAP (" << uri << ")" << CategoryStream::ENDLINE;

		DOMElement* e = doc->getDocumentElement();
        if (XMLString::compareString(XML::EDUPERSON_NS,e->getNamespaceURI()) ||
            XMLString::compareString(XML::Literals::AttributeAcceptancePolicy,e->getLocalName()))
        {
			log.error("Construction requires a valid AAP file: (edu:AttributeAcceptancePolicy as root element)");
			throw MalformedException("Construction requires a valid site file: (edu:AttributeAcceptancePolicy as root element)");
		}

		// Loop over the AttributeRule elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(XML::EDUPERSON_NS,XML::Literals::AttributeRule);
		for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            // Insert an empty rule, then get a reference to it.
            m_attrMap[static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,XML::Literals::Name)]=AttributeRule();
            AttributeRule& arule=m_attrMap[static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,XML::Literals::Name)];

            // Check for an AnySite rule.
			DOMNode* anysite = nlist->item(i)->getFirstChild();
			while (anysite && anysite->getNodeType()!=DOMNode::ELEMENT_NODE)
            {
				anysite = anysite->getNextSibling();
				continue;
			}

            if (anysite && !XMLString::compareString(XML::EDUPERSON_NS,static_cast<DOMElement*>(anysite)->getNamespaceURI()) &&
                !XMLString::compareString(XML::Literals::AnySite,static_cast<DOMElement*>(anysite)->getLocalName()))
            {
                // Process each Value element.
                DOMNodeList* vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(XML::EDUPERSON_NS,XML::Literals::Value);
                for (int j=0; vlist && j<vlist->getLength(); j++)
                {
                    DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                    DOMNode* valnode=ve->getFirstChild();
                    if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
                    {
                        if (!XMLString::compareString(XML::Literals::literal,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            arule.m_anySiteRule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::literal,valnode->getNodeValue())
                                );
                        else if (!XMLString::compareString(XML::Literals::regexp,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            arule.m_anySiteRule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::regexp,valnode->getNodeValue())
                                );
                        else if (!XMLString::compareString(XML::Literals::xpath,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            arule.m_anySiteRule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::xpath,valnode->getNodeValue())
                                );
                    }
                }
            }

            // Loop over the SiteRule elements.
            DOMNodeList* slist = e->getElementsByTagNameNS(XML::EDUPERSON_NS,XML::Literals::SiteRule);
		    for (int k=0; slist && k<slist->getLength(); k++)
            {
                arule.m_siteMap[static_cast<DOMElement*>(slist->item(k))->getAttributeNS(NULL,XML::Literals::Name)]=AttributeRule::SiteRule();
                AttributeRule::SiteRule& srule=arule.m_siteMap[static_cast<DOMElement*>(slist->item(k))->getAttributeNS(NULL,XML::Literals::Name)];

                // Process each Value element.
                DOMNodeList* vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(XML::EDUPERSON_NS,XML::Literals::Value);
                for (int j=0; vlist && j<vlist->getLength(); j++)
                {
                    DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                    DOMNode* valnode=ve->getFirstChild();
                    if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
                    {
                        if (!XMLString::compareString(XML::Literals::literal,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            srule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::literal,valnode->getNodeValue())
                                );
                        else if (!XMLString::compareString(XML::Literals::regexp,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            srule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::regexp,valnode->getNodeValue())
                                );
                        else if (!XMLString::compareString(XML::Literals::xpath,ve->getAttributeNS(NULL,XML::Literals::Type)))
                            srule.push_back(
                                pair<AttributeRule::value_type,xstring>(AttributeRule::xpath,valnode->getNodeValue())
                                );
                    }
                }
            }
		}
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing AAP: " << e.what() << CategoryStream::ENDLINE;
        if (doc)
            doc->release();
		throw;
	}
    catch (...)
    {
		log.error("Unexpected error while parsing AAP");
        if (doc)
            doc->release();
		throw;
    }

}

bool AAP::accept(const XMLCh* name, const XMLCh* originSite, DOMElement* e)
{
    NDC ndc("accept");
    log4cpp::Category& log=log4cpp::Category::getInstance("eduPerson.AAP");

    map<xstring,AttributeRule>::const_iterator arule=m_attrMap.find(name);
    if (arule==m_attrMap.end())
    {
        log.warn("attribute not found in AAP, any value is rejected");
        return false;
    }

    // Don't currently support non-simple content models...
    DOMNode* n=e->getFirstChild();
    if (!n || n->getNodeType()!=DOMNode::TEXT_NODE)
    {
        log.warn("implementation does not support complex attribute values");
        return false;
    }

    for (AttributeRule::SiteRule::const_iterator i=arule->second.m_anySiteRule.begin(); i!=arule->second.m_anySiteRule.end(); i++)
    {
        if (i->first==AttributeRule::literal && i->second==n->getNodeValue())
            return true;
        else if (i->first==AttributeRule::regexp)
        {
            try
            {
                RegularExpression re(i->second.c_str());
                if (re.matches(n->getNodeValue()))
                    return true;
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << log4cpp::CategoryStream::ENDLINE;
            }
        }
        else
            log.warn("implementation does not support XPath value rules");
    }

    map<xstring,AttributeRule::SiteRule>::const_iterator srule=arule->second.m_siteMap.find(originSite);
    if (srule==arule->second.m_siteMap.end())
    {
        log.warn("site not found in attribute ruleset, any value is rejected");
        return false;
    }

    for (AttributeRule::SiteRule::const_iterator j=srule->second.begin(); j!=srule->second.end(); j++)
    {
        if (j->first==AttributeRule::literal && j->second==n->getNodeValue())
            return true;
        else if (j->first==AttributeRule::regexp)
        {
            try
            {
                RegularExpression re(j->second.c_str());
                if (re.matches(n->getNodeValue()))
                    return true;
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << log4cpp::CategoryStream::ENDLINE;
            }
        }
        else
            log.warn("implementation does not support XPath value rules");
    }

    log.warn("attribute value could not be validated by AAP, rejecting it");
    return false;
}
