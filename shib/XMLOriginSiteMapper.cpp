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

/* XMLOriginSiteMapper.h - a mapper implementation that uses an XML-based registry

   Scott Cantor
   9/27/02

   $History:$
*/

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

#include "shib.h"
#include <log4cpp/Category.hh>
using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

#include <xercesc/framework/URLInputSource.hpp>

XMLOriginSiteMapper::XMLOriginSiteMapper(const char* registryURI,
                                         const Iterator<X509Certificate*>& roots,
                                         Key* verifyKey)
{
    NDC ndc("XMLOriginSiteMapper");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLOriginSiteMapper");

    // Register extension schema.
    saml::XML::registerSchema(XML::SHIB_NS,XML::SHIB_SCHEMA_ID);

    saml::XML::Parser p;
    DOMDocument* doc=NULL;
	try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,registryURI);
        Wrapper4InputSource dsrc(&src,false);
		doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed site file (" << registryURI << ")"
            << CategoryStream::ENDLINE;

		DOMElement* e = doc->getDocumentElement();
        if (XMLString::compareString(XML::SHIB_NS,e->getNamespaceURI()) ||
            XMLString::compareString(XML::Literals::Sites,e->getLocalName()))
        {
			log.error("Construction requires a valid site file: (shib:Sites as root element)");
			throw OriginSiteMapperException("Construction requires a valid site file: (shib:Sites as root element)");
		}

		// Loop over the OriginSite elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(XML::SHIB_NS,XML::Literals::OriginSite);
		for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            auto_ptr<XMLCh> os_name(XMLString::replicate(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,XML::Literals::Name)));
            XMLString::trim(os_name.get());
			if (!os_name.get() || !*os_name)
				continue;

			OriginSite* os_obj = new OriginSite();
			m_sites[os_name.get()]=os_obj;

			DOMNode* os_child = nlist->item(i)->getFirstChild();
			while (os_child)
            {
                if (os_child->getNodeType()!=DOMNode::ELEMENT_NODE)
                {
					os_child = os_child->getNextSibling();
					continue;
				}

				// Process the various kinds of OriginSite children that we care about...
                if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
					!XMLString::compareString(XML::Literals::HandleService,os_child->getLocalName()))
                {
                    auto_ptr<XMLCh> hs_name(XMLString::replicate(static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Name)));
                    XMLString::trim(hs_name.get());

					if (hs_name.get() && *hs_name)
                    {
						os_obj->m_handleServices.push_back(hs_name.get());

						/* Ignore KeyInfo for now...
						DOM*Node ki = os_child->getFirstChild();
                        while (ki && ki->getNodeType()!=DOMNode::ELEMENT_NODE)
							ki = ki->getNextSibling();
                        if (ki && !XMLString::compareString(saml::XML::XMLSIG_NS,ki->getNamespaceURI()) &&
                            !XMLString::compareString(saml::XML::Literals::KeyInfo,ki->getNamespaceURI()))
                        {
						}
                        */
					}
				}
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
					     !XMLString::compareString(XML::Literals::Domain,os_child->getLocalName()))
                {
                    auto_ptr<XMLCh> dom(XMLString::replicate(os_child->getFirstChild()->getNodeValue()));
                    XMLString::trim(dom.get());
					if (dom.get() && *dom)
						os_obj->m_domains.push_back(dom.get());
				}
				os_child = os_child->getNextSibling();
			}
		}

		if (verifyKey)
        {
			log.info("Initialized with a key: attempting to verify document signature.");
            log.error("Signature verification not implemented yet, this may be a forged file!");
			// validateSignature(verifyKey, e);
		}
        else
			log.info("Initialized without key: skipping signature verification.");
    }
    catch (SAMLException& e)
    {
		log.errorStream() << "XML error while parsing site configuration: " << e.what()
            << CategoryStream::ENDLINE;
        if (doc)
            doc->release();
		throw;
	}
    catch (...)
    {
		log.error("Unexpected error while parsing site configuration");
        if (doc)
            doc->release();
		throw;
    }
}

XMLOriginSiteMapper::~XMLOriginSiteMapper()
{
    for (map<xstring,OriginSite*>::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
        delete i->second;
}

/* TBD...
private void validateSignature(Key verifyKey, Element e) throws OriginSiteMapperException {

	Node n = e.getLastChild();
	while (n != null && n.getNodeType() != Node.ELEMENT_NODE)
		n = n.getPreviousSibling();

	if (n != null
		&& org.opensaml.XML.XMLSIG_NS.equals(n.getNamespaceURI())
		&& "Signature".equals(n.getLocalName())) {
			log.info("Located signature in document... verifying.");
		try {
			XMLSignature sig = new XMLSignature((Element) n, null);
			if (sig.checkSignatureValue(verifyKey)) {
				// Now we verify that what is signed is what we expect.
				SignedInfo sinfo = sig.getSignedInfo();
				if (sinfo.getLength() == 1
					&& (sinfo
						.getCanonicalizationMethodURI()
						.equals(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS)
						|| sinfo.getCanonicalizationMethodURI().equals(
							Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS))) {
					Reference ref = sinfo.item(0);
					if (ref.getURI() == null || ref.getURI().equals("")) {
						Transforms trans = ref.getTransforms();
						if (trans.getLength() == 1
							&& trans.item(0).getURI().equals(Transforms.TRANSFORM_ENVELOPED_SIGNATURE))
							log.info("Signature verification successful.");
							return;
					}
					log.error(
						"Unable to verify signature on registry file: Unsupported dsig reference or transform data submitted with signature.");
					throw new OriginSiteMapperException("Unable to verify signature on registry file: Unsupported dsig reference or transform data submitted with signature.");
				} else {
					log.error(
						"Unable to verify signature on registry file: Unsupported canonicalization method.");
					throw new OriginSiteMapperException("Unable to verify signature on registry file: Unsupported canonicalization method.");
				}
			} else {
				log.error(
					"Unable to verify signature on registry file: signature cannot be verified with the specified key.");
				throw new OriginSiteMapperException("Unable to verify signature on registry file: signature cannot be verified with the specified key.");
			}
		} catch (Exception sigE) {
			log.error(
				"Unable to verify signature on registry file: An error occured while attempting to verify the signature:"
					+ sigE);
			throw new OriginSiteMapperException(
				"Unable to verify signature on registry file: An error occured while attempting to verify the signature:"
					+ sigE);
		}
	} else {
		log.error("Unable to verify signature on registry file: no signature found in document.");
		throw new OriginSiteMapperException("Unable to verify signature on registry file: no signature found in document.");
	}

}
*/

Iterator<xstring> XMLOriginSiteMapper::getHandleServiceNames(const XMLCh* originSite)
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return Iterator<xstring>();
    return Iterator<xstring>(i->second->m_handleServices);
}

Key* XMLOriginSiteMapper::getHandleServiceKey(const XMLCh* handleService)
{
    map<xstring,Key*>::const_iterator i=m_hsKeys.find(handleService);
    return (i!=m_hsKeys.end()) ? i->second : NULL;
}

Iterator<xstring> XMLOriginSiteMapper::getSecurityDomains(const XMLCh* originSite)
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return Iterator<xstring>();
    return Iterator<xstring>(i->second->m_domains);
}

Iterator<X509Certificate*> XMLOriginSiteMapper::getTrustedRoots()
{
	return Iterator<X509Certificate*>(m_roots);
}

