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

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

#include <xercesc/framework/URLInputSource.hpp>


XMLOriginSiteMapper::XMLOriginSiteMapper(const char* pathname) : m_filestamp(0)
{
    NDC ndc("XMLOriginSiteMapper");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLOriginSiteMapper");

#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(ShibConfig::getConfig().mapperFile.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(ShibConfig::getConfig().mapperFile.c_str(), &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;

    saml::XML::Parser p;
    DOMDocument* doc=NULL;
	try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,pathname);
        Wrapper4InputSource dsrc(&src,false);
		doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed site file (" << pathname << ")" << CategoryStream::ENDLINE;

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
            DOMElement* os_e=static_cast<DOMElement*>(nlist->item(i));
            auto_ptr<XMLCh> os_name(XMLString::replicate(os_e->getAttributeNS(NULL,XML::Literals::Name)));
            XMLString::trim(os_name.get());
			if (!os_name.get() || !*os_name)
				continue;

			OriginSite* os_obj = new OriginSite(os_e->getAttributeNS(NULL,XML::Literals::ErrorURL));
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
                    !XMLString::compareString(XML::Literals::Contact,os_child->getLocalName()))
                {
                    OriginSite::ContactInfo::ContactType type;
                    DOMElement* contact=static_cast<DOMElement*>(os_child);
                    if (!XMLString::compareString(contact->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::technical))
                        type=IContactInfo::technical;
                    else if (!XMLString::compareString(contact->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::administrative))
                        type=IContactInfo::administrative;
                    else if (!XMLString::compareString(contact->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::billing))
                        type=IContactInfo::billing;
                    else if (!XMLString::compareString(contact->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::other))
                        type=IContactInfo::other;
                    OriginSite::ContactInfo* cinfo=new OriginSite::ContactInfo(
                        type,
                        contact->getAttributeNS(NULL,XML::Literals::Name),
                        contact->getAttributeNS(NULL,XML::Literals::Email)
                        );
                    os_obj->m_contacts.push_back(cinfo);
                }
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
					      !XMLString::compareString(XML::Literals::HandleService,os_child->getLocalName()))
                {
                    auto_ptr<XMLCh> hs_name(XMLString::replicate(static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Name)));
                    XMLString::trim(hs_name.get());

					if (hs_name.get() && *hs_name)
                    {
						os_obj->m_handleServices.push_back(hs_name.get());

                        // Look for ds:KeyInfo.
						DOMNode* ki=os_child->getFirstChild();
                        while (ki && ki->getNodeType()!=DOMNode::ELEMENT_NODE)
							ki=ki->getNextSibling();
                        if (ki && !XMLString::compareString(saml::XML::XMLSIG_NS,ki->getNamespaceURI()) &&
                            !XMLString::compareString(saml::XML::Literals::KeyInfo,ki->getNamespaceURI()))
                        {
                            // Look for ds:X509Data.
                            DOMNode* xdata=ki->getFirstChild();
                            while (xdata && xdata->getNodeType()!=DOMNode::ELEMENT_NODE)
							    xdata=xdata->getNextSibling();
                            if (xdata && !XMLString::compareString(saml::XML::XMLSIG_NS,xdata->getNamespaceURI()) &&
                                !XMLString::compareString(saml::XML::Literals::X509Data,xdata->getNamespaceURI()))
                            {
                                // Look for ds:X509Certificate.
                                DOMNode* x509=xdata->getFirstChild();
                                while (x509 && x509->getNodeType()!=DOMNode::ELEMENT_NODE)
							        x509=x509->getNextSibling();
                                if (x509 && !XMLString::compareString(saml::XML::XMLSIG_NS,x509->getNamespaceURI()) &&
                                    !XMLString::compareString(saml::XML::Literals::X509Certificate,x509->getNamespaceURI()))
                                {
                                    auto_ptr<char> blob(XMLString::transcode(x509->getFirstChild()->getNodeValue()));
                                    XSECCryptoX509* cert=new OpenSSLCryptoX509();
                                    cert->loadX509Base64Bin(blob.get(),strlen(blob.get()));
                                    m_hsCerts[hs_name.get()]=cert;
                                }
                            }
						}
					}
				}
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
					     !XMLString::compareString(XML::Literals::Domain,os_child->getLocalName()))
                {
                    auto_ptr<XMLCh> dom(XMLString::replicate(os_child->getFirstChild()->getNodeValue()));
                    XMLString::trim(dom.get());
					if (dom.get() && *dom)
                    {
                        static const XMLCh one[]={ chDigit_1, chNull };
                        static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                        const XMLCh* regexp=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::regexp);
                        bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
						os_obj->m_domains.push_back(pair<xstring,bool>(dom.get(),flag));
                    }
				}
				os_child = os_child->getNextSibling();
			}
		}
    }
    catch (SAMLException& e)
    {
		log.errorStream() << "XML error while parsing site configuration: " << e.what() << CategoryStream::ENDLINE;
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
    for (map<xstring,XSECCryptoX509*>::iterator j=m_hsCerts.begin(); j!=m_hsCerts.end(); j++)
        delete j->second;
}

XMLOriginSiteMapper::OriginSite::ContactInfo::ContactInfo(ContactType type, const XMLCh* name, const XMLCh* email)
    : m_type(type), m_name(XMLString::transcode(name)), m_email(XMLString::transcode(email)) {}

XMLOriginSiteMapper::OriginSite::~OriginSite()
{
    for (vector<const IContactInfo*>::iterator i=m_contacts.begin(); i!=m_contacts.end(); i++)
        delete const_cast<IContactInfo*>(*i);
}

Iterator<const IContactInfo*> XMLOriginSiteMapper::getContacts(const XMLCh* originSite) const
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return Iterator<const IContactInfo*>();
    return Iterator<const IContactInfo*>(i->second->m_contacts);
}

const char* XMLOriginSiteMapper::getErrorURL(const XMLCh* originSite) const
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return NULL;
    return i->second->m_errorURL.get();
}

Iterator<xstring> XMLOriginSiteMapper::getHandleServiceNames(const XMLCh* originSite) const
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return Iterator<xstring>();
    return Iterator<xstring>(i->second->m_handleServices);
}

XSECCryptoX509* XMLOriginSiteMapper::getHandleServiceCert(const XMLCh* handleService) const
{
    map<xstring,XSECCryptoX509*>::const_iterator i=m_hsCerts.find(handleService);
    return (i!=m_hsCerts.end()) ? i->second : NULL;
}

Iterator<pair<xstring,bool> > XMLOriginSiteMapper::getSecurityDomains(const XMLCh* originSite) const
{
    map<xstring,OriginSite*>::const_iterator i=m_sites.find(originSite);
    if (i==m_sites.end())
        return Iterator<pair<xstring,bool> >();
    return Iterator<pair<xstring,bool> >(i->second->m_domains);
}

/*
void XMLOriginSiteMapper::validateSignature(const X509Certificate* verifyKey, DOMElement* e)
{
    if (verifyKey->getFormat()!=X509Certificate::PEM)
        throw OriginSiteMapperException("XMLOriginSiteMapper::validateSignature() requires a PEM certificate");

    ostringstream os;
    os << *e;
    string libxmlbuf(os.str());

    // Parse the document with libxml
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
    xmlDocPtr libxmlDoc=xmlParseMemory(libxmlbuf.c_str(),libxmlbuf.length());
    if (!libxmlDoc || !xmlDocGetRootElement(libxmlDoc))
        throw OriginSiteMapperException("XMLOriginSiteMapper::validateSignature() unable to parse with libxml");

    // Look for a ds:Signature below the root element.
    xmlNodePtr sigNode=xmlSecFindNode(xmlDocGetRootElement(libxmlDoc),(xmlChar*)"Signature",xmlSecDSigNs);
    if (!sigNode)
    {
        xmlFreeDoc(libxmlDoc);
        throw OriginSiteMapperException("XMLOriginSiteMapper::validateSignature() unable to find a ds:Signature");
    }

    // To get the bloody key to work, we have to do things to fool xmlsec into allowing it.
    // First we load the cert in as a trusted root.
    xmlSecX509StorePtr pStore=xmlSecX509StoreCreate();
    if (!pStore)
    {
        xmlFreeDoc(libxmlDoc);
        throw bad_alloc();
    }

    int ret=xmlSecX509StoreLoadPemCert(pStore,verifyKey->getPath(),1);
    if (ret<0)
    {
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw OriginSiteMapperException(
            string("XMLOriginSiteMapper::validateSignature() unable to load certificate from file: ") + verifyKey->getPath());
    }

    xmlSecX509DataPtr pX509=xmlSecX509DataCreate();
    if (!pX509)
    {
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw bad_alloc();
    }

    // Now load the cert again and "verify" the cert against itself, which will mark it verified.
    if (xmlSecX509DataReadPemCert(pX509,verifyKey->getPath())<0 || xmlSecX509StoreVerify(pStore,pX509)<0)
    {
        xmlSecX509DataDestroy(pX509);
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw OriginSiteMapperException("XMLOriginSiteMapper::validateSignature() unable to load certificate and verify against itself");
    }

    // Now we can get the key out.
    xmlSecKeyPtr key=xmlSecX509DataCreateKey(pX509);
    if (!key)
    {
//        xmlSecX509DataDestroy(pX509);
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw OriginSiteMapperException("XMLOriginSiteMapper::validateSignature() failed to extract key from certificate");
    }

    // Set up for validation.
    xmlSecKeysMngrPtr keymgr=xmlSecSimpleKeysMngrCreate();
    if (!keymgr)
    {
        xmlSecKeyDestroy(key);
//        xmlSecX509DataDestroy(pX509);
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw bad_alloc();
    }

    xmlSecDSigCtxPtr context=xmlSecDSigCtxCreate(keymgr);
    if (!context)
    {
        xmlSecSimpleKeysMngrDestroy(keymgr);
        xmlSecKeyDestroy(key);
//        xmlSecX509DataDestroy(pX509);
        xmlSecX509StoreDestroy(pStore);
        xmlFreeDoc(libxmlDoc);
        throw bad_alloc();
    }
    context->processManifests=0;
    context->storeSignatures=0;
    context->storeReferences=0;
    context->fakeSignatures=0;

    // Finally...check the bloody thing.
    xmlSecDSigResultPtr result=NULL;
    ret=xmlSecDSigValidate(context,NULL,key,sigNode,&result);
    xmlSecKeyDestroy(key);
//    xmlSecX509DataDestroy(pX509);
    xmlSecX509StoreDestroy(pStore);
    if (ret<0 || result->result!=xmlSecTransformStatusOk)
    {
        if (result)
            xmlSecDSigResultDestroy(result);
        xmlSecDSigCtxDestroy(context);
        xmlSecSimpleKeysMngrDestroy(keymgr);
        xmlFreeDoc(libxmlDoc);
        throw InvalidCryptoException("XMLOriginSiteMapper::validateSignature() failed to validate signature");
    }

    // Now check for any trust violations (wrong stuff signed, etc.)
    string msg;

    if (result->signMethod!=xmlSecSignRsaSha1)
        msg="XMLOriginSiteMapper::validateSignature() rejected signature algorithm";
    else if (result->firstSignRef!=result->lastSignRef)
        msg="XMLOriginSiteMapper::validateSignature() found more than one ds:Reference";
    else
    {
        xmlSecReferenceResultPtr ref=result->firstSignRef;
        if (ref->digestMethod!=xmlSecDigestSha1)
            msg="XMLOriginSiteMapper::validateSignature() rejected digest algorithm";
        else if (ref->uri && ref->uri[0])
            msg="XMLOriginSiteMapper::validateSignature() found a ds:Reference with a non-empty URL";
        else
        {
            xmlNodePtr transforms=ref->self->children;
            while (transforms && (transforms->type!=XML_ELEMENT_NODE ||
                   !xmlSecCheckNodeName(transforms,reinterpret_cast<const xmlChar*>("Transforms"),xmlSecDSigNs)))
                transforms=transforms->next;
            if (!transforms)
                msg="XMLOriginSiteMapper::validateSignature() unable to locate the ds:Transforms element";
            else
            {
                transforms=transforms->children;
                while (transforms && (transforms->type!=XML_ELEMENT_NODE ||
                       !xmlSecCheckNodeName(transforms,reinterpret_cast<const xmlChar*>("Transform"),xmlSecDSigNs)))
                    transforms=transforms->next;
                if (!transforms)
                    msg="XMLOriginSiteMapper::validateSignature() unable to locate a ds:Transform element";
                else
                {
                    xmlChar* alg=xmlGetProp(transforms,reinterpret_cast<const xmlChar*>("Algorithm"));
                    if (xmlStrcmp(alg,reinterpret_cast<const xmlChar*>("http://www.w3.org/2000/09/xmldsig#enveloped-signature")))
                        msg="XMLOriginSiteMapper::validateSignature() found a non-enveloped ds:Transform";
                    if (alg)
                        xmlFree(alg);
                    if (msg.empty())
                    {
                        transforms=transforms->next;
                        while (transforms && transforms->type==XML_TEXT_NODE)
                            transforms=transforms->next;
                        if (transforms)
                            msg="XMLOriginSiteMapper::validateSignature() found an extra ds:Transform element";
                    }
                }
            }
        }
    }
    
    xmlSecDSigResultDestroy(result);
    xmlSecDSigCtxDestroy(context);
    xmlSecSimpleKeysMngrDestroy(keymgr);
    xmlFreeDoc(libxmlDoc);

    if (!msg.empty())
        throw TrustException(msg);
}
*/
