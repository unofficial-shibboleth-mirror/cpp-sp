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
#include <xercesc/framework/URLInputSource.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

class shibboleth::XMLOriginSiteMapperImpl
{
public:
    XMLOriginSiteMapperImpl(const char* pathname, bool loadTrust);
    ~XMLOriginSiteMapperImpl();
    
    struct OriginSite
    {
        OriginSite(const XMLCh* errorURL) : m_errorURL(XMLString::transcode(errorURL)) {}
        ~OriginSite();

        class ContactInfo : public IContactInfo
        {
        public:
            ContactInfo(ContactType type, const XMLCh* name, const XMLCh* email);
            
            ContactType getType() const { return m_type; }
            const char* getName() const { return m_name.get(); }            
            const char* getEmail() const { return m_email.get(); }
            
        private:
            ContactType m_type;
            std::auto_ptr<char> m_name, m_email;
        };
        
        std::vector<const IContactInfo*> m_contacts;
        std::auto_ptr<char> m_errorURL;
        std::vector<saml::xstring> m_handleServices;
        std::vector<std::pair<saml::xstring,bool> > m_domains;
    };

    std::map<saml::xstring,OriginSite*> m_sites;
    std::map<saml::xstring,XSECCryptoX509*> m_hsCerts;
};

XMLOriginSiteMapperImpl::XMLOriginSiteMapperImpl(const char* pathname, bool loadTrust)
{
    NDC ndc("XMLOriginSiteMapperImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLOriginSiteMapperImpl");

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
    if (doc)
        doc->release();
}

XMLOriginSiteMapperImpl::~XMLOriginSiteMapperImpl()
{
    for (map<xstring,OriginSite*>::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
        delete i->second;
    for (map<xstring,XSECCryptoX509*>::iterator j=m_hsCerts.begin(); j!=m_hsCerts.end(); j++)
        delete j->second;
}

XMLOriginSiteMapper::XMLOriginSiteMapper(const char* pathname, bool loadTrust)
    : m_filestamp(0), m_source(pathname), m_trust(loadTrust), m_impl(NULL)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(pathname, &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(pathname, &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;
    m_impl=new XMLOriginSiteMapperImpl(pathname,loadTrust);
    m_lock=RWLock::create();
}

XMLOriginSiteMapperImpl::OriginSite::ContactInfo::ContactInfo(ContactType type, const XMLCh* name, const XMLCh* email)
    : m_type(type), m_name(XMLString::transcode(name)), m_email(XMLString::transcode(email)) {}

XMLOriginSiteMapperImpl::OriginSite::~OriginSite()
{
    for (vector<const IContactInfo*>::iterator i=m_contacts.begin(); i!=m_contacts.end(); i++)
        delete const_cast<IContactInfo*>(*i);
}

XMLOriginSiteMapper::~XMLOriginSiteMapper()
{
    delete m_lock;
    delete m_impl;
}

void XMLOriginSiteMapper::lock()
{
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
        {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
            {
                try
                {
                    XMLOriginSiteMapperImpl* new_mapper=new XMLOriginSiteMapperImpl(m_source.c_str(),m_trust);
                    delete m_impl;
                    m_impl=new_mapper;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLOriginSiteMapper").error("failed to reload metadata, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLOriginSiteMapper").error("caught an unknown exception, sticking with what we have");
                }
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
}

void XMLOriginSiteMapper::unlock()
{
    m_lock->unlock();
}

bool XMLOriginSiteMapper::has(const XMLCh* originSite) const
{
    return m_impl->m_sites.find(originSite)!=m_impl->m_sites.end();
}

Iterator<const IContactInfo*> XMLOriginSiteMapper::getContacts(const XMLCh* originSite) const
{
    map<xstring,XMLOriginSiteMapperImpl::OriginSite*>::const_iterator i=m_impl->m_sites.find(originSite);
    if (i==m_impl->m_sites.end())
        return Iterator<const IContactInfo*>();
    return Iterator<const IContactInfo*>(i->second->m_contacts);
}

const char* XMLOriginSiteMapper::getErrorURL(const XMLCh* originSite) const
{
    map<xstring,XMLOriginSiteMapperImpl::OriginSite*>::const_iterator i=m_impl->m_sites.find(originSite);
    if (i==m_impl->m_sites.end())
        return NULL;
    return i->second->m_errorURL.get();
}

Iterator<xstring> XMLOriginSiteMapper::getHandleServiceNames(const XMLCh* originSite) const
{
    map<xstring,XMLOriginSiteMapperImpl::OriginSite*>::const_iterator i=m_impl->m_sites.find(originSite);
    if (i==m_impl->m_sites.end())
        return Iterator<xstring>();
    return Iterator<xstring>(i->second->m_handleServices);
}

XSECCryptoX509* XMLOriginSiteMapper::getHandleServiceCert(const XMLCh* handleService) const
{
    map<xstring,XSECCryptoX509*>::const_iterator i=m_impl->m_hsCerts.find(handleService);
    return (i!=m_impl->m_hsCerts.end()) ? i->second : NULL;
}

Iterator<pair<xstring,bool> > XMLOriginSiteMapper::getSecurityDomains(const XMLCh* originSite) const
{
    map<xstring,XMLOriginSiteMapperImpl::OriginSite*>::const_iterator i=m_impl->m_sites.find(originSite);
    if (i==m_impl->m_sites.end())
        return Iterator<pair<xstring,bool> >();
    return Iterator<pair<xstring,bool> >(i->second->m_domains);
}
