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

/* XMLMetadata.h - a metadata implementation that uses an XML-based registry

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

class shibboleth::XMLMetadataImpl
{
public:
    XMLMetadataImpl(const char* pathname);
    ~XMLMetadataImpl();
    
    class ContactInfo : public IContactInfo
    {
    public:
        ContactInfo(ContactType type, const XMLCh* name, const XMLCh* email)
            : m_type(type), m_name(XMLString::transcode(name)), m_email(XMLString::transcode(email)) {}
        
        ContactType getType() const { return m_type; }
        const char* getName() const { return m_name.get(); }            
        const char* getEmail() const { return m_email.get(); }
        
    private:
        ContactType m_type;
        std::auto_ptr<char> m_name, m_email;
    };
        
    class Authority : public IAuthority
    {
    public:
        Authority(const XMLCh* name, const XMLCh* url) : m_name(name), m_url(XMLString::transcode(url)) {}
        
        const XMLCh* getName() const { return m_name; }
        const char* getURL() const { return m_url.get(); }
        Iterator<XSECCryptoX509*> getCertificates() const { return Iterator<XSECCryptoX509*>(); }
        
    private:
        const XMLCh* m_name;
        auto_ptr<char> m_url;
    };
    
    struct OriginSite : public IOriginSite
    {
        OriginSite(const XMLCh* errorURL) : m_errorURL(XMLString::transcode(errorURL)) {}
        ~OriginSite();

        Iterator<const IContactInfo*> getContacts() const;
        const char* getErrorURL() const;
        void validate(XSECCryptoX509* cert) const;
        void validate(const XMLCh* cert) const;
        Iterator<const IAuthority*> getHandleServices() const { return m_handleServices; }
        Iterator<const IAuthority*> getAttributeAuthorities() const { return m_attributes; }
        Iterator<std::pair<const XMLCh*,bool> > getSecurityDomains() const { return m_domains; }

        auto_ptr<char> m_errorURL;
        vector<const IContactInfo*> m_contacts;
        vector<const IAuthority*> m_handleServices;
        vector<const IAuthority*> m_attributes;
        vector<pair<const XMLCh*,bool> > m_domains;
    };

    std::map<saml::xstring,OriginSite*> m_sites;
    DOMDocument* m_doc;
};

XMLMetadataImpl::OriginSite::~OriginSite()
{
    for (vector<const IContactInfo*>::iterator i=m_contacts.begin(); i!=m_contacts.end(); i++)
        delete const_cast<IContactInfo*>(*i);
    for (vector<const IAuthority*>::iterator j=m_handleServices.begin(); j!=m_handleServices.end(); j++)
        delete const_cast<IAuthority*>(*j);
    for (j=m_attributes.begin(); j!=m_attributes.end(); j++)
        delete const_cast<IAuthority*>(*j);
}

XMLMetadataImpl::XMLMetadataImpl(const char* pathname)
{
    NDC ndc("XMLMetadataImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLMetadataImpl");

    saml::XML::Parser p;
    try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,pathname);
        Wrapper4InputSource dsrc(&src,false);
        m_doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed site file (" << pathname << ")" << CategoryStream::ENDLINE;

        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(XML::SHIB_NS,e->getNamespaceURI()) ||
            XMLString::compareString(XML::Literals::Sites,e->getLocalName()))
        {
            log.error("Construction requires a valid site file: (shib:Sites as root element)");
            throw MetadataException("Construction requires a valid site file: (shib:Sites as root element)");
        }

        // Loop over the OriginSite elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(XML::SHIB_NS,XML::Literals::OriginSite);
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            const XMLCh* os_name=static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,XML::Literals::Name);
            if (!os_name || !*os_name)
                continue;

            OriginSite* os_obj =
                new OriginSite(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,XML::Literals::ErrorURL));
            m_sites[os_name]=os_obj;

            DOMNode* os_child=nlist->item(i)->getFirstChild();
            while (os_child)
            {
                if (os_child->getNodeType()!=DOMNode::ELEMENT_NODE)
                {
                    os_child=os_child->getNextSibling();
                    continue;
                }

                // Process the various kinds of OriginSite children that we care about...
                if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
                    !XMLString::compareString(XML::Literals::Contact,os_child->getLocalName()))
                {
                    ContactInfo::ContactType type;
                    DOMElement* con=static_cast<DOMElement*>(os_child);
                    if (!XMLString::compareString(con->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::technical))
                        type=IContactInfo::technical;
                    else if (!XMLString::compareString(con->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::administrative))
                        type=IContactInfo::administrative;
                    else if (!XMLString::compareString(con->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::billing))
                        type=IContactInfo::billing;
                    else if (!XMLString::compareString(con->getAttributeNS(NULL,XML::Literals::Type),XML::Literals::other))
                        type=IContactInfo::other;
                    ContactInfo* cinfo=new ContactInfo(
                        type,
                        con->getAttributeNS(NULL,XML::Literals::Name),
                        con->getAttributeNS(NULL,XML::Literals::Email)
                        );
                    os_obj->m_contacts.push_back(cinfo);
                }
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
                       !XMLString::compareString(XML::Literals::HandleService,os_child->getLocalName()))
                {
                    const XMLCh* hs_name=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Name);
                    const XMLCh* hs_loc=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Location);
                    if (hs_name && *hs_name && hs_loc && *hs_loc)
                        os_obj->m_handleServices.push_back(new Authority(hs_name,hs_loc));
                }
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
                       !XMLString::compareString(XML::Literals::AttributeAuthority,os_child->getLocalName()))
                {
                    const XMLCh* aa_name=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Name);
                    const XMLCh* aa_loc=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::Location);
                    if (aa_name && *aa_name && aa_loc && *aa_loc)
                        os_obj->m_attributes.push_back(new Authority(aa_name,aa_loc));
                }
                else if (!XMLString::compareString(XML::SHIB_NS,os_child->getNamespaceURI()) &&
                            !XMLString::compareString(XML::Literals::Domain,os_child->getLocalName()))
                {
                    const XMLCh* dom=os_child->getFirstChild()->getNodeValue();
                    if (dom && *dom)
                    {
                        static const XMLCh one[]={ chDigit_1, chNull };
                        static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                        const XMLCh* regexp=static_cast<DOMElement*>(os_child)->getAttributeNS(NULL,XML::Literals::regexp);
                        bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
                        os_obj->m_domains.push_back(pair<const XMLCh*,bool>(dom,flag));
                    }
                }
                os_child = os_child->getNextSibling();
            }
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing site configuration: " << e.what() << CategoryStream::ENDLINE;
        for (map<xstring,OriginSite*>::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing site configuration");
        for (map<xstring,OriginSite*>::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
}

XMLMetadataImpl::~XMLMetadataImpl()
{
    for (map<xstring,OriginSite*>::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
        delete i->second;
    if (m_doc)
        m_doc->release();
}

XMLMetadata::XMLMetadata(const char* pathname) : m_filestamp(0), m_source(pathname), m_impl(NULL)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(pathname, &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(pathname, &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;
    m_impl=new XMLMetadataImpl(pathname);
    m_lock=RWLock::create();
}

XMLMetadata::~XMLMetadata()
{
    delete m_lock;
    delete m_impl;
}

void XMLMetadata::lock()
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
                    XMLMetadataImpl* new_mapper=new XMLMetadataImpl(m_source.c_str());
                    delete m_impl;
                    m_impl=new_mapper;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLMetadata").error("failed to reload metadata, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLMetadata").error("caught an unknown exception, sticking with what we have");
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

void XMLMetadata::unlock()
{
    m_lock->unlock();
}

const ISite* XMLMetadata::lookup(const XMLCh* site) const
{
    map<xstring,XMLMetadataImpl::OriginSite*>::const_iterator i=m_impl->m_sites.find(site);
    return (i==m_impl->m_sites.end()) ? NULL : i->second;
}

                        /*
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
                        */
