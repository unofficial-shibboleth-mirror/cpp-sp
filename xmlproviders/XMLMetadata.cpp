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

/* XMLMetadata.cpp - a metadata implementation that uses an XML-based registry

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

namespace {

    class XMLMetadataImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLMetadataImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLMetadataImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
        ~XMLMetadataImpl();
    
        class ContactPerson : public IContactPerson
        {
        public:
            ContactPerson(const DOMElement* e);
            ~ContactPerson() {}
        
            ContactType getType() const { return m_type; }
            const char* getCompany() const { return NULL; }
            const char* getName() const { return m_name.get(); }
            Iterator<string> getEmails() const { return m_emails; }
            Iterator<string> getTelephones() const { return EMPTY(string); }
            const DOMElement* getElement() const { return m_root; }
        
        private:
            const DOMElement* m_root;
            ContactType m_type;
            auto_ptr_char m_name;
            vector<string> m_emails;
        };

        class Provider;
        
        class KeyDescriptor : public IKeyDescriptor
        {
        public:
            KeyDescriptor() : m_klist(NULL) {}
            ~KeyDescriptor() {}
            
            KeyUse getUse() const { return signing; }
            const XMLCh* getEncryptionMethod() const { return NULL; }
            int getKeySize() const { return 0; }
            DSIGKeyInfoList* getKeyInfo() const { return &m_klist; }
            const DOMElement* getElement() const { return NULL; }
        
        private:
            mutable DSIGKeyInfoList m_klist;
            friend class Provider;
        };
        
        class Role : public virtual IProviderRole
        {
        public:
            Role(const Provider* provider, const DOMElement* e) : m_provider(provider), m_root(e) { }
            ~Role();
            
            // External contract
            const IProvider* getProvider() const {return m_provider;}
            Iterator<const XMLCh*> getProtocolSupportEnumeration() const {return m_protocolEnum;}
            bool hasSupport(const XMLCh* version) const;
            Iterator<const IKeyDescriptor*> getKeyDescriptors() const {return m_keys;}
            const IOrganization* getOrganization() const {return NULL;}
            Iterator<const IContactPerson*> getContacts() const {return m_provider->getContacts();}
            const char* getErrorURL() const {return m_provider->getErrorURL();}
            const DOMElement* getElement() const {return m_root;}
        
        protected:
            vector<const XMLCh*> m_protocolEnum;

        private:
            const Provider* m_provider;
            const DOMElement* m_root;
            vector<const IKeyDescriptor*> m_keys;
            friend class Provider;
        };
        
        class Endpoint : public IEndpoint
        {
        public:
            Endpoint(const XMLCh* binding, const XMLCh* loc) : m_binding(binding), m_location(loc) {}
            ~Endpoint() {}
            
            const XMLCh* getBinding() const { return m_binding; }
            const XMLCh* getVersion() const { return NULL; }
            const XMLCh* getLocation() const { return m_location; }
            const XMLCh* getResponseLocation() const { return NULL; }
            const DOMElement* getElement() const { return NULL; }
        
        private:
            const XMLCh* m_binding;
            const XMLCh* m_location;
        };
        
        class SSORole : public Role, public virtual ISSOProviderRole
        {
        public:
            SSORole(const Provider* provider, const DOMElement* e) : Role(provider,e) {}
            ~SSORole() {}
            Iterator<const IEndpoint*> getSingleLogoutServices() const {return EMPTY(const IEndpoint*);}
            Iterator<const IEndpoint*> getManageNameIdentifierServices() const {return EMPTY(const IEndpoint*);}
        };
        
        class IDPRole : public SSORole, public virtual IIDPProviderRole
        {
        public:
            IDPRole(const Provider* provider, const DOMElement* e) : SSORole(provider,e) {m_protocolEnum.push_back(::XML::SHIB_NS);}
            ~IDPRole() {}
            Iterator<const IEndpoint*> getSingleSignOnServices() const {return m_pepv;}
            Iterator<const IEndpoint*> getNameIdentifierMappingServices() const {return EMPTY(const IEndpoint*);}
        
        private:
            vector<Endpoint> m_epv;
            vector<const IEndpoint*> m_pepv;
            friend class Provider;
        };

        class AARole : public Role, public virtual IAttributeAuthorityRole
        {
        public:
            AARole(const Provider* provider, const DOMElement* e) : Role(provider,e) {m_protocolEnum.push_back(saml::XML::SAMLP_NS);}
            ~AARole() {}
            Iterator<const IEndpoint*> getAttributeServices() const {return m_pepv;}
            Iterator<const SAMLAttributeDesignator*> getAttributeDesignators() const {return EMPTY(const SAMLAttributeDesignator*);}
        
        private:
            vector<Endpoint> m_epv;
            vector<const IEndpoint*> m_pepv;
            friend class Provider;
        };
    
        class Provider : public IProvider
        {
        public:
            Provider(const DOMElement* e);
            ~Provider();
        
            // External contract
            const XMLCh* getId() const {return m_id;}
            Iterator<const XMLCh*> getGroups() const {return m_groups;}
            const IOrganization* getOrganization() const {return NULL;}
            Iterator<const IContactPerson*> getContacts() const {return m_contacts;}
            Iterator<const IProviderRole*> getRoles() const {return m_roles;}
            const DOMElement* getElement() const {return m_root;}
            Iterator<std::pair<const XMLCh*,bool> > getSecurityDomains() const {return m_domains;}

            // Used internally
            const char* getErrorURL() const {return m_errorURL.get();}
        private:
            friend class XMLMetadataImpl;
            const XMLCh* m_id;
            const DOMElement* m_root;
            auto_ptr_char m_errorURL;
            vector<const IContactPerson*> m_contacts;
            vector<const IProviderRole*> m_roles;
            IDPRole* m_IDP;
            AARole* m_AA;
            vector<pair<const XMLCh*,bool> > m_domains;
            vector<const XMLCh*> m_groups;
        };

    #ifdef HAVE_GOOD_STL
        typedef map<xstring,Provider*> sitemap_t;
    #else
        typedef map<string,Provider*> sitemap_t;
    #endif
        sitemap_t m_sites;
    };

    class XMLMetadata : public IMetadata, public ReloadableXMLFile
    {
    public:
        XMLMetadata(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLMetadata() {}

        const IProvider* lookup(const XMLCh* providerId) const;
        
    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };
}

IPlugIn* XMLMetadataFactory(const DOMElement* e)
{
    XMLMetadata* m=new XMLMetadata(e);
    try {
        m->getImplementation();
    }
    catch (...) {
        delete m;
        throw;
    }
    return m;    
}

ReloadableXMLFileImpl* XMLMetadata::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLMetadataImpl(e);
}

ReloadableXMLFileImpl* XMLMetadata::newImplementation(const char* pathname, bool first) const
{
    return new XMLMetadataImpl(pathname);
}

XMLMetadataImpl::Role::~Role()
{
    for (vector<const IKeyDescriptor*>::iterator i=m_keys.begin(); i!=m_keys.end(); i++)
        delete const_cast<IKeyDescriptor*>(*i);
}

bool XMLMetadataImpl::Role::hasSupport(const XMLCh* version) const
{
    Iterator<const XMLCh*> i(m_protocolEnum);
    while (i.hasNext()) {
        if (!XMLString::compareString(version,i.next()))
            return true;
    }
    return false;
}

XMLMetadataImpl::ContactPerson::ContactPerson(const DOMElement* e) : m_root(e), m_name(e->getAttributeNS(NULL,SHIB_L(Name)))
{
    ContactPerson::ContactType type;
    if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(Type)),SHIB_L(technical)))
        m_type=IContactPerson::technical;
    else if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(Type)),SHIB_L(support)))
        type=IContactPerson::support;
    else if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(Type)),SHIB_L(administrative)))
        type=IContactPerson::administrative;
    else if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(Type)),SHIB_L(billing)))
        type=IContactPerson::billing;
    else if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(Type)),SHIB_L(other)))
        type=IContactPerson::other;
    
    auto_ptr_char temp(e->getAttributeNS(NULL,SHIB_L(Email)));
    if (temp.get())
        m_emails.push_back(temp.get());
}

XMLMetadataImpl::Provider::Provider(const DOMElement* e) : m_root(e), m_IDP(NULL), m_AA(NULL),
    m_id(e->getAttributeNS(NULL,SHIB_L(Name))), m_errorURL(e->getAttributeNS(NULL,SHIB_L(ErrorURL)))
{
    // Record all the SiteGroups containing this site.
    DOMNode* group=e->getParentNode();
    while (group && group->getNodeType()==DOMNode::ELEMENT_NODE) {
        m_groups.push_back(static_cast<DOMElement*>(group)->getAttributeNS(NULL,SHIB_L(Name)));
        group=group->getParentNode();
    }

    DOMElement* child=saml::XML::getFirstChildElement(e);
    while (child) {
        // Process the various kinds of OriginSite children that we care about...
        if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(Contact))) {
            m_contacts.push_back(new ContactPerson(child));
        }
        else if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(HandleService))) {
            // Create the IDP role if needed.
            if (!m_IDP) {
                m_IDP=new IDPRole(this, child);
                m_IDP->m_keys.push_back(new KeyDescriptor());
            }
            m_roles.push_back(m_IDP);
            
            // Manufacture an endpoint for this role.
            m_IDP->m_epv.push_back(Endpoint(::XML::SHIB_NS,child->getAttributeNS(NULL,SHIB_L(Location))));
            m_IDP->m_pepv.push_back(&(m_IDP->m_epv.back()));

            // We're going to "mock up" a KeyInfo that contains the specified Name as KeyName.
            DOMElement* kne=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            kne->appendChild(e->getOwnerDocument()->createTextNode(child->getAttributeNS(NULL,SHIB_L(Name))));
            KeyDescriptor* kd=const_cast<KeyDescriptor*>(static_cast<const KeyDescriptor*>(m_IDP->m_keys.back()));
            if (!kd->m_klist.addXMLKeyInfo(kne))
                throw MetadataException("Provider::Provider() unable to mock up ds:KeyName");
        }
        else if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(AttributeAuthority))) {
            // Create the AA role if needed.
            if (!m_AA) {
                m_AA=new AARole(this, child);
                m_AA->m_keys.push_back(new KeyDescriptor());
            }
            m_roles.push_back(m_AA);
            
            // Manufacture an endpoint for this role.
            m_AA->m_epv.push_back(Endpoint(SAMLBinding::SAML_SOAP_HTTPS,child->getAttributeNS(NULL,SHIB_L(Location))));
            m_AA->m_pepv.push_back(&(m_AA->m_epv.back()));

            // We're going to "mock up" a KeyInfo that contains the specified Name as KeyName.
            DOMElement* kne=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            kne->appendChild(e->getOwnerDocument()->createTextNode(child->getAttributeNS(NULL,SHIB_L(Name))));
            KeyDescriptor* kd=const_cast<KeyDescriptor*>(static_cast<const KeyDescriptor*>(m_AA->m_keys.back()));
            if (!kd->m_klist.addXMLKeyInfo(kne))
                throw MetadataException("Provider::Provider() unable to mock up ds:KeyName");
        }
        else if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(Domain))) {
            const XMLCh* dom=child->getFirstChild()->getNodeValue();
            if (dom && *dom) {
                static const XMLCh one[]={ chDigit_1, chNull };
                static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                const XMLCh* regexp=child->getAttributeNS(NULL,SHIB_L(regexp));
                bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
                m_domains.push_back(pair<const XMLCh*,bool>(dom,flag));
            }
        }
        child = saml::XML::getNextSiblingElement(child);
    }
}

XMLMetadataImpl::Provider::~Provider()
{
    for (vector<const IContactPerson*>::iterator i=m_contacts.begin(); i!=m_contacts.end(); i++)
        delete const_cast<IContactPerson*>(*i);
    delete m_IDP;
    delete m_AA;
}

void XMLMetadataImpl::init()
{
    NDC ndc("XMLMetadataImpl");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLMetadataImpl");

    try
    {
        if (!saml::XML::isElementNamed(m_root,::XML::SHIB_NS,SHIB_L(SiteGroup))) {
            log.error("Construction requires a valid site file: (shib:SiteGroup as root element)");
            throw MetadataException("Construction requires a valid site file: (shib:SiteGroup as root element)");
        }

        // Loop over the OriginSite elements.
        DOMNodeList* nlist = m_root->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(OriginSite));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            const XMLCh* os_name=static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Name));
            if (!os_name || !*os_name)
                continue;

            Provider* p = new Provider(static_cast<DOMElement*>(nlist->item(i)));
#ifdef HAVE_GOOD_STL
            m_sites[os_name]=p;
#else
            auto_ptr_char os_name2(os_name);
            m_sites[os_name2.get()]=p;
#endif
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "Error while parsing site configuration: " << e.what() << CategoryStream::ENDLINE;
        for (sitemap_t::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
            delete i->second;
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing site configuration");
        for (sitemap_t::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
            delete i->second;
        throw;
    }
}

XMLMetadataImpl::~XMLMetadataImpl()
{
    for (sitemap_t::iterator i=m_sites.begin(); i!=m_sites.end(); i++)
        delete i->second;
}

const IProvider* XMLMetadata::lookup(const XMLCh* providerId) const
{
    XMLMetadataImpl* impl=dynamic_cast<XMLMetadataImpl*>(getImplementation());
#ifdef HAVE_GOOD_STL
    XMLMetadataImpl::sitemap_t::const_iterator i=impl->m_sites.find(providerId);
#else
    auto_ptr_char temp(providerId);
    XMLMetadataImpl::sitemap_t::const_iterator i=impl->m_sites.find(temp.get());
#endif
    return (i==impl->m_sites.end()) ? NULL : i->second;
}
