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
#include <xercesc/util/XMLChar.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {

    class XMLMetadataImpl : public ReloadableXMLFileImpl
    {
    public:
        class ContactPerson : public IContactPerson
        {
        public:
            ContactPerson(const DOMElement* e);
            ~ContactPerson() {}
        
            ContactType getType() const { return m_type; }
            const char* getCompany() const { return m_company.get(); }
            const char* getGivenName() const { return m_givenName.get(); }
            const char* getSurName() const { return m_surName.get(); }
            Iterator<string> getEmailAddresses() const { return m_emails; }
            Iterator<string> getTelephoneNumbers() const { return m_phones; }
            const DOMElement* getElement() const { return m_root; }
        
        private:
            const DOMElement* m_root;
            ContactType m_type;
            auto_ptr<char> m_givenName,m_surName,m_company;
            vector<string> m_emails,m_phones;
        };
        
        class Organization : public IOrganization
        {
        public:
            Organization(const DOMElement* e);
            ~Organization() {}
            
            const char* getName(const char* lang="en") const { return forLang(m_names,lang); }
            const char* getDisplayName(const char* lang="en") const { return forLang(m_displays,lang); }
            const char* getURL(const char* lang="en") const { return forLang(m_urls,lang); }
            const DOMElement* getElement() const { return m_root; }
        
        private:
            const char* forLang(const map<string,string>& m, const char* lang) const {
                map<string,string>::const_iterator i=m.find(lang);
                return (i==m.end()) ? NULL : i->second.c_str();
            }
            const DOMElement* m_root;
            map<string,string> m_names,m_displays,m_urls;
        };

        class EntityDescriptor;
        
        class EncryptionMethod : public XENCEncryptionMethod
        {
        public:
            EncryptionMethod(const DOMElement* e);
            ~EncryptionMethod() {}
            
            const XMLCh * getAlgorithm(void) const { return m_alg; }
            const XMLCh * getDigestMethod(void) const { return m_digest; }
            const XMLCh * getOAEPparams(void) const { return m_params; }
            int getKeySize(void) const { return m_size; }
            DOMElement* getElement(void) const { return const_cast<DOMElement*>(m_root); }
            void setDigestMethod(const XMLCh * method) {throw exception();}
            void setOAEPparams(const XMLCh * params) {throw exception();}
            void setKeySize(int size) {throw exception();}
        
        private:
            const DOMElement* m_root;
            const XMLCh* m_alg;
            const XMLCh* m_digest;
            const XMLCh* m_params;
            int m_size;
        };
        
        class KeyDescriptor : public IKeyDescriptor
        {
        public:
            KeyDescriptor(const DOMElement* e);
            ~KeyDescriptor();
            
            KeyUse getUse() const { return m_use; }
            DSIGKeyInfoList* getKeyInfo() const { return m_klist; }
            saml::Iterator<const XENCEncryptionMethod*> getEncryptionMethods() const { return m_methods; }
            const DOMElement* getElement() const { return m_root; }
        
        private:
            const DOMElement* m_root;
            KeyUse m_use;
            mutable DSIGKeyInfoList* m_klist;
            vector<const XENCEncryptionMethod*> m_methods;
        };
        
        class KeyAuthority : public IKeyAuthority
        {
        public:
            KeyAuthority(const DOMElement* e);
            ~KeyAuthority();
            
            int getVerifyDepth() const { return m_depth; }
            Iterator<DSIGKeyInfoList*> getKeyInfos() const { return m_klists; }
        
        private:
            int m_depth;
            vector<DSIGKeyInfoList*> m_klists;
        };
        
        class Role : public virtual IRoleDescriptor
        {
        public:
            Role(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e);
            ~Role();
            
            // External contract
            const IEntityDescriptor* getEntityDescriptor() const {return m_provider;}
            Iterator<const XMLCh*> getProtocolSupportEnumeration() const {return m_protocolEnum;}
            bool hasSupport(const XMLCh* protocol) const;
            const char* getErrorURL() const {return (m_errorURL ? m_errorURL : m_provider->getErrorURL());}
            bool isValid() const {return time(NULL) < m_validUntil;}
            Iterator<const IKeyDescriptor*> getKeyDescriptors() const {return m_keys;}
            const IOrganization* getOrganization() const {return m_org ? m_org : m_provider->getOrganization();}
            Iterator<const IContactPerson*> getContactPersons() const
                {return (m_contacts.empty() ? m_provider->getContactPersons() : m_contacts);}
            const DOMElement* getElement() const {return m_root;}
        
        protected:
            vector<const XMLCh*> m_protocolEnum;
            vector<const IKeyDescriptor*> m_keys;

        private:
            const EntityDescriptor* m_provider;
            const DOMElement* m_root;
            XMLCh* m_protocolEnumCopy;
            char* m_errorURL;
            Organization* m_org;
            vector<const IContactPerson*> m_contacts;
            time_t m_validUntil;
        };
        
        class Endpoint : public virtual IEndpoint
        {
        public:
            Endpoint(const DOMElement* e) : m_root(e),
                m_binding(e->getAttributeNS(NULL,L(Binding))),
                m_location(e->getAttributeNS(NULL,SHIB_L(Location))),
                m_resploc(e->getAttributeNS(NULL,SHIB_L(ResponseLocation))) {}
            Endpoint(const XMLCh* binding, const XMLCh* loc)
                : m_root(NULL), m_binding(binding), m_location(loc), m_resploc(NULL) {}
            ~Endpoint() {}
            
            const XMLCh* getBinding() const { return m_binding; }
            const XMLCh* getLocation() const { return m_location; }
            const XMLCh* getResponseLocation() const { return m_resploc; }
            const DOMElement* getElement() const { return m_root; }
        
        private:
            const DOMElement* m_root;
            const XMLCh* m_binding;
            const XMLCh* m_location;
            const XMLCh* m_resploc;
        };
        
        class IndexedEndpoint : public Endpoint, public virtual IIndexedEndpoint
        {
        public:
            IndexedEndpoint(const DOMElement* e) : Endpoint(e), m_index(XMLString::parseInt(e->getAttributeNS(NULL,SHIB_L(index)))) {}
            unsigned short getIndex() const {return m_index;}
            
        private:
            unsigned short m_index;
        };
        
        class EndpointManager : public IEndpointManager
        {
        public:
            EndpointManager() : m_soft(NULL), m_hard(NULL) {}
            ~EndpointManager() {
                for (vector<const IEndpoint*>::iterator i=m_endpoints.begin(); i!=m_endpoints.end(); i++)
                    delete const_cast<IEndpoint*>(*i);
            }
            saml::Iterator<const IEndpoint*> getEndpoints() const {return m_endpoints;}
            const IEndpoint* getDefaultEndpoint() const {
                if (m_hard) return m_hard;
                if (m_soft) return m_soft;
                if (!m_endpoints.empty()) return *(m_endpoints.begin());
                return NULL;
            }
            const IEndpoint* getEndpointByIndex(unsigned short index) const {
                for (vector<const IEndpoint*>::const_iterator i=m_endpoints.begin(); i!=m_endpoints.end(); i++) {
                    const IIndexedEndpoint* temp=dynamic_cast<const IIndexedEndpoint*>(*i);
                    if (temp && index==temp->getIndex())
                        return temp;
                }
                return NULL;
            }
            const IEndpoint* getEndpointByBinding(const XMLCh* binding) const {
                for (vector<const IEndpoint*>::const_iterator i=m_endpoints.begin(); i!=m_endpoints.end(); i++)
                    if (!XMLString::compareString(binding,(*i)->getBinding()))
                        return *i;
                return NULL;
            }
            void add(IEndpoint* e) {
                m_endpoints.push_back(e);
                if (!m_hard && e->getElement()) {
                    const XMLCh* v=e->getElement()->getAttributeNS(NULL,SHIB_L(isDefault));
                    if (v && (*v==chDigit_1 || *v==chLatin_t))  // explicit default
                        m_hard=e;
                    else if ((!v || !*v) && !m_soft)            // implicit default
                        m_soft=e;
                }
                else if (!m_hard && !m_soft) {
                    // No default yet, so this one qualifies as an implicit.
                    m_soft=e;
                }
            }
            
        private:
            vector<const IEndpoint*> m_endpoints;
            const IEndpoint* m_soft;    // Soft default (not explicit)
            const IEndpoint* m_hard;    // Hard default (explicit)
        };
        
        class SSORole : public Role, public virtual ISSODescriptor
        {
        public:
            SSORole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e);
            ~SSORole() {}
            const IEndpointManager* getArtifactResolutionServiceManager() const {return &m_artifact;}
            const IEndpointManager* getSingleLogoutServiceManager() const {return &m_logout;}
            const IEndpointManager* getManageNameIDServiceManager() const {return &m_nameid;}
            saml::Iterator<const XMLCh*> getNameIDFormats() const {return m_formats;}
            
        private:
            EndpointManager m_artifact,m_logout,m_nameid;
            vector<const XMLCh*> m_formats;
        };

        class ScopedRole : public virtual IScopedRoleDescriptor
        {
        public:
            ScopedRole(const DOMElement* e);
            saml::Iterator<std::pair<const XMLCh*,bool> > getScopes() const {return m_scopes;}

        private:
            vector<pair<const XMLCh*,bool> > m_scopes;
        };
        
        class IDPRole : public SSORole, public ScopedRole, public virtual IIDPSSODescriptor
        {
        public:
            IDPRole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e);
            ~IDPRole();
            bool getWantAuthnRequestsSigned() const {return m_wantAuthnRequestsSigned;}
            const IEndpointManager* getSingleSignOnServiceManager() const {return &m_sso;}
            const IEndpointManager* getNameIDMappingServiceManager() const {return &m_mapping;}
            const IEndpointManager* getAssertionIDRequestServiceManager() const {return &m_idreq;}
            saml::Iterator<const XMLCh*> getAttributeProfiles() const {return m_attrprofs;}
            saml::Iterator<const saml::SAMLAttribute*> getAttributes() const {return m_attrs;}
        
        private:
            EndpointManager m_sso,m_mapping,m_idreq;
            vector<const XMLCh*> m_attrprofs;
            vector<const SAMLAttribute*> m_attrs;
            bool m_wantAuthnRequestsSigned;
            const XMLCh* m_sourceId;
            friend class EntityDescriptor;
        };

        class AARole : public Role, public ScopedRole, public virtual IAttributeAuthorityDescriptor
        {
        public:
            AARole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e);
            ~AARole();
            const IEndpointManager* getAttributeServiceManager() const {return &m_query;}
            const IEndpointManager* getAssertionIDRequestServiceManager() const {return &m_idreq;}
            saml::Iterator<const XMLCh*> getNameIDFormats() const {return m_formats;}
            saml::Iterator<const XMLCh*> getAttributeProfiles() const {return m_attrprofs;}
            saml::Iterator<const saml::SAMLAttribute*> getAttributes() const {return m_attrs;}
        
        private:
            EndpointManager m_query,m_idreq;
            vector<const XMLCh*> m_formats,m_attrprofs;
            vector<const SAMLAttribute*> m_attrs;
        };
    
        class EntityDescriptor : public IExtendedEntityDescriptor
        {
        public:
            EntityDescriptor(
                const DOMElement* e,
                XMLMetadataImpl* wrapper,
                time_t validUntil=LONG_MAX,
                const IEntitiesDescriptor* parent=NULL
                );
            ~EntityDescriptor();
        
            // External contract
            const XMLCh* getId() const {return m_id;}
            bool isValid() const {return time(NULL) < m_validUntil;}
            Iterator<const IRoleDescriptor*> getRoleDescriptors() const {return m_roles;}
            const IIDPSSODescriptor* getIDPSSODescriptor(const XMLCh* protocol) const;
            const ISPSSODescriptor* getSPSSODescriptor(const XMLCh* protocol) const {return NULL;}
            const IAuthnAuthorityDescriptor* getAuthnAuthorityDescriptor(const XMLCh* protocol) const {return NULL;}
            const IAttributeAuthorityDescriptor* getAttributeAuthorityDescriptor(const XMLCh* protocol) const;
            const IPDPDescriptor* getPDPDescriptor(const XMLCh* protocol) const {return NULL;}
            const IAffiliationDescriptor* getAffiliationDescriptor() const {return NULL;}
            const IOrganization* getOrganization() const {return m_org;}
            Iterator<const IContactPerson*> getContactPersons() const {return m_contacts;}
            Iterator<pair<const XMLCh*,const XMLCh*> > getAdditionalMetadataLocations() const {return m_locs;}
            const IEntitiesDescriptor* getEntitiesDescriptor() const {return m_parent;}
            Iterator<const IKeyAuthority*> getKeyAuthorities() const {return m_keyauths;}
            const DOMElement* getElement() const {return m_root;}

            // Used internally
            const char* getErrorURL() const {return m_errorURL.get();}
            time_t getValidUntil() const {return m_validUntil;}
        private:
            const DOMElement* m_root;
            const IEntitiesDescriptor* m_parent;
            const XMLCh* m_id;
            auto_ptr<char> m_errorURL;
            IOrganization* m_org;
            vector<const IContactPerson*> m_contacts;
            vector<const IRoleDescriptor*> m_roles;
            vector<pair<const XMLCh*,const XMLCh*> > m_locs;
            vector<const IKeyAuthority*> m_keyauths;
            time_t m_validUntil;
        };

        class EntitiesDescriptor : public IExtendedEntitiesDescriptor
        {
        public:
            EntitiesDescriptor(
                const DOMElement* e,
                XMLMetadataImpl* wrapper,
                time_t validUntil=LONG_MAX,
                const IEntitiesDescriptor* parent=NULL
                );
            ~EntitiesDescriptor();
            
            const XMLCh* getName() const {return m_name;}
            bool isValid() const {return time(NULL) < m_validUntil;}
            const IEntitiesDescriptor* getEntitiesDescriptor() const {return m_parent;}
            Iterator<const IEntitiesDescriptor*> getEntitiesDescriptors() const {return m_groups;}
            Iterator<const IEntityDescriptor*> getEntityDescriptors() const {return m_providers;}
            Iterator<const IKeyAuthority*> getKeyAuthorities() const {return m_keyauths;}
            const DOMElement* getElement() const {return m_root;}
        
        private:
            const DOMElement* m_root;
            const IEntitiesDescriptor* m_parent;
            const XMLCh* m_name;
            vector<const IEntitiesDescriptor*> m_groups;
            vector<const IEntityDescriptor*> m_providers;
            vector<const IKeyAuthority*> m_keyauths;
            time_t m_validUntil;
        };

        XMLMetadataImpl(const char* pathname) : ReloadableXMLFileImpl(pathname), m_rootProvider(NULL), m_rootGroup(NULL) { init(); }
        XMLMetadataImpl(const DOMElement* e) : ReloadableXMLFileImpl(e), m_rootProvider(NULL), m_rootGroup(NULL) { init(); }
        void init();
        ~XMLMetadataImpl();

        typedef multimap<string,const EntityDescriptor*> sitemap_t;
        sitemap_t m_sites;
        sitemap_t m_sources;
        EntityDescriptor* m_rootProvider;
        EntitiesDescriptor* m_rootGroup;
    };

    class XMLMetadata : public IMetadata, public ReloadableXMLFile
    {
    public:
        XMLMetadata(const DOMElement* e) : ReloadableXMLFile(e), m_exclusions(true) {
            static const XMLCh uri[] = { chLatin_u, chLatin_r, chLatin_i, chNull };
            if (e->hasAttributeNS(NULL,uri)) {
                // First check for explicit enablement of entities.
                DOMNodeList* nlist=e->getElementsByTagName(SHIB_L(Include));
                for (int i=0; nlist && i<nlist->getLength(); i++) {
                    if (nlist->item(i)->hasChildNodes()) {
                        auto_ptr_char temp(nlist->item(i)->getFirstChild()->getNodeValue());
                        if (temp.get()) {
                            m_set.insert(temp.get());
                            m_exclusions=false;
                        }
                    }
                }
                // If there was no explicit enablement, build a set of exclusions.
                if (m_exclusions) {
                    nlist=e->getElementsByTagName(SHIB_L(Exclude));
                    for (int j=0; nlist && j<nlist->getLength(); j++) {
                        if (nlist->item(j)->hasChildNodes()) {
                            auto_ptr_char temp(nlist->item(j)->getFirstChild()->getNodeValue());
                            if (temp.get())
                                m_set.insert(temp.get());
                        }
                    }
                }
            }
        }
        ~XMLMetadata() {}

        const IEntityDescriptor* lookup(const char* providerId, bool strict=true) const;
        const IEntityDescriptor* lookup(const XMLCh* providerId, bool strict=true) const;
        const IEntityDescriptor* lookup(const saml::SAMLArtifact* artifact) const;
        
    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
        
    private:
        bool m_exclusions;
        set<string> m_set;
    };
}

IPlugIn* XMLMetadataFactory(const DOMElement* e)
{
    auto_ptr<XMLMetadata> m(new XMLMetadata(e));
    m->getImplementation();
    return m.release();
}

ReloadableXMLFileImpl* XMLMetadata::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLMetadataImpl(e);
}

ReloadableXMLFileImpl* XMLMetadata::newImplementation(const char* pathname, bool first) const
{
    return new XMLMetadataImpl(pathname);
}

XMLMetadataImpl::ContactPerson::ContactPerson(const DOMElement* e) : m_root(e)
{
    const XMLCh* type=NULL;
    
    // Old metadata or new?
    if (saml::XML::isElementNamed(e,::XML::SHIB_NS,SHIB_L(Contact))) {
        type=e->getAttributeNS(NULL,SHIB_L(Type));
        m_surName=auto_ptr<char>(toUTF8(e->getAttributeNS(NULL,SHIB_L(Name))));
        if (e->hasAttributeNS(NULL,SHIB_L(Email))) {
            auto_ptr<char> temp(toUTF8(e->getAttributeNS(NULL,SHIB_L(Email))));
            if (temp.get())
                m_emails.push_back(temp.get());
        }
    }
    else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(ContactPerson))) {
        type=e->getAttributeNS(NULL,SHIB_L(contactType));
        DOMNode* n=NULL;
        e=saml::XML::getFirstChildElement(e);
        while (e) {
            if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(Company))) {
                n=e->getFirstChild();
                if (n) m_company=auto_ptr<char>(toUTF8(n->getNodeValue()));
            }
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(GivenName))) {
                n=e->getFirstChild();
                if (n) m_givenName=auto_ptr<char>(toUTF8(n->getNodeValue()));
            }
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(SurName))) {
                n=e->getFirstChild();
                if (n) m_surName=auto_ptr<char>(toUTF8(n->getNodeValue()));
            }
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(EmailAddress))) {
                n=e->getFirstChild();
                if (n) {
                    auto_ptr<char> temp(toUTF8(n->getNodeValue()));
                    if (temp.get()) m_emails.push_back(temp.get());
                }
            }
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(TelephoneNumber))) {
                n=e->getFirstChild();
                if (n) {
                    auto_ptr<char> temp(toUTF8(n->getNodeValue()));
                    if (temp.get()) m_phones.push_back(temp.get());
                }
            }
            e=saml::XML::getNextSiblingElement(e);
        }
    }
    
    if (!XMLString::compareString(type,SHIB_L(technical)))
        m_type=IContactPerson::technical;
    else if (!XMLString::compareString(type,SHIB_L(support)))
        m_type=IContactPerson::support;
    else if (!XMLString::compareString(type,SHIB_L(administrative)))
        m_type=IContactPerson::administrative;
    else if (!XMLString::compareString(type,SHIB_L(billing)))
        m_type=IContactPerson::billing;
    else if (!XMLString::compareString(type,SHIB_L(other)))
        m_type=IContactPerson::other;
}

XMLMetadataImpl::Organization::Organization(const DOMElement* e) : m_root(e)
{
    DOMNode* n=NULL;
    e=saml::XML::getFirstChildElement(e);
    while (e) {
        if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(OrganizationName))) {
            n=e->getFirstChild();
            if (n) {
                auto_ptr<char> name(toUTF8(n->getNodeValue()));
                auto_ptr_char lang(e->getAttributeNS(saml::XML::XML_NS,L(lang)));
                m_names[lang.get()]=name.get();
            }
        }
        else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(OrganizationDisplayName))) {
            n=e->getFirstChild();
            if (n) {
                auto_ptr<char> display(toUTF8(n->getNodeValue()));
                auto_ptr_char lang(e->getAttributeNS(saml::XML::XML_NS,L(lang)));
                m_displays[lang.get()]=display.get();
            }
        }
        else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(OrganizationURL))) {
            n=e->getFirstChild();
            if (n) {
                auto_ptr<char> url(toUTF8(n->getNodeValue()));
                auto_ptr_char lang(e->getAttributeNS(saml::XML::XML_NS,L(lang)));
                m_urls[lang.get()]=url.get();
            }
        }
        e=saml::XML::getNextSiblingElement(e);
    }
}

XMLMetadataImpl::EncryptionMethod::EncryptionMethod(const DOMElement* e) : m_root(e)
{
    m_alg=e->getAttributeNS(NULL,SHIB_L(Algorithm));
    e=saml::XML::getFirstChildElement(e);
    while (e) {
        if (saml::XML::isElementNamed(e,::XML::XMLENC_NS,SHIB_L(KeySize))) {
            DOMNode* n=e->getFirstChild();
            if (n) m_size=XMLString::parseInt(n->getNodeValue());
        }
        else if (saml::XML::isElementNamed(e,saml::XML::XMLSIG_NS,SHIB_L(DigestMethod))) {
            DOMNode* n=e->getFirstChild();
            if (n) m_digest=n->getNodeValue();
        }
        else if (saml::XML::isElementNamed(e,::XML::XMLENC_NS,SHIB_L(OAEParams))) {
            DOMNode* n=e->getFirstChild();
            if (n) m_params=n->getNodeValue();
        }
        e=saml::XML::getNextSiblingElement(e);
    }
}

XMLMetadataImpl::KeyDescriptor::KeyDescriptor(const DOMElement* e) : m_root(e), m_use(unspecified), m_klist(NULL)
{
#ifdef _DEBUG
    saml::NDC ndc("KeyDescriptor");
#endif
    if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(use)),SHIB_L(encryption)))
        m_use=encryption;
    else if (!XMLString::compareString(e->getAttributeNS(NULL,SHIB_L(use)),SHIB_L(signing)))
        m_use=signing;
    
    m_klist = new DSIGKeyInfoList(NULL);

    // Process ds:KeyInfo
    e=saml::XML::getFirstChildElement(e);

    // We let XMLSec hack through anything it can. This should evolve over time, or we can
    // plug in our own KeyResolver later...
    DOMElement* child=saml::XML::getFirstChildElement(e);
    while (child) {
        try {
            if (!m_klist->addXMLKeyInfo(child)) {
                Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").warn(
                    "skipped unsupported ds:KeyInfo child element");
            }
        }
        catch (XSECCryptoException& xe) {
            Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").error(
                "unable to process ds:KeyInfo child element: %s",xe.getMsg());
        }
        child=saml::XML::getNextSiblingElement(child);
    }
    
    // Check for encryption methods.
    e=saml::XML::getNextSiblingElement(e);
    while (e && saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(EncryptionMethod)))
        m_methods.push_back(new EncryptionMethod(e));
}

XMLMetadataImpl::KeyDescriptor::~KeyDescriptor()
{
    for (vector<const XENCEncryptionMethod*>::iterator i=m_methods.begin(); i!=m_methods.end(); i++)
        delete const_cast<XENCEncryptionMethod*>(*i);
    delete m_klist;
}

XMLMetadataImpl::KeyAuthority::KeyAuthority(const DOMElement* e) : m_depth(1)
{
#ifdef _DEBUG
    saml::NDC ndc("KeyAuthority");
#endif
    if (e->hasAttributeNS(NULL,SHIB_L(VerifyDepth)))
        m_depth=XMLString::parseInt(e->getAttributeNS(NULL,SHIB_L(VerifyDepth)));
    
    // Process ds:KeyInfo children
    e=saml::XML::getFirstChildElement(e,saml::XML::XMLSIG_NS,L(KeyInfo));
    while (e) {
        auto_ptr<DSIGKeyInfoList> klist(new DSIGKeyInfoList(NULL));

        // We let XMLSec hack through anything it can. This should evolve over time, or we can
        // plug in our own KeyResolver later...
        DOMElement* child=saml::XML::getFirstChildElement(e);
        while (child) {
            try {
                if (!klist->addXMLKeyInfo(child)) {
                    Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").warn(
                        "skipped unresolvable ds:KeyInfo child element");
                }
            }
            catch (XSECCryptoException& xe) {
                Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").error(
                    "unable to process ds:KeyInfo child element: %s",xe.getMsg());
            }
            child=saml::XML::getNextSiblingElement(child);
        }
        
        if (klist->getSize()>0)
            m_klists.push_back(klist.release());
        else
            Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").warn(
                "skipping ds:KeyInfo with no resolvable child elements");
        e=saml::XML::getNextSiblingElement(e,saml::XML::XMLSIG_NS,L(KeyInfo));
    }
}

XMLMetadataImpl::KeyAuthority::~KeyAuthority()
{
    for (vector<DSIGKeyInfoList*>::iterator i=m_klists.begin(); i!=m_klists.end(); i++)
        delete (*i);
}

XMLMetadataImpl::Role::Role(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e)
    : m_provider(provider), m_errorURL(NULL), m_protocolEnumCopy(NULL), m_org(NULL), m_validUntil(validUntil), m_root(e)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (e && !XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
       
        if (e->hasAttributeNS(NULL,SHIB_L(validUntil))) {
            SAMLDateTime exp(e->getAttributeNS(NULL,SHIB_L(validUntil)));
            exp.parseDateTime();
            m_validUntil=min(m_validUntil,exp.getEpoch());
        }
        
        if (e->hasAttributeNS(NULL,SHIB_L(errorURL)))
            m_errorURL=toUTF8(e->getAttributeNS(NULL,SHIB_L(errorURL)));
        
        // Chop the protocol list into pieces...assume any whitespace can appear in between.
        m_protocolEnumCopy=XMLString::replicate(e->getAttributeNS(NULL,SHIB_L(protocolSupportEnumeration)));
        XMLCh* temp=m_protocolEnumCopy;
        while (temp && *temp) {
            XMLCh* start=temp++;
            while (*temp && !XMLChar1_1::isWhitespace(*temp)) temp++;
            if (*temp)
                *temp++=chNull;
            m_protocolEnum.push_back(start);
            while (*temp && XMLChar1_1::isWhitespace(*temp)) temp++;
        }
        
        e=saml::XML::getFirstChildElement(m_root,::XML::SAML2META_NS,SHIB_L(KeyDescriptor));
        while (e) {
            m_keys.push_back(new KeyDescriptor(e));
            e=saml::XML::getNextSiblingElement(e,::XML::SAML2META_NS,SHIB_L(KeyDescriptor));
        }

        e=saml::XML::getFirstChildElement(m_root,::XML::SAML2META_NS,SHIB_L(Organization));
        if (e)
            m_org=new Organization(e);

        e=saml::XML::getFirstChildElement(m_root,::XML::SAML2META_NS,SHIB_L(ContactPerson));
        while (e) {
            m_contacts.push_back(new ContactPerson(e));
            e=saml::XML::getNextSiblingElement(e,::XML::SAML2META_NS,SHIB_L(ContactPerson));
        }
    }
}

XMLMetadataImpl::Role::~Role()
{
    delete m_org;
    delete m_errorURL;
    if (m_protocolEnumCopy) XMLString::release(&m_protocolEnumCopy);
    for (vector<const IKeyDescriptor*>::iterator i=m_keys.begin(); i!=m_keys.end(); i++)
        delete const_cast<IKeyDescriptor*>(*i);
    for (vector<const IContactPerson*>::iterator j=m_contacts.begin(); j!=m_contacts.end(); j++)
        delete const_cast<IContactPerson*>(*j);
}

bool XMLMetadataImpl::Role::hasSupport(const XMLCh* protocol) const
{
    Iterator<const XMLCh*> i(m_protocolEnum);
    while (i.hasNext()) {
        if (!XMLString::compareString(protocol,i.next()))
            return true;
    }
    return false;
}

XMLMetadataImpl::SSORole::SSORole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e)
    : Role(provider,validUntil,e)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(ArtifactResolutionService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_artifact.add(new IndexedEndpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(SingleLogoutService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_logout.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(ManageNameIDService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_nameid.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(NameIDFormat));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            DOMNode* n=nlist->item(i)->getFirstChild();
            if (n) m_formats.push_back(n->getNodeValue());
        }
    }
    else {
        // For old style, we just do SAML 1.1 compatibility with Shib handles.
        m_protocolEnum.push_back(saml::XML::SAML11_PROTOCOL_ENUM);
        m_formats.push_back(shibboleth::Constants::SHIB_NAMEID_FORMAT_URI);
    }
}

XMLMetadataImpl::ScopedRole::ScopedRole(const DOMElement* e)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    DOMNodeList* nlist=NULL;
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
        e=saml::XML::getFirstChildElement(e,::XML::SAML2META_NS,SHIB_L(Extensions));
        nlist=e->getElementsByTagNameNS(::XML::SHIBMETA_NS,SHIB_L(Scope));
    }
    else {
        nlist=e->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(Domain));
    }
    
    for (int i=0; nlist && i < nlist->getLength(); i++) {
        const XMLCh* dom=(nlist->item(i)->hasChildNodes()) ? nlist->item(i)->getFirstChild()->getNodeValue() : NULL;
        if (dom && *dom) {
            const XMLCh* regexp=static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(regexp));
            m_scopes.push_back(
                pair<const XMLCh*,bool>(dom,(regexp && (*regexp==chLatin_t || *regexp==chDigit_1)))
                );
        }
    }
}

XMLMetadataImpl::IDPRole::IDPRole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e)
    : SSORole(provider,validUntil,e), ScopedRole(e), m_wantAuthnRequestsSigned(false), m_sourceId(NULL)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
        const XMLCh* flag=e->getAttributeNS(NULL,SHIB_L(WantAuthnRequestsSigned));
        m_wantAuthnRequestsSigned=(flag && (*flag==chDigit_1 || *flag==chLatin_t));
        
        // Check for SourceID extension.
        DOMElement* ext=saml::XML::getFirstChildElement(e,::XML::SAML2META_NS,SHIB_L(Extensions));
        if (ext) {
            ext=saml::XML::getFirstChildElement(ext,saml::XML::SAML_ARTIFACT_SOURCEID,SHIB_L(SourceID));
            if (ext && ext->hasChildNodes())
                m_sourceId=ext->getFirstChild()->getNodeValue();
        }
        
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(SingleSignOnService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_sso.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(NameIDMappingService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_mapping.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(AssertionIDRequestService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_idreq.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(AttributeProfile));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            DOMNode* n=nlist->item(i)->getFirstChild();
            if (n) m_attrprofs.push_back(n->getNodeValue());
        }

        nlist=e->getElementsByTagNameNS(::XML::SAML2ASSERT_NS,L(Attribute));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            // For now, we need to convert these to plain SAML 1.1 attributes.
            DOMElement* src=static_cast<DOMElement*>(nlist->item(i));
            DOMElement* copy=e->getOwnerDocument()->createElementNS(saml::XML::SAML_NS,L(Attribute));
            copy->setAttributeNS(NULL,L(AttributeName),src->getAttributeNS(NULL,SHIB_L(Name)));
            copy->setAttributeNS(NULL,L(AttributeNamespace),src->getAttributeNS(NULL,SHIB_L(NameFormat)));
            src=saml::XML::getFirstChildElement(src,::XML::SAML2ASSERT_NS,L(AttributeValue));
            while (src) {
                src=saml::XML::getNextSiblingElement(src,::XML::SAML2ASSERT_NS,L(AttributeValue));
                DOMElement* val=e->getOwnerDocument()->createElementNS(saml::XML::SAML_NS,L(AttributeValue));
                DOMNamedNodeMap* attrs = src->getAttributes();
                for (int j=0; j<attrs->getLength(); j++)
                    val->setAttributeNodeNS(static_cast<DOMAttr*>(e->getOwnerDocument()->importNode(attrs->item(j),true)));
                while (src->hasChildNodes())
                    val->appendChild(src->getFirstChild());
                copy->appendChild(val);
            }
            m_attrs.push_back(SAMLAttribute::getInstance(copy));
        }
    }
    else {
        m_attrprofs.push_back(Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(HandleService));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            // Manufacture an endpoint for the "Shib" binding.
            m_sso.add(
                new Endpoint(Constants::SHIB_AUTHNREQUEST_PROFILE_URI,static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Location)))
                );

            // We're going to "mock up" a KeyDescriptor that contains the specified Name as a ds:KeyName.
            DOMElement* kd=e->getOwnerDocument()->createElementNS(::XML::SAML2META_NS,SHIB_L(KeyDescriptor));
            DOMElement* ki=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,L(KeyInfo));
            DOMElement* kn=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            kn->appendChild(
                e->getOwnerDocument()->createTextNode(
                    static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Name))
                    )
                );
            ki->appendChild(kn);
            kd->appendChild(ki);
            kd->setAttributeNS(NULL,SHIB_L(use),SHIB_L(signing));
            m_keys.push_back(new KeyDescriptor(kd));
        }
    }
}

XMLMetadataImpl::IDPRole::~IDPRole()
{
    for (vector<const SAMLAttribute*>::iterator i=m_attrs.begin(); i!=m_attrs.end(); i++)
        delete const_cast<SAMLAttribute*>(*i);
}

XMLMetadataImpl::AARole::AARole(const EntityDescriptor* provider, time_t validUntil, const DOMElement* e)
    : Role(provider,validUntil,e), ScopedRole(e)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(AttributeService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_query.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(AssertionIDRequestService));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_idreq.add(new Endpoint(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(NameIDFormat));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            DOMNode* n=nlist->item(i)->getFirstChild();
            if (n) m_formats.push_back(n->getNodeValue());
        }

        nlist=e->getElementsByTagNameNS(::XML::SAML2META_NS,SHIB_L(AttributeProfile));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            DOMNode* n=nlist->item(i)->getFirstChild();
            if (n) m_attrprofs.push_back(n->getNodeValue());
        }

        nlist=e->getElementsByTagNameNS(::XML::SAML2ASSERT_NS,L(Attribute));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            // For now, we need to convert these to plain SAML 1.1 attributes.
            DOMElement* src=static_cast<DOMElement*>(nlist->item(i));
            DOMElement* copy=e->getOwnerDocument()->createElementNS(saml::XML::SAML_NS,L(Attribute));
            copy->setAttributeNS(NULL,L(AttributeName),src->getAttributeNS(NULL,SHIB_L(Name)));
            copy->setAttributeNS(NULL,L(AttributeNamespace),src->getAttributeNS(NULL,SHIB_L(NameFormat)));
            src=saml::XML::getFirstChildElement(src,::XML::SAML2ASSERT_NS,L(AttributeValue));
            while (src) {
                src=saml::XML::getNextSiblingElement(src,::XML::SAML2ASSERT_NS,L(AttributeValue));
                DOMElement* val=e->getOwnerDocument()->createElementNS(saml::XML::SAML_NS,L(AttributeValue));
                DOMNamedNodeMap* attrs = src->getAttributes();
                for (int j=0; j<attrs->getLength(); j++)
                    val->setAttributeNodeNS(static_cast<DOMAttr*>(e->getOwnerDocument()->importNode(attrs->item(j),true)));
                while (src->hasChildNodes())
                    val->appendChild(src->getFirstChild());
                copy->appendChild(val);
            }
            m_attrs.push_back(SAMLAttribute::getInstance(copy));
        }
    }
    else {
        // For old style, we just do SAML 1.1 compatibility with Shib handles.
        m_protocolEnum.push_back(saml::XML::SAML11_PROTOCOL_ENUM);
        m_formats.push_back(Constants::SHIB_NAMEID_FORMAT_URI);
        m_attrprofs.push_back(Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(AttributeAuthority));
        for (i=0; nlist && i<nlist->getLength(); i++) {
            // Manufacture an endpoint for the SOAP binding.
            m_query.add(
                new Endpoint(
                    SAMLBinding::SOAP,
                    static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Location))
                    )
                );

            // We're going to "mock up" a KeyDescriptor that contains the specified Name as a ds:KeyName.
            DOMElement* kd=e->getOwnerDocument()->createElementNS(::XML::SAML2META_NS,SHIB_L(KeyDescriptor));
            DOMElement* ki=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,L(KeyInfo));
            DOMElement* kn=e->getOwnerDocument()->createElementNS(saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            kn->appendChild(
                e->getOwnerDocument()->createTextNode(
                    static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Name))
                    )
                );
            ki->appendChild(kn);
            kd->appendChild(ki);
            m_keys.push_back(new KeyDescriptor(kd));
        }
    }
}

XMLMetadataImpl::AARole::~AARole()
{
    for (vector<const SAMLAttribute*>::iterator i=m_attrs.begin(); i!=m_attrs.end(); i++)
        delete const_cast<SAMLAttribute*>(*i);
}

XMLMetadataImpl::EntityDescriptor::EntityDescriptor(
    const DOMElement* e, XMLMetadataImpl* wrapper, time_t validUntil, const IEntitiesDescriptor* parent
    ) : m_root(e), m_parent(parent), m_org(NULL), m_validUntil(validUntil)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {
        m_id=e->getAttributeNS(NULL,SHIB_L(entityID));

        if (e->hasAttributeNS(NULL,SHIB_L(validUntil))) {
            SAMLDateTime exp(e->getAttributeNS(NULL,SHIB_L(validUntil)));
            exp.parseDateTime();
            m_validUntil=min(validUntil,exp.getEpoch());
        }

        DOMElement* child=saml::XML::getFirstChildElement(e);
        while (child) {
            // Process the various kinds of children that we care about...
            if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(Extensions))) {
                DOMElement* ext = saml::XML::getFirstChildElement(child,::XML::SHIBMETA_NS,SHIB_L(KeyAuthority));
                while (ext) {
                    m_keyauths.push_back(new KeyAuthority(ext));
                    ext = saml::XML::getNextSiblingElement(ext,::XML::SHIBMETA_NS,SHIB_L(KeyAuthority));
                }
            }
            else if (saml::XML::isElementNamed(child,::XML::SAML2META_NS,SHIB_L(ContactPerson))) {
                m_contacts.push_back(new ContactPerson(child));
            }
            else if (saml::XML::isElementNamed(child,::XML::SAML2META_NS,SHIB_L(Organization))) {
                m_org=new Organization(child);
            }
            else if (saml::XML::isElementNamed(child,::XML::SAML2META_NS,SHIB_L(AdditionalMetadataLocation))) {
                DOMNode* loc=child->getFirstChild();
                if (loc)
                    m_locs.push_back(
                    pair<const XMLCh*,const XMLCh*>(child->getAttributeNS(NULL,::XML::Literals::_namespace),loc->getNodeValue())
                        );
            }
            else if (saml::XML::isElementNamed(child,::XML::SAML2META_NS,SHIB_L(IDPSSODescriptor))) {
                m_roles.push_back(new IDPRole(this,m_validUntil,child));
            }
            else if (saml::XML::isElementNamed(child,::XML::SAML2META_NS,SHIB_L(AttributeAuthorityDescriptor))) {
                m_roles.push_back(new AARole(this,m_validUntil,child));
            }
            child = saml::XML::getNextSiblingElement(child);
        }
    }
    else {
        m_id=e->getAttributeNS(NULL,SHIB_L(Name));
        m_errorURL=auto_ptr<char>(toUTF8(e->getAttributeNS(NULL,SHIB_L(ErrorURL))));
        
        bool idp=false,aa=false;    // only want to build a role once
        DOMElement* child=saml::XML::getFirstChildElement(e);
        while (child) {
            // Process the various kinds of OriginSite children that we care about...
            if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(Contact))) {
                m_contacts.push_back(new ContactPerson(child));
            }
            else if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(HandleService)) && !idp) {
                // Create the IDP role if needed.
                m_roles.push_back(new IDPRole(this, m_validUntil, e));
                idp=true;
            }
            else if (saml::XML::isElementNamed(child,::XML::SHIB_NS,SHIB_L(AttributeAuthority)) && !aa) {
                // Create the AA role if needed.
                m_roles.push_back(new AARole(this, m_validUntil, e));
                aa=true;
            }
            child = saml::XML::getNextSiblingElement(child);
        }
    }

    auto_ptr_char id(m_id);
    wrapper->m_sites.insert(pair<string,const EntityDescriptor*>(id.get(),this));
    
    // Look for an IdP role, and register the artifact source ID and endpoints.
    const IDPRole* idp=NULL;
    for (vector<const IRoleDescriptor*>::const_iterator r=m_roles.begin(); r!=m_roles.end(); r++) {
        if (idp=dynamic_cast<const IDPRole*>(*r)) {
            if (idp->m_sourceId) {
                auto_ptr_char sourceid(idp->m_sourceId);
                wrapper->m_sources.insert(pair<string,const EntityDescriptor*>(sourceid.get(),this));
            }
            else {
                string sourceid=SAMLArtifact::toHex(SAMLArtifactType0001::generateSourceId(id.get()));
                Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata").debug(
                    "generated artifact SourceID (%s) for entity (%s)",sourceid.c_str(),id.get()
                    );
                wrapper->m_sources.insert(pair<string,const EntityDescriptor*>(sourceid,this));
            }
            Iterator<const IEndpoint*> locs=idp->getArtifactResolutionServiceManager()->getEndpoints();
            while (locs.hasNext()) {
                auto_ptr_char loc(locs.next()->getLocation());
                wrapper->m_sources.insert(pair<string,const EntityDescriptor*>(loc.get(),this));
            }
        }
    }
}

const IIDPSSODescriptor* XMLMetadataImpl::EntityDescriptor::getIDPSSODescriptor(const XMLCh* protocol) const
{
    const IIDPSSODescriptor* ret=NULL;
    for (vector<const IRoleDescriptor*>::const_iterator i=m_roles.begin(); i!=m_roles.end(); i++) {
        if ((*i)->hasSupport(protocol) && (*i)->isValid() && (ret=dynamic_cast<const IIDPSSODescriptor*>(*i)))
            return ret;
    }
    return NULL;
}

const IAttributeAuthorityDescriptor* XMLMetadataImpl::EntityDescriptor::getAttributeAuthorityDescriptor(const XMLCh* protocol) const
{
    const IAttributeAuthorityDescriptor* ret=NULL;
    for (vector<const IRoleDescriptor*>::const_iterator i=m_roles.begin(); i!=m_roles.end(); i++) {
        if ((*i)->hasSupport(protocol) && (*i)->isValid() && (ret=dynamic_cast<const IAttributeAuthorityDescriptor*>(*i)))
            return ret;
    }
    return NULL;
}

XMLMetadataImpl::EntityDescriptor::~EntityDescriptor()
{
    delete m_org;
    for (vector<const IContactPerson*>::iterator i=m_contacts.begin(); i!=m_contacts.end(); i++)
        delete const_cast<IContactPerson*>(*i);
    for (vector<const IRoleDescriptor*>::iterator j=m_roles.begin(); j!=m_roles.end(); j++)
        delete const_cast<IRoleDescriptor*>(*j);
    for (vector<const IKeyAuthority*>::iterator k=m_keyauths.begin(); k!=m_keyauths.end(); k++)
        delete const_cast<IKeyAuthority*>(*k);
}

XMLMetadataImpl::EntitiesDescriptor::EntitiesDescriptor(
    const DOMElement* e, XMLMetadataImpl* wrapper, time_t validUntil, const IEntitiesDescriptor* parent
    ) : m_root(e), m_name(e->getAttributeNS(NULL,SHIB_L(Name))), m_parent(parent), m_validUntil(validUntil)
{
    // Check the root element namespace. If SAML2, assume it's the std schema.
    if (!XMLString::compareString(e->getNamespaceURI(),::XML::SAML2META_NS)) {

        if (e->hasAttributeNS(NULL,SHIB_L(validUntil))) {
            SAMLDateTime exp(e->getAttributeNS(NULL,SHIB_L(validUntil)));
            exp.parseDateTime();
            m_validUntil=min(validUntil,exp.getEpoch());
        }

        e=saml::XML::getFirstChildElement(e);
        while (e) {
            if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(Extensions))) {
                DOMElement* ext = saml::XML::getFirstChildElement(e,::XML::SHIBMETA_NS,SHIB_L(KeyAuthority));
                while (ext) {
                    m_keyauths.push_back(new KeyAuthority(ext));
                    ext = saml::XML::getNextSiblingElement(ext,::XML::SHIBMETA_NS,SHIB_L(KeyAuthority));
                }
            }
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(EntitiesDescriptor)))
                m_groups.push_back(new EntitiesDescriptor(e,wrapper,m_validUntil,this));
            else if (saml::XML::isElementNamed(e,::XML::SAML2META_NS,SHIB_L(EntityDescriptor)))
                m_providers.push_back(new EntityDescriptor(e,wrapper,m_validUntil,this));
            e=saml::XML::getNextSiblingElement(e);
        }
    }
    else {
        e=saml::XML::getFirstChildElement(e);
        while (e) {
            if (saml::XML::isElementNamed(e,::XML::SHIB_NS,SHIB_L(SiteGroup)))
                m_groups.push_back(new EntitiesDescriptor(e,wrapper,m_validUntil,this));
            else if (saml::XML::isElementNamed(e,::XML::SHIB_NS,SHIB_L(OriginSite)))
                m_providers.push_back(new EntityDescriptor(e,wrapper,m_validUntil,this));
            e=saml::XML::getNextSiblingElement(e);
        }
    }
}

XMLMetadataImpl::EntitiesDescriptor::~EntitiesDescriptor()
{
    for (vector<const IEntityDescriptor*>::iterator i=m_providers.begin(); i!=m_providers.end(); i++)
        delete const_cast<IEntityDescriptor*>(*i);
    for (vector<const IEntitiesDescriptor*>::iterator j=m_groups.begin(); j!=m_groups.end(); j++)
        delete const_cast<IEntitiesDescriptor*>(*j);
    for (vector<const IKeyAuthority*>::iterator k=m_keyauths.begin(); k!=m_keyauths.end(); k++)
        delete const_cast<IKeyAuthority*>(*k);
}

void XMLMetadataImpl::init()
{
#ifdef _DEBUG
    NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Metadata");

    try
    {
        if (saml::XML::isElementNamed(m_root,::XML::SAML2META_NS,SHIB_L(EntitiesDescriptor)))
            m_rootGroup=new EntitiesDescriptor(m_root,this);
        else if (saml::XML::isElementNamed(m_root,::XML::SAML2META_NS,SHIB_L(EntityDescriptor)))
            m_rootProvider=new EntityDescriptor(m_root,this);
        else if (saml::XML::isElementNamed(m_root,::XML::SHIB_NS,SHIB_L(SiteGroup)))
            m_rootGroup=new EntitiesDescriptor(m_root,this);
        else if (saml::XML::isElementNamed(m_root,::XML::SHIB_NS,SHIB_L(OriginSite)))
            m_rootProvider=new EntityDescriptor(m_root,this);
        else {
            log.error("Construction requires a valid SAML metadata file");
            throw MetadataException("Construction requires a valid SAML metadata file");
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "Error while parsing SAML metadata: " << e.what() << CategoryStream::ENDLINE;
        this->~XMLMetadataImpl();
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log.error("Unexpected error while parsing SAML metadata");
        this->~XMLMetadataImpl();
        throw;
    }
#endif
}

XMLMetadataImpl::~XMLMetadataImpl()
{
    delete m_rootGroup;
    delete m_rootProvider;
}

const IEntityDescriptor* XMLMetadata::lookup(const char* providerId, bool strict) const
{
    if (strict && m_exclusions && m_set.find(providerId)!=m_set.end())
        return NULL;
    else if (strict && !m_exclusions && m_set.find(providerId)==m_set.end())
        return NULL;
        
    XMLMetadataImpl* impl=dynamic_cast<XMLMetadataImpl*>(getImplementation());
    pair<XMLMetadataImpl::sitemap_t::const_iterator,XMLMetadataImpl::sitemap_t::const_iterator> range=
        impl->m_sites.equal_range(providerId);

    time_t now=time(NULL);
    for (XMLMetadataImpl::sitemap_t::const_iterator i=range.first; i!=range.second; i++)
        if (now < i->second->getValidUntil())
            return i->second;
    
    if (!strict && range.first!=range.second)
        return range.first->second;
        
    return NULL;
}

const IEntityDescriptor* XMLMetadata::lookup(const XMLCh* providerId, bool strict) const
{
    auto_ptr_char temp(providerId);
    return lookup(temp.get(),strict);
}

const IEntityDescriptor* XMLMetadata::lookup(const SAMLArtifact* artifact) const
{
    time_t now=time(NULL);
    XMLMetadataImpl* impl=dynamic_cast<XMLMetadataImpl*>(getImplementation());
    pair<XMLMetadataImpl::sitemap_t::const_iterator,XMLMetadataImpl::sitemap_t::const_iterator> range;
    
    // Depends on type of artifact.
    const SAMLArtifactType0001* type1=dynamic_cast<const SAMLArtifactType0001*>(artifact);
    if (type1) {
        range=impl->m_sources.equal_range(SAMLArtifact::toHex(type1->getSourceID()));
    }
    else {
        const SAMLArtifactType0002* type2=dynamic_cast<const SAMLArtifactType0002*>(artifact);
        if (type2) {
            range=impl->m_sources.equal_range(type2->getSourceLocation());
        }
        else
            return NULL;
    }

    // Check exclude list.
    if (range.first!=range.second) {
        auto_ptr_char id(range.first->second->getId());
        if (m_exclusions && m_set.find(id.get())!=m_set.end())
            return NULL;
        else if (!m_exclusions && m_set.find(id.get())==m_set.end())
            return NULL;

        for (XMLMetadataImpl::sitemap_t::const_iterator i=range.first; i!=range.second; i++)
            if (now < i->second->getValidUntil())
                return i->second;
    }
    
    return NULL;
}
