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


/* shib.h - Shibboleth header file

   Scott Cantor
   6/4/02

   $History:$
*/

#ifndef __shib_h__
#define __shib_h__

#include <saml/saml.h>
#include <shib/shib-threads.h>
#include <xsec/xenc/XENCEncryptionMethod.hpp>

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
    DECLARE_SAML_EXCEPTION(SHIB_EXPORTS,ResourceAccessException,SAMLException);
    DECLARE_SAML_EXCEPTION(SHIB_EXPORTS,MetadataException,SAMLException);
    DECLARE_SAML_EXCEPTION(SHIB_EXPORTS,CredentialException,SAMLException);
    DECLARE_SAML_EXCEPTION(SHIB_EXPORTS,InvalidHandleException,RetryableProfileException);
    DECLARE_SAML_EXCEPTION(SHIB_EXPORTS,InvalidSessionException,RetryableProfileException);

    // Metadata abstract interfaces, based on SAML 2.0
    
    struct SHIB_EXPORTS IContactPerson
    {
        enum ContactType { technical, support, administrative, billing, other };
        virtual ContactType getType() const=0;
        virtual const char* getCompany() const=0;
        virtual const char* getGivenName() const=0;
        virtual const char* getSurName() const=0;
        virtual saml::Iterator<std::string> getEmailAddresses() const=0;
        virtual saml::Iterator<std::string> getTelephoneNumbers() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IContactPerson() {}
    };

    struct SHIB_EXPORTS IOrganization
    {
        virtual const char* getName(const char* lang="en") const=0;
        virtual const char* getDisplayName(const char* lang="en") const=0;
        virtual const char* getURL(const char* lang="en") const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IOrganization() {}
    };
    
    struct SHIB_EXPORTS IKeyDescriptor
    {
        enum KeyUse { unspecified, encryption, signing };
        virtual KeyUse getUse() const=0;
        virtual DSIGKeyInfoList* getKeyInfo() const=0;
        virtual saml::Iterator<const XENCEncryptionMethod*> getEncryptionMethods() const=0;
        virtual ~IKeyDescriptor() {}
    };

    struct SHIB_EXPORTS IEndpoint
    {
        virtual const XMLCh* getBinding() const=0;
        virtual const XMLCh* getLocation() const=0;
        virtual const XMLCh* getResponseLocation() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IEndpoint() {}
    };

    struct SHIB_EXPORTS IIndexedEndpoint : public virtual IEndpoint
    {
        virtual unsigned short getIndex() const=0;
        virtual ~IIndexedEndpoint() {}
    };
    
    struct SHIB_EXPORTS IEndpointManager
    {
        virtual saml::Iterator<const IEndpoint*> getEndpoints() const=0;
        virtual const IEndpoint* getDefaultEndpoint() const=0;
        virtual const IEndpoint* getEndpointByIndex(unsigned short index) const=0;
        virtual const IEndpoint* getEndpointByBinding(const XMLCh* binding) const=0;
        virtual ~IEndpointManager() {}
    };

    struct SHIB_EXPORTS IEntityDescriptor;
    struct SHIB_EXPORTS IRoleDescriptor
    {
        virtual const IEntityDescriptor* getEntityDescriptor() const=0;
        virtual saml::Iterator<const XMLCh*> getProtocolSupportEnumeration() const=0;
        virtual bool hasSupport(const XMLCh* protocol) const=0;
        virtual bool isValid() const=0;
        virtual const char* getErrorURL() const=0;
        virtual saml::Iterator<const IKeyDescriptor*> getKeyDescriptors() const=0;
        virtual const IOrganization* getOrganization() const=0;
        virtual saml::Iterator<const IContactPerson*> getContactPersons() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IRoleDescriptor() {}
    };

    struct SHIB_EXPORTS ISSODescriptor : public virtual IRoleDescriptor
    {
        virtual const IEndpointManager* getArtifactResolutionServiceManager() const=0;
        virtual const IEndpointManager* getSingleLogoutServiceManager() const=0;
        virtual const IEndpointManager* getManageNameIDServiceManager() const=0;
        virtual saml::Iterator<const XMLCh*> getNameIDFormats() const=0;
        virtual ~ISSODescriptor() {}
    };
    
    struct SHIB_EXPORTS IIDPSSODescriptor : public virtual ISSODescriptor
    {
        virtual bool getWantAuthnRequestsSigned() const=0;
        virtual const IEndpointManager* getSingleSignOnServiceManager() const=0;
        virtual const IEndpointManager* getNameIDMappingServiceManager() const=0;
        virtual const IEndpointManager* getAssertionIDRequestServiceManager() const=0;
        virtual saml::Iterator<const XMLCh*> getAttributeProfiles() const=0;
        virtual saml::Iterator<const saml::SAMLAttribute*> getAttributes() const=0;
        virtual ~IIDPSSODescriptor() {}
    };
    
    struct SHIB_EXPORTS IAttributeConsumingService
    {
        virtual const XMLCh* getName(const char* lang="en") const=0;
        virtual const XMLCh* getDescription(const char* lang="en") const=0;
        virtual saml::Iterator<std::pair<const saml::SAMLAttribute*,bool> > getRequestedAttributes() const=0;
        virtual ~IAttributeConsumingService() {}
    };

    struct SHIB_EXPORTS ISPSSODescriptor : public virtual ISSODescriptor
    {
        virtual bool getAuthnRequestsSigned() const=0;
        virtual bool getWantAssertionsSigned() const=0;
        virtual const IEndpointManager* getAssertionConsumerServiceManager() const=0;
        virtual saml::Iterator<const IAttributeConsumingService*> getAttributeConsumingServices() const=0;
        virtual const IAttributeConsumingService* getDefaultAttributeConsumingService() const=0;
        virtual const IAttributeConsumingService* getAttributeConsumingServiceByID(const XMLCh* id) const=0;
        virtual ~ISPSSODescriptor() {}
    };

    struct SHIB_EXPORTS IAuthnAuthorityDescriptor : public virtual IRoleDescriptor
    {
        virtual const IEndpointManager* getAuthnQueryServiceManager() const=0;
        virtual const IEndpointManager* getAssertionIDRequestServiceManager() const=0;
        virtual saml::Iterator<const XMLCh*> getNameIDFormats() const=0;
        virtual ~IAuthnAuthorityDescriptor() {}
    };

    struct SHIB_EXPORTS IPDPDescriptor : public virtual IRoleDescriptor
    {
        virtual const IEndpointManager* getAuthzServiceManager() const=0;
        virtual const IEndpointManager* getAssertionIDRequestServiceManager() const=0;
        virtual saml::Iterator<const XMLCh*> getNameIDFormats() const=0;
        virtual ~IPDPDescriptor() {}
    };

    struct SHIB_EXPORTS IAttributeAuthorityDescriptor : public virtual IRoleDescriptor
    {
        virtual const IEndpointManager* getAttributeServiceManager() const=0;
        virtual const IEndpointManager* getAssertionIDRequestServiceManager() const=0;
        virtual saml::Iterator<const XMLCh*> getNameIDFormats() const=0;
        virtual saml::Iterator<const XMLCh*> getAttributeProfiles() const=0;
        virtual saml::Iterator<const saml::SAMLAttribute*> getAttributes() const=0;
        virtual ~IAttributeAuthorityDescriptor() {}
    };
    
    struct SHIB_EXPORTS IAffiliationDescriptor
    {
        virtual const IEntityDescriptor* getEntityDescriptor() const=0;
        virtual const XMLCh* getOwnerID() const=0;
        virtual bool isValid() const=0;
        virtual saml::Iterator<const XMLCh*> getMembers() const=0;
        virtual bool isMember(const XMLCh* id) const=0;
        virtual saml::Iterator<const IKeyDescriptor*> getKeyDescriptors() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IAffiliationDescriptor() {}
    };

    struct SHIB_EXPORTS IEntitiesDescriptor;
    struct SHIB_EXPORTS IEntityDescriptor
    {
        virtual const XMLCh* getId() const=0;
        virtual bool isValid() const=0;
        virtual saml::Iterator<const IRoleDescriptor*> getRoleDescriptors() const=0;
        virtual const IIDPSSODescriptor* getIDPSSODescriptor(const XMLCh* protocol) const=0;
        virtual const ISPSSODescriptor* getSPSSODescriptor(const XMLCh* protocol) const=0;
        virtual const IAuthnAuthorityDescriptor* getAuthnAuthorityDescriptor(const XMLCh* protocol) const=0;
        virtual const IAttributeAuthorityDescriptor* getAttributeAuthorityDescriptor(const XMLCh* protocol) const=0;
        virtual const IPDPDescriptor* getPDPDescriptor(const XMLCh* protocol) const=0;
        virtual const IAffiliationDescriptor* getAffiliationDescriptor() const=0;
        virtual const IOrganization* getOrganization() const=0;
        virtual saml::Iterator<const IContactPerson*> getContactPersons() const=0;
        virtual saml::Iterator<std::pair<const XMLCh*,const XMLCh*> > getAdditionalMetadataLocations() const=0;
        virtual const IEntitiesDescriptor* getEntitiesDescriptor() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IEntityDescriptor() {}
    };
    
    struct SHIB_EXPORTS IEntitiesDescriptor
    {
        virtual const XMLCh* getName() const=0;
        virtual bool isValid() const=0;
        virtual const IEntitiesDescriptor* getEntitiesDescriptor() const=0;
        virtual saml::Iterator<const IEntitiesDescriptor*> getEntitiesDescriptors() const=0;
        virtual saml::Iterator<const IEntityDescriptor*> getEntityDescriptors() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IEntitiesDescriptor() {}
    };
    
    // Supports Shib role extension describing attribute scoping rules
    struct SHIB_EXPORTS IScopedRoleDescriptor : public virtual IRoleDescriptor
    {
        virtual saml::Iterator<std::pair<const XMLCh*,bool> > getScopes() const=0;
        virtual ~IScopedRoleDescriptor() {}
    };
    
    // Shib extension interfaces to key authority data
    struct SHIB_EXPORTS IKeyAuthority
    {
        virtual int getVerifyDepth() const=0;
        virtual saml::Iterator<DSIGKeyInfoList*> getKeyInfos() const=0;
        virtual ~IKeyAuthority() {}
    };
    
    struct SHIB_EXPORTS IExtendedEntityDescriptor : public virtual IEntityDescriptor
    {
        virtual saml::Iterator<const IKeyAuthority*> getKeyAuthorities() const=0;
        virtual ~IExtendedEntityDescriptor() {}
    };

    struct SHIB_EXPORTS IExtendedEntitiesDescriptor : public virtual IEntitiesDescriptor
    {
        virtual saml::Iterator<const IKeyAuthority*> getKeyAuthorities() const=0;
        virtual ~IExtendedEntitiesDescriptor() {}
    };
       
    struct SHIB_EXPORTS IMetadata : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        virtual const IEntityDescriptor* lookup(const char* id, bool strict=true) const=0;
        virtual const IEntityDescriptor* lookup(const XMLCh* id, bool strict=true) const=0;
        virtual const IEntityDescriptor* lookup(const saml::SAMLArtifact* artifact) const=0;
        virtual const IEntitiesDescriptor* lookupGroup(const char* name, bool strict=true) const=0;
        virtual const IEntitiesDescriptor* lookupGroup(const XMLCh* name, bool strict=true) const=0;
        virtual std::pair<const IEntitiesDescriptor*,const IEntityDescriptor*> getRoot() const=0;
        virtual ~IMetadata() {}
    };

    // Trust interface hides *all* details of signature and SSL validation.
    // Pluggable providers can fully override the Shibboleth trust model here.
    
    struct SHIB_EXPORTS ITrust : public virtual saml::IPlugIn
    {
        // Performs certificate validation processing of an untrusted certificates
        // using a library-specific representation, in this case an OpenSSL X509*
        virtual bool validate(
            void* certEE,
            const saml::Iterator<void*>& certChain,
            const IRoleDescriptor* role,
            bool checkName=true
            )=0;

        // Validates signed SAML messages and assertions sent by an entity acting in a specific role.
        // If certificate validation is required, the trust provider used can be overridden using
        // the last parameter, or left null and the provider will rely on itself.
        virtual bool validate(
            const saml::SAMLSignedObject& token,
            const IRoleDescriptor* role,
            ITrust* certValidator=NULL
            )=0;
        
        virtual ~ITrust() {}
    };

    // Credentials interface abstracts access to "owned" keys and certificates.
    
    struct SHIB_EXPORTS ICredResolver : public virtual saml::IPlugIn
    {
        virtual void attach(void* ctx) const=0;
        virtual XSECCryptoKey* getKey() const=0;
        virtual saml::Iterator<XSECCryptoX509*> getCertificates() const=0;
        virtual void dump(FILE* f) const=0;
        virtual void dump() const { dump(stdout); }
        virtual ~ICredResolver() {}
    };

    struct SHIB_EXPORTS ICredentials : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        virtual const ICredResolver* lookup(const char* id) const=0;
        virtual ~ICredentials() {}
    };
    
    // Attribute acceptance processing interfaces, applied to incoming attributes.

    struct SHIB_EXPORTS IAttributeRule
    {
        virtual const XMLCh* getName() const=0;
        virtual const XMLCh* getNamespace() const=0;
        virtual const char* getAlias() const=0;
        virtual const char* getHeader() const=0;
        virtual bool getCaseSensitive() const=0;
        virtual void apply(saml::SAMLAttribute& attribute, const IRoleDescriptor* role=NULL) const=0;
        virtual ~IAttributeRule() {}
    };
    
    struct SHIB_EXPORTS IAAP : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        virtual bool anyAttribute() const=0;
        virtual const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const=0;
        virtual const IAttributeRule* lookup(const char* alias) const=0;
        virtual saml::Iterator<const IAttributeRule*> getAttributeRules() const=0;
        virtual ~IAAP() {}
    };
    
    struct SHIB_EXPORTS IAttributeFactory : public virtual saml::IPlugIn
    {
        virtual saml::SAMLAttribute* build(DOMElement* e) const=0;
        virtual ~IAttributeFactory() {}
    };

#ifdef SHIB_INSTANTIATE
    template class SHIB_EXPORTS saml::Iterator<const IContactPerson*>;
    template class SHIB_EXPORTS saml::Iterator<const XENCEncryptionMethod*>;
    template class SHIB_EXPORTS saml::Iterator<const IKeyDescriptor*>;
    template class SHIB_EXPORTS saml::Iterator<const IAttributeConsumingService*>;
    template class SHIB_EXPORTS saml::Iterator<const IRoleDescriptor*>;
    template class SHIB_EXPORTS saml::Iterator<const IEntityDescriptor*>;
    template class SHIB_EXPORTS saml::Iterator<const IEntitiesDescriptor*>;
    template class SHIB_EXPORTS saml::Iterator<const IEndpoint*>;
    template class SHIB_EXPORTS saml::Iterator<const IAttributeRule*>;
    template class SHIB_EXPORTS saml::Iterator<const IKeyAuthority*>;
    template class SHIB_EXPORTS saml::Iterator<DSIGKeyInfoList*>;
    template class SHIB_EXPORTS saml::Iterator<IMetadata*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IMetadata*>;
    template class SHIB_EXPORTS saml::Iterator<ITrust*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ITrust*>;
    template class SHIB_EXPORTS saml::Iterator<ICredentials*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ICredentials*>;
    template class SHIB_EXPORTS saml::Iterator<IAAP*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IAAP*>;
#endif

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
        static const XMLCh SHIB_NAMEID_FORMAT_URI[];
        static const XMLCh SHIB_AUTHNREQUEST_PROFILE_URI[];
        static const XMLCh SHIB_LEGACY_AUTHNREQUEST_PROFILE_URI[];
        static const XMLCh SHIB_SESSIONINIT_PROFILE_URI[];
        static const XMLCh SHIB_LOGOUT_PROFILE_URI[];
        static const XMLCh SHIB_NS[];
        static const XMLCh InvalidHandle[];
    };

    // Glue classes between abstract metadata and concrete providers
    
    class SHIB_EXPORTS Metadata
    {
    public:
        Metadata(const saml::Iterator<IMetadata*>& metadatas) : m_metadatas(metadatas), m_mapper(NULL) {}
        ~Metadata();

        const IEntityDescriptor* lookup(const char* id, bool strict=true);
        const IEntityDescriptor* lookup(const XMLCh* id, bool strict=true);
        const IEntityDescriptor* lookup(const saml::SAMLArtifact* artifact);

    private:
        Metadata(const Metadata&);
        void operator=(const Metadata&);
        IMetadata* m_mapper;
        const saml::Iterator<IMetadata*>& m_metadatas;
    };

    class SHIB_EXPORTS Trust
    {
    public:
        Trust(const saml::Iterator<ITrust*>& trusts) : m_trusts(trusts) {}
        ~Trust() {}

        bool validate(
            void* certEE,
            const saml::Iterator<void*>& certChain,
            const IRoleDescriptor* role,
            bool checkName=true
            ) const;
        bool validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role) const;
        
    private:
        Trust(const Trust&);
        void operator=(const Trust&);
        const saml::Iterator<ITrust*>& m_trusts;
    };
    
    class SHIB_EXPORTS Credentials
    {
    public:
        Credentials(const saml::Iterator<ICredentials*>& creds) : m_creds(creds), m_mapper(NULL) {}
        ~Credentials();

        const ICredResolver* lookup(const char* id);

    private:
        Credentials(const Credentials&);
        void operator=(const Credentials&);
        ICredentials* m_mapper;
        const saml::Iterator<ICredentials*>& m_creds;
    };

    class SHIB_EXPORTS AAP
    {
    public:
        AAP(const saml::Iterator<IAAP*>& aaps, const XMLCh* attrName, const XMLCh* attrNamespace=NULL);
        AAP(const saml::Iterator<IAAP*>& aaps, const char* alias);
        ~AAP();
        bool fail() const {return m_mapper==NULL;}
        const IAttributeRule* operator->() const {return m_rule;}
        operator const IAttributeRule*() const {return m_rule;}
        
        static void apply(const saml::Iterator<IAAP*>& aaps, saml::SAMLAssertion& assertion, const IRoleDescriptor* role=NULL);
        
    private:
        AAP(const AAP&);
        void operator=(const AAP&);
        IAAP* m_mapper;
        const IAttributeRule* m_rule;
    };

    // Subclass around the OpenSAML browser profile interface,
    // incoporates additional functionality using Shib-defined APIs.
    class SHIB_EXPORTS ShibBrowserProfile : virtual public saml::SAMLBrowserProfile
    {
    public:
        ShibBrowserProfile(
            const saml::Iterator<IMetadata*>& metadatas=EMPTY(IMetadata*),
            const saml::Iterator<ITrust*>& trusts=EMPTY(ITrust*)
            );
        virtual ~ShibBrowserProfile();

        virtual saml::SAMLBrowserProfile::BrowserProfileResponse receive(
            const char* packet,
            const XMLCh* recipient,
            int supportedProfiles,
            saml::IReplayCache* replayCache=NULL,
            saml::SAMLBrowserProfile::ArtifactMapper* callback=NULL,
            int minorVersion=1
            ) const;

    private:
        saml::SAMLBrowserProfile* m_profile;
        saml::Iterator<IMetadata*> m_metadatas;
        saml::Iterator<ITrust*> m_trusts;
    };

    // Instead of wrapping the binding to deal with mutual authentication, we
    // just use the HTTP hook functionality offered by OpenSAML. The hook will
    // register "itself" as a globalCtx pointer with the SAML binding and the caller
    // will declare and pass the embedded struct as callCtx for use by the hook.
    class SHIB_EXPORTS ShibHTTPHook : virtual public saml::SAMLSOAPHTTPBinding::HTTPHook
    {
    public:
        ShibHTTPHook(const saml::Iterator<ITrust*>& trusts, const saml::Iterator<ICredentials*>& creds)
            : m_trusts(trusts), m_creds(creds) {}
        virtual ~ShibHTTPHook() {}
        
        // Only hook we need here is for outgoing connection to server.
        virtual bool outgoing(saml::HTTPClient* conn, void* globalCtx=NULL, void* callCtx=NULL);

        // Client declares a context object and pass as callCtx to send() method.
        class SHIB_EXPORTS ShibHTTPHookCallContext {
        public:
            ShibHTTPHookCallContext(const char* credResolverId, const IRoleDescriptor* role)
                : m_credResolverId(credResolverId), m_role(role), m_hook(NULL), m_authenticated(false) {}
            const ShibHTTPHook* getHook() {return m_hook;}
            const char* getCredResolverId() {return m_credResolverId;}
            const IRoleDescriptor* getRoleDescriptor() {return m_role;}
            bool isAuthenticated() const {return m_authenticated;}
            void setAuthenticated() {m_authenticated=true;}
            
        private:
            const char* m_credResolverId;
            const IRoleDescriptor* m_role;
            ShibHTTPHook* m_hook;
            bool m_authenticated;
            friend class ShibHTTPHook;
        };
        
        const saml::Iterator<ITrust*>& getTrustProviders() const {return m_trusts;}
        const saml::Iterator<ICredentials*>& getCredentialProviders() const {return m_creds;}
    private:
        saml::Iterator<ITrust*> m_trusts;
        saml::Iterator<ICredentials*> m_creds;
    };

    class SHIB_EXPORTS ShibConfig
    {
    public:
        ShibConfig() {}
        virtual ~ShibConfig() {}

        // global per-process setup and shutdown of Shibboleth runtime
        virtual bool init();
        virtual void term();

        // manages specific attribute name to factory mappings
        void regAttributeMapping(const XMLCh* name, const IAttributeFactory* factory);
        void unregAttributeMapping(const XMLCh* name);
        void clearAttributeMappings();

        // enables runtime and clients to access configuration
        static ShibConfig& getConfig();
    };

    /* Helper classes for implementing reloadable XML-based config files
       The ILockable interface will usually be inherited twice, once as
       part of the external interface to clients and once as an implementation
       detail of the reloading class below.
     */
    
    class SHIB_EXPORTS ReloadableXMLFileImpl
    {
    public:
        ReloadableXMLFileImpl(const char* pathname);
        ReloadableXMLFileImpl(const DOMElement* pathname);
        virtual ~ReloadableXMLFileImpl();
        
    protected:
        DOMDocument* m_doc;
        const DOMElement* m_root;
    };

    class SHIB_EXPORTS ReloadableXMLFile : protected virtual saml::ILockable
    {
    public:
        ReloadableXMLFile(const DOMElement* e);
        ~ReloadableXMLFile() { delete m_lock; delete m_impl; }

        virtual void lock();
        virtual void unlock() { if (m_lock) m_lock->unlock(); }

        ReloadableXMLFileImpl* getImplementation() const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const=0;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const=0;
        mutable ReloadableXMLFileImpl* m_impl;
        
    private:
        const DOMElement* m_root;
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
    };

    /* These helpers attach metadata-derived information as exception properties and then
     * rethrow the object. The following properties are attached, when possible:
     * 
     *  providerId          The unique ID of the entity
     *  errorURL            The error support URL of the entity or role
     *  contactName         A formatted support or technical contact name
     *  contactEmail        A contact email address
     */
    SHIB_EXPORTS void annotateException(saml::SAMLException* e, const IEntityDescriptor* entity, bool rethrow=true);
    SHIB_EXPORTS void annotateException(saml::SAMLException* e, const IRoleDescriptor* role, bool rethrow=true);
}

#endif
