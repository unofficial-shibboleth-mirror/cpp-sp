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

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
    #define DECLARE_SHIB_EXCEPTION(name,base) \
        class SHIB_EXPORTS name : public saml::base \
        { \
        public: \
            name(const char* msg) : saml::base(msg) {RTTI(name);} \
            name(const std::string& msg) : saml::base(msg) {RTTI(name);} \
            name(const saml::Iterator<saml::QName>& codes, const char* msg) : saml::base(codes,msg) {RTTI(name);} \
            name(const saml::Iterator<saml::QName>& codes, const std::string& msg) : saml::base(codes, msg) {RTTI(name);} \
            name(const saml::QName& code, const char* msg) : saml::base(code,msg) {RTTI(name);} \
            name(const saml::QName& code, const std::string& msg) : saml::base(code, msg) {RTTI(name);} \
            name(DOMElement* e) : saml::base(e) {RTTI(name);} \
            name(std::istream& in) : saml::base(in) {RTTI(name);} \
            virtual ~name() throw () {} \
        }

    DECLARE_SHIB_EXCEPTION(MetadataException,SAMLException);
    DECLARE_SHIB_EXCEPTION(CredentialException,SAMLException);
    DECLARE_SHIB_EXCEPTION(InvalidHandleException,RetryableProfileException);

    // Manages pluggable implementations of interfaces
    // Would prefer this to be a template, but the Windows STL isn't DLL-safe.

    struct SHIB_EXPORTS IPlugIn
    {
        virtual ~IPlugIn() {}
    };

    class SHIB_EXPORTS PlugManager
    {
    public:
        PlugManager() {}
        ~PlugManager() {}

        typedef IPlugIn* Factory(const DOMElement* source);
        void regFactory(const char* type, Factory* factory);
        void unregFactory(const char* type);
        IPlugIn* newPlugin(const char* type, const DOMElement* source);

    private:
        typedef std::map<std::string, Factory*> FactoryMap;
        FactoryMap m_map;
    };

    // Metadata abstract interfaces, inching toward SAML 2.0...
    
    struct SHIB_EXPORTS ILockable
    {
        virtual void lock()=0;
        virtual void unlock()=0;
        virtual ~ILockable() {}
    };
    
    struct SHIB_EXPORTS IContactPerson
    {
        enum ContactType { technical, support, administrative, billing, other };
        virtual ContactType getType() const=0;
        virtual const char* getCompany() const=0;
        virtual const char* getName() const=0;
        virtual saml::Iterator<std::string> getEmails() const=0;
        virtual saml::Iterator<std::string> getTelephones() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IContactPerson() {}
    };

    struct SHIB_EXPORTS IOrganization
    {
        virtual const char* getName(const char* lang) const=0;
        virtual const char* getDisplayName(const char* lang) const=0;
        virtual const char* getURL(const char* lang) const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IOrganization() {}
    };
    
    struct SHIB_EXPORTS IKeyDescriptor
    {
        enum KeyUse { encryption, signing };
        virtual KeyUse getUse() const=0;
        virtual const XMLCh* getEncryptionMethod() const=0;
        virtual int getKeySize() const=0;
        virtual DSIGKeyInfoList* getKeyInfo() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IKeyDescriptor() {}
    };

    struct SHIB_EXPORTS IEndpoint
    {
        virtual const XMLCh* getBinding() const=0;
        virtual const XMLCh* getVersion() const=0;
        virtual const XMLCh* getLocation() const=0;
        virtual const XMLCh* getResponseLocation() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IEndpoint() {}
    };

    struct SHIB_EXPORTS IProvider;
    struct SHIB_EXPORTS IProviderRole
    {
        virtual const IProvider* getProvider() const=0;
        virtual saml::Iterator<const XMLCh*> getProtocolSupportEnumeration() const=0;
        virtual bool hasSupport(const XMLCh* version) const=0;
        virtual saml::Iterator<const IKeyDescriptor*> getKeyDescriptors() const=0;
        virtual const IOrganization* getOrganization() const=0;
        virtual saml::Iterator<const IContactPerson*> getContacts() const=0;
        virtual saml::Iterator<const IEndpoint*> getDefaultEndpoints() const=0;
        virtual const char* getErrorURL() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IProviderRole() {}
    };
       
    struct SHIB_EXPORTS ISSOProviderRole : public virtual IProviderRole
    {
        virtual saml::Iterator<const IEndpoint*> getSingleLogoutServices() const=0;
        virtual saml::Iterator<const IEndpoint*> getFederationTerminationServices() const=0;
        virtual saml::Iterator<const IEndpoint*> getRegisterNameIdentifierServices() const=0;
        virtual ~ISSOProviderRole() {}
    };
    
    struct SHIB_EXPORTS IIDPProviderRole : public virtual ISSOProviderRole
    {
        virtual saml::Iterator<const IEndpoint*> getSingleSignOnServices() const=0;
        virtual ~IIDPProviderRole() {}
    };
    
    struct SHIB_EXPORTS ISPProviderRole : public virtual ISSOProviderRole
    {
        virtual bool getAuthnRequestsSigned() const=0;
        virtual const IEndpoint* getDefaultAssertionConsumerServiceURL() const=0;
        virtual const IEndpoint* getAssertionConsumerServiceURL(const XMLCh* id) const=0;
        virtual ~ISPProviderRole() {}
    };

    struct SHIB_EXPORTS IPDPProviderRole : public virtual IProviderRole
    {
        virtual saml::Iterator<const IEndpoint*> getAuthorizationServices() const=0;
        virtual ~IPDPProviderRole() {}
    };

    struct SHIB_EXPORTS IAttributeAuthorityRole : public virtual IProviderRole
    {
        virtual saml::Iterator<const IEndpoint*> getAttributeServices() const=0;
        virtual ~IAttributeAuthorityRole() {}
    };

    struct SHIB_EXPORTS IAttributeConsumingService
    {
        virtual const XMLCh* getName(const XMLCh* lang) const=0;
        virtual const XMLCh* getDescription(const XMLCh* lang) const=0;
        virtual saml::Iterator<std::pair<const saml::SAMLAttributeDesignator*,bool> > getWantedAttributes() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IAttributeConsumingService() {}
    };

    struct SHIB_EXPORTS IAttributeConsumerRole : public virtual IProviderRole
    {
        virtual const IAttributeConsumingService* getDefaultAttributeConsumingService() const=0;
        virtual const IAttributeConsumingService* getAttributeConsumingService(const XMLCh* id) const=0;
        virtual saml::Iterator<const IAttributeConsumingService*> getAttributeConsumingServices() const=0;
        virtual ~IAttributeConsumerRole() {}
    };

    struct SHIB_EXPORTS IProvider
    {
        virtual const XMLCh* getId() const=0;
        virtual saml::Iterator<const XMLCh*> getGroups() const=0;
        virtual const IOrganization* getOrganization() const=0;
        virtual saml::Iterator<const IContactPerson*> getContacts() const=0;
        virtual saml::Iterator<const IProviderRole*> getRoles() const=0;
        virtual const DOMElement* getElement() const=0;
        virtual saml::Iterator<std::pair<const XMLCh*,bool> > getSecurityDomains() const=0;
        virtual ~IProvider() {}
    };
    
    struct SHIB_EXPORTS IMetadata : public virtual ILockable, public virtual IPlugIn
    {
        virtual const IProvider* lookup(const XMLCh* providerId) const=0;
        virtual ~IMetadata() {}
    };

    struct SHIB_EXPORTS IRevocation : public virtual ILockable, public virtual IPlugIn
    {
        virtual saml::Iterator<void*> getRevocationLists(const IProvider* provider, const IProviderRole* role=NULL) const=0;
        virtual ~IRevocation() {}
    };

    // Trust interface hides *all* details of signature and SSL validation.
    // Pluggable providers can fully override the Shibboleth trust model here.
    
    struct SHIB_EXPORTS ITrust : public virtual IPlugIn
    {
        virtual bool validate(
            const saml::Iterator<IRevocation*>& revocations,
            const IProviderRole* role, const saml::SAMLSignedObject& token,
            const saml::Iterator<IMetadata*>& metadatas=EMPTY(IMetadata*)
            )=0;
        virtual bool attach(const saml::Iterator<IRevocation*>& revocations, const IProviderRole* role, void* ctx)=0;
        virtual ~ITrust() {}
    };
    
    struct SHIB_EXPORTS ICredResolver : public virtual IPlugIn
    {
        virtual void attach(void* ctx) const=0;
        virtual XSECCryptoKey* getKey() const=0;
        virtual saml::Iterator<XSECCryptoX509*> getCertificates() const=0;
        virtual void dump(FILE* f) const=0;
        virtual void dump() const { dump(stdout); }
        virtual ~ICredResolver() {}
    };

    struct SHIB_EXPORTS ICredentials : public virtual ILockable, public virtual IPlugIn
    {
        virtual const ICredResolver* lookup(const char* id) const=0;
        virtual ~ICredentials() {}
    };
    
    struct SHIB_EXPORTS IAttributeRule
    {
        virtual const XMLCh* getName() const=0;
        virtual const XMLCh* getNamespace() const=0;
        virtual const char* getFactory() const=0;
        virtual const char* getAlias() const=0;
        virtual const char* getHeader() const=0;
        virtual void apply(const IProvider* originSite, saml::SAMLAttribute& attribute) const=0;
        virtual ~IAttributeRule() {}
    };
    
    struct SHIB_EXPORTS IAAP : public virtual ILockable, public virtual IPlugIn
    {
        virtual const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const=0;
        virtual const IAttributeRule* lookup(const char* alias) const=0;
        virtual saml::Iterator<const IAttributeRule*> getAttributeRules() const=0;
        virtual ~IAAP() {}
    };

#ifdef SHIB_INSTANTIATE
    template class SHIB_EXPORTS saml::Iterator<const IContactPerson*>;
    template class SHIB_EXPORTS saml::Iterator<const IProviderRole*>;
    template class SHIB_EXPORTS saml::Iterator<const IKeyDescriptor*>;
    template class SHIB_EXPORTS saml::Iterator<const IEndpoint*>;
    template class SHIB_EXPORTS saml::Iterator<const IAttributeRule*>;
    template class SHIB_EXPORTS saml::Iterator<IMetadata*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IMetadata*>;
    template class SHIB_EXPORTS saml::Iterator<ITrust*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ITrust*>;
    template class SHIB_EXPORTS saml::Iterator<IRevocation*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IRevocation*>;
    template class SHIB_EXPORTS saml::Iterator<ICredentials*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ICredentials*>;
    template class SHIB_EXPORTS saml::Iterator<IAAP*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IAAP*>;
#endif

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
        static const XMLCh SHIB_NAMEID_FORMAT_URI[];
        static const XMLCh SHIB_NS[];
        static const XMLCh InvalidHandle[];
    };

    // Glue classes between abstract metadata and concrete providers
    
    class SHIB_EXPORTS Locker
    {
    public:
        Locker(ILockable* lockee) : m_lockee(lockee) {m_lockee->lock();}
        ~Locker() {if (m_lockee) m_lockee->unlock();}
        
    private:
        Locker(const Locker&);
        void operator=(const Locker&);
        ILockable* m_lockee;
    };
    
    class SHIB_EXPORTS Metadata
    {
    public:
        Metadata(const saml::Iterator<IMetadata*>& metadatas) : m_metadatas(metadatas), m_mapper(NULL) {}
        ~Metadata();

        const IProvider* lookup(const XMLCh* providerId);

    private:
        Metadata(const Metadata&);
        void operator=(const Metadata&);
        IMetadata* m_mapper;
        const saml::Iterator<IMetadata*>& m_metadatas;
    };

    class SHIB_EXPORTS Revocation
    {
    public:
        Revocation(const saml::Iterator<IRevocation*>& revocations) : m_revocations(revocations), m_mapper(NULL) {}
        ~Revocation();

        saml::Iterator<void*> getRevocationLists(const IProvider* provider, const IProviderRole* role=NULL);

    private:
        Revocation(const Revocation&);
        void operator=(const Revocation&);
        IRevocation* m_mapper;
        const saml::Iterator<IRevocation*>& m_revocations;
    };

    class SHIB_EXPORTS Trust
    {
    public:
        Trust(const saml::Iterator<ITrust*>& trusts) : m_trusts(trusts) {}
        ~Trust() {}

        bool validate(
            const saml::Iterator<IRevocation*>& revocations,
            const IProviderRole* role, const saml::SAMLSignedObject& token,
            const saml::Iterator<IMetadata*>& metadatas=EMPTY(IMetadata*)
            ) const;
        bool attach(const saml::Iterator<IRevocation*>& revocations, const IProviderRole* role, void* ctx) const;
        
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
        
        static void apply(const saml::Iterator<IAAP*>& aaps, const IProvider* originSite, saml::SAMLAssertion& assertion);
        
    private:
        AAP(const AAP&);
        void operator=(const AAP&);
        IAAP* m_mapper;
        const IAttributeRule* m_rule;
    };

    // Wrapper classes around the POST profile and SAML binding

    class SHIB_EXPORTS ShibPOSTProfile
    {
    public:
        ShibPOSTProfile(
            const saml::Iterator<IMetadata*>& metadatas=EMPTY(IMetadata*),
            const saml::Iterator<IRevocation*>& revocations=EMPTY(IRevocation*),
            const saml::Iterator<ITrust*>& trusts=EMPTY(ITrust*),
            const saml::Iterator<ICredentials*>& creds=EMPTY(ICredentials*)
            );
        virtual ~ShibPOSTProfile() {}

        virtual const saml::SAMLAssertion* getSSOAssertion(
            const saml::SAMLResponse& r, const saml::Iterator<const XMLCh*>& audiences=EMPTY(const XMLCh*)
            );
        virtual const saml::SAMLAuthenticationStatement* getSSOStatement(const saml::SAMLAssertion& a);
        virtual saml::SAMLResponse* accept(
            const XMLByte* buf,
            const XMLCh* recipient,
            int ttlSeconds,
            const saml::Iterator<const XMLCh*>& audiences=EMPTY(const XMLCh*),
            XMLCh** pproviderId=NULL
            );
        virtual saml::SAMLResponse* prepare(
            const IIDPProviderRole* role,
            const char* credResolverId,
            const XMLCh* recipient,
            const XMLCh* authMethod,
            time_t authInstant,
            const XMLCh* name,
            const XMLCh* format=Constants::SHIB_NAMEID_FORMAT_URI,
            const XMLCh* nameQualifier=NULL,
            const XMLCh* subjectIP=NULL,
            const saml::Iterator<const XMLCh*>& audiences=EMPTY(const XMLCh*),
            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings=EMPTY(saml::SAMLAuthorityBinding*)
            );
        virtual bool checkReplayCache(const saml::SAMLAssertion& a);
        virtual const XMLCh* getProviderId(const saml::SAMLResponse& r);

    protected:
        const saml::Iterator<IMetadata*>& m_metadatas;
        const saml::Iterator<IRevocation*>& m_revocations;
        const saml::Iterator<ITrust*>& m_trusts;
        const saml::Iterator<ICredentials*>& m_creds;
    };

    class SHIB_EXPORTS ShibBinding
    {
    public:
        ShibBinding(
            const saml::Iterator<IRevocation*>& revocations,
            const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<ICredentials*>& creds
            ) : m_revocations(revocations), m_trusts(trusts), m_creds(creds),
                m_credResolverId(NULL), m_AA(NULL), m_binding(NULL) {}
        virtual ~ShibBinding() {delete m_binding;}

        saml::SAMLResponse* send(
            saml::SAMLRequest& req,
            const IAttributeAuthorityRole* AA,
            const char* credResolverId=NULL,
            const saml::Iterator<const XMLCh*>& audiences=EMPTY(const XMLCh*),
            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings=EMPTY(saml::SAMLAuthorityBinding*),
            saml::SAMLConfig::SAMLBindingConfig& conf=saml::SAMLConfig::getConfig().binding_defaults
            );

    private:
        friend bool ssl_ctx_callback(void* ssl_ctx, void* userptr);
        const saml::Iterator<IRevocation*>& m_revocations;
        const saml::Iterator<ITrust*>& m_trusts;
        const saml::Iterator<ICredentials*>& m_creds;
        const char* m_credResolverId;
        const IAttributeAuthorityRole* m_AA;
        saml::SAMLBinding* m_binding;
    };

    class SHIB_EXPORTS ShibConfig
    {
    public:
        ShibConfig() {}
        virtual ~ShibConfig() {}

        // global per-process setup and shutdown of Shibboleth runtime
        virtual bool init();
        virtual void term();

        // enables runtime and clients to access configuration
        static ShibConfig& getConfig();

        // allows pluggable implementations of metadata and configuration data
        PlugManager m_plugMgr;
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

    class SHIB_EXPORTS ReloadableXMLFile : protected virtual ILockable
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
}

#endif
