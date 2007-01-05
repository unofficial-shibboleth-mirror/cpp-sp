/*
 *  Copyright 2001-2005 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* shib.h - Shibboleth header file

   Scott Cantor
   6/4/02

   $History:$
*/

#ifndef __shib_h__
#define __shib_h__

#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/TrustEngine.h>
#include <xmltooling/signature/CredentialResolver.h>
#include <xmltooling/util/Threads.h>

#include <saml/saml.h>
#undef SAML10_PROTOCOL_ENUM

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
    // Credentials interface abstracts access to "owned" keys and certificates.
    
    struct SHIB_EXPORTS ICredentials : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        virtual xmlsignature::CredentialResolver* lookup(const char* id) const=0;
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
        virtual void apply(saml::SAMLAttribute& attribute, const opensaml::saml2md::RoleDescriptor* role=NULL) const=0;
        virtual ~IAttributeRule() {}
    };
    
    struct SHIB_EXPORTS IAAP : public virtual xmltooling::Lockable, public virtual saml::IPlugIn
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
    template class SHIB_EXPORTS saml::Iterator<ICredentials*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ICredentials*>;
    template class SHIB_EXPORTS saml::Iterator<IAAP*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IAAP*>;
#endif

    class SHIB_EXPORTS Credentials
    {
    public:
        Credentials(const saml::Iterator<ICredentials*>& creds) : m_creds(creds), m_mapper(NULL) {}
        ~Credentials();

        xmlsignature::CredentialResolver* lookup(const char* id);

    private:
        Credentials(const Credentials&);
        void operator=(const Credentials&);
        ICredentials* m_mapper;
        saml::Iterator<ICredentials*> m_creds;
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
        
        static void apply(
            const saml::Iterator<IAAP*>& aaps, saml::SAMLAssertion& assertion, const opensaml::saml2md::RoleDescriptor* role=NULL
            );
        
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
        struct SHIB_EXPORTS ITokenValidator {
            virtual void validateToken(
                saml::SAMLAssertion* token,
                time_t=0,
                const opensaml::saml2md::RoleDescriptor* role=NULL,
                const xmltooling::TrustEngine* trustEngine=NULL
                ) const=0;
            virtual ~ITokenValidator() {}
        };

        ShibBrowserProfile(
            const ITokenValidator* validator,
            opensaml::saml2md::MetadataProvider* metadata=NULL,
            xmltooling::TrustEngine* trust=NULL
            );
        virtual ~ShibBrowserProfile();

        virtual saml::SAMLBrowserProfile::BrowserProfileResponse receive(
            const char* samlResponse,
            const XMLCh* recipient,
            saml::IReplayCache* replayCache,
            int minorVersion=1
            ) const;
        virtual saml::SAMLBrowserProfile::BrowserProfileResponse receive(
            saml::Iterator<const char*> artifacts,
            const XMLCh* recipient,
            saml::SAMLBrowserProfile::ArtifactMapper* artifactMapper,
            saml::IReplayCache* replayCache,
            int minorVersion=1
            ) const;

    private:
        void postprocess(saml::SAMLBrowserProfile::BrowserProfileResponse& bpr, int minorVersion=1) const;

        saml::SAMLBrowserProfile* m_profile;
        opensaml::saml2md::MetadataProvider* m_metadata;
        xmltooling::TrustEngine* m_trust;
        const ITokenValidator* m_validator;
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
        xmltooling::RWLock* m_lock;
    };
}

#endif
