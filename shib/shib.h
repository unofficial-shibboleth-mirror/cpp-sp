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
#include <openssl/ssl.h>

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

#define SHIB_L(s) shibboleth::XML::Literals::s
#define SHIB_L_QNAME(p,s) shibboleth::XML::Literals::p##_##s

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

    DECLARE_SHIB_EXCEPTION(UnsupportedProtocolException,SAMLException);
    DECLARE_SHIB_EXCEPTION(MetadataException,SAMLException);

    // Metadata abstract interfaces
    
    struct SHIB_EXPORTS ILockable
    {
        virtual void lock()=0;
        virtual void unlock()=0;
        virtual ~ILockable() {}
    };
    
    struct SHIB_EXPORTS IContactInfo
    {
        enum ContactType { technical, administrative, billing, other };
        virtual ContactType getType() const=0;
        virtual const char* getName() const=0;
        virtual const char* getEmail() const=0;
        virtual ~IContactInfo() {}
    };
    
    struct SHIB_EXPORTS ITrust; // forward decl
    
    struct SHIB_EXPORTS ISite
    {
        virtual const XMLCh* getName() const=0;
        virtual saml::Iterator<const XMLCh*> getGroups() const=0;
        virtual saml::Iterator<const IContactInfo*> getContacts() const=0;
        virtual const char* getErrorURL() const=0;
        virtual bool validate(const saml::Iterator<ITrust*>& trusts, const saml::Iterator<XSECCryptoX509*>& certs) const=0;
        virtual bool validate(const saml::Iterator<ITrust*>& trusts, const saml::Iterator<const XMLCh*>& certs) const=0;
        virtual ~ISite() {}
    };
    
    struct SHIB_EXPORTS IAuthority
    {
        virtual const XMLCh* getName() const=0;
        virtual const char* getURL() const=0;
        virtual ~IAuthority() {}
    };

    struct SHIB_EXPORTS IOriginSite : public ISite
    {
        virtual saml::Iterator<const IAuthority*> getHandleServices() const=0;
        virtual saml::Iterator<const IAuthority*> getAttributeAuthorities() const=0;
        virtual saml::Iterator<std::pair<const XMLCh*,bool> > getSecurityDomains() const=0;
        virtual ~IOriginSite() {}
    };

    struct SHIB_EXPORTS IMetadata : public virtual ILockable
    {
        virtual const ISite* lookup(const XMLCh* site) const=0;
        virtual ~IMetadata() {}
    };

    struct SHIB_EXPORTS ITrust : public virtual ILockable
    {
        virtual saml::Iterator<XSECCryptoX509*> getCertificates(const XMLCh* subject) const=0;
        virtual bool validate(const ISite* site, const saml::Iterator<XSECCryptoX509*>& certs) const=0;
        virtual bool validate(const ISite* site, const saml::Iterator<const XMLCh*>& certs) const=0;
        virtual bool attach(const ISite* site, SSL_CTX* ctx) const=0;
        virtual ~ITrust() {}
    };
    
    struct SHIB_EXPORTS ICredentials : public virtual ILockable
    {
        virtual bool attach(const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx) const=0;
        virtual ~ICredentials() {}
    };
    
    struct SHIB_EXPORTS ICredResolver
    {
        virtual void resolveKey(SSL_CTX* ctx) const=0;
        virtual void resolveCert(SSL_CTX* ctx) const=0;
        virtual void dump(FILE* f) const=0;
        virtual void dump() const { dump(stdout); }
        virtual ~ICredResolver() {}
    };

    struct SHIB_EXPORTS IAttributeRule
    {
        virtual const XMLCh* getName() const=0;
        virtual const XMLCh* getNamespace() const=0;
        virtual const char* getFactory() const=0;
        virtual const char* getAlias() const=0;
        virtual const char* getHeader() const=0;
        virtual void apply(const IOriginSite* originSite, saml::SAMLAttribute& attribute) const=0;
        virtual ~IAttributeRule() {}
    };
    
    struct SHIB_EXPORTS IAAP : public virtual ILockable
    {
        virtual const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const=0;
        virtual const IAttributeRule* lookup(const char* alias) const=0;
        virtual saml::Iterator<const IAttributeRule*> getAttributeRules() const=0;
        virtual ~IAAP() {}
    };

#ifdef SHIB_INSTANTIATE
    template class SHIB_EXPORTS saml::Iterator<const IContactInfo*>;
    template class SHIB_EXPORTS saml::ArrayIterator<const IContactInfo*>;
    template class SHIB_EXPORTS saml::Iterator<const IAuthority*>;
    template class SHIB_EXPORTS saml::ArrayIterator<const IAuthority*>;
    template class SHIB_EXPORTS saml::Iterator<const IAttributeRule*>;
    template class SHIB_EXPORTS saml::ArrayIterator<const IAttributeRule*>;
    template class SHIB_EXPORTS saml::Iterator<IMetadata*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IMetadata*>;
    template class SHIB_EXPORTS saml::Iterator<ITrust*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ITrust*>;
    template class SHIB_EXPORTS saml::Iterator<ICredentials*>;
    template class SHIB_EXPORTS saml::ArrayIterator<ICredentials*>;
    template class SHIB_EXPORTS saml::Iterator<IAAP*>;
    template class SHIB_EXPORTS saml::ArrayIterator<IAAP*>;
#endif

    class SHIB_EXPORTS ScopedAttribute : public saml::SAMLAttribute
    {
    public:
        ScopedAttribute(const XMLCh* name, const XMLCh* ns, long lifetime=0,
                        const saml::Iterator<const XMLCh*>& scopes=EMPTY(const XMLCh*),
                        const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*));
        ScopedAttribute(DOMElement* e);
        virtual ~ScopedAttribute();

        virtual saml::SAMLObject* clone() const;

        virtual saml::Iterator<const XMLCh*> getValues() const;
        virtual saml::Iterator<std::string> getSingleByteValues() const;
        virtual void setValues(const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*));
        virtual void addValue(const XMLCh* value);
        virtual void removeValue(unsigned int index);

    protected:
        virtual void valueToDOM(unsigned int index, DOMElement* e) const;

        const XMLCh* m_originSite;
        std::vector<const XMLCh*> m_scopes;
        mutable std::vector<const XMLCh*> m_scopedValues;
    };

    class SHIB_EXPORTS ShibPOSTProfile
    {
    public:
        ShibPOSTProfile(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds
            );
        ShibPOSTProfile(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ICredentials*>& creds,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer
            );
        virtual ~ShibPOSTProfile() {}

        virtual const saml::SAMLAssertion* getSSOAssertion(const saml::SAMLResponse& r);
        virtual const saml::SAMLAuthenticationStatement* getSSOStatement(const saml::SAMLAssertion& a);
        virtual saml::SAMLResponse* accept(const XMLByte* buf, XMLCh** originSitePtr=NULL);
        virtual saml::SAMLResponse* prepare(
            const XMLCh* recipient,
            const XMLCh* name,
            const XMLCh* nameQualifier,
            const XMLCh* subjectIP,
            const XMLCh* authMethod,
            time_t authInstant,
            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings,
            XSECCryptoKey* responseKey,
            const saml::Iterator<XSECCryptoX509*>& responseCerts=EMPTY(XSECCryptoX509*),
            XSECCryptoKey* assertionKey=NULL,
            const saml::Iterator<XSECCryptoX509*>& assertionCerts=EMPTY(XSECCryptoX509*)
            );
        virtual bool checkReplayCache(const saml::SAMLAssertion& a);

        virtual const XMLCh* getOriginSite(const saml::SAMLResponse& r);

    protected:
        virtual void verifySignature(
            const saml::SAMLSignedObject& obj,
            const IOriginSite* originSite,
            const XMLCh* signerName,
            XSECCryptoKey* knownKey=NULL);

        signatureMethod m_algorithm;
        const saml::Iterator<const XMLCh*>& m_policies;
        const saml::Iterator<IMetadata*>& m_metadatas;
        const saml::Iterator<ITrust*>& m_trusts;
        const saml::Iterator<ICredentials*>& m_creds;
        const XMLCh* m_issuer;
        const XMLCh* m_receiver;
        int m_ttlSeconds;
    };

    class SHIB_EXPORTS ShibPOSTProfileFactory
    {
    public:
        static ShibPOSTProfile* getInstance(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds
            );
        static ShibPOSTProfile* getInstance(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ICredentials*>& creds,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer
            );
    };

    // Glue classes between abstract metadata and concrete providers
    
    class SHIB_EXPORTS OriginMetadata
    {
    public:
        OriginMetadata(const saml::Iterator<IMetadata*>& metadatas, const XMLCh* site);
        ~OriginMetadata();
        bool fail() const {return m_mapper==NULL;}
        const IOriginSite* operator->() const {return m_site;}
        operator const IOriginSite*() const {return m_site;}
        
    private:
        OriginMetadata(const OriginMetadata&);
        void operator=(const OriginMetadata&);
        IMetadata* m_mapper;
        const IOriginSite* m_site;
    };

    class SHIB_EXPORTS Trust
    {
    public:
        Trust(const saml::Iterator<ITrust*>& trusts) : m_trusts(trusts), m_mapper(NULL) {}
        ~Trust();
        saml::Iterator<XSECCryptoX509*> getCertificates(const XMLCh* subject);
        bool validate(const ISite* site, saml::Iterator<XSECCryptoX509*> certs) const;
        bool validate(const ISite* site, saml::Iterator<const XMLCh*> certs) const;
        bool attach(const ISite* site, SSL_CTX* ctx) const;
        
    private:
        Trust(const Trust&);
        void operator=(const Trust&);
        ITrust* m_mapper;
        const saml::Iterator<ITrust*>& m_trusts;
    };
    
    class SHIB_EXPORTS Credentials
    {
    public:
        static bool attach(
            const saml::Iterator<ICredentials*>& creds, const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx
            );
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
        
        static void apply(const saml::Iterator<IAAP*>& aaps, const IOriginSite* originSite, saml::SAMLAssertion& assertion);
        
    private:
        AAP(const AAP&);
        void operator=(const AAP&);
        IAAP* m_mapper;
        const IAttributeRule* m_rule;
    };

    extern "C" {
        typedef IMetadata* MetadataFactory(const DOMElement* source);
        typedef ITrust* TrustFactory(const DOMElement* source);
        typedef ICredentials* CredentialsFactory(const DOMElement* source);
        typedef ICredResolver* CredResolverFactory(const DOMElement* source);
        typedef IAAP* AAPFactory(const DOMElement* source);
    }
    
    class SHIB_EXPORTS ShibConfig
    {
    public:
        ShibConfig() {}
        virtual ~ShibConfig();

        // global per-process setup and shutdown of Shibboleth runtime
        virtual bool init()=0;
        virtual void term()=0;

        // enables runtime and clients to access configuration
        static ShibConfig& getConfig();

        // allows pluggable implementations of metadata and configuration data
        virtual void regFactory(const char* type, MetadataFactory* factory)=0;
        virtual void regFactory(const char* type, TrustFactory* factory)=0;
        virtual void regFactory(const char* type, CredentialsFactory* factory)=0;
        virtual void regFactory(const char* type, CredResolverFactory* factory)=0;
        virtual void regFactory(const char* type, AAPFactory* factory)=0;
        virtual void unregFactory(const char* type)=0;
        
        // build a specific metadata lookup object
        virtual IMetadata* newMetadata(const char* type, const DOMElement* source) const=0;
        virtual ITrust* newTrust(const char* type, const DOMElement* source) const=0;
        virtual ICredentials* newCredentials(const char* type, const DOMElement* source) const=0;
        virtual IAAP* newAAP(const char* type, const DOMElement* source) const=0;
        virtual ICredResolver* newCredResolver(const char* type, const DOMElement* source) const=0;
    };

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
        static const XMLCh SHIB_NAMEID_FORMAT_URI[];
        
        static const XMLCh XMLSIG_RETMETHOD_RAWX509[];  // DER X.509 defined by xmlsig
        
        static saml::QName SHIB_ATTRIBUTE_VALUE_TYPE;
    };

    class SHIB_EXPORTS XML
    {
    public:
        // URI constants
        static const XMLCh SHIB_NS[];
        static const XMLCh SHIB_SCHEMA_ID[];

        struct SHIB_EXPORTS Literals
        {
            // Shibboleth vocabulary
            static const XMLCh AttributeValueType[];

            static const XMLCh Scope[];

            static const XMLCh AttributeAuthority[];
            static const XMLCh Contact[];
            static const XMLCh Domain[];
            static const XMLCh Email[];
            static const XMLCh ErrorURL[];
            static const XMLCh HandleService[];
            static const XMLCh InvalidHandle[];
            static const XMLCh Location[];
            static const XMLCh Name[];
            static const XMLCh OriginSite[];
            static const XMLCh SiteGroup[];
            
            static const XMLCh CertificateRef[];
            static const XMLCh Class[];
            static const XMLCh Credentials[];
            static const XMLCh CustomCredResolver[];
            static const XMLCh Exponent[];
            static const XMLCh FileCredResolver[];
            static const XMLCh Id[];
            static const XMLCh KeyAuthority[];
            static const XMLCh KeyRef[];
            static const XMLCh KeyUse[];
            static const XMLCh Modulus[];
            static const XMLCh Password[];
            static const XMLCh Path[];
            static const XMLCh RelyingParty[];
            static const XMLCh RetrievalMethod[];
            static const XMLCh RSAKeyValue[];
            static const XMLCh Trust[];
            static const XMLCh URI[];
            static const XMLCh VerifyDepth[];

            static const XMLCh Accept[];
            static const XMLCh Alias[];
            static const XMLCh AnySite[];
            static const XMLCh AnyValue[];
            static const XMLCh AttributeAcceptancePolicy[];
            static const XMLCh AttributeRule[];
            static const XMLCh Factory[];
            static const XMLCh Header[];
            static const XMLCh Namespace[];
            static const XMLCh SiteRule[];
            static const XMLCh Type[];
            static const XMLCh Value[];

            static const XMLCh literal[];
            static const XMLCh regexp[];
            static const XMLCh xpath[];

            static const XMLCh technical[];
            static const XMLCh administrative[];
            static const XMLCh billing[];
            static const XMLCh other[];
            
            static const XMLCh url[];

            // XML vocabulary
            static const XMLCh xmlns_shib[];
        };
    };

    class SHIB_EXPORTS SAMLBindingFactory
    {
    public:
        static saml::SAMLBinding* getInstance(
            const saml::Iterator<IMetadata*>& metadatas,
            const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<ICredentials*>& creds,
            const XMLCh* subject,
            const ISite* relyingParty,
            const XMLCh* protocol=saml::SAMLBinding::SAML_SOAP_HTTPS);
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
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname) const=0;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e) const=0;
        
    private:
        const DOMElement* m_root;
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
        mutable ReloadableXMLFileImpl* m_impl;
    };
}

#endif
