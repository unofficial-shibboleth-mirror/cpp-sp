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
#include <openssl/x509.h>

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
#ifdef NO_RTTI
  extern SHIB_EXPORTS const unsigned short RTTI_UnsupportedProtocolException;
  extern SHIB_EXPORTS const unsigned short RTTI_OriginSiteMapperException;
#endif

    #define DECLARE_SHIB_EXCEPTION(name,base) \
        class SHIB_EXPORTS name : public saml::base \
        { \
        public: \
            name(const char* msg) : saml::base(msg) {RTTI(name); m_typename=#name;} \
            name(const std::string& msg) : saml::base(msg) {RTTI(name); m_typename=#name;} \
            name(const saml::Iterator<saml::QName>& codes, const char* msg) : saml::base(codes,msg) {RTTI(name); m_typename=#name;} \
            name(const saml::Iterator<saml::QName>& codes, const std::string& msg) : saml::base(codes, msg) {RTTI(name); m_typename=#name;} \
            name(const saml::QName& code, const char* msg) : saml::base(code,msg) {RTTI(name); m_typename=#name;} \
            name(const saml::QName& code, const std::string& msg) : saml::base(code, msg) {RTTI(name); m_typename=#name;} \
            name(DOMElement* e) : saml::base(e) {RTTI(name); m_typename=#name;} \
            name(std::istream& in) : saml::base(in) {RTTI(name); m_typename=#name;} \
            virtual ~name() throw () {} \
        }

    DECLARE_SHIB_EXCEPTION(UnsupportedProtocolException,SAMLException);
    DECLARE_SHIB_EXCEPTION(MetadataException,SAMLException);

    // Metadata abstract interfaces
    
    struct SHIB_EXPORTS IContactInfo
    {
        enum ContactType { technical, administrative, billing, other };
        virtual ContactType getType() const=0;
        virtual const char* getName() const=0;
        virtual const char* getEmail() const=0;
        virtual ~IContactInfo() {}
    };

    struct SHIB_EXPORTS ISite
    {
        virtual const XMLCh* getName() const=0;
        virtual saml::Iterator<const XMLCh*> getGroups() const=0;
        virtual saml::Iterator<const IContactInfo*> getContacts() const=0;
        virtual const char* getErrorURL() const=0;
        virtual bool validate(saml::Iterator<XSECCryptoX509*> certs) const=0;
        virtual bool validate(saml::Iterator<const XMLCh*> certs) const=0;
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

    struct SHIB_EXPORTS IMetadata
    {
        virtual void lock()=0;
        virtual void unlock()=0;
        virtual const ISite* lookup(const XMLCh* site) const=0;
        virtual ~IMetadata() {}
    };

    struct SHIB_EXPORTS ITrust
    {
        virtual void lock()=0;
        virtual void unlock()=0;
        virtual saml::Iterator<XSECCryptoX509*> getCertificates(const XMLCh* subject) const=0;
        virtual bool validate(const ISite* site, saml::Iterator<XSECCryptoX509*> certs) const=0;
        virtual bool validate(const ISite* site, saml::Iterator<const XMLCh*> certs) const=0;
        virtual ~ITrust() {}
    };

#ifdef SHIB_INSTANTIATE
# ifdef NO_RTTI
    const unsigned short RTTI_UnsupportedProtocolException=     RTTI_EXTENSION_BASE;
    const unsigned short RTTI_MetadataException=                RTTI_EXTENSION_BASE+1;
# endif
    template class SHIB_EXPORTS saml::Iterator<std::pair<saml::xstring,bool> >;
    template class SHIB_EXPORTS saml::ArrayIterator<std::pair<saml::xstring,bool> >;
    template class SHIB_EXPORTS saml::Iterator<const IContactInfo*>;
    template class SHIB_EXPORTS saml::ArrayIterator<const IContactInfo*>;
    template class SHIB_EXPORTS saml::Iterator<const IAuthority*>;
    template class SHIB_EXPORTS saml::ArrayIterator<const IAuthority*>;
#endif

    class SHIB_EXPORTS SimpleAttribute : public saml::SAMLAttribute
    {
    public:
        SimpleAttribute(const XMLCh* name, const XMLCh* ns, long lifetime=0,
                        const saml::Iterator<const XMLCh*>& values=saml::Iterator<const XMLCh*>());
        SimpleAttribute(DOMElement* e);
        virtual saml::SAMLObject* clone() const;
        virtual ~SimpleAttribute();

    protected:
        virtual bool accept(DOMElement* e) const;

        saml::xstring m_originSite;
    };

    class SHIB_EXPORTS ScopedAttribute : public SimpleAttribute
    {
    public:
        ScopedAttribute(const XMLCh* name, const XMLCh* ns, long lifetime=0,
                        const saml::Iterator<const XMLCh*>& scopes=saml::Iterator<const XMLCh*>(),
                        const saml::Iterator<const XMLCh*>& values=saml::Iterator<const XMLCh*>());
        ScopedAttribute(DOMElement* e);
        virtual ~ScopedAttribute();

        virtual DOMNode* toDOM(DOMDocument* doc=NULL, bool xmlns=true) const;
        virtual saml::SAMLObject* clone() const;

        virtual saml::Iterator<saml::xstring> getValues() const;
        virtual saml::Iterator<std::string> getSingleByteValues() const;

        static const XMLCh Scope[];

    protected:
        virtual bool accept(DOMElement* e) const;
        virtual bool addValue(DOMElement* e);

        std::vector<saml::xstring> m_scopes;
        mutable std::vector<saml::xstring> m_scopedValues;
    };

    class SHIB_EXPORTS ShibPOSTProfile
    {
    public:
        ShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds);
        ShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
        virtual ~ShibPOSTProfile();

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
            const saml::Iterator<XSECCryptoX509*>& responseCerts=saml::Iterator<XSECCryptoX509*>(),
            XSECCryptoKey* assertionKey=NULL,
            const saml::Iterator<XSECCryptoX509*>& assertionCerts=saml::Iterator<XSECCryptoX509*>()
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
        std::vector<const XMLCh*> m_policies;
        XMLCh* m_issuer;
        XMLCh* m_receiver;
        int m_ttlSeconds;

    private:
        ShibPOSTProfile(const ShibPOSTProfile&) {}
        ShibPOSTProfile& operator=(const ShibPOSTProfile&) {return *this;}
    };

    class SHIB_EXPORTS ClubShibPOSTProfile : public ShibPOSTProfile
    {
    public:
        ClubShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds);
        ClubShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
        virtual ~ClubShibPOSTProfile();

        virtual saml::SAMLResponse* prepare(
            const XMLCh* recipient,
            const XMLCh* name,
            const XMLCh* nameQualifier,
            const XMLCh* subjectIP,
            const XMLCh* authMethod,
            time_t authInstant,
            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings,
            XSECCryptoKey* responseKey,
            const saml::Iterator<XSECCryptoX509*>& responseCerts=saml::Iterator<XSECCryptoX509*>(),
            XSECCryptoKey* assertionKey=NULL,
            const saml::Iterator<XSECCryptoX509*>& assertionCerts=saml::Iterator<XSECCryptoX509*>()
            );

    protected:
        virtual void verifySignature(
            const saml::SAMLSignedObject& obj,
            const IOriginSite* originSite,
            const XMLCh* signerName,
            XSECCryptoKey* knownKey=NULL);
    };

    class SHIB_EXPORTS ShibPOSTProfileFactory
    {
    public:
        static ShibPOSTProfile* getInstance(const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds);
        static ShibPOSTProfile* getInstance(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
    };

    // Glue classes between abstract metadata and concrete providers
    
    class SHIB_EXPORTS OriginMetadata
    {
    public:
        OriginMetadata(const XMLCh* site);
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
        Trust() : m_mapper(NULL) {}
        ~Trust();
        saml::Iterator<XSECCryptoX509*> getCertificates(const XMLCh* subject);
        bool validate(const ISite* site, saml::Iterator<XSECCryptoX509*> certs) const;
        bool validate(const ISite* site, saml::Iterator<const XMLCh*> certs) const;
        
    private:
        Trust(const Trust&);
        void operator=(const Trust&);
        ITrust* m_mapper;
    };

    extern "C" { typedef IMetadata* MetadataFactory(const char* source); }
    extern "C" { typedef ITrust* TrustFactory(const char* source); }
    
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

        // allows pluggable implementations of metadata
        virtual void regFactory(const char* type, MetadataFactory* factory)=0;
        virtual void regFactory(const char* type, TrustFactory* factory)=0;
        virtual void unregFactory(const char* type)=0;
        
        // builds a specific metadata lookup object
        virtual bool addMetadata(const char* type, const char* source)=0;
        
    /* start of external configuration */
        std::string aapFile;
    /* end of external configuration */
    };

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
        static const XMLCh SHIB_NAMEID_FORMAT_URI[];
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
            
            static const XMLCh KeyAuthority[];
            static const XMLCh Trust[];

            static const XMLCh AnySite[];
            static const XMLCh AnyValue[];
            static const XMLCh AttributeAcceptancePolicy[];
            static const XMLCh AttributeRule[];
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

            // XML vocabulary
            static const XMLCh xmlns_shib[];
        };
    };


    class SHIB_EXPORTS SAMLBindingFactory
    {
    public:
        static saml::SAMLBinding* getInstance(const XMLCh* protocol=saml::SAMLBinding::SAML_SOAP_HTTPS);
    };

    // OpenSSL Utilities

    // Log errors from OpenSSL error queue.
    void log_openssl();

    // build an OpenSSL cert out of a base-64 encoded DER buffer (XML style)
    X509* B64_to_X509(const char* buf);
}

#endif
