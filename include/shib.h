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

#include <saml.h>

#define SHIB_LOGCAT "Shibboleth"

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
            name(const char* msg) : saml::base(msg) {} \
            name(const std::string& msg) : saml::base(msg) {} \
            name(const saml::Iterator<saml::QName>& codes, const char* msg) : saml::base(codes,msg) {} \
            name(const saml::Iterator<saml::QName>& codes, const std::string& msg) : saml::base(codes, msg) {} \
            name(const saml::QName& code, const char* msg) : saml::base(code,msg) {} \
            name(const saml::QName& code, const std::string& msg) : saml::base(code, msg) {} \
            name(DOMElement* e) : saml::base(e) {} \
            name(std::istream& in) : saml::base(in) {} \
            virtual ~name() throw () {} \
        }

    DECLARE_SHIB_EXCEPTION(UnsupportedProtocolException,SAMLException);
    DECLARE_SHIB_EXCEPTION(OriginSiteMapperException,SAMLException);

    struct SHIB_EXPORTS IOriginSiteMapper
    {
        virtual saml::Iterator<saml::xstring> getHandleServiceNames(const XMLCh* originSite)=0;
        virtual saml::Key* getHandleServiceKey(const XMLCh* handleService)=0;
        virtual saml::Iterator<saml::xstring> getSecurityDomains(const XMLCh* originSite)=0;
        virtual saml::Iterator<saml::X509Certificate*> getTrustedRoots()=0;
    };

    class SHIB_EXPORTS XMLOriginSiteMapper : public IOriginSiteMapper
    {
    public:
        XMLOriginSiteMapper(const char* registryURI,
                            const saml::Iterator<saml::X509Certificate*>& roots,
                            saml::Key* verifyKey=NULL);
        ~XMLOriginSiteMapper();

        virtual saml::Iterator<saml::xstring> getHandleServiceNames(const XMLCh* originSite);
        virtual saml::Key* getHandleServiceKey(const XMLCh* handleService);
        virtual saml::Iterator<saml::xstring> getSecurityDomains(const XMLCh* originSite);
        virtual saml::Iterator<saml::X509Certificate*> getTrustedRoots();

    private:
        struct OriginSite
        {
            std::vector<saml::xstring> m_handleServices;
            std::vector<saml::xstring> m_domains;
        };

        std::vector<saml::X509Certificate*> m_roots;
        std::map<saml::xstring,OriginSite*> m_sites;
        std::map<saml::xstring,saml::Key*> m_hsKeys;
    };

    class SHIB_EXPORTS ShibPOSTProfile
    {
    public:
        ShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, IOriginSiteMapper* mapper, const XMLCh* receiver, int ttlSeconds);
        ShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
        virtual ~ShibPOSTProfile();

        virtual saml::SAMLAssertion* getSSOAssertion(const saml::SAMLResponse& r);
        virtual saml::SAMLAuthenticationStatement* getSSOStatement(const saml::SAMLAssertion& a);
        virtual saml::SAMLResponse* accept(const XMLByte* buf);
        virtual saml::SAMLResponse* prepare(const XMLCh* recipient,
                                            const XMLCh* name,
                                            const XMLCh* nameQualifier,
                                            const XMLCh* subjectIP,
                                            const XMLCh* authMethod,
                                            time_t authInstant,
                                            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings,
                                            const saml::Key& responseKey, const saml::X509Certificate* responseCert=NULL,
                                            const saml::Key* assertionKey=NULL, const saml::X509Certificate* assertionCert=NULL);
        virtual bool checkReplayCache(const saml::SAMLAssertion& a);

    protected:
        virtual bool verifySignature(const saml::SAMLSignedObject& obj, const XMLCh* signerName,
                                     const saml::Iterator<saml::X509Certificate*>& roots, const saml::Key* knownKey);

        saml::SAMLSignedObject::sigs_t m_algorithm;
        IOriginSiteMapper* m_mapper;
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
        ClubShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, IOriginSiteMapper* mapper, const XMLCh* receiver, int ttlSeconds);
        ClubShibPOSTProfile(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
        virtual ~ClubShibPOSTProfile();

        virtual saml::SAMLResponse* prepare(const XMLCh* recipient,
                                            const XMLCh* name,
                                            const XMLCh* nameQualifier,
                                            const XMLCh* subjectIP,
                                            const XMLCh* authMethod,
                                            time_t authInstant,
                                            const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings,
                                            const saml::Key& responseKey, const saml::X509Certificate* responseCert=NULL,
                                            const saml::Key* assertionKey=NULL, const saml::X509Certificate* assertionCert=NULL);

    protected:
        virtual bool verifySignature(const saml::SAMLSignedObject& obj, const XMLCh* signerName,
                                     const saml::Iterator<saml::X509Certificate*>& roots, const saml::Key* knownKey);
    };

    class SHIB_EXPORTS ShibPOSTProfileFactory
    {
    public:
        static ShibPOSTProfile* getInstance(const saml::Iterator<const XMLCh*>& policies, IOriginSiteMapper* mapper,
                                            const XMLCh* receiver, int ttlSeconds);
        static ShibPOSTProfile* getInstance(const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer);
    };

    class SHIB_EXPORTS ShibConfig
    {
    public:
        // global per-process setup and shutdown of Shibboleth runtime
        virtual bool init();
        virtual void term();

        // enables runtime and clients to access configuration
        static ShibConfig& getConfig();

    /* start of external configuration */
        IOriginSiteMapper* origin_mapper;
    /* end of external configuration */
    };

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh POLICY_CLUBSHIB[];
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
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
            static const XMLCh Domain[];
            static const XMLCh HandleService[];
            static const XMLCh InvalidHandle[];
            static const XMLCh Name[];
            static const XMLCh OriginSite[];
            static const XMLCh Sites[];

            // XML vocabulary
            static const XMLCh xmlns_shib[];
        };
    };


    class SHIB_EXPORTS SAMLBindingFactory
    {
    public:
        static saml::SAMLBinding* getInstance(const XMLCh* protocol=saml::SAMLBinding::SAML_SOAP_HTTPS);
    };
}

#endif
