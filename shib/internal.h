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


/* internal.h - internally visible classes

   Scott Cantor
   9/6/02

   $History:$
*/

#ifndef __shib_internal_h__
#define __shib_internal_h__

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include "shib.h"

#include <openssl/x509.h>

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth
{
    class ClubShibPOSTProfile : public ShibPOSTProfile
    {
    public:
        ClubShibPOSTProfile(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds
            );
        ClubShibPOSTProfile(
            const saml::Iterator<IMetadata*>& metadatas, const saml::Iterator<ICredentials*>& creds,
            const saml::Iterator<const XMLCh*>& policies, const XMLCh* issuer
            );
        virtual ~ClubShibPOSTProfile();

        saml::SAMLResponse* prepare(
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

    protected:
        void verifySignature(
            const saml::SAMLSignedObject& obj,
            const IOriginSite* originSite,
            const XMLCh* signerName,
            XSECCryptoKey* knownKey=NULL);
    };
    
    class ShibSOAPBinding : public saml::SAMLSOAPBinding
    {
    public:
        ShibSOAPBinding(
            const saml::Iterator<IMetadata*>& metadatas,
            const saml::Iterator<ITrust*>& trusts,
            const saml::Iterator<ICredentials*>& creds,
            const XMLCh* subject,
            const ISite* relyingParty
            ) : m_metadatas(metadatas), m_creds(creds), m_trusts(trusts), m_subject(subject), m_relyingParty(relyingParty) {}
        virtual ~ShibSOAPBinding() {}

        virtual saml::SAMLResponse* send(
            const saml::SAMLAuthorityBinding& bindingInfo,
            saml::SAMLRequest& req,
            saml::SAMLConfig::SAMLBindingConfig& conf=saml::SAMLConfig::getConfig().binding_defaults
            );

    private:
        friend bool ssl_ctx_callback(void* ssl_ctx, void* userptr);
        const XMLCh* m_subject;
        const ISite* m_relyingParty;
        const saml::Iterator<IMetadata*>& m_metadatas;
        const saml::Iterator<ITrust*>& m_trusts;
        const saml::Iterator<ICredentials*>& m_creds;
    };

    class ShibInternalConfig : public ShibConfig
    {
    public:
        ShibInternalConfig() {}

        bool init();
        void term() {}

        void regFactory(const char* type, MetadataFactory* factory);
        void regFactory(const char* type, TrustFactory* factory);
        void regFactory(const char* type, CredentialsFactory* factory);
        void regFactory(const char* type, CredResolverFactory* factory);
        void regFactory(const char* type, AAPFactory* factory);
        void unregFactory(const char* type);
        
        IMetadata* newMetadata(const char* type, const char* source) const;
        ITrust* newTrust(const char* type, const char* source) const;
        ICredentials* newCredentials(const char* type, const char* source) const;
        IAAP* newAAP(const char* type, const char* source) const;
        ICredResolver* newCredResolver(const char* type, const DOMElement* source) const;

    private:
        friend class OriginMetadata;
        friend class Trust;
        friend class Credentials;
        friend class AAP;
        
        typedef std::map<std::string, MetadataFactory*> MetadataFactoryMap;
        typedef std::map<std::string, TrustFactory*> TrustFactoryMap;
        typedef std::map<std::string, CredentialsFactory*> CredentialsFactoryMap;
        typedef std::map<std::string, CredResolverFactory*> CredResolverFactoryMap;
        typedef std::map<std::string, AAPFactory*> AAPFactoryMap;
        MetadataFactoryMap m_metadataFactoryMap;
        TrustFactoryMap m_trustFactoryMap;
        CredentialsFactoryMap m_credFactoryMap;
        CredResolverFactoryMap m_credResolverFactoryMap;
        AAPFactoryMap m_aapFactoryMap;
    };

    // OpenSSL Utilities
    
    // Custom metadata-driven SSL context callback
    bool ssl_ctx_callback(void* ssl_ctx, void* userptr);
    
    // Log errors from OpenSSL error queue
    void log_openssl();

    // build an OpenSSL cert out of a base-64 encoded DER buffer (XML style)
    X509* B64_to_X509(const char* buf);
}

#endif
