/*
 * The OpenSAML License, Version 1.
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
 * Neither the name of OpenSAML nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact opensaml@opensaml.org
 *
 * Products derived from this software may not be called OpenSAML, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may OpenSAML appear in their name, without prior written permission of the
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
#include "shib-threads.h"

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth
{
    class XMLMetadataImpl;
    class SHIB_EXPORTS XMLMetadata : public IMetadata
    {
    public:
        XMLMetadata(const char* pathname);
        ~XMLMetadata();

        void lock();
        void unlock();
        const ISite* lookup(const XMLCh* site) const;

    private:
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
        XMLMetadataImpl* m_impl;
    };

    class XMLTrustImpl;
    class SHIB_EXPORTS XMLTrust : public ITrust
    {
    public:
        XMLTrust(const char* pathname);
        ~XMLTrust();

        void lock();
        void unlock();
        saml::Iterator<XSECCryptoX509*> getCertificates(const XMLCh* subject) const;
        bool validate(const ISite* site, saml::Iterator<XSECCryptoX509*> certs) const;
        bool validate(const ISite* site, saml::Iterator<const XMLCh*> certs) const;

    private:
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
        XMLTrustImpl* m_impl;
    };

    class XMLAAPImpl;
    class SHIB_EXPORTS XMLAAP : public IAAP
    {
    public:
        XMLAAP(const char* pathname);
        ~XMLAAP();
        
        void lock();
        void unlock();
        const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const;
        const IAttributeRule* lookup(const char* alias) const;
        saml::Iterator<const IAttributeRule*> getAttributeRules() const;

    private:
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
        XMLAAPImpl* m_impl;
    };
    
    class ShibInternalConfig : public ShibConfig
    {
    public:
        ShibInternalConfig() {}

        bool init();
        void term();

        void regFactory(const char* type, MetadataFactory* factory);
        void regFactory(const char* type, TrustFactory* factory);
        void regFactory(const char* type, AAPFactory* factory);
        void unregFactory(const char* type);
        
        bool addMetadata(const char* type, const char* source);

        saml::Iterator<IMetadata*> getMetadataProviders() const {return m_providers;}
        saml::Iterator<ITrust*> getTrustProviders() const {return m_trust_providers;}
        saml::Iterator<IAAP*> getAAPProviders() const {return m_aap_providers;}

    private:
        friend class OriginMetadata;
        friend class Trust;
        friend class AAP;
        
        typedef std::map<std::string, MetadataFactory*> MetadataFactoryMap;
        typedef std::map<std::string, TrustFactory*> TrustFactoryMap;
        typedef std::map<std::string, AAPFactory*> AAPFactoryMap;
        MetadataFactoryMap m_metadataFactoryMap;
        TrustFactoryMap m_trustFactoryMap;
        AAPFactoryMap m_aapFactoryMap;
        std::vector<IMetadata*> m_providers;
        std::vector<ITrust*> m_trust_providers;
        std::vector<IAAP*> m_aap_providers;
    };
}

#endif
