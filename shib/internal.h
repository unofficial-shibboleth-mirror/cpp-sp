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

#include <log4cpp/Category.hh>

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth
{
    class ShibInternalConfig : public ShibConfig
    {
    public:
        ShibInternalConfig() {}

        bool init();
        void term() {}

        void regFactory(const char* type, MetadataFactory* factory);
        void regFactory(const char* type, RevocationFactory* factory);
        void regFactory(const char* type, TrustFactory* factory);
        void regFactory(const char* type, CredentialsFactory* factory);
        void regFactory(const char* type, AAPFactory* factory);
        void regFactory(const char* type, CredResolverFactory* factory);
        void unregFactory(const char* type);
        
        IMetadata* newMetadata(const char* type, const DOMElement* source) const;
        IRevocation* newRevocation(const char* type, const DOMElement* source) const;
        ITrust* newTrust(const char* type, const DOMElement* source) const;
        ICredentials* newCredentials(const char* type, const DOMElement* source) const;
        IAAP* newAAP(const char* type, const DOMElement* source) const;
        ICredResolver* newCredResolver(const char* type, const DOMElement* source) const;

    private:
        typedef std::map<std::string, MetadataFactory*> MetadataFactoryMap;
        typedef std::map<std::string, RevocationFactory*> RevocationFactoryMap;
        typedef std::map<std::string, TrustFactory*> TrustFactoryMap;
        typedef std::map<std::string, CredentialsFactory*> CredentialsFactoryMap;
        typedef std::map<std::string, AAPFactory*> AAPFactoryMap;
        typedef std::map<std::string, CredResolverFactory*> CredResolverFactoryMap;
        MetadataFactoryMap m_metadataFactoryMap;
        RevocationFactoryMap m_revocationFactoryMap;
        TrustFactoryMap m_trustFactoryMap;
        CredentialsFactoryMap m_credFactoryMap;
        AAPFactoryMap m_aapFactoryMap;
        CredResolverFactoryMap m_credResolverFactoryMap;
    };

    // OpenSSL Utilities
    
    // Custom metadata-driven SSL context callback
    bool ssl_ctx_callback(void* ssl_ctx, void* userptr);
    
    // Log errors from OpenSSL error queue
    void log_openssl();
}

#endif
