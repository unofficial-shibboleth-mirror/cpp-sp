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


/* ShibConfig.cpp - Shibboleth runtime configuration

   Scott Cantor
   6/4/02

   $History:$
*/

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SHIB_INSTANTIATE

#include "internal.h"
#include <openssl/err.h>

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;
using namespace std;

SAML_EXCEPTION_FACTORY(UnsupportedProtocolException);
SAML_EXCEPTION_FACTORY(MetadataException);
SAML_EXCEPTION_FACTORY(CredentialException);

namespace {
    ShibInternalConfig g_config;
}

ShibConfig::~ShibConfig() {}

bool ShibInternalConfig::init()
{
    saml::NDC ndc("init");

    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,UnsupportedProtocolException);
    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,MetadataException);
    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,CredentialException);

    return true;
}

void ShibInternalConfig::regFactory(const char* type, MetadataFactory* factory)
{
    if (type && factory)
        m_metadataFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, RevocationFactory* factory)
{
    if (type && factory)
        m_revocationFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, TrustFactory* factory)
{
    if (type && factory)
        m_trustFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, CredentialsFactory* factory)
{
    if (type && factory)
    {
        m_credFactoryMap[type]=factory;
        SAMLConfig::getConfig().binding_defaults.ssl_ctx_callback=
            reinterpret_cast<SAMLConfig::SAMLBindingConfig::ssl_ctx_callback_fn>(ssl_ctx_callback);
    }
}

void ShibInternalConfig::regFactory(const char* type, CredResolverFactory* factory)
{
    if (type && factory)
        m_credResolverFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, AAPFactory* factory)
{
    if (type && factory)
        m_aapFactoryMap[type]=factory;
}

void ShibInternalConfig::unregFactory(const char* type)
{
    if (type) {
        m_metadataFactoryMap.erase(type);
        m_revocationFactoryMap.erase(type);
        m_trustFactoryMap.erase(type);
        m_credFactoryMap.erase(type);
        m_aapFactoryMap.erase(type);
        m_credResolverFactoryMap.erase(type);
    }
}

IMetadata* ShibInternalConfig::newMetadata(const char* type, const DOMElement* source) const
{
    MetadataFactoryMap::const_iterator i=m_metadataFactoryMap.find(type);
    if (i==m_metadataFactoryMap.end())
    {
        NDC ndc("newMetadata");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown metadata type: %s",type);
        return NULL;
    }
    return i->second(source);
}

IRevocation* ShibInternalConfig::newRevocation(const char* type, const DOMElement* source) const
{
    RevocationFactoryMap::const_iterator i=m_revocationFactoryMap.find(type);
    if (i==m_revocationFactoryMap.end())
    {
        NDC ndc("newRevocation");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown revocation type: %s",type);
        return NULL;
    }
    return i->second(source);
}

ITrust* ShibInternalConfig::newTrust(const char* type, const DOMElement* source) const
{
    TrustFactoryMap::const_iterator i=m_trustFactoryMap.find(type);
    if (i==m_trustFactoryMap.end())
    {
        NDC ndc("newTrust");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown trust type: %s",type);
        return NULL;
    }
    return i->second(source);
}

ICredentials* ShibInternalConfig::newCredentials(const char* type, const DOMElement* source) const
{
    CredentialsFactoryMap::const_iterator i=m_credFactoryMap.find(type);
    if (i==m_credFactoryMap.end())
    {
        NDC ndc("newCredentials");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown credentials type: %s",type);
        return NULL;
    }
    return i->second(source);
}

IAAP* ShibInternalConfig::newAAP(const char* type, const DOMElement* source) const
{
    AAPFactoryMap::const_iterator i=m_aapFactoryMap.find(type);
    if (i==m_aapFactoryMap.end())
    {
        NDC ndc("newAAP");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown AAP type: %s",type);
        return NULL;
    }
    return i->second(source);
}

ICredResolver* ShibInternalConfig::newCredResolver(const char* type, const DOMElement* source) const
{
    CredResolverFactoryMap::const_iterator i=m_credResolverFactoryMap.find(type);
    if (i==m_credResolverFactoryMap.end())
    {
        NDC ndc("newCredResolver");
        Category::getInstance(SHIB_LOGCAT".ShibInternalConfig").error("unknown cred resolver type: %s",type);
        return NULL;
    }
    return i->second(source);
}

ShibConfig& ShibConfig::getConfig()
{
    return g_config;
}

void shibboleth::log_openssl()
{
    const char* file;
    const char* data;
    int flags,line;

    unsigned long code=ERR_get_error_line_data(&file,&line,&data,&flags);
    while (code)
    {
        Category& log=Category::getInstance("OpenSSL");
        log.errorStream() << "error code: " << code << " in " << file << ", line " << line << CategoryStream::ENDLINE;
        if (data && (flags & ERR_TXT_STRING))
            log.errorStream() << "error data: " << data << CategoryStream::ENDLINE;
        code=ERR_get_error_line_data(&file,&line,&data,&flags);
    }
}
