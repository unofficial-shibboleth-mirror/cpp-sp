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
#include <log4cpp/Category.hh>
#include <openssl/err.h>

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;
using namespace std;

SAML_EXCEPTION_FACTORY(UnsupportedProtocolException);
SAML_EXCEPTION_FACTORY(MetadataException);

namespace {
    ShibInternalConfig g_config;
}

ShibConfig::~ShibConfig() {}

extern "C" IMetadata* XMLMetadataFactory(const char* source)
{
    return new XMLMetadata(source);
}

extern "C" ITrust* XMLTrustFactory(const char* source)
{
    return new XMLTrust(source);
}

extern "C" IAAP* XMLAAPFactory(const char* source)
{
    return new XMLAAP(source);
}

bool ShibInternalConfig::init()
{
    saml::NDC ndc("init");

    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,UnsupportedProtocolException);
    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,MetadataException);

    // Register extension schema.
    saml::XML::registerSchema(XML::SHIB_NS,XML::SHIB_SCHEMA_ID);

    regFactory("edu.internet2.middleware.shibboleth.metadata.XML",&XMLMetadataFactory);
    regFactory("edu.internet2.middleware.shibboleth.trust.XML",&XMLTrustFactory);
    regFactory("edu.internet2.middleware.shibboleth.target.AAP.XML",&XMLAAPFactory);

    return true;
}

void ShibInternalConfig::term()
{
    for (vector<IMetadata*>::iterator i=m_providers.begin(); i!=m_providers.end(); i++)
        delete *i;
    for (vector<ITrust*>::iterator j=m_trust_providers.begin(); j!=m_trust_providers.end(); j++)
        delete *j;
    for (vector<IAAP*>::iterator k=m_aap_providers.begin(); k!=m_aap_providers.end(); k++)
        delete *k;
}

void ShibInternalConfig::regFactory(const char* type, MetadataFactory* factory)
{
    if (type && factory)
        m_metadataFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, TrustFactory* factory)
{
    if (type && factory)
        m_trustFactoryMap[type]=factory;
}

void ShibInternalConfig::regFactory(const char* type, AAPFactory* factory)
{
    if (type && factory)
        m_aapFactoryMap[type]=factory;
}

void ShibInternalConfig::unregFactory(const char* type)
{
    if (type)
    {
        m_metadataFactoryMap.erase(type);
        m_trustFactoryMap.erase(type);
        m_aapFactoryMap.erase(type);
    }
}

bool ShibInternalConfig::addMetadata(const char* type, const char* source)
{
    saml::NDC ndc("addMetadata");

    bool ret=false;
    try
    {
        MetadataFactoryMap::const_iterator i=m_metadataFactoryMap.find(type);
        if (i!=m_metadataFactoryMap.end())
        {
            m_providers.push_back((i->second)(source));
            ret=true;
        }
        else
        {
            TrustFactoryMap::const_iterator j=m_trustFactoryMap.find(type);
            if (j!=m_trustFactoryMap.end())
            {
                m_trust_providers.push_back((j->second)(source));
                ret=true;
            }
            else
            {
                AAPFactoryMap::const_iterator k=m_aapFactoryMap.find(type);
                if (k!=m_aapFactoryMap.end())
                {
                    m_aap_providers.push_back((k->second)(source));
                    ret=true;
                }
                else
                    throw MetadataException("ShibConfig::addMetadata() unable to locate a metadata factory of the requested type");
            }
        }
    }
    catch (SAMLException& e)
    {
        Category::getInstance(SHIB_LOGCAT".ShibConfig").error(
            "failed to add %s provider to system using source '%s': %s", type, source, e.what()
            );
    }
    catch (...)
    {
        Category::getInstance(SHIB_LOGCAT".ShibConfig").error(
            "failed to add %s provider to system using source '%s': unknown exception", type, source
            );
    }
    return ret;
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

X509* shibboleth::B64_to_X509(const char* buf)
{
	BIO* bmem = BIO_new_mem_buf((void*)buf,-1);
	BIO* b64 = BIO_new(BIO_f_base64());
	b64 = BIO_push(b64, bmem);
    X509* x=NULL;
    d2i_X509_bio(b64,&x);
    if (!x)
        log_openssl();
    BIO_free_all(b64);
    return x;
}
