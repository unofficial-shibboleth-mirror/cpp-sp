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

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;

SAML_EXCEPTION_FACTORY(UnsupportedProtocolException);
SAML_EXCEPTION_FACTORY(OriginSiteMapperException);

namespace {
    ShibInternalConfig g_config;
}

ShibConfig::~ShibConfig() {}

bool ShibInternalConfig::init()
{
    saml::NDC ndc("init");

    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,UnsupportedProtocolException);
    REGISTER_EXCEPTION_FACTORY(edu.internet2.middleware.shibboleth.common,OriginSiteMapperException);

    // Register extension schema.
    saml::XML::registerSchema(XML::SHIB_NS,XML::SHIB_SCHEMA_ID);

    if (!aapFile.empty())
    {
        try
        {
            m_AAP=new AAP(aapFile.c_str());
        }
        catch(SAMLException& e)
        {
            Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to initialize AAP: %s", e.what());
            return false;
        }
    }

    m_lock=RWLock::create();
    if (!m_lock)
    {
        Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to create mapper locks");
        delete m_lock;
        delete m_AAP;
        return false;
    }

    try
    {
        m_mapper=new XMLOriginSiteMapper(mapperFile.c_str());
    }
    catch(SAMLException& e)
    {
        Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to initialize origin site mapper: %s", e.what());
        delete m_lock;
        delete m_AAP;
        return false;
    }

    return true;
}

void ShibInternalConfig::term()
{
    delete m_mapper;
    delete m_lock;
    delete m_AAP;
}

IOriginSiteMapper* ShibInternalConfig::getMapper()
{
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(mapperFile.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(mapperFile.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_mapper->getTimestamp()>0 && m_mapper->getTimestamp()<stat_buf.st_mtime)
        {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_mapper->getTimestamp()>0 && m_mapper->getTimestamp()<stat_buf.st_mtime)
            {
                try
                {
                    IOriginSiteMapper* new_mapper=new XMLOriginSiteMapper(mapperFile.c_str());
                    delete m_mapper;
                    m_mapper=new_mapper;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("getMapper");
                    Category::getInstance(SHIB_LOGCAT".ShibConfig").error("failed to reload origin site mapper, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("getMapper");
                    Category::getInstance(SHIB_LOGCAT".ShibConfig").error("caught an unknown exception, sticking with what we have");
                }
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
    
    return m_mapper;
}

void ShibInternalConfig::releaseMapper(IOriginSiteMapper* mapper)
{
    m_lock->unlock();
}

ShibConfig& ShibConfig::getConfig()
{
    return g_config;
}
