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
#include <signal.h>

#define SHIB_INSTANTIATE

#include "internal.h"
#include <log4cpp/Category.hh>

using namespace saml;
using namespace shibboleth;

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

    if (!aapURL.empty())
    {
        try
        {
            m_AAP=new AAP(aapURL.c_str());
        }
        catch(SAMLException& e)
        {
            log4cpp::Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to initialize AAP: %s", e.what());
            return false;
        }
    }

    m_lock=RWLock::create();
    m_shutdown_wait = CondWait::create();
    if (!m_lock || !m_shutdown_wait)
    {
        log4cpp::Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to create mapper locks");
        delete m_lock;
        delete m_shutdown_wait;
        delete m_AAP;
        return false;
    }

    try
    {
        m_mapper=new XMLOriginSiteMapper(mapperURL.c_str(),SAMLConfig::getConfig().ssl_calist.c_str(),mapperCert);
    }
    catch(SAMLException& e)
    {
        log4cpp::Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to initialize origin site mapper: %s", e.what());
        delete m_lock;
        delete m_shutdown_wait;
        delete m_AAP;
        return false;
    }

    m_manager=xmlSecSimpleKeysMngrCreate();
    const char* roots=m_mapper->getTrustedRoots();
    if (roots && *roots && xmlSecSimpleKeysMngrLoadPemCert(m_manager,roots,true) < 0)
    {
        log4cpp::Category::getInstance(SHIB_LOGCAT".ShibConfig").fatal("init: failed to load CAs into simple key manager");
        xmlSecSimpleKeysMngrDestroy(m_manager);
        delete m_mapper;
        delete m_lock;
        delete m_shutdown_wait;
        delete m_AAP;
        return false;
    }
    SAMLConfig::getConfig().xmlsig_ptr=m_manager;
    if (mapperRefreshInterval)
        m_refresh_thread = Thread::create(&refresh_fn, (void*)this);

    return true;
}

void ShibInternalConfig::term()
{
    // Shut down the refresh thread and let it know...
    if (m_refresh_thread)
    {
        m_shutdown = true;
        m_shutdown_wait->signal();
        m_refresh_thread->join(NULL);
    }

    delete m_mapper;
    if (m_manager)
        xmlSecSimpleKeysMngrDestroy(m_manager);
    delete mapperCert;
    delete m_lock;
    delete m_shutdown_wait;
    delete m_AAP;
}

IOriginSiteMapper* ShibInternalConfig::getMapper()
{
    m_lock->rdlock();
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

void* ShibInternalConfig::refresh_fn(void* config_p)
{
  ShibInternalConfig* config = reinterpret_cast<ShibInternalConfig*>(config_p);

  // First, let's block all signals
  sigset_t sigmask;
  sigfillset(&sigmask);
  Thread::mask_signals(SIG_BLOCK, &sigmask, NULL);

  // Now run the refresh process.
  config->refresh();
}

void ShibInternalConfig::refresh()
{
    Mutex* mutex = Mutex::create();
    saml::NDC ndc("refresh");
    log4cpp::Category& log=log4cpp::Category::getInstance(SHIB_LOGCAT".ShibConfig");

    mutex->lock();

    log.debug("XMLMapper refresh thread started...");

    while (!m_shutdown)
    {
        struct timespec ts;
        memset (&ts, 0, sizeof(ts));
        ts.tv_sec = time(NULL) + mapperRefreshInterval;

        m_shutdown_wait->timedwait(mutex, &ts);

        if (m_shutdown)
            break;

        log.info("Refresh thread running...");

        // To refresh the mapper, we basically build a new one in the background and if it works,
        // we grab the write lock and replace the official pointer with the new one.
        try
        {
            IOriginSiteMapper* new_mapper=new XMLOriginSiteMapper(mapperURL.c_str(),SAMLConfig::getConfig().ssl_calist.c_str(),mapperCert);
            m_lock->wrlock();
            delete m_mapper;
            m_mapper=new_mapper;
            m_lock->unlock();
        }
        catch(SAMLException& e)
        {
            log.error("failed to build a refreshed origin site mapper, sticking with what we have: %s", e.what());
        }
        catch(...)
        {
            log.error("caught an unknown exception, sticking with what we have");
        }
    }

    mutex->unlock();
    delete mutex;
    Thread::exit(NULL);
}
