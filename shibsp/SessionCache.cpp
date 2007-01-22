/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * SessionCache.cpp
 * 
 * SessionCache base class and factory registration
 */

#include "internal.h"
#include "SessionCache.h"

using namespace shibsp;
using namespace xmltooling;

namespace shibsp {

    SHIBSP_DLLLOCAL PluginManager<SessionCache,const DOMElement*>::Factory RemotedCacheFactory;
    SHIBSP_DLLLOCAL PluginManager<SessionCache,const DOMElement*>::Factory StorageServiceCacheFactory;

    static const XMLCh cleanupInterval[] =  UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
    static const XMLCh cacheTimeout[] =     UNICODE_LITERAL_12(c,a,c,h,e,T,i,m,e,o,u,t);
    static const XMLCh strictValidity[] =   UNICODE_LITERAL_14(s,t,r,i,c,t,V,a,l,i,d,i,t,y);
    static const XMLCh writeThrough[] =     UNICODE_LITERAL_12(w,r,i,t,e,T,h,r,o,u,g,h);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
    SPConfig& conf = SPConfig::getConfig();
    conf.SessionCacheManager.registerFactory(REMOTED_SESSION_CACHE, RemotedCacheFactory);
    conf.SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceCacheFactory);
}

SessionCache::SessionCache(const DOMElement* e)
    : m_cleanupInterval(60*5), m_cacheTimeout(60*60*8), m_strictValidity(true), m_writeThrough(false)
{
    if (e) {
        const XMLCh* tag=e->getAttributeNS(NULL,cleanupInterval);
        if (tag && *tag) {
            m_cleanupInterval = XMLString::parseInt(tag);
            if (!m_cleanupInterval)
                m_cleanupInterval=60*5;
        }

        tag=e->getAttributeNS(NULL,cacheTimeout);
        if (tag && *tag) {
            m_cacheTimeout = XMLString::parseInt(tag);
            if (!m_cacheTimeout)
                m_cacheTimeout=60*60*8;
        }
        
        tag=e->getAttributeNS(NULL,strictValidity);
        if (tag && (*tag==chDigit_0 || *tag==chLatin_f))
            m_strictValidity=false;
            
        tag=e->getAttributeNS(NULL,writeThrough);
        if (tag && (*tag==chDigit_1 || *tag==chLatin_t))
            m_writeThrough=true;
    }
}
