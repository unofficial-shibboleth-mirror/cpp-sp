/*
 *  Copyright 2001-2007 Internet2
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

    static const XMLCh cacheTimeout[] =     UNICODE_LITERAL_12(c,a,c,h,e,T,i,m,e,o,u,t);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
    SPConfig& conf = SPConfig::getConfig();
    conf.SessionCacheManager.registerFactory(REMOTED_SESSION_CACHE, RemotedCacheFactory);
    conf.SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceCacheFactory);
}

SessionCache::SessionCache(const DOMElement* e) : m_cacheTimeout(60*60*8)
{
    if (e) {
        const XMLCh* tag=e->getAttributeNS(NULL,cacheTimeout);
        if (tag && *tag) {
            m_cacheTimeout = XMLString::parseInt(tag);
            if (!m_cacheTimeout)
                m_cacheTimeout=60*60*8;
        }
    }
}
