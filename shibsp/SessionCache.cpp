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

#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;

namespace shibsp {

#ifndef SHIBSP_LITE
    SHIBSP_DLLLOCAL PluginManager<SessionCache,std::string,const DOMElement*>::Factory StorageServiceCacheFactory;
#else
    SHIBSP_DLLLOCAL PluginManager<SessionCache,std::string,const DOMElement*>::Factory RemotedCacheFactory;
#endif

    static const XMLCh cacheTimeout[] =     UNICODE_LITERAL_12(c,a,c,h,e,T,i,m,e,o,u,t);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
#ifndef SHIBSP_LITE
    SPConfig::getConfig().SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceCacheFactory);
#else
    SPConfig::getConfig().SessionCacheManager.registerFactory(REMOTED_SESSION_CACHE, RemotedCacheFactory);
#endif
}

SessionCache::SessionCache(const DOMElement* e, unsigned long defaultTimeout) : m_cacheTimeout(defaultTimeout)
{
    if (e) {
        const XMLCh* tag=e->getAttributeNS(NULL,cacheTimeout);
        if (tag && *tag) {
            m_cacheTimeout = XMLString::parseInt(tag);
            if (!m_cacheTimeout)
                m_cacheTimeout=defaultTimeout;
        }
    }
}
