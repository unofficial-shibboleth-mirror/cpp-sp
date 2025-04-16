/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * session/impl/AbstractSessionCache.cpp
 *
 * Base class for SessionCache implementations.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
    extern SessionCache* SHIBSP_DLLLOCAL FilesystemSessionCacheFactory(ptree& pt, bool deprecationSupport);
    extern SessionCache* SHIBSP_DLLLOCAL StorageServiceSessionCacheFactory(ptree& pt, bool deprecationSupport);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
    AgentConfig::getConfig().SessionCacheManager.registerFactory(FILESYSTEM_SESSION_CACHE, FilesystemSessionCacheFactory);
    //AgentConfig::getConfig().SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceSessionCacheFactory);
}

Session::Session()
{
}

Session::~Session()
{
}

SessionCache::SessionCache()
{
}

SessionCache::~SessionCache()
{
}

AbstractSessionCache::AbstractSessionCache()
{
}

AbstractSessionCache::~AbstractSessionCache()
{
}

bool AbstractSessionCache::start()
{
}
