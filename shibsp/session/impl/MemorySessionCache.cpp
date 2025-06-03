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
 * session/impl/MemorySessionCache.cpp
 *
 * SessionCache implementation using non-shared memory.
 * 
 * <p>This is a degenerate implementation for testing and perhaps very constrained use cases
 * in which only a single agent process can exist. It essentially no-ops all the operations
 * such that the base class in-process cache is the only store.</p>
 */

#include "internal.h"
#include "exceptions.h"
#include "csprng/csprng.hpp"
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class MemorySessionCache : public virtual AbstractSessionCache {
    public:
        MemorySessionCache(const ptree& pt);
        ~MemorySessionCache();

        string cache_create(DDF& sessionData);
        DDF cache_read(
            const char* applicationId,
            const char* key,
            unsigned int lifetime=0,
            unsigned int timeout=0,
            const char* client_addr=nullptr
            ) const;
        bool cache_touch(const char* key, unsigned int timeout=0) const;
        void cache_remove(const char* key);
    
    private:
        duthomhas::csprng m_rng;
    };
};

namespace shibsp {
    SessionCache* SHIBSP_DLLLOCAL MemorySessionCacheFactory(ptree& pt, bool deprecationSupport) {
        return new MemorySessionCache(pt);
    }
}

MemorySessionCache::MemorySessionCache(const ptree& pt) : AbstractSessionCache(pt)
{
}

MemorySessionCache::~MemorySessionCache()
{
}

string MemorySessionCache::cache_create(DDF& sessionData)
{
    return m_rng(string(16,0));
}

DDF MemorySessionCache::cache_read(
    const char* applicationId,
    const char* key,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    ) const
{
    return DDF();
}

bool MemorySessionCache::cache_touch(const char* key, unsigned int timeout) const
{
    return true;
}

void MemorySessionCache::cache_remove(const char* key)
{
}
