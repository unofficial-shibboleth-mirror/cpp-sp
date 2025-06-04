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
 * session/impl/FilesystemSessionCache.cpp
 *
 * SessionCache implementation using the file system for storage.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "csprng/csprng.hpp"
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"
#include "util/Misc.h"
#include "util/PathResolver.h"

#include <cstdio>
#include <fstream>

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class FilesystemSessionCache : public virtual AbstractSessionCache {
    public:
        FilesystemSessionCache(const ptree& pt);
        ~FilesystemSessionCache();

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
        string m_dir;
        duthomhas::csprng m_rng;
    };

    static const char CACHE_DIRECTORY_PROP_NAME[] = "cacheDirectory";
    static const char CACHE_DIRECTORY_PROP_DEFAULT[] = "sessions";
};

namespace shibsp {
    SessionCache* SHIBSP_DLLLOCAL FilesystemSessionCacheFactory(ptree& pt, bool deprecationSupport) {
        return new FilesystemSessionCache(pt);
    }
}

FilesystemSessionCache::FilesystemSessionCache(const ptree& pt) : AbstractSessionCache(pt)
{
    m_dir = getString(CACHE_DIRECTORY_PROP_NAME, CACHE_DIRECTORY_PROP_DEFAULT);
    AgentConfig::getConfig().getPathResolver().resolve(m_dir, PathResolver::SHIBSP_CACHE_FILE);

    string testPath = m_dir + '/' + hex_encode(m_rng(string(16,0)));

    bool failed = true;

    DDF obj("test");
    DDFJanitor objjanitor(obj);
    ofstream os(testPath);
    if (os) {
        os << obj;
        os.close();
        ifstream is(testPath);
        if (is) {
            DDF obj2(nullptr);
            DDFJanitor obj2janitor(obj2);
            is >> obj2;
            is.close();
            if (obj2.name() && !strcmp(obj.name(), obj2.name())) {
                failed = false;
            }
        }
    }

    std::remove(testPath.c_str());

    if (failed) {
        log().error("could not perform read/write in cache directory (%s), check permissions", m_dir.c_str());
        throw ConfigurationException("Configured session cache directory was inaccessible to agent process.");
    }
}

FilesystemSessionCache::~FilesystemSessionCache()
{
}

string FilesystemSessionCache::cache_create(DDF& sessionData)
{
    return string();
}

DDF FilesystemSessionCache::cache_read(
    const char* applicationId,
    const char* key,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    ) const
{
    return DDF();
}

bool FilesystemSessionCache::cache_touch(const char* key, unsigned int timeout) const
{
    return false;
}

void FilesystemSessionCache::cache_remove(const char* key)
{
}
