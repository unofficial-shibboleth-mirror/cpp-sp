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
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class FilesystemSessionCache : public virtual AbstractSessionCache {
    public:
        FilesystemSessionCache(const ptree& pt);
        ~FilesystemSessionCache();

        // For now this is just a dummy implementation to support further development.

        string active(const SPRequest& request) {return "";}
        Session* find(SPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr) {return nullptr;}
        void remove(SPRequest& request, time_t revocationExp=0) {}
        Session* find(const char* bucketID, const char* key) {return nullptr;}
        void remove(const char* bucketID, const char* key, time_t revocationExp=0) {}
    };
};

namespace shibsp {
    SessionCache* SHIBSP_DLLLOCAL FilesystemSessionCacheFactory(ptree& pt, bool deprecationSupport) {
        return new FilesystemSessionCache(pt);
    }
}

FilesystemSessionCache::FilesystemSessionCache(const ptree& pt)
{
}

FilesystemSessionCache::~FilesystemSessionCache()
{
}
