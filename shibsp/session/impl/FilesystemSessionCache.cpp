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
#include "util/Date.h"
#include "util/Misc.h"
#include "util/PathResolver.h"

#include <cstdio>
#include <fstream>

#ifdef WIN32
# define _utime utime
# include <sys/utime.h>
#else
# include <utime.h>
#endif

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class FilesystemSessionCache : public virtual AbstractSessionCache {
    public:
        FilesystemSessionCache(const ptree& pt);
        ~FilesystemSessionCache();

        string cache_create(SPRequest* request, DDF& sessionData);
        DDF cache_read(
            SPRequest* request,
            const char* applicationId,
            const char* key,
            unsigned int lifetime=0,
            unsigned int timeout=0,
            const char* client_addr=nullptr
            );
        bool cache_touch(SPRequest* request, const char* key, unsigned int timeout=0);
        void cache_remove(SPRequest* request, const char* key);

    private:
        Category& m_spilog;
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

FilesystemSessionCache::FilesystemSessionCache(const ptree& pt)
    : AbstractSessionCache(pt), m_spilog(Category::getInstance(SHIBSP_LOGCAT ".SessionCache.Filesystem"))
{
    m_dir = getString(CACHE_DIRECTORY_PROP_NAME, CACHE_DIRECTORY_PROP_DEFAULT);
    AgentConfig::getConfig().getPathResolver().resolve(m_dir, PathResolver::SHIBSP_CACHE_FILE);
    if (m_dir.back() != '/') {
        m_dir += '/';
    }

    string testPath = m_dir + hex_encode(m_rng(string(16,0)));

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
        m_spilog.error("could not perform read/write in cache directory (%s), check permissions", m_dir.c_str());
        throw ConfigurationException("Configured session cache directory was inaccessible to agent process.");
    }
}

FilesystemSessionCache::~FilesystemSessionCache()
{
}

string FilesystemSessionCache::cache_create(SPRequest* request, DDF& sessionData)
{
    string key;
    string path;
    int attempts = 0;
    do {
        key = hex_encode(m_rng(string(16,0)));
        path = m_dir + key;
        if (!FileSupport::exists(path.c_str())) {
            ofstream os (path);
            if (os) {
                os << sessionData;
                if (os) {
                    m_spilog.debug("stored new session (%s)", key.c_str());
                    return key;
                }
            }

            m_spilog.error("error writing new session to file (%s), errno=%d", path.c_str(), errno);
            throw IOException("Error writing new session to file.");
        }
    } while (++attempts < 3);

    m_spilog.error("failed to write new session after 3 attempts to generate a unique key");
    throw IOException("Exhausted attempts to generate a unique session key.");
}

DDF FilesystemSessionCache::cache_read(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
    DDF obj;

    string path = m_dir + key;
    time_t lastAccess = FileSupport::getModificationTime(path.c_str());
    ifstream is(path);
    if (!is) {
        int e = errno;
        if (e == ENOENT) {
            m_spilog.debug("session file (%s) does not exist", path.c_str());
        }
        else {
            m_spilog.error("error opening session file (%s) for reading, errno=%d", path.c_str(), e);
        }
        return obj;
    }

    time_t now = time(nullptr);

    if (timeout) {
        if (lastAccess == 0) {
            m_spilog.error("timeout specified, unable to obtain access time for session file (%s)", path.c_str());
            return obj;
        }
        else if (lastAccess + timeout < now) {
            if (m_spilog.isInfoEnabled()) {
                string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(lastAccess)));
                m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
                cache_remove(request, key);
            }
            return obj;
        }
    }

    is >> obj;
    is.close();

    if (!isSessionDataValid(obj)) {
        obj.destroy();
        m_spilog.error("deserialized session from file (%s) was invalid", path.c_str());
        return obj;
    }

    const char* appId = obj["appId"].string();
    if (strcmp(applicationId, appId)) {
        obj.destroy();
        m_spilog.warn("session (%s) issued for application (%s), accessed via application (%s)", key, appId, applicationId);
        return obj;
    }

    // TODO: Implement the fuzzy address matching.
    if (client_addr) {
        const char* addr = obj["addr"].string();
        if (addr && strcmp(client_addr, addr)) {
            obj.destroy();
            m_spilog.info("session (%s) invalid, bound to address (%s), accessed from (%s)", key, addr, client_addr);
            cache_remove(request, key);
            return obj;
        }
    }

    if (lifetime) {
        time_t start = obj["ts"].longinteger();
        if (start + lifetime < now) {
            obj.destroy();
            if (m_spilog.isInfoEnabled()) {
                string created(date::format("%FT%TZ", chrono::system_clock::from_time_t(start)));
                string expired(date::format("%FT%TZ", chrono::system_clock::from_time_t(start + lifetime)));
                m_spilog.info("session (%s) has expired, created (%s), expired (%s)", key, created.c_str(), expired.c_str());
            }
            cache_remove(request, key);
            return obj;
        }
    }

    if (utime(path.c_str(), nullptr) != 0) {
        m_spilog.error("unable to update access time for session (%s), errno=%d", path.c_str(), errno);
    }

    return obj;
}

bool FilesystemSessionCache::cache_touch(SPRequest* request, const char* key, unsigned int timeout)
{
    string path = m_dir + key;
    if (timeout) {
        time_t lastAccess = FileSupport::getModificationTime(path.c_str());
        if (lastAccess == 0) {
            int e = errno;
            if (e == ENOENT) {
                m_spilog.info("unable to update access time, session file (%s) did not exist", path.c_str());
            }
            else {
                m_spilog.error("unable to obtain access time for session file (%s), errno=%d", path.c_str(), e);
            }
            return false;
        }
        else if (lastAccess + timeout < time(nullptr)) {
            if (m_spilog.isInfoEnabled()) {
                string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(lastAccess)));
                m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
            }
            cache_remove(request, key);
            return false;
        }
    }

    if (utime(path.c_str(), nullptr) != 0) {
        m_spilog.error("unable to update access time for session (%s), errno=%d", path.c_str(), errno);
        // Debatable if we fall into returning true, but maybe we don't care?
    }
    return true;
}

void FilesystemSessionCache::cache_remove(SPRequest* request, const char* key)
{
    string path = m_dir + key;
    if (std::remove(path.c_str()) != 0) {
        int e = errno;
        if (e == ENOENT) {
            m_spilog.debug("session file (%s) did not exist", path.c_str());
        }
        else {
            m_spilog.error("error removing file for session (%s), errno=%d", key, e);
        }
    }
    else {
        m_spilog.debug("removed session file for (%s)", key);
    }
}
