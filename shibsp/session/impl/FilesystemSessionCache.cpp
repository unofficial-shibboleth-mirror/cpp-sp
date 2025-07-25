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
#include "util/DirectoryWalker.h"
#include "util/Misc.h"
#include "util/PathResolver.h"

#include <fstream>

#include <fcntl.h>

#ifdef WIN32
# include <sys/utime.h>
# include <io.h>
#else
# include <utime.h>
# include <signal.h>
# ifdef HAVE_PTHREAD
#  include <pthread.h>
# else
#  error "This implementation is for POSIX platforms."
# endif
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

        bool start();
        void stop();

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
        static void* file_cleanup_fn(void*);
        static void file_cleanup_callback(const char* pathname, const char* filename, struct stat& stat_buf, void* data);
        
        Category& m_spilog;
        string m_dir;
        duthomhas::csprng m_rng;
        time_t m_cleanupInterval;
        unsigned int m_fileTimeout;
        condition_variable m_file_cleanup_wait;
        thread m_file_cleanup_thread;
    };

    static const char CACHE_DIRECTORY_PROP_NAME[] = "cacheDirectory";
    static const char FILE_CLEANUP_TRACKING_FILE_PROP_NAME[] = "fileCleanupTrackingFile";
    static const char FILE_CLEANUP_INTERVAL_PROP_NAME[] = "fileCleanupInterval";
    static const char FILE_TIMEOUT_PROP_NAME[] = "fileTimeout";

    static const char CACHE_DIRECTORY_PROP_DEFAULT[] = "sessions";
    static const char FILE_CLEANUP_TRACKING_FILE_PROP_DEFAULT[] = "shibsp_cache_cleanup";
    static unsigned int FILE_CLEANUP_INTERVAL_PROP_DEFAULT = 1800;
    static unsigned int FILE_TIMEOUT_PROP_DEFAULT = 3600 * 8;
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

    m_cleanupInterval = getUnsignedInt(FILE_CLEANUP_INTERVAL_PROP_NAME, FILE_CLEANUP_INTERVAL_PROP_DEFAULT);
    if (m_cleanupInterval) {
        m_fileTimeout = getUnsignedInt(FILE_TIMEOUT_PROP_NAME, FILE_TIMEOUT_PROP_DEFAULT);
    }
    else {
        m_spilog.info("%s was zero, disabling file cleanup thread", FILE_CLEANUP_INTERVAL_PROP_NAME);
    }
}

FilesystemSessionCache::~FilesystemSessionCache()
{
}

bool FilesystemSessionCache::start()
{
    if (!AbstractSessionCache::start()) {
        return false;
    }

#ifdef HAVE_CXX17
    if (m_cleanupInterval) {
        try {
            m_file_cleanup_thread = thread(file_cleanup_fn, this);
            return true;
        }
        catch (const system_error& e) {
            m_spilog.error("error starting cleanup thread: %s", e.what());
        }
        return false;
    }
#endif
    return true;
}

void FilesystemSessionCache::stop()
{
    AbstractSessionCache::stop();
#ifdef HAVE_CXX17
    if (m_cleanupInterval) {
        m_file_cleanup_wait.notify_all();
        if (m_file_cleanup_thread.joinable()) {
            m_file_cleanup_thread.join();
        }
    }
#endif
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
            }
            cache_remove(request, key);
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

    const char* appId = obj["app_id"].string();
    if (strcmp(applicationId, appId)) {
        m_spilog.warn("session (%s) issued for application (%s), accessed via application (%s)", key, appId, applicationId);
        obj.destroy();
        return obj;
    }

    // TODO: Implement the fuzzy address matching.
    if (client_addr) {
        const char* addr = obj["addr"].string();
        if (addr && strcmp(client_addr, addr)) {
            m_spilog.info("session (%s) invalid, bound to address (%s), accessed from (%s)", key, addr, client_addr);
            obj.destroy();
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

void* FilesystemSessionCache::file_cleanup_fn(void* p)
{
    FilesystemSessionCache* pcache = reinterpret_cast<FilesystemSessionCache*>(p);

#ifndef WIN32
    // Bblock all signals.
    sigset_t sigmask;
    sigfillset(&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, nullptr);
#endif

    // Load our configuration details...
    string cleanupTracker = pcache->m_dir + pcache->getString(
        FILE_CLEANUP_TRACKING_FILE_PROP_NAME, FILE_CLEANUP_TRACKING_FILE_PROP_DEFAULT);

    // Create cleanup tracking file if not already present.

#ifdef WIN32
    int f = _open(cleanupTracker.c_str(), _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
#else
    int f = open(cleanupTracker.c_str(), O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
    if (f < 0) {
        int e = errno;
        if (e == EEXIST) {
            pcache->m_spilog.debug("detected existing cleanup tracking file at %s", cleanupTracker.c_str());
        } else {
            pcache->m_spilog.error("error creating cleanup tracking file at %s, errno=%d",
                cleanupTracker.c_str(), e);
        }
    }
    else {
        pcache->m_spilog.debug("created initial cleanup tracking file at %s", cleanupTracker.c_str());
#ifdef WIN32
        _close(f);
#else
        close(f);
#endif
    }

    mutex internal_mutex;
    unique_lock lock(internal_mutex);

    pcache->m_spilog.info("file cleanup thread started...run every %u secs, purge after %u seconds of disuse",
        pcache->m_cleanupInterval, pcache->m_fileTimeout);

    while (!pcache->isShutdown()) {
        pcache->m_file_cleanup_wait.wait_for(lock, chrono::seconds(pcache->m_cleanupInterval));
        
        if (pcache->isShutdown()) {
            pcache->m_spilog.debug("file cleanup thread shutting down");
            break;
        }

        pcache->m_spilog.debug("file cleanup thread running");

        time_t now = time(nullptr);
        
        // When we wake up, we check the timestamp on the tracking file to determine if we need to do work.
        // This should limit runs across all processes to roughly as much as we intend.
        time_t lastCleanup = FileSupport::getModificationTime(cleanupTracker.c_str());
        if (lastCleanup == 0) {
            pcache->m_spilog.error("unable to get last modification to cleanup tracking file, errno=%d", errno);
            continue;
        }
        else if (lastCleanup + pcache->m_cleanupInterval > now) {
            pcache->m_spilog.debug("file cleanup thread going back to sleep");
            continue;
        }

        // We're ready to work, so update the tracking file to signal other agents to back off.
        if (utime(cleanupTracker.c_str(), nullptr) != 0) {
            pcache->m_spilog.error("error updating tracking file timestamp, errno=%d", errno);
            continue;
        }

        try {
            DirectoryWalker dirWalker(pcache->m_spilog, pcache->m_dir.c_str());
            dirWalker.walk(&file_cleanup_callback, p);
        }
        catch (const exception& e) {
            pcache->m_spilog.error("caught exception during cleanup: %s", e.what());
        }

        pcache->m_spilog.debug("file cleanup thread completed work");
    }

    pcache->m_spilog.info("file cleanup thread exiting");

    return nullptr;
}

void FilesystemSessionCache::file_cleanup_callback(
    const char* pathname, const char* filename, struct stat& stat_buf, void* data
    )
{
    FilesystemSessionCache* pcache = reinterpret_cast<FilesystemSessionCache*>(data);

    if (strlen(filename) != 32) {
        pcache->m_spilog.warn("skipping unexpected filename (%s)", filename);
        return;
    }

    if (stat_buf.st_mtime > 0 && time(nullptr) - stat_buf.st_mtime > pcache->m_fileTimeout) {
        if (std::remove(pathname) == 0) {
            pcache->m_spilog.info("removed stale session file (%s)", filename);
        }
        else {
            pcache->m_spilog.info("error removing stale session file (%s), errno=%d", filename, errno);
        }
    }

}