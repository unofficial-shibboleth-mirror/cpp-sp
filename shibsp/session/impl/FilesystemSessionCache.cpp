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
            unsigned int version=1,
            unsigned int lifetime=0,
            unsigned int timeout=0,
            const char* client_addr=nullptr
            );
        bool cache_update(SPRequest* request, const char* key, unsigned int version, DDF& data);
        bool cache_touch(SPRequest* request, const char* key, unsigned int version=1, unsigned int timeout=0);
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
        computeVersionedFilename(path, 1);
        // We attempt an exclusive open to "reserve" the new session file name.
#ifdef WIN32
        int f = _open(path.c_str(), _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
#else
        int f = open(path.c_str(), O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
        if (f > 0) {
            // Worked, so close the "reserved" file so we can overwrite it.
#ifdef WIN32
            _close(f);
#else
            close(f);
#endif
            ofstream os(path);
            if (!os) {
                m_spilog.error("error writing new session to file (%s), errno=%d", path.c_str(), errno);
                throw IOException("Error writing new session to file.");
            }

            os << sessionData;
            if (os) {
                m_spilog.debug("stored new session (%s)", key.c_str());
                return key;
            }
        }
        // If we get here, we're attempting a retry until we exhaust.
        int e = errno;
        if (e != EEXIST) {
            m_spilog.error("error opening new session file (%s), errno=%d", path.c_str(), e);
        }
    } while (++attempts < 3);

    m_spilog.error("failed to write new session after 3 attempts to generate a unique key");
    throw IOException("Exhausted attempts to generate a unique session key.");
}

DDF FilesystemSessionCache::cache_read(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int version,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
    DDF obj;
    time_t effective_access = 0;
    string effective_path;
    string base_path = m_dir + key;

    // Figure out what the latest version on disk is and its last modification time.
    unsigned int effective_version = version;
    while (true) {
        string path(base_path);
        computeVersionedFilename(path, effective_version);
        time_t lastAccess = FileSupport::getModificationTime(path.c_str());
        if (lastAccess == 0) {
            int e = errno;
            if (e != ENOENT) {
                m_spilog.error("unable to obtain access time for session file (%s), errno=%d", path.c_str(), e);
            }
            // If this is the first loop iteration, we fail outright, assuming the session was removed.
            if (version == effective_version) {
                m_spilog.info("session file (%s) does not exist", path.c_str());
                return obj;
            }
            // Need to decrement back to the last known good value.
            effective_version--;
            break;
        }
        effective_access = lastAccess;
        effective_path = path;
        effective_version++;
    }

    // If we get here, we have the effective variables are set correctly.

    ifstream is(effective_path);
    if (!is) {
        int e = errno;
        if (e == ENOENT) {
            m_spilog.info("session file (%s) does not exist, deleted behind us?", effective_path.c_str());
        }
        else {
            m_spilog.error("error opening session file (%s) for reading, errno=%d", effective_path.c_str(), e);
        }
        throw IOException("Session file could not be found or read after acquisition of modification time.");
    }

    time_t now = time(nullptr);

    if (timeout ) {
        if (effective_access + timeout < now) {
            if (m_spilog.isInfoEnabled()) {
                string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(effective_access)));
                m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
            }
            cache_remove(request, key);
            return obj;
        }
    }

    is >> obj;
    is.close();

    if (!isSessionDataValid(obj)) {
        m_spilog.error("deserialized session from file (%s) was invalid", effective_path.c_str());
        throw IOException("Session data was invalid.");
    }

    const char* appId = obj["app_id"].string();
    if (strcmp(applicationId, appId)) {
        m_spilog.warn("session (%s) issued for application (%s), accessed via application (%s)", key, appId, applicationId);
        return obj.destroy();
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

    bool updateTimestamp = true;

    if (client_addr) {
        const char* family = getAddressFamily(client_addr);
        const char* addr = obj[family].string();
        if (addr) {
            if (!isAddressMatch(client_addr, addr)) {
                m_spilog.info("session (%s) use invalid, bound to address (%s), accessed from (%s)", key, addr, client_addr);
                return obj.destroy();
            }
        }
        else {
            // We have to rebind the session to a new address family, requiring an update to the session.
            m_spilog.info("attempting update of session (%s) to rebind to new address (%s)", key, client_addr);

            // Flag the subsequent code to skip updating the timestamp as it will have been done for us in
            // the act of creating a new file version.
            updateTimestamp = false;

            // Fill in the new address and attempt the update.
            obj.addmember(family).string(client_addr);
            try {
                if (!cache_update(request, key, version, obj)) {
                    obj.destroy();
                    // This signals a version mismatch in which the original session we were asked to read
                    // has already been updated by another thread or process. In this case, we recurse the
                    // read attempt. This has to terminate eventually...right?

                    // We bump the version once, under the assunption it shouldn't be likely that it's been
                    // updated behind us more than once...
                    return cache_read(request, applicationId, key, version + 1, lifetime, timeout, client_addr);
                }
            }
            catch (const exception& ex) {
                // This is an outright error attempting the update, so we just fail hard.
                m_spilog.error("exception attempting to update session (%s): %s", key, ex.what());
                throw;
            }
        }
    }

    // We update the last modified timestamp here since we are returning this version of the session.
    if (updateTimestamp && utime(effective_path.c_str(), nullptr) != 0) {
        m_spilog.error("unable to update access time for session (%s), errno=%d", effective_path.c_str(), errno);
        // Failure here is just ignored.
    }

    return obj;
}

bool FilesystemSessionCache::cache_update(SPRequest* request, const char* key, unsigned int version, DDF& sessionData)
{
    // The essence of this operation is to grab the "next" version by reserving a new session file under the
    // correct name for the new version.

    // The workking theory is that any other thread that comes in after us will fail to reserve that filename,
    // where as *we* know (if we can do so) that we're the only ones authorised to write to that newly created
    // file.

    version++;
    string path = m_dir + key;
    computeVersionedFilename(path, version);

    // We attempt an exclusive open to "reserve" the new version's file name.
#ifdef WIN32
    int f = _open(path.c_str(), _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
#else
    int f = open(path.c_str(), O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
    if (f < 0) {
        int e = errno;
        if (e == EEXIST) {
            // This should indicate a version race condition with somebody else having created
            // this version, so this update attempt is a version mismatch.
            m_spilog.info("collision trying to create file for update of session (%s) to version (%u)",
                path.c_str(), version);
            return false;
        }
        else {
            m_spilog.warn("error trying to create file for update of session (%s) to version (%u), errno=%d",
                path.c_str(), version, e);
            throw IOException("Error attempting to create file for updated session.");
        }
    }

    // Having reserved the new filename, we should have a clear runway to populate the new file
    // and signal back success unless something blows up.
#ifdef WIN32
    _close(f);
#else
    close(f);
#endif

    ofstream os(path);
    if (!os) {
        m_spilog.error("error writing new version of session to file (%s), errno=%d", path.c_str(), errno);
        throw IOException("Error attempting to open file for writing of updated session.");
    }

    // Ensure the new version is set accurately.
    sessionData.addmember("ver").integer(version);
    os << sessionData;
    if (os) {
        m_spilog.debug("stored new version of session to file (%s)", path.c_str());
        return true;
    }

    m_spilog.error("error writing new version of session to file (%s), errno=%d", path.c_str(), errno);
    throw IOException("Error attempting to write to file holding updated session version.");
}

bool FilesystemSessionCache::cache_touch(SPRequest* request, const char* key, unsigned int version, unsigned int timeout)
{
    time_t effective_access = 0;
    string effective_path;
    string base_path = m_dir + key;

    // Figure out what the latest version on disk is and its last modification time.
    unsigned int effective_version = version;
    while (true) {
        string path(base_path);
        computeVersionedFilename(path, effective_version);
        time_t lastAccess = FileSupport::getModificationTime(path.c_str());
        if (lastAccess == 0) {
            int e = errno;
            if (e != ENOENT) {
                m_spilog.error("unable to obtain access time for session file (%s), errno=%d", path.c_str(), e);
            }
            // If this is the first loop iteration, we fail outright, assuming the session was removed.
            if (version == effective_version) {
                m_spilog.info("unable to update access time, session file (%s) did not exist", path.c_str());
                return false;
            }
            // Need to decrement back to the last known good value.
            effective_version--;
            break;
        }
        effective_access = lastAccess;
        effective_path = path;
        effective_version++;
    }

    // If we get here, we have the effective variables are set correctly.

    if (timeout && effective_access + timeout < time(nullptr)) {
        if (m_spilog.isInfoEnabled()) {
            string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(effective_access)));
            m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
        }
        cache_remove(request, key);
        return false;
    }

    if (utime(effective_path.c_str(), nullptr) != 0) {
        m_spilog.error("unable to update access time for session (%s), version (%d), errno=%d",
            effective_path.c_str(), effective_version, errno);
        // Debatable if we fall into returning true, but maybe we don't care?
    }
    return true;
}

void FilesystemSessionCache::cache_remove(SPRequest* request, const char* key)
{
    string base_path = m_dir + key;

    for (unsigned int version = 1; true; ++version) {
        string path(base_path);
        computeVersionedFilename(path, version);
        if (std::remove(path.c_str()) != 0) {
            int e = errno;
            if (e != ENOENT) {
                m_spilog.error("error removing file for session (%s), version (%u), errno=%d", key, version, e);
            }
            else {
                break;
            }
        }
        else {
            m_spilog.debug("removed file for session (%s), version (%u)", key, version);
        }
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
    unique_lock<mutex> lock(internal_mutex);

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

    if (stat_buf.st_mtime > 0 && time(nullptr) - stat_buf.st_mtime > pcache->m_fileTimeout) {
        if (std::remove(pathname) == 0) {
            pcache->m_spilog.info("removed stale session file (%s)", filename);
        }
        else {
            pcache->m_spilog.info("error removing stale session file (%s), errno=%d", filename, errno);
        }
    }

}
