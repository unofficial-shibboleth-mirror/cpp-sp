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
#include "util/Date.h"
#include "util/Misc.h"

#include <boost/property_tree/ptree.hpp>

#ifndef WIN32
# include <signal.h>
# ifdef HAVE_PTHREAD
#  include <pthread.h>
# else
#  error "This implementation is for POSIX platforms."
# endif
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class MemorySessionCache : public virtual AbstractSessionCache {
    public:
        MemorySessionCache(const ptree& pt);
        ~MemorySessionCache();

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
        bool cache_update(SPRequest* request, const char* key, unsigned int version, DDF& sessionData);
        bool cache_touch(SPRequest* request, const char* key, unsigned int version=1, unsigned int timeout=0);
        void cache_remove(SPRequest* request, const char* key);
    
    private:
        static void* memory_cleanup_fn(void*);

        Category& m_spilog;
        duthomhas::csprng m_rng;
        mutex m_lock;
        map<string,pair<DDF,time_t>> m_storage;

        time_t m_cleanupInterval;
        condition_variable m_mem_cleanup_wait;
        thread m_mem_cleanup_thread;
    };
};

static const char MEMORY_CLEANUP_INTERVAL_PROP_NAME[] = "memoryCleanupInterval";
static unsigned int MEMORY_CLEANUP_INTERVAL_PROP_DEFAULT = 1800;
    
namespace shibsp {
    SessionCache* SHIBSP_DLLLOCAL MemorySessionCacheFactory(ptree& pt, bool deprecationSupport) {
        return new MemorySessionCache(pt);
    }
}

MemorySessionCache::MemorySessionCache(const ptree& pt)
    : AbstractSessionCache(pt), m_spilog(Category::getInstance(SHIBSP_LOGCAT ".SessionCache.Memory"))
{
    m_cleanupInterval = getUnsignedInt(MEMORY_CLEANUP_INTERVAL_PROP_NAME, MEMORY_CLEANUP_INTERVAL_PROP_DEFAULT);
    if (!m_cleanupInterval) {
        m_spilog.info("%s was zero, disabling memmory back-end cleanup thread", MEMORY_CLEANUP_INTERVAL_PROP_NAME);
    }
}

MemorySessionCache::~MemorySessionCache()
{
}

bool MemorySessionCache::start()
{
    if (!AbstractSessionCache::start()) {
        return false;
    }

#ifdef HAVE_CXX17
    if (m_cleanupInterval) {
        try {
            m_mem_cleanup_thread = thread(memory_cleanup_fn, this);
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

void MemorySessionCache::stop()
{
    AbstractSessionCache::stop();
#ifdef HAVE_CXX17
    if (m_cleanupInterval) {
        m_mem_cleanup_wait.notify_all();
        if (m_mem_cleanup_thread.joinable()) {
            m_mem_cleanup_thread.join();
        }
    }
#endif
}
string MemorySessionCache::cache_create(SPRequest* request, DDF& sessionData)
{
    lock_guard<mutex> locker(m_lock);

    int attempts = 0;
    do {
        string key = hex_encode(m_rng(string(16,0)));
        if (m_storage.find(key) == m_storage.end()) {
            m_storage[key] = make_pair(sessionData.copy(), time(nullptr));
            return key;
        }
    } while (++attempts < 3);

    m_spilog.error("failed to write new session after 3 attempts to generate a unique key");
    throw IOException("Exhausted attempts to generate a unique session key.");
}

DDF MemorySessionCache::cache_read(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int version,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
    lock_guard<mutex> locker(m_lock);

    auto entry = m_storage.find(key);
    if (entry == m_storage.end()) {
        m_lock.unlock();
        return DDF();
    }

    time_t now = time(nullptr);

    if (timeout ) {
        if (entry->second.second + timeout < now) {
            if (m_spilog.isInfoEnabled()) {
                string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(entry->second.second)));
                m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
            }
            m_lock.unlock();
            cache_remove(request, key);
            return DDF();
        }
    }

    const char* appId = entry->second.first["app_id"].string();
    if (strcmp(applicationId, appId)) {
        m_spilog.warn("session (%s) issued for application (%s), accessed via application (%s)", key, appId, applicationId);
        return DDF();
    }

    if (lifetime) {
        time_t start = entry->second.first["ts"].longinteger();
        if (start + lifetime < now) {
            if (m_spilog.isInfoEnabled()) {
                string created(date::format("%FT%TZ", chrono::system_clock::from_time_t(start)));
                string expired(date::format("%FT%TZ", chrono::system_clock::from_time_t(start + lifetime)));
                m_spilog.info("session (%s) has expired, created (%s), expired (%s)", key, created.c_str(), expired.c_str());
            }
            m_lock.unlock();
            cache_remove(request, key);
            return DDF();
        }
    }

    if (client_addr) {
        const char* family = getAddressFamily(client_addr);
        const char* addr = entry->second.first[family].string();
        if (addr) {
            if (!isAddressMatch(client_addr, addr)) {
                m_spilog.info("session (%s) use invalid, bound to address (%s), accessed from (%s)", key, addr, client_addr);
                m_lock.unlock();
                return DDF();
            }
        }
        else {
            // We have to rebind the session to a new address family, requiring an update to the session.
            m_spilog.info("attempting update of session (%s) to rebind to new address (%s)", key, client_addr);

            // Fill in the new address and attempt the update.
            entry->second.first.addmember(family).string(client_addr);
            unsigned int oldver = entry->second.first.getmember("ver").integer();
            entry->second.first.addmember("ver").integer(oldver == 0 ? 2 : oldver + 1);
        }
    }

    entry->second.second = now;
    return entry->second.first.copy();
}

bool MemorySessionCache::cache_update(SPRequest* request, const char* key, unsigned int version, DDF& sessionData)
{
    lock_guard<mutex> locker(m_lock);

    auto entry = m_storage.find(key);
    if (entry == m_storage.end()) {
        return false;
    }

    unsigned int oldver = entry->second.first.getmember("ver").integer();
    if (oldver == 0) {
        oldver = 1;
    }

    if (version != oldver) {
        return false;
    }

    sessionData.addmember("ver").integer(++version);
    entry->second.first.destroy();
    entry->second.first = sessionData.copy();
    entry->second.second = time(nullptr);
    return true;
}

bool MemorySessionCache::cache_touch(SPRequest* request, const char* key, unsigned int version, unsigned int timeout)
{
    lock_guard<mutex> locker(m_lock);

    auto entry = m_storage.find(key);
    if (entry != m_storage.end()) {

        time_t now = time(nullptr);

        if (timeout && entry->second.second + timeout < now) {
            if (m_spilog.isInfoEnabled()) {
                string ts(date::format("%FT%TZ", chrono::system_clock::from_time_t(entry->second.second)));
                m_spilog.info("session (%s) expired for inactivity, timeout (%lu), last access (%s)", key, timeout, ts.c_str());
            }
            m_storage.erase(entry);
            return false;
        }

        entry->second.second = now;
        return true;
    }

    return false;
}

void MemorySessionCache::cache_remove(SPRequest* request, const char* key)
{
    lock_guard<mutex> locker(m_lock);
    m_storage.erase(key);
}

void* MemorySessionCache::memory_cleanup_fn(void* p)
{
    MemorySessionCache* pcache = reinterpret_cast<MemorySessionCache*>(p);

    static const char MEMORY_TIMEOUT_PROP_NAME[] = "memoryTimeout";
    static unsigned int MEMORY_TIMEOUT_PROP_DEFAULT = 3600 * 4;

    unsigned int memoryTimeout = pcache->getUnsignedInt(MEMORY_TIMEOUT_PROP_NAME, MEMORY_TIMEOUT_PROP_DEFAULT);
    if (memoryTimeout == 0) {
        memoryTimeout = MEMORY_TIMEOUT_PROP_DEFAULT;
    }

#ifndef WIN32
    // Bblock all signals.
    sigset_t sigmask;
    sigfillset(&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, nullptr);
#endif

    mutex internal_mutex;
    unique_lock<mutex> lock(internal_mutex);

    pcache->m_spilog.info("memory back-end cleanup thread started...run every %u secs, timeout after %u secs",
        pcache->m_cleanupInterval, memoryTimeout);

    while (!pcache->isShutdown()) {
        pcache->m_mem_cleanup_wait.wait_for(lock, chrono::seconds(pcache->m_cleanupInterval));
        
        if (pcache->isShutdown()) {
            pcache->m_spilog.debug("memory back-end cleanup thread shutting down");
            break;
        }

        // Ok, let's run through the cleanup process and clean out
        // really old sessions. We're brute forcing this because this
        // implementation is really just for testing anyway.

        time_t stale = time(nullptr) - memoryTimeout;

        pcache->m_spilog.debug("memory back-end cleanup thread running");

        vector<string> stale_keys;

        lock_guard<mutex> locker(pcache->m_lock);
        for (auto& session : pcache->m_storage) {
            // If the last access was BEFORE the stale timeout...
            if (session.second.second < stale) {
                session.second.first.destroy();
                stale_keys.push_back(session.first);
            }
        }
        for (const auto& key : stale_keys) {
            pcache->m_storage.erase(key);
        }

        pcache->m_spilog.debug("memory back-end cleanup thread completed work");
    }

    pcache->m_spilog.info("memory back-end cleanup thread exiting");

    return nullptr;
}
