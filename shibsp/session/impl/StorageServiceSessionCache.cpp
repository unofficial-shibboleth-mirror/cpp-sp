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
 * session/impl/StorageServiceSessionCache.cpp
 *
 * SessionCache implementation using remoted access to StorageService via Hub.
 * 
 * <p>This is not a heavily optimized implementation at present, as there are
 * definitely more round trips than would be possible with additional purpose-
 * specific work in various places in the Hub to optimize the semantics of
 * some of the operations.</p>
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "csprng/csprng.hpp"
#include "remoting/RemotingService.h"
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"
#include "util/Date.h"
#include "util/Misc.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class StorageServiceSessionCache : public virtual AbstractSessionCache {
    public:
        StorageServiceSessionCache(const ptree& pt);
        ~StorageServiceSessionCache();

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
        Category& m_spilog;
        duthomhas::csprng m_rng;
        unsigned int m_storageTimeout;
    };

    static const char STORAGE_TIMEOUT_PROP_NAME[] = "storageTimeout";

    static unsigned int STORAGE_TIMEOUT_PROP_DEFAULT = 3600 * 2;
};

namespace shibsp {
    SessionCache* SHIBSP_DLLLOCAL StorageServiceSessionCacheFactory(ptree& pt, bool deprecationSupport) {
        return new StorageServiceSessionCache(pt);
    }
}

StorageServiceSessionCache::StorageServiceSessionCache(const ptree& pt)
    : AbstractSessionCache(pt), m_spilog(Category::getInstance(SHIBSP_LOGCAT ".SessionCache.StorageService"))
{
    m_storageTimeout = getUnsignedInt(STORAGE_TIMEOUT_PROP_NAME, STORAGE_TIMEOUT_PROP_DEFAULT);
}

StorageServiceSessionCache::~StorageServiceSessionCache()
{
}

string StorageServiceSessionCache::cache_create(SPRequest* request, DDF& sessionData)
{
    DDF in("storage");
    DDFJanitor injanitor(in);

    ostringstream sink;
    sink << sessionData;

    in.addmember("op").string("C");
    in.addmember("context").string("sessions");
    in.addmember("value").string(sink.str());
    in.addmember("exp").longinteger(time(nullptr) + m_storageTimeout);

    // Extremely unlikely to collide but we try 3 times just in case.

    int attempts = 0;
    do {
        string key = hex_encode(m_rng(string(16,0)));
        in.addmember("key").string(key);

        try {
            DDF out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
            out.destroy();
            return key;
        }
        catch (const OperationException& e) {
            const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
            if (!event || strcmp(event, "DuplicateRecord")) {
                m_spilog.error("failure storing session via Hub: event (%s): %s",
                    event ? event : "null", e.what());
                throw;
            }
        }
        catch (const exception& e) {
            m_spilog.error("exception attempting to store session via hub: %s", e.what());
            throw;
        }

    } while (++attempts < 3);

    m_spilog.error("failed to store new session via Hub after 3 attempts to generate a unique key");
    throw IOException("Exhausted attempts to generate a unique session key.");
}

/*
DDF StorageServiceSessionCache::cache_read(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int version,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
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

bool StorageServiceSessionCache::cache_touch(SPRequest* request, const char* key, unsigned int version, unsigned int timeout)
{
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

bool StorageServiceSessionCache::cache_update(SPRequest* request, const char* key, unsigned int version, DDF& data)
{
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

    data.addmember("ver").integer(++version);
    entry->second.first.destroy();
    entry->second.first = data.copy();
    entry->second.second = time(nullptr);
    return true;
}
*/

void StorageServiceSessionCache::cache_remove(SPRequest* request, const char* key)
{
    DDF in("storage");
    DDFJanitor injanitor(in);

    in.addmember("op").string("D");
    in.addmember("context").string("sessions");
    in.addmember("key").string(key);

    try {
        DDF out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
        out.destroy();
    }
    catch (const OperationException& e) {
        const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
        m_spilog.error("failure deleting session via Hub: event (%s): %s", event ? event : "null", e.what());
        throw;
    }
    catch (const exception& e) {
        m_spilog.error("exception attempting to delete session via hub: %s", e.what());
        throw;
    }

    m_spilog.debug("removed session from storage (%s)", key);
}
