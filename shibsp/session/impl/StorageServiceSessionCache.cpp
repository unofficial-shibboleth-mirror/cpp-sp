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

// Logging Macros
#define DEBUG_MARK request, m_spilog, Priority::SHIB_DEBUG
#define INFO_MARK request, m_spilog, Priority::SHIB_INFO
#define WARN_MARK request, m_spilog, Priority::SHIB_WARN
#define ERROR_MARK request, m_spilog, Priority::SHIB_ERROR
#define CRIT_MARK request, m_spilog, Priority::SHIB_CRIT

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
    DDF in = DDF("session-cache").structure();
    DDFJanitor injanitor(in);
    DDF sessionCopy = sessionData.copy();
    in.add(sessionCopy.name("session"));
    in.addmember("op").string("C");
    // setting needs to be forwarded to Hub to preserve last access time
    in.addmember("storage_timeout").longinteger(m_storageTimeout);

    try {
        DDF out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
        DDFJanitor outJanitor(out);
        const char* key = out["key"].string();
        if (!key || !*key) {
            log(ERROR_MARK, "no session key returned from create operation");
            throw OperationException("No session key returned from create operation.");
        }
        return string(key);
    }
    catch (const exception& e) {
        log(ERROR_MARK, "exception attempting to store session via Hub: %s", e.what());
        throw;
    }
}

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
    DDF in = DDF("session-cache").structure();
    DDFJanitor injanitor(in);

    in.addmember("op").string("R");
    // setting needs to be forwarded to Hub to recover last access time
    in.addmember("storage_timeout").integer(m_storageTimeout);
    in.addmember("key").string(key);

    if (timeout) {
        in.addmember("timeout").integer(timeout);
    }

    DDF out;
    try {
        out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
    }
    catch (const OperationException& e) {
        // Check for policy events.
        const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
        if (event && !strcmp(event, "InvalidSession")) {
            log(WARN_MARK, "stored session (%s) was invalid", key);
            return DDF();
        }
        else if (event && !strcmp(event, "ExpiredSession")) {
            log(WARN_MARK, "session (%s) expired due to lifetime or inactivity", key);
            return DDF();
        }
        log(ERROR_MARK, "exception attempting to update session (%s) via Hub: %s", key, e.what());
        throw;
    }
    catch (const exception& e) {
        log(ERROR_MARK, "exception attempting to read session (%s) from Hub: %s", key, e.what());
        throw;
    }

    DDFJanitor outjanitor(out);

    DDF sessionData = out["session"];
    if (sessionData.isnull()) {
        return sessionData;
    }

    if (!isSessionDataValid(sessionData)) {
        log(ERROR_MARK, "session data returned from Hub for (%s) was invalid", key);
        throw IOException("Session data was invalid.");
    }

    // Check application. We know the member exists due to the previous check.
    const char* appId = sessionData["app_id"].string();
    if (strcmp(applicationId, appId)) {
        log(WARN_MARK, "session (%s) issued for application (%s), accessed via application (%s)", key, appId, applicationId);
        return DDF();
    }

    if (lifetime) {
        time_t now = time(nullptr);
        time_t start = sessionData["ts"].longinteger();
        if (start + lifetime < now) {
            if (m_spilog.isInfoEnabled()) {
                string created(date::format("%FT%TZ", chrono::system_clock::from_time_t(start)));
                string expired(date::format("%FT%TZ", chrono::system_clock::from_time_t(start + lifetime)));
                log(INFO_MARK, "session (%s) has expired, created (%s), expired (%s)", key, created.c_str(), expired.c_str());
            }
            cache_remove(request, key);
            return DDF();
        }
    }

    if (client_addr) {
        const char* family = getAddressFamily(client_addr);
        const char* addr = sessionData[family].string();
        if (addr) {
            if (!isAddressMatch(client_addr, addr)) {
                log(INFO_MARK, "session (%s) use invalid, bound to address (%s), accessed from (%s)", key, addr, client_addr);
                return DDF();
            }
        }
        else {
            // We have to rebind the session to a new address family, requiring an update to the session.
            log(INFO_MARK, "attempting update of session (%s) to rebind to new address (%s)", key, client_addr);

            // Fill in the new address and attempt the update. We can do this using the "existing" output
            // because we have the object janitor'd and the cache_update copies the object internally.
            sessionData.addmember(family).string(client_addr);
            try {
                if (!cache_update(request, key, version, sessionData)) {
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
                log(ERROR_MARK, "exception attempting to update session (%s): %s", key, ex.what());
                throw;
            }
        }
    }    

    // Otherwise return the detached session structure.
    return sessionData.remove();
}

bool StorageServiceSessionCache::cache_update(SPRequest* request, const char* key, unsigned int version, DDF& sessionData)
{
    DDF in = DDF("session-cache").structure();
    DDFJanitor injanitor(in);

    DDF sessionCopy = sessionData.copy();
    in.add(sessionCopy.name("session"));
    in.addmember("op").string("U");
    // setting needs to be forwarded to Hub to set last access time
    in.addmember("storage_timeout").integer(m_storageTimeout);
    in.addmember("key").string(key);
    in.addmember("ver").integer(version);

    DDF out;
    try {
        out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
    }
    catch (const OperationException& e) {
        // Check for VersionMismatch event.
        const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
        if (event && !strcmp(event, "VersionMismatch")) {
            return false;
        }
        log(ERROR_MARK, "exception attempting to update session (%s) via Hub: %s", key, e.what());
        throw;
    }
    catch (const exception& e) {
        log(ERROR_MARK, "exception attempting to update session (%s) via Hub: %s", key, e.what());
        throw;
    }

    DDFJanitor outjanitor(out);

    DDF newver = out["ver"];
    if (newver.isnull()) {
        log(INFO_MARK, "session (%s) no longer exists", key);
        throw IOException("Session no longer exists.");
    }
    else if (newver.integer() <= (long) version) {
        log(ERROR_MARK, "missing/unexpected version returned from Hub from update of session (%s)", key);
        throw IOException("Missing/unexpected version returned from Hub from session update.");
    }

    // Ensure the new version is set accurately.
    sessionData.addmember("ver").integer(newver.integer());
    return true;
}

bool StorageServiceSessionCache::cache_touch(SPRequest* request, const char* key, unsigned int version, unsigned int timeout)
{
    DDF in = DDF("session-cache").structure();
    DDFJanitor injanitor(in);
    in.addmember("op").string("T");
    in.addmember("key").string(key);
    // setting needs to be forwarded to Hub to recover last access time
    in.addmember("storage_timeout").integer(m_storageTimeout);
    // Policy settings to enforce on Hub.
    if (timeout) {
        in.addmember("timeout").integer(timeout);
    }

    DDF out;
    try {
        out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
    }
    catch (const OperationException& e) {
        // Check for policy events.
        const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
        if (event) {
            if (!strcmp(event, "MissingSession")) {
                log(INFO_MARK, "stored session (%s) went missing", key);
                return false;
            }
            else if (!strcmp(event, "InvalidSession")) {
                log(WARN_MARK, "stored session (%s) was invalid", key);
                return false;
            }
            else if (!strcmp(event, "ExpiredSession")) {
                log(WARN_MARK, "session (%s) expired due to lifetime or inactivity", key);
                return false;
            }
        }
        log(ERROR_MARK, "exception attempting to touch session (%s) via Hub: %s", key, e.what());
        throw;
    }
    catch (const exception& e) {
        log(ERROR_MARK, "exception attempting to touch session (%s) via Hub: %s", key, e.what());
        throw;
    }

    DDFJanitor outjanitor(out);

    if (out.getmember("key").isstring()) {
        return true;
    }
    return false;
}

void StorageServiceSessionCache::cache_remove(SPRequest* request, const char* key)
{
    DDF in = DDF("session-cache").structure();
    DDFJanitor injanitor(in);

    in.addmember("op").string("D");
    in.addmember("key").string(key);

    try {
        DDF out = AgentConfig::getConfig().getAgent().getRemotingService()->send(in);
        out.destroy();
        log(DEBUG_MARK, "removed session from storage via Hub (%s)", key);
    }
    catch (const OperationException& e) {
        // Check for policy events.
        const char* event = e.getProperty(AgentException::EVENT_PROP_NAME);
        if (event && !strcmp(event, "MissingSession")) {
            log(DEBUG_MARK, "stored session (%s) went missing", key);
            return;
        }
        log(ERROR_MARK, "exception attempting to touch session (%s) via Hub: %s", key, e.what());
        throw;
    }
    catch (const exception& e) {
        log(ERROR_MARK, "exception attempting to delete session via hub: %s", e.what());
        throw;
    }
}
