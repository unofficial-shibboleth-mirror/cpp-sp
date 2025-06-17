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
#include "Agent.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "attribute/AttributeConfiguration.h"
#include "io/CookieManager.h"
#include "logging/Category.h"
#include "session/AbstractSessionCache.h"
#include "util/Date.h"

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

namespace shibsp {
    extern SessionCache* SHIBSP_DLLLOCAL FilesystemSessionCacheFactory(ptree& pt, bool deprecationSupport);
    extern SessionCache* SHIBSP_DLLLOCAL StorageServiceSessionCacheFactory(ptree& pt, bool deprecationSupport);
    extern SessionCache* SHIBSP_DLLLOCAL MemorySessionCacheFactory(ptree& pt, bool deprecationSupport);
}

static const char CLEANUP_INTERVAL_PROP_NAME[] = "cleanupInterval";
static const char STORAGE_ACCESS_INTERVAL_PROP_NAME[] = "storageAccessInterval";
static const char INPROC_TIMEOUT_PROP_NAME[] = "inprocTimeout";
static const char ISSUER_ATTRIBUTE_PROP_NAME[] = "issuerAttribute";
static const char COOKIE_NAME_PROP_NAME[] = "cookieName";
static const char COOKIE_SECURE_PROP_NAME[] = "cookieSecure";
static const char COOKIE_HTTPONLY_PROP_NAME[] = "cookieHttpOnly";
static const char COOKIE_PATH_PROP_NAME[] = "cookiePath";
static const char COOKIE_DOMAIN_PROP_NAME[] = "cookieDomain";
static const char COOKIE_MAXAGE_PROP_NAME[] = "cookieMaxAge";
static const char COOKIE_SAMESITE_PROP_NAME[] = "cookieSameSite";

static unsigned int CLEANUP_INTERVAL_PROP_DEFAULT = 900;
static unsigned int STORAGE_ACCESS_INTERVAL_PROP_DEFAULT = 600;
static unsigned int INPROC_TIMEOUT_PROP_DEFAULT = 900;
static const char ISSUER_ATTRIBUTE_PROP_DEFAULT[] = "Shib-Identity-Provider";
static const char COOKIE_NAME_PROP_DEFAULT[] = "__Host-shibsession";
static bool COOKIE_SECURE_PROP_DEFAULT = true;
static bool COOKIE_HTTPONLY_PROP_DEFAULT = true;
static const char COOKIE_PATH_PROP_DEFAULT[] = "/";
static int COOKIE_MAXAGE_PROP_DEFAULT = -1;

void SHIBSP_API shibsp::registerSessionCaches()
{
    AgentConfig::getConfig().SessionCacheManager.registerFactory(FILESYSTEM_SESSION_CACHE, FilesystemSessionCacheFactory);
    AgentConfig::getConfig().SessionCacheManager.registerFactory(MEMORY_SESSION_CACHE, MemorySessionCacheFactory);
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

SessionCacheSPI::SessionCacheSPI()
{
}

SessionCacheSPI::~SessionCacheSPI()
{
}

bool AbstractSessionCache::isSessionDataValid(DDF& sessionData)
{
    // Must be a structure
    // Must have a non-empty string "app_id" member
    // Must have a positive longinteger "ts" member

    const char* appId = sessionData["app_id"].string();
    if (!appId || !*appId) {
        return false;
    }

    if (sessionData["ts"].longinteger() < 0) {
        return false;
    }

    // Must have a non-empty list "attributes" member with the session's
    // data. Each attribute must have a non-null name and at least one
    // non-null string value, and no other value types.

    DDF attrs = sessionData["attributes"];
    if (!attrs.islist()) {
        return false;
    }
    else if (attrs.integer() == 0) {
        // Empty list.
        return true;
    }

    DDF attr = attrs.first();

    // If the values aren't in a list, bail.
    if (!attr.islist()) {
        return false;
    }

    // Runs loop for each "value collection", i.e. each attribute.
    do {
        // No values?
        if (attr.integer() == 0) {
            return false;
        }

        // Empty/null name?
        const char* name = attr.name();
        if (!name || !*name) {
            return false;
        }

        DDF val = attr.first();

        // Value not a string?
        if (!val.isstring()) {
            return false;
        }

        // Run loop for each value.
        do {
            // Value empty/null?
            const char* s = val.string();
            if (!s || !*s) {
                return false;
            }
            
            // Get next value.
            val = attr.next();
        } while (val.isstring());

        // A string would continue the loop, so if not null now, bail.
        if (!val.isnull()) {
            return false;
        }

        // Get next attribute.
        attr = attrs.next();
    } while (attr.islist());

    // A list would continue the loop, so if not null now, bail.
    if (!attr.isnull()) {
        return false;
    }

    return true;
}

AbstractSessionCache::AbstractSessionCache(const ptree& pt)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".SessionCache")), m_shutdown(false)
{
    load(pt);

    m_issuerAttribute = getString(ISSUER_ATTRIBUTE_PROP_NAME, ISSUER_ATTRIBUTE_PROP_DEFAULT);
    m_storageAccessInterval = getUnsignedInt(STORAGE_ACCESS_INTERVAL_PROP_NAME, STORAGE_ACCESS_INTERVAL_PROP_DEFAULT);

    // Set up cookie manager.
    m_cookieManager.reset(new CookieManager(getString(COOKIE_NAME_PROP_NAME, COOKIE_NAME_PROP_DEFAULT)));
    m_cookieManager->setCookieNamePolicy(RequestMapper::SESSION_COOKIE_NAME_PROP_NAME, true);
    m_cookieManager->setSecure(getBool(COOKIE_SECURE_PROP_NAME, COOKIE_SECURE_PROP_DEFAULT));
    m_cookieManager->setHttpOnly(getBool(COOKIE_HTTPONLY_PROP_NAME, COOKIE_HTTPONLY_PROP_DEFAULT));
    m_cookieManager->setPath(getString(COOKIE_PATH_PROP_NAME, COOKIE_PATH_PROP_DEFAULT));
    m_cookieManager->setMaxAge(getInt(COOKIE_MAXAGE_PROP_NAME, COOKIE_MAXAGE_PROP_DEFAULT));
    m_cookieManager->setDomain(getString(COOKIE_DOMAIN_PROP_NAME));
    m_cookieManager->setSameSite(getString(COOKIE_SAMESITE_PROP_NAME));
}

AbstractSessionCache::~AbstractSessionCache()
{
}

Category& AbstractSessionCache::log() const
{
    return m_log;
}

bool AbstractSessionCache::isShutdown() const
{
    return m_shutdown;
}

bool AbstractSessionCache::start()
{
    try {
        m_cleanup_thread = thread(cleanup_fn, this);
        return true;
    }
    catch (const system_error& e) {
        m_log.error("error starting cleanup thread: %s", e.what());
    }
    return false;
}

void AbstractSessionCache::stop()
{
    // Notify and join with the cleanup thread.
    m_shutdown = true;
    m_shutdown_wait.notify_all();
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
}

string AbstractSessionCache::create(SPRequest& request, DDF& session)
{
    m_log.debug("creating new session");

    // Isolate from parent.
    session.remove();

    // Add additional fields managed by agent.
    // The attributes member should be present from hub.
    session.addmember("ts").longinteger(time(nullptr));
    session.addmember("app_id").string(request.getRequestSettings().first->getString(
        RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT));
    session.addmember("addr").string(request.getRemoteAddr());

    const AttributeConfiguration& attrConfig = request.getAgent().getAttributeConfiguration(
        request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME));
    DDF attrs = session["attributes"];
    if (!attrConfig.processAttributes(attrs)) {
        m_log.warn("error processing session attributes for storage/use");
        session.destroy();
        throw SessionException("Error while processing session attributes for storage.");
    }

    // Write the data to the back-end, obtaining a key.
    string key;
    try {
        m_log.debug("writing new session to persistent store");
        key = cache_create(&request, session);
    }
    catch (const exception& ex) {
        // Should be logged by the SPI.
        session.destroy();
        throw;
    }

    session.name(key.c_str());
    unique_ptr<BasicSession> sessionObject(new BasicSession(*this, session));

    const char* issuer = nullptr;
    const auto& attr = sessionObject->getAttributes().find(m_issuerAttribute);
    if (attr != sessionObject->getAttributes().end()) {
        issuer = const_cast<DDF&>(attr->second).first().string();
    }

    m_log.info("new session created: ID (%s), Issuer (%s), Address (%s)",
        key.c_str(), issuer ? issuer : "unknown", request.getRemoteAddr().c_str());

    // Drop a cookie with the session ID.
    m_cookieManager->setCookie(request, key.c_str());

    // Lock the cache and insert the new session.

    // Note, the C23 standard includes a typeof operator, but until then...
#if defined(HAVE_CXX17)
    lock_guard<shared_mutex> locker(m_lock);
#elif defined(HAVE_CXX14)
    lock_guard<shared_timed_mutex> locker(m_lock);
#else
    lock_guard<mutex> locker(m_lock);
#endif

    m_hashtable[key] = std::move_if_noexcept(sessionObject);

    return key;
}

unique_lock<Session> AbstractSessionCache::find(SPRequest& request, bool checkTimeout, bool ignoreAddress)
{
    // Validation here depends on request content settings plus the input flags. The resulting policy
    // is passed to the _find method for enforcement.

    const char* key = m_cookieManager->getCookieValue(request);
    if (!key) {
        m_log.debug("no session cookie present");
        return unique_lock<Session>();
    }

    const auto& settings = request.getRequestSettings().first;

    const char* applicationId = settings->getString(RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_NAME);
    unsigned int lifetime = settings->getUnsignedInt(RequestMapper::LIFETIME_PROP_NAME, RequestMapper::LIFETIME_PROP_DEFAULT);
    unsigned int timeout = 0;
    if (checkTimeout) {
        timeout = settings->getUnsignedInt(RequestMapper::TIMEOUT_PROP_NAME, RequestMapper::TIMEOUT_PROP_DEFAULT);
    }
    const char* client_addr = nullptr;
    if (!ignoreAddress && settings->getBool(RequestMapper::CONSISTENT_ADDRESS_PROP_NAME, RequestMapper::CONSISTENT_ADDRESS_PROP_DEFAULT)) {
        client_addr = request.getRemoteAddr().c_str();
    }

    unique_lock<Session> session = _find(&request, applicationId, key, lifetime, timeout, client_addr);
    if (!session) {
        // If no session, we need to clear the session cookie to prevent further use.
        m_log.debug("clearing cookie for session (%s)", key);
        m_cookieManager->unsetCookie(request);
    }

    return session;
}

unique_lock<Session> AbstractSessionCache::find(const char* applicationId, const char* key)
{
    // This variant does no request-based validation so it returns the session best effort
    // using the underlying _find method. It does ensure the applicationId matches if set.
    return _find(nullptr, applicationId, key, 0, 0, nullptr);
}

unique_lock<Session> AbstractSessionCache::_find(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
    m_log.debug("searching local cache for session (%s)", key);
#if defined(HAVE_CXX17)
    shared_lock<shared_mutex> readlocker(m_lock);
#elif defined(HAVE_CXX14)
    shared_lock<shared_timed_mutex> readlocker(m_lock);
#else
    unique_lock<mutex> readlocker(m_lock);
#endif
    const auto& i = m_hashtable.find(key);
    if (i != m_hashtable.end()) {
        // Save off and lock the session.
        unique_lock<Session> session(*(i->second));
        readlocker.unlock();

        m_log.debug("session (%s) found locally, validating for use", key);

        // Cross-check application.
        if (strcmp(applicationId, session.mutex()->getApplicationID())) {
            m_log.warn("session (%s) issued for application (%s), accessed via application (%s)",
                key, session.mutex()->getApplicationID(), applicationId);
            session.unlock();
        }
        else if (!dynamic_cast<BasicSession*>(session.mutex())->isValid(request, lifetime, timeout, client_addr)) {
            // Locally invalid on its face, so remove and return nothing.
            session.unlock();
            m_log.debug("session (%s) invalid, removing it", key);
            // The record should be gone from the back-end but we need to dump it locally.
            dormant(string(key));
        }

        // Return locked session or empty wrapper.
        return session;
    }
    else {
        readlocker.unlock();
        m_log.debug("session (%s) not found locally, loading from persistent store", key);
    }

    DDF obj;
    try {
        // Note this performs the relevant enforcement for us.
        obj = cache_read(request, applicationId, key, lifetime, timeout, client_addr);
    }
    catch (const exception& ex) {
        // Should be logged by the SPI.
        return unique_lock<Session>();
    }

    if (obj.isnull()) {
        m_log.info("session (%s) not found in persistent store", key);
        return unique_lock<Session>();
    }

    m_log.info("valid session (%s) loaded from persistent store");

    // Wrap the object in a local wraper to guard it before it's saved off.
    unique_ptr<BasicSession> newSession(new BasicSession(*this, obj));

    // Lock the cache and check for a race condition with another thread...

    // Note, the C23 standard includes a typeof operator, but until then...
#if defined(HAVE_CXX17)
    lock_guard<shared_mutex> locker(m_lock);
#elif defined(HAVE_CXX14)
    lock_guard<shared_timed_mutex> locker(m_lock);
#else
    lock_guard<mutex> locker(m_lock);
#endif

    if (m_hashtable.count(key)) {
        // There was an existing entry, but we want to swap the "newest" copy in place of it.
        // Since we're holding the cache write lock, we know nobody can have a lock on the
        // new copy yet, but the old copy might be locked by somebody. However, once we acquire
        // a lock on the old Session, we know nobody else is waiting for that lock because they
        // would have to be inside the cache critical section to get to it.
        // Thus, this sequence transfers ownership out of the table, removes the entry, then
        // locks, unlocks, and finally deletes the old session object.
        m_log.debug("replacing session (%s) with fresh copy", key);
        unique_ptr<BasicSession> oldSession;
        oldSession.swap(m_hashtable[key]);
        m_hashtable.erase(key);
        lock_guard<BasicSession> oldSessionLock(*oldSession.get());
    }

    // Finally, get an "empty" smart pointer out of the table to "insert" the new entry,
    // swap over ownership from our copy, and finally return a locked wrapper around it.
    unique_ptr<BasicSession>& ref = m_hashtable[key];
    ref.swap(newSession);
    return unique_lock<Session>(*ref);
}

void AbstractSessionCache::remove(SPRequest& request)
{
    const char* key = m_cookieManager->getCookieValue(request);
    if (!key) {
        m_log.debug("no session cookie present, no session bound to request");
        return;
    }
    dormant(string(key));
    try {
        cache_remove(&request, key);
    }
    catch (const exception& ex) {
        // Should be logged by the SPI.
    }
    m_cookieManager->unsetCookie(request);
}

void AbstractSessionCache::remove(const char* key)
{
    dormant(string(key));
    cache_remove(nullptr, key);
}

void AbstractSessionCache::dormant(const string& key)
{
    m_log.debug("deleting local copy of session (%s)", key.c_str());

    // lock the cache for writing, which means we know nobody is sitting in a lookup.
    m_lock.lock();

    // grab the entry from the table
    const auto& i = m_hashtable.find(key);
    if (i == m_hashtable.end()) {
        m_lock.unlock();
        return;
    }

    // ok, swap ownership of the entry, remove from cache
    unique_ptr<BasicSession> session;
    session.swap(i->second);
    m_hashtable.erase(key);

    // lock the entry, ensuring nobody else has a copy
    session->lock();

    // unlock the cache
    m_lock.unlock();

    // we can release the cache entry lock because we know we're not in the cache anymore
    session->unlock();
}

void* AbstractSessionCache::cleanup_fn(void* p)
{
    AbstractSessionCache* pcache = reinterpret_cast<AbstractSessionCache*>(p);

#ifndef WIN32
    // Bblock all signals.
    sigset_t sigmask;
    sigfillset(&sigmask);
    pthread_sigmask(SIG_BLOCK, &sigmask, nullptr);
#endif

    // Load our configuration details...
    unsigned int cleanupInterval = pcache->getUnsignedInt(CLEANUP_INTERVAL_PROP_NAME, CLEANUP_INTERVAL_PROP_DEFAULT);
    unsigned int inprocTimeout = pcache->getUnsignedInt(INPROC_TIMEOUT_PROP_NAME, INPROC_TIMEOUT_PROP_DEFAULT);

    mutex internal_mutex;
    unique_lock lock(internal_mutex);

    pcache->m_log.info("cleanup thread started...run every %u secs, timeout after %u secs", cleanupInterval, inprocTimeout);

    while (!pcache->m_shutdown) {
        pcache->m_shutdown_wait.wait_for(lock, chrono::seconds(cleanupInterval));
        
        if (pcache->m_shutdown) {
            pcache->m_log.debug("cleanup thread shutting down");
            break;
        }

        // Ok, let's run through the cleanup process and clean out
        // really old sessions.  This is a two-pass process.  The
        // first pass is done holding a read-lock while we iterate over
        // the cache.  The second pass doesn't need a lock because
        // the 'deletes' will lock the cache.

        // Pass 1: iterate over the map and find all entries that have not been
        // used in the allotted timeout.
        vector<string> stale_keys;
        time_t stale = time(nullptr) - inprocTimeout;

        pcache->m_log.debug("cleanup thread running");

#ifdef HAVE_CXX14
        pcache->m_lock.lock_shared();
#else
        pcache->m_lock.lock();
#endif
        for (const auto& session : pcache->m_hashtable) {
            // If the last access was BEFORE the stale timeout...
            session.second->lock();
            time_t last = session.second->getLastAccess();
            session.second->unlock();
            if (last < stale)
                stale_keys.push_back(session.first);
        }

        pcache->m_lock.unlock();

        if (!stale_keys.empty()) {
            pcache->m_log.info("purging %u old sessions", stale_keys.size());

            // Pass 2: walk through the list of stale entries and remove them from the local cache.
            for (const string& key : stale_keys) {
                pcache->dormant(key.c_str());
            }
        }

        pcache->m_log.debug("cleanup thread completed work");
    }

    pcache->m_log.info("cleanup thread exiting");

    return nullptr;
}

BasicSession::BasicSession(AbstractSessionCache& cache, DDF& obj)
    : m_obj(obj), m_cache(cache), m_lastAccess(time(nullptr)), m_lastAccessReported(m_lastAccess)
{
    // This is safe to directly expose for iteration of the attributes
    // as long as we maintain the mutex-based lock approach for exclusive
    // Session access. If we made that a shared lock, this all has to change.

    // We do have to index the attributes.
    DDF attrs = m_obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        if (attr.name()) {
            m_attributes[attr.name()] = attr;
        }
        attr = attrs.next();
    }
}

BasicSession::~BasicSession()
{
    m_obj.destroy();
}

const char* BasicSession::getID() const
{
    return m_obj.name();
}

const char* BasicSession::getApplicationID() const
{
    return m_obj["app_id"].string();
}

const char* BasicSession::getClientAddress() const
{
    return m_obj["addr"].string();
}

const std::map<std::string,DDF>& BasicSession::getAttributes() const
{
    return m_attributes;
}

bool BasicSession::isValid(SPRequest* request, unsigned int lifetime, unsigned int timeout, const char* client_addr)
{
    // Check client address.
    // TODO: Implement the fuzzy address matching.
    if (client_addr && strcmp(client_addr, getClientAddress())) {
        m_cache.log().warn("session (%s) invalid, bound to address (%s), accessed from (%s)", getID(), getClientAddress(), client_addr);
        m_cache.cache_remove(request, getID());
        return false;
    }

    time_t now = time(nullptr);

    // Enforce session lifetime.
    if (lifetime) {
        if (getCreation() + lifetime < now) {
            if (m_cache.log().isWarnEnabled()) {
                string created(date::format("%FT%TZ", chrono::system_clock::from_time_t(getCreation())));
                string expired(date::format("%FT%TZ", chrono::system_clock::from_time_t(getCreation() + lifetime)));
                m_cache.log().warn("session (%s) has expired, created (%s), expired (%s)", getID(), created.c_str(), expired.c_str());
            }
            m_cache.cache_remove(request, getID());
            return false;
        }
    }

    if (!timeout || m_lastAccess + timeout > now) {

        // Being locally valid, we want to update the activity timestamp in the persistent store.
        // This check also notices a session having been revoked, so implements the concept of the cache being
        // "eventually consistent" across agent processes.

        if (m_lastAccess - m_lastAccessReported > m_cache.m_storageAccessInterval) {
            try {
                // Pass a zero to bypass timeout enforcement as we know as well or better than the back-end...
                if (!m_cache.cache_touch(request, getID(), 0)) {
                    m_cache.log().warn("session (%) missing in persistent store, invalidating locally", getID());
                    return false;
                }
            }
            catch (const exception& ex) {
                // Should be logged by the SPI.
                return false;
            }
            // Update reporting timestamp.
            m_lastAccessReported = now;
        }
    }
    else {
        try {
            // The session is locally invalid due to inactivity, but this isn't "truth" because other agent processes may
            // actively be using it.
            if (!m_cache.cache_touch(request, getID(), timeout)) {
                m_cache.log().warn("session (%s) timed out due to inactivity", getID());
                return false;
            }
        }
        catch (const exception& ex) {
            // Should be logged by the SPI.
            return false;
        }
        // Update reporting timestamp.
        m_lastAccessReported = now;
    }

    // Update last access time locally.
    m_lastAccess = now;

    return true;
}

time_t BasicSession::getCreation() const
{
    return m_obj["ts"].longinteger();
}

time_t BasicSession::getLastAccess() const
{
    return m_lastAccess;
}

void BasicSession::lock()
{
    m_lock.lock();
}

bool BasicSession::try_lock()
{
    return m_lock.try_lock();
}

void BasicSession::unlock()
{
    m_lock.unlock();
}
