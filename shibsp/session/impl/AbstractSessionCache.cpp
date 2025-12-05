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
#include "util/IPRange.h"
#include "util/Misc.h"

#include <boost/lexical_cast.hpp>
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
static const char UNRELIABLE_NETWORKS_PROP_NAME[] = "unreliableNetworks";
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

// Logging Macros
#define DEBUG_MARK request, m_log, Priority::SHIB_DEBUG
#define INFO_MARK request, m_log, Priority::SHIB_INFO
#define WARN_MARK request, m_log, Priority::SHIB_WARN
#define ERROR_MARK request, m_log, Priority::SHIB_ERROR
#define CRIT_MARK request, m_log, Priority::SHIB_CRIT

void SHIBSP_API shibsp::registerSessionCaches()
{
    AgentConfig::getConfig().SessionCacheManager.registerFactory(FILESYSTEM_SESSION_CACHE, FilesystemSessionCacheFactory);
    AgentConfig::getConfig().SessionCacheManager.registerFactory(MEMORY_SESSION_CACHE, MemorySessionCacheFactory);
    AgentConfig::getConfig().SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceSessionCacheFactory);
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

    if (!sessionData.isstruct()) {
        return false;
    }

    const char* appId = sessionData["app_id"].string();
    if (!appId || !*appId) {
        return false;
    }

    if (sessionData["ts"].longinteger() <= 0) {
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

    const char* unreliableNetworks = getString(UNRELIABLE_NETWORKS_PROP_NAME);
    if (unreliableNetworks) {
        vector<string> tokenized;
        split_to_container(tokenized, unreliableNetworks);
        for (const string& s : tokenized) {
            try {
                m_unreliableNetworks.push_back(IPRange::parseCIDRBlock(s.c_str()));
            }
            catch (const ConfigurationException& e) {
                m_log.error("error parsing CIDR expressioon (%s): %s", s.c_str(), e.what());
            }
        }
    }
}

AbstractSessionCache::~AbstractSessionCache()
{
}

Category& AbstractSessionCache::logger() const
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

const char* AbstractSessionCache::getAddressFamily(const std::string& addr)
{
    if (strchr(addr.c_str(), ':'))
        return "6";
    else
        return "4";
}

bool AbstractSessionCache::isAddressMatch(const char* one, const char* two) const
{
    if (!one || !two) {
        return false;
    }

    if (!strcmp(one, two)) {
        return true;
    }

    for (const IPRange& cidr : m_unreliableNetworks) {
        if (cidr.contains(one) && cidr.contains(two)) {
            return true;
        }
    }

    return false;
}

void AbstractSessionCache::computeVersionedFilename(string& path, unsigned int version)
{
    try {
        path = path + '.' + boost::lexical_cast<string>(version);
    }
    catch (const boost::bad_lexical_cast& e) {
        // Should never happen. In principle the path will effectively not exist when this happens.
        Category::getInstance(SHIBSP_LOGCAT ".SessionCache").error(
            "error converting version (%u) into string to compute filename: %s", version, e.what());
    }
}

void AbstractSessionCache::log(const SPRequest* request, Category& log, Priority::Value level, const char* formatString, ...)
{
    va_list va;
    va_start(va, formatString);
    if (request) {
        request->log(level, formatString, va);
    }
    else {
        log.logva(level, formatString, va);
    }
    va_end(va);
}

pair<string,unsigned int> AbstractSessionCache::parseCookieValue(const char* value)
{
    const char* sep = strrchr(value, '.');
    if (!sep) {
        // Shouldn't happen, but we can handle it.
        return make_pair(string(value), 1);
    }
    else if (!isdigit(*(sep + 1))) {
        // Check for negative
        return make_pair(string(value, sep), 1);
    }

    return make_pair(string(value, sep), atoi(sep +1));
}

string AbstractSessionCache::create(SPRequest& request, DDF& data)
{
    request.debug("creating new session");

    // Isolate from parent.
    data.remove();

    // Add additional fields managed by agent.
    // The version is absent, implying 1, as the common case.
    // The attributes member should be present from hub.
    data.addmember("ts").longinteger(time(nullptr));
    data.addmember("app_id").string(request.getRequestSettings().first->getString(
        RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT));
    data.addmember(getAddressFamily(request.getRemoteAddr())).string(request.getRemoteAddr());

    const AttributeConfiguration& attrConfig = request.getAgent().getAttributeConfiguration(
        request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME));
    DDF attrs = data["attributes"];
    if (!attrConfig.processAttributes(attrs)) {
        request.warn("error processing session attributes for storage/use");
        data.destroy();
        throw SessionException("Error while processing session attributes for storage.");
    }

    // Write the data to the back-end, obtaining a key.
    string key;
    try {
        request.debug("writing new session to persistent store");
        key = cache_create(&request, data);
    }
    catch (const exception&) {
        // Should be logged by the SPI.
        data.destroy();
        throw;
    }

    data.name(key.c_str());
    unique_ptr<BasicSession> sessionObject(new BasicSession(*this, data));

    const char* issuer = nullptr;
    const auto& attr = sessionObject->getAttributes().find(m_issuerAttribute);
    if (attr != sessionObject->getAttributes().end()) {
        issuer = const_cast<DDF&>(attr->second).first().string();
    }

    request.info("new session created: ID (%s), Issuer (%s), Address (%s)",
        key.c_str(), issuer ? issuer : "unknown", request.getRemoteAddr().c_str());

    // Drop a cookie with the session ID (the initial version suffix is 1).
    string cookieval = key + ".1";
    m_cookieManager->setCookie(request, cookieval.c_str());

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

    const char* cookieval = m_cookieManager->getCookieValue(request);
    if (!cookieval) {
        request.debug("no session cookie present");
        return unique_lock<Session>();
    }

    const auto& settings = request.getRequestSettings().first;

    const char* applicationId = settings->getString(RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT);
    unsigned int lifetime = settings->getUnsignedInt(RequestMapper::LIFETIME_PROP_NAME, RequestMapper::LIFETIME_PROP_DEFAULT);
    unsigned int timeout = 0;
    if (checkTimeout) {
        timeout = settings->getUnsignedInt(RequestMapper::TIMEOUT_PROP_NAME, RequestMapper::TIMEOUT_PROP_DEFAULT);
    }
    string client_addr;
    if (!ignoreAddress && settings->getBool(RequestMapper::CONSISTENT_ADDRESS_PROP_NAME, RequestMapper::CONSISTENT_ADDRESS_PROP_DEFAULT)) {
        client_addr = request.getRemoteAddr();
    }

    pair<string,unsigned int> keyver = parseCookieValue(cookieval);

    unique_lock<Session> session = _find(
        &request,
        applicationId,
        keyver.first.c_str(),
        keyver.second,
        lifetime,
        timeout,
        client_addr.empty() ? nullptr : client_addr.c_str());
    if (!session) {
        // No session, we need to clear the session cookie to prevent further use.
        request.debug("clearing cookie for session (%s)", keyver.first.c_str());
        m_cookieManager->unsetCookie(request);
    } else if (session.mutex()->getVersion() > keyver.second) {
        // The returned session's version is newer than our cookie value, we need to update our cookie.
        string new_cookieval(keyver.first);
        computeVersionedFilename(new_cookieval, session.mutex()->getVersion());
        m_cookieManager->setCookie(request, new_cookieval.c_str());
    }

    return session;
}

unique_lock<Session> AbstractSessionCache::find(const char* applicationId, const char* key, unsigned int version)
{
    // This variant does no request-based validation so it returns the session best effort
    // using the underlying _find method. It does ensure the applicationId matches if set.
    return _find(nullptr, applicationId, key, version, 0, 0, nullptr);
}

unique_lock<Session> AbstractSessionCache::_find(
    SPRequest* request,
    const char* applicationId,
    const char* key,
    unsigned int version,
    unsigned int lifetime,
    unsigned int timeout,
    const char* client_addr
    )
{
    log(DEBUG_MARK, "searching local cache for session (%s)", key);
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

        log(DEBUG_MARK, "session (%s) found locally, validating for use", key);

        // Cross-check application and check version for currency.
        if (strcmp(applicationId, session.mutex()->getApplicationID())) {
            log(WARN_MARK, "session (%s) issued for application (%s), accessed via application (%s)",
                key, session.mutex()->getApplicationID(), applicationId);
            session.unlock();
            return session;
        }
        else if (version > session.mutex()->getVersion()) {
            // The version we want is newer than the one we have cached.
            log(DEBUG_MARK, "session (%s) has stale version, removing it to reload", key);
            // We need to dump the local copy so we can recurse back in to load in the "later" version.
            session.unlock();   // need to unlock for dormant() to work
            dormant(request, key);
            // We want to fall into the cache_read step below to reload the latest version.
        }
        else if (!dynamic_cast<BasicSession*>(session.mutex())->isValid(request, lifetime, timeout)) {
            // Locally invalid on its face, so remove and return nothing.
            session.unlock();
            log(DEBUG_MARK, "session (%s) invalid, removing it", key);
            // The record should be gone from the back-end but we need to dump it locally.
            dormant(request, key);
            return session;
        }
        else if (client_addr) {
            // Check client address.
            const char* family = AbstractSessionCache::getAddressFamily(client_addr);
            const char* bound_addr = dynamic_cast<BasicSession*>(session.mutex())->getClientAddress(family);
            if (bound_addr) {
                if (!isAddressMatch(client_addr, bound_addr)) {
                    log(WARN_MARK, "session (%s) access invalid, bound to (%s), accessed from (%s)", key, bound_addr, client_addr);
                    session.unlock();
                }
                // Return locked session or empty wrapper depending on the check result.
                return session;
            }
            else {
                // We need to rebind the session and the cleanest way to do so is to leverage the
                // back-end's cache_read operation from scratch to refresh the session.
                log(DEBUG_MARK, "session (%s) is unbound to address family (%s), removing session for update/reload", key, family);
                // We need to dump the local copy so we can recurse back in to load in the "later" version.
                session.unlock();   // need to unlock for dormant() to work
                dormant(request, key);
                // We want to fall into the cache_read step below to reload the latest version.
            }
        }
        else {
            // Return the locked and valid session.
            return session;
        }
    }
    else {
        // No copy locally at all, so just fall into cache_read step below.
        readlocker.unlock();
        log(DEBUG_MARK, "session (%s) not found locally, loading from persistent store", key);
    }

    DDF obj;
    try {
        // Note this performs the relevant enforcement for us.
        obj = cache_read(request, applicationId, key, version, lifetime, timeout, client_addr);
        if (obj.isnull()) {
            log(DEBUG_MARK, "session (%s) not available in persistent store", key);
            return unique_lock<Session>();
        }
    }
    catch (const exception&) {
        // Should be logged by the SPI.
        return unique_lock<Session>();
    }

    log(DEBUG_MARK, "valid session (%s) loaded from persistent store", key);

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
        // There was an existing entry, but we want to swap in the "newest" copy in it's place.
        // Since we're holding the cache write lock, we know nobody can have a lock on the
        // new object yet, but the old object might be locked by somebody. However, once we
        // acquire a lock on the old Session, we know nobody else is waiting for that lock because
        // they would have to be inside the cache's critical section to get to it.
        // Thus, this sequence transfers ownership out of the table, removes the entry, then
        // locks, unlocks, and finally deletes the old session object.
        log(DEBUG_MARK, "replacing session (%s) with fresh copy", key);
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

bool AbstractSessionCache::update(SPRequest& request, unique_lock<Session>& session, DDF& data, const char* reason)
{
    // On input we hold an exclusive lock on the relevant session.

    DDF newData;

    try {
        // Validate and reformat attribute data.
        const AttributeConfiguration& attrConfig = request.getAgent().getAttributeConfiguration(
            request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME));
        DDF attrs = data["attributes"];
        if (!attrConfig.processAttributes(attrs)) {
            request.warn("error processing updated session attributes for storage/use");
            data.destroy();
            throw SessionException("Error while processing updated session attributes for storage.");
        }

        request.info("updating session (%s), version (%u), reason (%s)",
            session.mutex()->getID(), session.mutex()->getVersion(), reason ? reason : "(unspecified)");

        // The update requires that we copy the existing DDF from the original session and then
        // replace members with "like" names.
        newData = dynamic_cast<BasicSession*>(session.mutex())->cloneData();
        DDFJanitor janitor(newData);
        DDF child = data.first();
        while (!child.isnull()) {
            // This call defends against an empty name, and handles cleanup of an existing member by the same name.
            newData.add(child);
            child = data.next();
        }
        // Free whatever's left of the input.
        data.destroy();

        // Attempt to update the back-end.
        if (cache_update(&request, session.mutex()->getID(), session.mutex()->getVersion(), newData)) {
            // On success, the version field will have been updated and we need to overwrite the local copy of
            // this session's data.
            dynamic_cast<BasicSession*>(session.mutex())->updateData(newData);
            janitor.release();

            // We need to update our cookie since by definition we incremented the version.
            string new_cookieval(session.mutex()->getID());
            computeVersionedFilename(new_cookieval, session.mutex()->getVersion());
            m_cookieManager->setCookie(request, new_cookieval.c_str());
            return true;
        }
        else {
            return false;
        }
    }
    catch (const exception&) {
        // Should be logged by the SPI.
        data.destroy();
        throw;
    }
}

void AbstractSessionCache::remove(SPRequest& request)
{
    const char* cookieval = m_cookieManager->getCookieValue(request);
    if (!cookieval) {
        request.debug("no session cookie present, no session bound to request for removal");
        return;
    }

    pair<string,unsigned int> keyver = parseCookieValue(cookieval);

    dormant(&request, keyver.first);
    try {
        cache_remove(&request, keyver.first.c_str());
    }
    catch (const exception&) {
        // Should be logged by the SPI.
    }
    m_cookieManager->unsetCookie(request);
}

void AbstractSessionCache::remove(const char* key)
{
    dormant(nullptr, key);
    try {
        cache_remove(nullptr, key);
    }
    catch (const exception&) {
        // Should be logged by the SPI.
    }
}

void AbstractSessionCache::dormant(const SPRequest* request, const string& key)
{
    log(DEBUG_MARK, "deleting local copy of session (%s)", key.c_str());

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
    if (cleanupInterval == 0) {
        cleanupInterval = CLEANUP_INTERVAL_PROP_DEFAULT;
    }
    unsigned int inprocTimeout = pcache->getUnsignedInt(INPROC_TIMEOUT_PROP_NAME, INPROC_TIMEOUT_PROP_DEFAULT);
    if (inprocTimeout == 0) {
        inprocTimeout = INPROC_TIMEOUT_PROP_DEFAULT;
    }

    mutex internal_mutex;
    unique_lock<mutex> lock(internal_mutex);

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
                pcache->dormant(nullptr, key.c_str());
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

unsigned int BasicSession::getVersion() const
{
    unsigned int ver = m_obj["ver"].integer();
    return ver > 0 ? ver : 1;
}

const char* BasicSession::getApplicationID() const
{
    return m_obj["app_id"].string();
}

const char* BasicSession::getClientAddress(const char* family) const
{
    return m_obj[family].string();
}

const std::map<std::string,DDF>& BasicSession::getAttributes() const
{
    return m_attributes;
}

DDF BasicSession::getOpaqueData() const
{
    return m_obj["opaque"];
}

DDF BasicSession::cloneData() const
{
    return m_obj.copy();
}

void BasicSession::updateData(DDF& data)
{
    m_obj.destroy();
    m_obj = data;
}

bool BasicSession::isValid(SPRequest* request, unsigned int lifetime, unsigned int timeout)
{
    time_t now = time(nullptr);

    if (lifetime) {
        // Enforce session lifetime.
        if (getCreation() + lifetime < now) {
            if ((request && request->isPriorityEnabled(Priority::SHIB_WARN)) || m_cache.logger().isWarnEnabled()) {
                string created(date::format("%FT%TZ", chrono::system_clock::from_time_t(getCreation())));
                string expired(date::format("%FT%TZ", chrono::system_clock::from_time_t(getCreation() + lifetime)));
                AbstractSessionCache::log(request, m_cache.logger(), Priority::SHIB_WARN,
                    "session (%s) has expired, created (%s), expired (%s)", getID(), created.c_str(), expired.c_str());
            }
            try {
                m_cache.cache_remove(request, getID());
            }
            catch (const exception&) {
                // Should be logged by SPI.
            }
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
                if (!m_cache.cache_touch(request, getID(), getVersion(), 0)) {
                    AbstractSessionCache::log(request, m_cache.logger(), Priority::SHIB_WARN,
                        "session (%) missing in persistent store, invalidating locally", getID());
                    return false;
                }
            }
            catch (const exception&) {
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
            if (!m_cache.cache_touch(request, getID(), getVersion(), timeout)) {
                AbstractSessionCache::log(request, m_cache.logger(), Priority::SHIB_WARN,
                    "session (%s) timed out due to inactivity", getID());
                return false;
            }
        }
        catch (const exception&) {
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
