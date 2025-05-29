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
#include "AgentConfig.h"
#include "SPRequest.h"
#include "io/CookieManager.h"
#include "logging/Category.h"
#include "session/AbstractSessionCache.h"

#include <chrono>
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
}

static const char CLEANUP_INTERVAL_PROP_NAME[] = "cleanupInterval";
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

AbstractSessionCache::AbstractSessionCache(const ptree& pt) : m_log(Category::getInstance(SHIBSP_LOGCAT ".SessionCache"))
{
    load(pt);

    m_issuerAttribute = getString(ISSUER_ATTRIBUTE_PROP_NAME, ISSUER_ATTRIBUTE_PROP_DEFAULT);

    // Set up cookie manager.
    m_cookieManager.reset(new CookieManager(getString(COOKIE_NAME_PROP_NAME, COOKIE_NAME_PROP_DEFAULT)));
    m_cookieManager->setCookieNamePolicy("sessionCookieName", true);
    m_cookieManager->setSecure(getBool(COOKIE_SECURE_PROP_NAME, COOKIE_SECURE_PROP_DEFAULT));
    m_cookieManager->setHttpOnly(getBool(COOKIE_HTTPONLY_PROP_NAME, COOKIE_HTTPONLY_PROP_DEFAULT));
    m_cookieManager->setPath(getString(COOKIE_PATH_PROP_NAME, COOKIE_PATH_PROP_DEFAULT));
    m_cookieManager->setMaxAge(getInt(COOKIE_MAXAGE_PROP_NAME, COOKIE_MAXAGE_PROP_DEFAULT));
    m_cookieManager->setDomain(getString(COOKIE_DOMAIN_PROP_NAME));
    m_cookieManager->setSameSite(getString(COOKIE_SAMESITE_PROP_NAME));
}

AbstractSessionCache::~AbstractSessionCache()
{
    // Notify and join with the cleanup thread.
    m_shutdown = true;
    m_shutdown_wait.notify_all();
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
}

Category& AbstractSessionCache::log() const
{
    return m_log;
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

string AbstractSessionCache::create(SPRequest& request, DDF& session)
{
    m_log.debug("creating new session");

    // Isolate from parent.
    session.remove();

    // Add additional fields managed by agent.
    // attributes and data members should be present from hub.
    session.addmember("creation").longinteger(time(nullptr));
    session.addmember("app_id").string(request.getRequestSettings().first->getString("applicationId"));
    session.addmember("addr").string(request.getRemoteAddr());

    // Write the data to the back-end, obtaining a key.
    string key;
    try {
        m_log.debug("writing new session to persistent store");
        key = cache_create(session);
    }
    catch (const IOException& ex) {
        m_log.error("IOException writing new session to persistent store: %s", ex.what());
        session.destroy();
        return string();
    }

    unique_ptr<BasicSession> sessionObject(new BasicSession(*this, session));

    const char* issuer = nullptr;
    const auto& attr = sessionObject->getAttributes().find(m_issuerAttribute);
    if (attr != sessionObject->getAttributes().end()) {
        issuer = const_cast<DDF&>(attr->second).first().string();
    }
    m_log.info("new session created: ID (%s), Issuer (%s), Address (%s)",
        key.c_str(), issuer ? issuer : "none", request.getRemoteAddr().c_str());

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
        m_log.debug("no session cookie present, no session found");
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

    unique_lock<Session> session = _find(applicationId, key, lifetime, timeout, client_addr);
    if (!session) {
        // If no session, we need to clear the session cookie to prevent further use.
        m_log.debug("clearing cookie for session (%s)", key);
        m_cookieManager->unsetCookie(request);
    }

    // Update last access (if this was just loaded from storage, this is a no-op.
    dynamic_cast<BasicSession*>(session.mutex())->setLastAccess(time(nullptr));
    return session;
}

unique_lock<Session> AbstractSessionCache::find(const char* applicationId, const char* key)
{
    // This variant does no request-based validation so it returns the session best effort
    // using the underlying _find method. It does ensure the applicationId matches if set.
    return _find(applicationId, key, 0, 0, nullptr);
}

unique_lock<Session> AbstractSessionCache::_find(
    const char* applicationId, const char* key, unsigned int lifetime, unsigned int timeout, const char* client_addr
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
        m_log.debug("session found locally, validating it for use");
        if (!dynamic_cast<BasicSession*>(session.mutex())->isValid(applicationId, lifetime, timeout, client_addr)) {
            session.unlock();
            m_log.debug("session (%s) was found but was invalid, removing it", key);
            remove(applicationId, key);
        }
        return session;
    }
    else {
        readlocker.unlock();
    }

    DDF obj;
    try {
        // Note this performs the relevant enforcement for us.
        obj = cache_read(applicationId, key, lifetime, timeout, client_addr);
    }
    catch (const exception& ex) {
        m_log.error("error reading session (%s) from persistent store: %s", key, ex.what());
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
        m_log.debug("session (%s) already inserted by another thread, replacing with our copy", key);
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

void AbstractSessionCache::remove(SPRequest& request, time_t revocationExp)
{
}

void AbstractSessionCache::remove(const char* applicationId, const char* key, time_t revocationExp)
{
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

    mutex internal_mutex;

    // Load our configuration details...
    unsigned int cleanupInterval = pcache->getUnsignedInt(CLEANUP_INTERVAL_PROP_NAME, CLEANUP_INTERVAL_PROP_DEFAULT);
    unsigned int inprocTimeout = pcache->getUnsignedInt(INPROC_TIMEOUT_PROP_NAME, INPROC_TIMEOUT_PROP_DEFAULT);

    unique_lock lock(internal_mutex);

    pcache->m_log.info("cleanup thread started...run every %u secs; timeout after %u secs", cleanupInterval, inprocTimeout);

    while (!pcache->m_shutdown) {
        pcache->m_shutdown_wait.wait_for(lock, chrono::seconds(cleanupInterval));
        
        if (pcache->m_shutdown) {
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

            // Pass 2: walk through the list of stale entries and remove them from the cache
            for (const string& key : stale_keys) {
                pcache->dormant(key.c_str());
            }
        }

        pcache->m_log.debug("cleanup thread completed");
    }

    pcache->m_log.info("cleanup thread exiting");

    return nullptr;
}

BasicSession::BasicSession(AbstractSessionCache& cache, DDF& obj)
    : m_obj(obj), m_cache(cache), m_creation(0), m_lastAccess(time(nullptr)), m_lastAccessReported(m_lastAccess)
{
    m_creation = m_obj["creation"].longinteger();

    // This is safe to directly expose for iteration of the attributes
    // as long as we maintain the mutex-based lock approach for exclusive
    // Session access. If we made that a shared lock, this all has to change.

    // We do have to index the attributes.
    DDF attrs = m_obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        m_attributes[attr.name()] = attr;
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

bool BasicSession::isValid(const char* applicationId, unsigned int lifetime, unsigned int timeout, const char* client_addr)
{
    return false;
}

time_t BasicSession::getCreation() const
{
    return m_creation;
}

time_t BasicSession::getLastAccess() const
{
    return m_lastAccess;
}

void BasicSession::setLastAccess(time_t ts)
{
    m_lastAccess = ts;
    // TODO: interval-driven touch method call
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

/*

void BasicSession::validate(const char* applicationId, const char* client_addr, time_t* timeout)
{
    time_t now = time(nullptr);

    // Basic expiration?
    if (m_expires > 0) {
        if (now > m_expires) {
            m_cache.m_log.info("session expired (ID: %s)", getID());
            throw SessionException("Your session has expired, and you must re-authenticate.");
        }
    }

    // Address check?
    if (client_addr) {
        const char* saddr = getClientAddress(getAddressFamily(client_addr));
        if (saddr && *saddr) {
            if (!m_cache.compareAddresses(client_addr, saddr)) {
                m_cache.m_log.warn("client address mismatch, client (%s), session (%s)", client_addr, saddr);
                throw SessionException(
                    string("Your IP address (") + client_addr + ") does not match the address recorded at the time the session was established."
                    );
            }
            client_addr = nullptr;  // clear out parameter as signal that session need not be updated below
        }
        else {
            m_cache.m_log.info("session (%s) not yet bound to client address type, binding it to (%s)", getID(), client_addr);
        }
    }

    if (!timeout && !client_addr)
        return;

    if (true) {
        DDF in("touch::" STORAGESERVICE_SESSION_CACHE "::SessionCache"), out;
        DDFJanitor jin(in);
        in.structure();
        in.addmember("key").string(getID());
        in.addmember("version").integer(m_obj["version"].integer());
        in.addmember("bucket_id").string(bucketID);
        if (client_addr)    // signals we need to bind an additional address to the session
            in.addmember("client_addr").string(client_addr);
        if (timeout && *timeout) {
            // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
            struct tm* ptime = gmtime(timeout);
#else
            struct tm res;
            struct tm* ptime = gmtime_r(timeout,&res);
#endif
            char timebuf[32];
            strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
            in.addmember("timeout").string(timebuf);
        }

        //out = app.getServiceProvider().getListenerService()->send(in);
        if (out.isstruct()) {
            // We got an updated record back.
            m_cache.m_log.debug("session updated, reconstituting it");
            m_attributes.clear();
            m_attributeIndex.clear();
            m_obj.destroy();
            m_obj = out;
        }
        else {
            out.destroy();
        }
    }
    else {
#ifndef SHIBSP_LITE
        if (!m_cache.m_storage)
            throw ConfigurationException("Session touch requires a StorageService.");

        // Versioned read, since we already have the data in hand if it's current.
        string record;
        time_t lastAccess = 0;
        int curver = m_obj["version"].integer();
        int ver = m_cache.m_storage->readText(getID(), "session", &record, &lastAccess, curver);
        if (ver == 0) {
            m_cache.m_log.info("session (ID: %s) no longer in storage", getID());
            throw RetryableProfileException("Your session is not available in the session store, and you must re-authenticate.");
        }

        if (timeout) {
            if (lastAccess == 0) {
                m_cache.m_log.error("session (ID: %s) did not report time of last access", getID());
                throw RetryableProfileException("Your session's last access time was missing, and you must re-authenticate.");
            }
            // Adjust for expiration to recover last access time and check timeout.
            unsigned long cacheTimeout = m_cache.getCacheTimeout(app);
            lastAccess -= cacheTimeout;
            if (*timeout > 0 && now - lastAccess >= *timeout) {
                m_cache.m_log.info("session timed out (ID: %s)", getID());
                throw RetryableProfileException("Your session has timed out due to inactivity, and you must re-authenticate.");
            }

            // Update storage expiration, if possible.
            try {
                m_cache.m_storage->updateContext(getID(), now + cacheTimeout);
            }
            catch (std::exception& ex) {
                m_cache.m_log.error("failed to update session expiration: %s", ex.what());
            }
        }

        if (ver > curver) {
            // We got an updated record back.
            DDF newobj;
            istringstream in(record);
            in >> newobj;
            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_attributeIndex.clear();
            m_obj.destroy();
            m_obj = newobj;
        }

        // We may need to write back a new address into the session using a versioned update loop.
        if (client_addr) {
            short attempts = 0;
            do {
                const char* saddr = getClientAddress(getAddressFamily(client_addr));
                if (saddr) {
                    // Something snuck in and bound the session to this address type, so it better match what we have.
                    if (!m_cache.compareAddresses(client_addr, saddr)) {
                        m_cache.m_log.warn("client address mismatch, client (%s), session (%s)", client_addr, saddr);
                        throw RetryableProfileException(
                            "Your IP address ($1) does not match the address recorded at the time the session was established.",
                            params(1, client_addr)
                            );
                    }
                    break;  // No need to update.
                }
                else {
                    // Bind it into the session.
                    setClientAddress(client_addr);
                }

                // Tentatively increment the version.
                m_obj["version"].integer(m_obj["version"].integer() + 1);

                ostringstream str;
                str << m_obj;
                record = str.str();

                try {
                    ver = m_cache.m_storage->updateText(getID(), "session", record.c_str(), 0, m_obj["version"].integer() - 1);
                }
                catch (std::exception&) {
                    m_obj["version"].integer(m_obj["version"].integer() - 1);
                    throw;
                }

                if (ver <= 0) {
                    m_obj["version"].integer(m_obj["version"].integer() - 1);
                }

                if (!ver) {
                    // Fatal problem with update.
                    m_cache.m_log.error("updateText failed on StorageService for session (%s)", getID());
                    throw IOException("Unable to update stored session.");
                }
                else if (ver < 0) {
                    // Out of sync.
                    if (++attempts > 10) {
                        m_cache.m_log.error("failed to bind client address, update attempts exceeded limit");
                        throw IOException("Unable to update stored session, exceeded retry limit.");
                    }
                    m_cache.m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
                    ver = m_cache.m_storage->readText(getID(), "session", &record);
                    if (!ver) {
                        m_cache.m_log.error("readText failed on StorageService for session (%s)", getID());
                        throw IOException("Unable to read back stored session.");
                    }

                    // Reset object.
                    DDF newobj;
                    istringstream in(record);
                    in >> newobj;

                    m_ids.clear();
                    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
                    m_attributes.clear();
                    m_attributeIndex.clear();
                    newobj["version"].integer(ver);
                    m_obj.destroy();
                    m_obj = newobj;

                    ver = -1;
                }
            } while (ver < 0); // negative indicates a sync issue so we retry
        }
#else
        throw ConfigurationException("Session touch requires a StorageService.");
#endif
    }

    m_lastAccess = now;
}

*/
