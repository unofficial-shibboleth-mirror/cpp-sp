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
#include "attribute/Attribute.h"
#include "session/AbstractSessionCache.h"
#include "logging/Category.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
    extern SessionCache* SHIBSP_DLLLOCAL FilesystemSessionCacheFactory(ptree& pt, bool deprecationSupport);
    extern SessionCache* SHIBSP_DLLLOCAL StorageServiceSessionCacheFactory(ptree& pt, bool deprecationSupport);
}

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

AbstractSessionCache::AbstractSessionCache() : m_log(Category::getInstance(SHIBSP_LOGCAT ".SessionCache"))
{
}

AbstractSessionCache::~AbstractSessionCache()
{
}

bool AbstractSessionCache::start()
{
}

BasicSession::BasicSession(AbstractSessionCache& cache, DDF& obj)
    : m_obj(obj), m_cache(cache), m_creation(0), m_lastAccess(time(nullptr))
{
    m_creation = m_obj["creation"].longinteger();

    // We have to index and vector-up the values of the attributes.
    // (Among other reasons, the DDF iteration API isn't threadsafe.)
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
    return m_obj["applicaton_id"].string();
}

const char* BasicSession::getClientAddress(const char* family) const
{
    return m_obj["client_addr"][family].string();
}

void BasicSession::setClientAddress(const char* client_addr)
{
    DDF obj = m_obj["client_addr"];
    if (!obj.isstruct()) {
        obj = m_obj.addmember("client_addr").structure();
    }
    obj.addmember(getAddressFamily(client_addr)).string(client_addr);
}

const std::map<std::string,DDF>& BasicSession::getAttributes() const
{
    return m_attributes;
}

void BasicSession::validate(const char* applicationId, const char* client_addr, time_t* timeout)
{
}

time_t BasicSession::getCreation() const
{
    return m_creation;
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

// Allows the cache to bind sessions to multiple client address
// families based on whatever this function returns.
const char* BasicSession::getAddressFamily(const char* addr)
{
    if (strchr(addr, ':'))
        return "6";
    else
        return "4";
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