/*
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
 * @file shibsp/SessionCache.h
 *
 * Caches and manages user sessions.
 */

#ifndef __shibsp_sessioncache_spi_h__
#define __shibsp_sessioncache_spi_h__

#include <shibsp/base.h>

#include <string>

namespace shibsp {

    class SHIBSP_API DDF;

    /**
     * Interface to the "back-end" persistence mechanism to allow sessions to exist
     * independently of a specific agent process.
     */
    class SHIBSP_API SessionCacheSPI
    {
        MAKE_NONCOPYABLE(SessionCacheSPI);
    protected:
        SessionCacheSPI();
    public:
        virtual ~SessionCacheSPI();

        /**
         * Create a new "record" in the underlying storage medium and return a key/ID uniquely identifying
         * the session within the storage medium.
         * 
         * <p>The caller retains ownership of the input data.</p>
         * 
         * @param sessionData data to store in record of session
         * 
         * @return session key/ID created, this MUST be URL-safe
         */
        virtual std::string create(DDF sessionData)=0;

        /**
         * Read a session record from the underlying storage medium and return its data.
         * 
         * <p>To the extent possible, the implementation SHOULD ensure that the underlying
         * storage of the session reflects its use as of the time of this call such that
         * subsequent calls to this method will be actioned based on a time of last use that
         * is no older than the current time.</p>
         * 
         * <p>The caller owns the resulting data object.</p>
         * 
         * @param key session key/ID
         * @param lifetime if positive, the time since its creation the session may be valid
         * @param timeout if positive, a timeout duration to enforce against the estimated time of last use
         * 
         * @return reconstituted session data or a null object if the session was absent, expired, or inactive
         */
        virtual DDF read(const char* key, time_t lifetime, time_t timeout) const=0;

        /**
         * Informs the storage medium that a session is active at the current point in time.
         * 
         * @param key session key/ID
         * 
         * @return true iff the storage medium believes the information has been updated
         */
        virtual bool touch(const char* key) const=0;

        /**
         * Delete a session record from the underlying storage medium.
         * 
         * @param key/ID of session to delete
         */
        virtual void remove(const char* key)=0;
    };
};

#endif /* __shibsp_sessioncache_spi_h__ */
