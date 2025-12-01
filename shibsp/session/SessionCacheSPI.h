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
 * @file shibsp/SessionCacheSPI.h
 *
 * Interface to Back end implementation of session caches.
 */

#ifndef __shibsp_sessioncache_spi_h__
#define __shibsp_sessioncache_spi_h__

#include <shibsp/base.h>

#include <string>

namespace shibsp {

    class SHIBSP_API DDF;
    class SHIBSP_API SPRequest;

    /**
     * Interface to the "back-end" persistence mechanism to allow sessions to exist
     * independently of a specific agent process.
     * 
     * <p>As a general rule, implementations should log errors internally and raise exceptions
     * such that the caller need not log the resulting object to ensure adequate logging of the
     * outcome.</p>
     * 
     * <p>Errors that reflect unexpected or impossible-to-anticipate issues should be thrown as
     * an IOException, with return values used for more expected/controlled issues.</p>
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
         * <p>The version of the session should initially be 1.</p>
         * 
         * <p>The caller retains ownership of the input data.</p>
         * 
         * @param request agent request, if available
         * @param sessionData data to store in record of session
         * 
         * @return session key/ID created, this MUST be URL-safe
         */
        virtual std::string cache_create(SPRequest* request, DDF& sessionData)=0;

        /**
         * Read a session record from the underlying storage medium and return its data.
         * 
         * <p>The inputs direct the implementation to perform policy enforcement of various
         * sorts on the session prior to returning it. An invalid session MUST NOT be returned
         * to the caller.</p>
         * 
         * <p>To the extent possible, the implementation SHOULD ensure that the underlying
         * storage of the session (if returned) is updated such that subsequent calls to this
         * method will be actioned based on a time of last use that is no older than the current
         * time.</p>
         * 
         * <p>The returned session MAY be of a newer version than requested but will not be older.</p>
         * 
         * <p>The caller owns the resulting data object.</p>
         * 
         * @param request       agent request, if available
         * @param applicationId application ID
         * @param key           session key/ID
         * @param version       session version
         * @param lifetime      if positive, the time since its creation the session may be valid
         * @param timeout       if positive, a timeout duration to enforce against the estimated time of last use
         * @param client_addr   if set, a client address to enforce for use of the session
         * 
         * @return reconstituted session data or a null object if the session was absent or invalid
         */
        virtual DDF cache_read(
            SPRequest* request,
            const char* applicationId,
            const char* key,
            unsigned int version=1,
            unsigned int lifetime=0,
            unsigned int timeout=0,
            const char* client_addr=nullptr
            )=0;

        /**
         * Issue a new version of the specified session, updating the data as directed.
         * 
         * <p>The specified version MUST be the current version or the update should be aborted.</p>
         * 
         * <p>The caller retains ownership of the session data object, though it will be modified to
         * reflect the updated version.</p>
         * 
         * <p>The return value signals success or a version mismatch/collision.</p>
         * 
         * @param agent request, if available
         * @param key session key/ID
         * @param version old session version
         * @param sessionData updated session data
         * 
         * @return true iff the session was updated to a version one greater than the input version,
         *      false to signal a version collision such that a newer version was added behind us
         */
        virtual bool cache_update(SPRequest* request, const char* key, unsigned int version, DDF& sessionData)=0;

        /**
         * Informs the storage medium that a session was used at the current point in time.
         * 
         * <p>This method should return false to indicate that a session has been revoked, removed,
         * or is no longer valid.</p>
         * 
         * @param request   agent request, if available
         * @param key       session key/ID
         * @param version   session version
         * @param timeout   timeout to enforce if non-zero
         * 
         * @return true iff the session remains valid/available
         */
        virtual bool cache_touch(SPRequest* request, const char* key, unsigned int version=1, unsigned int timeout=0)=0;

        /**
         * Delete a session record from the underlying storage medium.
         * 
         * <p>All versions of the session will be removed.</p>
         * 
         * @param request   agent request, if available
         * @param key       key/ID of session to delete
         */
        virtual void cache_remove(SPRequest* request, const char* key)=0;
    };
};

#endif /* __shibsp_sessioncache_spi_h__ */
