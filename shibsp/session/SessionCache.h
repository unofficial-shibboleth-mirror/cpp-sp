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

#ifndef __shibsp_sessioncache_h__
#define __shibsp_sessioncache_h__

#include <shibsp/util/Lockable.h>

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <ctime>
#include <mutex>

namespace shibsp {

    class SHIBSP_API DDF;
    class SHIBSP_API SPRequest;

    /**
     * Encapsulates access to a session.
     * 
     * <p>Sessions are returned from APIs and generally will be returned in a
     * locked state and should be unlocked by the caller when done using them.</p>
     */
    class SHIBSP_API Session : public virtual BasicLockable
    {
        MAKE_NONCOPYABLE(Session);
    protected:
        Session();
        virtual ~Session();
    public:
        /**
         * Returns the session ID.
         *
         * @return unique ID of session
         */
        virtual const char* getID() const=0;

        /**
         * Returns the session's "application" ID, i.e., a value separating sessions into
         * specific buckets based on resources.
         *
         * @return unique ID of application/bucket
         */
        virtual const char* getApplicationID() const=0;

        /**
         * Returns the session creation time.
         *
         * @return  the session's creation time
         */
        virtual time_t getCreation() const=0;

        /**
         * Returns the last access time of the session.
         *
         * @return  the session's last access time
         */
        virtual time_t getLastAccess() const=0;

        /**
         * Returns the resolved attributes associated with the session, indexed by ID.
         * 
         * <p>Each "attribute" is a list containing the values (of various types).</p>
         *
         * @return an immutable map of attribute data keyed by attribute ID
         */
        virtual const std::map<std::string,DDF>& getAttributes() const=0;
    };

    /**
     * Creates and manages user sessions
     *
     * The cache abstracts a persistent (meaning across requests) cache of
     * instances of the Session interface. Creation of new entries and entry
     * lookup are confined to this interface to enable the implementation to
     * remote and/or optimize calls by implementing custom versions of the
     * Session interface as required.
     */
    class SHIBSP_API SessionCache
    {
        MAKE_NONCOPYABLE(SessionCache);
    protected:
        SessionCache();
    public:
        virtual ~SessionCache();
        
        /**
         * Signals the implementation it may start any background tasks or do any
         * additional once-per-process work.
         * 
         * <p>This method is guaranteed to be called only once per process.</p>
         */
        virtual bool start()=0;

        /**
         * Signals the implementation it should stop any background tasks.
         * 
         * <p>This method is guaranteed to be called only once per process.</p>
         */
        virtual void stop()=0;

        /**
         * Creates a new session and stores it persistently while binding the session
         * to the input request object.
         * 
         * <p>The second parameter's ownership is assumed by this method regardless of the
         * outcome.</p>
         * 
         * <p>An exception is raised in the event of an error.</p>
         * 
         * @param request request to bind the session to
         * @param session session data obtained from the hub
         * 
         * @return the newly created session ID
         */
        virtual std::string create(SPRequest& request, DDF& session)=0;

        /**
         * Locates an existing session bound to a request.
         *
         * <p>If a bound session is found to have expired, be invalid, etc., and if the request
         * can be used to "clear" the session from subsequent client requests, then it may be cleared.</p>
         *
         * @param request       request from client
         * @param checkTimeout  true iff the timeout policy should be enforced before returning session
         * @param ignoreAddress true iff address checking should be ignored, regardless of request's policy
         * 
         * @return locked Session (or an unbound wrapper)
         */
        virtual std::unique_lock<Session> find(SPRequest& request, bool checkTimeout, bool ignoreAddress)=0;

        /**
         * Locates an existing session by its key/ID.
         *
         * @param applicationID current application ID
         * @param key           session key to locate
         * 
         * @return locked Session (or an unbound wrapper)
         */
        virtual std::unique_lock<Session> find(const char* applicationId, const char* key)=0;

        /**
         * Removes an existing session bound to a request.
         *
         * @param request   request from client containing session
         */
        virtual void remove(SPRequest& request)=0;

       /**
        * Removes an existing session identified by its application and ID.
        *
        * @param key    session key/ID
        */
        virtual void remove(const char* key)=0;
    };

    /** SessionCache implementation backed by the file system. */
    #define FILESYSTEM_SESSION_CACHE    "filesystem"

    /** SessionCache implementation backed by a hub-hosted StorageService. */
    #define STORAGESERVICE_SESSION_CACHE    "storage"

    /** SessionCache implementation backed by single process memory, generally only for testing. */
    #define MEMORY_SESSION_CACHE    "memory"

    /**
     * Registers SessionCache classes into the runtime.
     */
    void SHIBSP_API registerSessionCaches();
};

#endif /* __shibsp_sessioncache_h__ */
