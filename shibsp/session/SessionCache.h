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

namespace shibsp {

    class SHIBSP_API Attribute;
    class SHIBSP_API SPRequest;

    /**
     * Encapsulates access to a user's security session.
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
         * Returns the session expiration.
         *
         * @return  the session's expiration time or 0 for none
         */
        virtual time_t getExpiration() const=0;

        /**
         * Returns the last access time of the session.
         *
         * @return  the session's last access time
         */
        virtual time_t getLastAccess() const=0;

        /**
         * Returns the resolved attributes associated with the session.
         *
         * @return an immutable array of attributes
         */
        virtual const std::vector<std::unique_ptr<Attribute>>& getAttributes() const=0;

        /**
         * Returns the resolved attributes associated with the session, indexed by ID.
         *
         * @return an immutable map of attributes keyed by attribute ID
         */
        virtual const std::multimap<std::string,const Attribute*>& getIndexedAttributes() const=0;
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

#ifndef SHIBSP_LITE
        /**
         * Inserts a new session into the cache and binds the session to the outgoing
         * client response.
         *
         * <p>The newly created session ID is placed into the first parameter.</p>
         *
         * <p>The SSO tokens and Attributes remain owned by the caller and are copied by the cache.</p>
         *
         * @param sessionID         reference to string to capture newly inserted session ID
         * @param request           request that initiated session
         * @param expires           expiration time of session
         * @param issuer            issuing metadata of assertion issuer, if known
         * @param protocol          protocol family used to initiate the session
         * @param nameid            principal identifier, normalized to SAML 2, if any
         * @param authn_instant     UTC timestamp of authentication at IdP, if known
         * @param session_index     index of session between principal and IdP, if any
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl specifics of authentication event, if known
         * @param tokens            assertions to cache with session, if any
         * @param attributes        optional array of resolved Attributes to cache with session
         */
        virtual void insert(
            std::string& sessionID,
            const SPRequest& request,
            time_t expires,
            const opensaml::saml2md::EntityDescriptor* issuer=nullptr,
            const XMLCh* protocol=nullptr,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authn_instant=nullptr,
            const XMLCh* session_index=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const std::vector<const opensaml::Assertion*>* tokens=nullptr,
            const std::vector<Attribute*>* attributes=nullptr
            )=0;

        /**
         * Determines whether the Session bound to a client request matches a set of input criteria.
         *
         * @param request       request in which to locate Session
         * @param issuer        required source of session(s)
         * @param nameid        required name identifier
         * @param indexes       session indexes
         * @return  true iff the Session exists and matches the input criteria
         */
        virtual bool matches(
            const SPRequest& request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes
            )=0;

        /**
        * Returns active sessions that match particular parameters and records the logout
        * to prevent race conditions.
        *
        * <p>On exit, the mapping between these sessions and the associated information MAY be
        * removed by the cache, so subsequent calls to this method may not return anything.
        *
        * <p>Until logout expiration, any attempt to create a session with the same parameters
        * will be blocked by the cache.
        *
        * @param bucketID      bucket for session
        * @param issuer        source of session(s)
        * @param nameid        name identifier associated with the session(s) to terminate
        * @param indexes       indexes of sessions, or nullptr for all sessions associated with other parameters
        * @param expires       logout expiration
        * @param sessions      on exit, contains the IDs of the matching sessions found
        */
        virtual std::vector<std::string>::size_type logout(
            const char* bucketID,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions
        )=0;

        /**
         * Executes a test of the cache's general health.
         */
        virtual void test()=0;
#endif

        /**
         * Returns the ID of the session bound to the specified client request, if possible.
         *
         * @param request   request from client containing session
         * @return  ID of session, if any known, or an empty string
         */
        virtual std::string active(const SPRequest& request)=0;

        /**
         * Locates an existing session bound to a request.
         *
         * <p>If the client address is supplied, then a check will be performed against
         * the address recorded in the record.</p>
         *
         * <p>If a bound session is found to have expired, be invalid, etc., and if the request
         * can be used to "clear" the session from subsequent client requests, then it may be cleared.</p>
         *
         * @param request       request from client bound to session
         * @param client_addr   network address of client (if known)
         * @param timeout       inactivity timeout to enforce (0 for none, nullptr to bypass check/update of last access)
         * @return  pointer to locked Session, or nullptr
         */
        virtual Session* find(SPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr)=0;

        /**
         * Deletes an existing session bound to a request.
         *
         * <p>Revocation may be supported by some implementations.</p>
         *
         * @param request       request from client containing session
         * @param revocationExp optional indicator for length of time to track revocation of this session
         */
        virtual void remove(SPRequest& request, time_t revocationExp=0)=0;

        /**
        * Locates an existing session by ID.
        *
        * @param bucketID      bucket for session
        * @param key           session key
        * @return  pointer to locked Session, or nullptr
        */
        virtual Session* find(const char* bucketID, const char* key)=0;

        /**
        * Deletes an existing session.
        *
        * <p>Revocation may be supported by some implementations.</p>
        *
        * @param bucketID      bucket for session
        * @param key           session key
        * @param revocationExp optional indicator for length of time to track revocation of this session
        */
        virtual void remove(const char* bucketID, const char* key, time_t revocationExp=0)=0;
    };

    /** SessionCache implementation backed by the file system. */
    #define FILESYSTEM_SESSION_CACHE    "filesystem"

    /** SessionCache implementation backed by a hub-hosted StorageService. */
    #define STORAGESERVICE_SESSION_CACHE    "storage"

    /**
     * Registers SessionCache classes into the runtime.
     */
    void SHIBSP_API registerSessionCaches();
};

#endif /* __shibsp_sessioncache_h__ */
