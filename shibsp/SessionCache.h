/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
 * Caches and manages user sessions
 */

#ifndef __shibsp_sessioncache_h__
#define __shibsp_sessioncache_h__

#include <shibsp/base.h>

#ifndef SHIBSP_LITE
# include <saml/saml1/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
#endif
#include <xmltooling/Lockable.h>

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Attribute;

    class SHIBSP_API Session : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(Session);
    protected:
        Session() {}
        virtual ~Session() {}
    public:
        /**
         * Returns the session key.
         *
         * @return unique ID of session
         */
        virtual const char* getID() const=0;

        /**
         * Returns the address of the client associated with the session.
         * 
         * @return  the client's network address
         */
        virtual const char* getClientAddress() const=0;

        /**
         * Returns the entityID of the IdP that initiated the session.
         * 
         * @return the IdP's entityID
         */
        virtual const char* getEntityID() const=0;

        /**
         * Returns the protocol family used to initiate the session.
         *
         * @return the protocol constant that represents the general SSO protocol used
         */
        virtual const char* getProtocol() const=0;

        /**
         * Returns the UTC timestamp on the authentication event at the IdP.
         * 
         * @return  the UTC authentication timestamp 
         */
        virtual const char* getAuthnInstant() const=0;

#ifndef SHIBSP_LITE
        /**
         * Returns the NameID associated with a session.
         * 
         * <p>SAML 1.x identifiers will be promoted to the 2.0 type.
         * 
         * @return a SAML 2.0 NameID associated with the session, if any
         */
        virtual const opensaml::saml2::NameID* getNameID() const=0;
#endif

        /**
         * Returns the SessionIndex provided with the session.
         * 
         * @return the SessionIndex from the original SSO assertion, if any
         */
        virtual const char* getSessionIndex() const=0;

        /**
         * Returns a URI containing an AuthnContextClassRef provided with the session.
         * 
         * <p>SAML 1.x AuthenticationMethods will be returned as class references.
         * 
         * @return  a URI identifying the authentication context class
         */
        virtual const char* getAuthnContextClassRef() const=0;

        /**
         * Returns a URI containing an AuthnContextDeclRef provided with the session.
         * 
         * @return  a URI identifying the authentication context declaration
         */
        virtual const char* getAuthnContextDeclRef() const=0;
        
        /**
         * Returns the resolved attributes associated with the session.
         * 
         * @return an immutable array of attributes
         */
        virtual const std::vector<Attribute*>& getAttributes() const=0;

        /**
         * Returns the resolved attributes associated with the session, indexed by ID
         * 
         * @return an immutable map of attributes keyed by attribute ID
         */
        virtual const std::multimap<std::string,const Attribute*>& getIndexedAttributes() const=0;
        
        /**
         * Returns the identifiers of the assertion(s) cached by the session.
         * 
         * <p>The SSO assertion is guaranteed to be first in the set.
         * 
         * @return  an immutable array of AssertionID values
         */
        virtual const std::vector<const char*>& getAssertionIDs() const=0;
        
#ifndef SHIBSP_LITE
        /**
         * Adds additional attributes to the session.
         * 
         * @param attributes    reference to an array of Attributes to cache (will be freed by cache)
         */
        virtual void addAttributes(const std::vector<Attribute*>& attributes)=0;

        /**
         * Returns an assertion cached by the session.
         * 
         * @param id    identifier of the assertion to retrieve
         * @return pointer to assertion, or NULL
         */
        virtual const opensaml::Assertion* getAssertion(const char* id) const=0;
        
        /**
         * Stores an assertion in the session.
         * 
         * @param assertion pointer to an assertion to cache (will be freed by cache)
         */
        virtual void addAssertion(opensaml::Assertion* assertion)=0;        
#endif
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
    
        /**
         * Constructor
         * 
         * <p>The following XML content is supported to configure the cache:
         * <dl>
         *  <dt>cacheTimeout</dt>
         *  <dd>attribute containing maximum lifetime in seconds for unused sessions to remain in cache</dd>
         * </dl>
         * 
         * @param e root of DOM tree to configure the cache
         */
        SessionCache(const xercesc::DOMElement* e);
        
        /** maximum lifetime in seconds for unused sessions to be cached */
        unsigned long m_cacheTimeout;
        
    public:
        virtual ~SessionCache() {}
        
#ifndef SHIBSP_LITE
        /**
         * Inserts a new session into the cache.
         * 
         * <p>The SSO tokens and Attributes remain owned by the caller and are copied by the cache.
         * 
         * @param expires           expiration time of session
         * @param application       reference to Application that owns the Session
         * @param client_addr       network address of client
         * @param issuer            issuing metadata of assertion issuer, if known
         * @param protocol          protocol family used to initiate the session
         * @param nameid            principal identifier, normalized to SAML 2, if any
         * @param authn_instant     UTC timestamp of authentication at IdP, if known
         * @param session_index     index of session between principal and IdP, if any
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl specifics of authentication event, if known
         * @param tokens            assertions to cache with session, if any
         * @param attributes        optional array of resolved Attributes to cache with session
         * @return  newly created session's key
         */
        virtual std::string insert(
            time_t expires,
            const Application& application,
            const char* client_addr=NULL,
            const opensaml::saml2md::EntityDescriptor* issuer=NULL,
            const XMLCh* protocol=NULL,
            const opensaml::saml2::NameID* nameid=NULL,
            const XMLCh* authn_instant=NULL,
            const XMLCh* session_index=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const std::vector<const opensaml::Assertion*>* tokens=NULL,
            const std::vector<Attribute*>* attributes=NULL
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
         * @param issuer        source of session(s)
         * @param nameid        name identifier associated with the session(s) to terminate
         * @param indexes       indexes of sessions, or NULL for all sessions associated with other parameters
         * @param expires       logout expiration
         * @param application   reference to Application that owns the session(s)
         * @param sessions      on exit, contains the IDs of the matching sessions found
         */
        virtual std::vector<std::string>::size_type logout(
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            const Application& application,
            std::vector<std::string>& sessions
            )=0;

        /**
         * Determines whether a given session (based on its ID) matches a set of input
         * criteria.
         * 
         * @param key           session key to check
         * @param issuer        required source of session(s)
         * @param nameid        required name identifier
         * @param indexes       session indexes
         * @param application   reference to Application that owns the Session
         * @return  true iff the session matches the input criteria
         */
        virtual bool matches(
            const char* key,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            const Application& application
            )=0;
#endif

        /**
         * Locates an existing session.
         * 
         * <p>If the client address is supplied, then a check will be performed against
         * the address recorded in the record.
         * 
         * @param key           session key
         * @param application   reference to Application that owns the Session
         * @param client_addr   network address of client (if known)
         * @param timeout       inactivity timeout to enforce (0 for none, NULL to bypass check/update of last access)
         * @return  pointer to locked Session, or NULL
         */
        virtual Session* find(
            const char* key, const Application& application, const char* client_addr=NULL, time_t* timeout=NULL
            )=0;
            
        /**
         * Deletes an existing session.
         * 
         * @param key           session key
         * @param application   reference to Application that owns the Session
         */
        virtual void remove(const char* key, const Application& application)=0;
    };

#ifndef SHIBSP_LITE
    /** SessionCache implementation backed by a StorageService. */
    #define STORAGESERVICE_SESSION_CACHE    "StorageService"
#endif

    /** SessionCache implementation for lite builds that delegates to a remoted version. */
    #define REMOTED_SESSION_CACHE    "Remoted"

    /**
     * Registers SessionCache classes into the runtime.
     */
    void SHIBSP_API registerSessionCaches();
};

#endif /* __shibsp_sessioncache_h__ */
