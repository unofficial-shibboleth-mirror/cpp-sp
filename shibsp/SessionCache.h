/*
 *  Copyright 2001-2006 Internet2
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
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
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
         * Returns the timestamp on the authentication event at the IdP.
         * 
         * @return  the authentication timestamp 
         */
        virtual time_t getAuthnInstant() const=0;
        
        /**
         * Returns the set of resolved attributes associated with the session.
         * 
         * @return an immutable array of attributes
         */
        virtual const std::vector<const Attribute*>& getAttributes() const=0;
        
        /**
         * Adds additional attributes to the session.
         * 
         * @param attributes    reference to an array of Attributes to cache (will be freed by cache)
         */
        virtual void addAttributes(const std::vector<Attribute*>& attributes)=0;
        
        /**
         * Returns the identifiers of the assertion(s) cached by the session.
         * 
         * <p>The SSO assertion is guaranteed to be first in the set.
         * 
         * @return  an immutable array of AssertionID values
         */
        virtual const std::vector<const char*>& getAssertionIDs() const=0;
        
        /**
         * Returns an assertion cached by the session.
         * 
         * @param id    identifier of the assertion to retrieve
         * @return pointer to assertion, or NULL
         */
        virtual const opensaml::RootObject* getAssertion(const char* id) const=0;
        
        /**
         * Stores an assertion in the session.
         * 
         * @param assertion pointer to an assertion to cache (will be freed by cache)
         */
        virtual void addAssertion(opensaml::RootObject* assertion)=0;        
    };
    
    class SHIBSP_API SAML1Session : public virtual Session
    {
    protected:
        SAML1Session() {}
        virtual ~SAML1Session() {}
        
    public:        
        /**
         * Returns the NameIdentifier associated with a SAML 1.x session.
         * 
         * @return reference to a SAML 1.x NameIdentifier
         */
        virtual const opensaml::saml1::NameIdentifier& getNameIdentifier() const=0;

        /**
         * Returns a URI containing the AuthenticationMethod.
         * 
         * @return  a URI identifying the authentication method
         */
        virtual const char* getAuthenticationMethod() const=0;

    };

    class SHIBSP_API SAML2Session : public virtual Session
    {
    protected:
        SAML2Session() {}
        virtual ~SAML2Session() {}
        
    public:        
        /**
         * Returns the NameID associated with a SAML 2.0 session.
         * 
         * @return reference to a SAML 2.0 NameID
         */
        virtual const opensaml::saml2::NameID& getNameID() const=0;

        /**
         * Returns the SessionIndex provided with the session.
         * 
         * @return the SessionIndex from the original SSO assertion, if any
         */
        virtual const char* getSessionIndex() const=0;

        /**
         * Returns a URI containing an AuthnContextClassRef provided with the session.
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
         *  <dd>attribute containing maximum lifetime in seconds for sessions in cache</dd>
         *  <dt>cleanupInterval</dt>
         *  <dd>attribute containing interval in seconds between attempts to purge expired sessions</dd>
         *  <dt>strictValidity</dt>
         *  <dd>boolean attribute indicating whether to honor SessionNotOnOrAfter information</dd>
         *  <dt>writeThrough</dt>
         *  <dd>boolean attribute indicating that every access to a session should update persistent storage</dd>
         * </dl>
         * 
         * @param e root of DOM tree to configure the cache
         */
        SessionCache(const DOMElement* e);
        
    public:
        virtual ~SessionCache() {}
        
        /**
         * Inserts a new session into the cache.
         * 
         * <p>The SSO token remains owned by the caller and must be copied by the
         * cache. Any Attributes supplied become the property of the cache.  
         * 
         * @param application   reference to Application that owns the Session
         * @param client_addr   network address of client
         * @param ssoToken      reference to SSO assertion initiating the session
         * @param issuer        issuing metadata role of assertion issuer, if known
         * @param attributes    optional set of resolved Attributes to cache with session
         * @return  pointer to newly created (and locked) Session
         */
        virtual Session* insert(
            const Application& application,
            const char* client_addr,
            const opensaml::RootObject& ssoToken,
            const opensaml::saml2md::RoleDescriptor* issuer=NULL,
            const std::vector<Attribute*>* attributes=NULL
            )=0;

        /**
         * Locates an existing session.
         * 
         * @param key           session key
         * @param application   reference to Application that owns the Session
         * @param client_addr   network address of client (if known)
         * @return  pointer to locked Session, or NULL
         */
        virtual Session* find(const char* key, const Application& application, const char* client_addr)=0;
            
        /**
         * Deletes an existing session.
         * 
         * @param key           session key
         * @param application   reference to Application that owns the Session
         * @param client_addr   network address of client (if known)
         */
        virtual void remove(const char* key, const Application& application, const char* client_addr)=0;
    };

    /** Remoting-aware SessionCache implementation backed by a StorageService. */
    #define STORAGESERVICE_SESSION_CACHE    "edu.internet2.middleware.shibboleth.sp.provider.StorageServiceSessionCache"

    /**
     * Registers SessionCache classes into the runtime.
     */
    void SHIBSP_API registerSessionCaches();
};

#endif /* __shibsp_sessioncache_h__ */
