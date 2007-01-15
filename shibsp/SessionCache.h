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

#include <xmltooling/Lockable.h>
#include <xercesc/dom/DOM.hpp>

namespace shibsp {

    class SHIBSP_API Application;

    class SHIBSP_API Session : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(Session);
    protected:
        Session() {}
        virtual ~Session() {}
    public:
        /* TODO: design new interface, probably with version-specific subinterfaces
        virtual const char* getClientAddress() const=0;
        virtual const char* getProviderId() const=0;
        virtual std::pair<const char*,const saml::SAMLSubject*> getSubject(bool xml=true, bool obj=false) const=0;
        virtual const char* getAuthnContext() const=0;
        virtual std::pair<const char*,const saml::SAMLResponse*> getTokens(bool xml=true, bool obj=false) const=0;
        virtual std::pair<const char*,const saml::SAMLResponse*> getFilteredTokens(bool xml=true, bool obj=false) const=0;
        */
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
    public:
        /**
         * Constructor
         *
         * @param e root of DOM to configure cache
         */
        SessionCache(const xercesc::DOMElement* e);

        virtual ~SessionCache();

        /** TODO: just a stub for now */
        virtual Session* find(const char* key, const Application& app, const char* address)=0;
    };
};

#endif /* __shibsp_sessioncache_h__ */
