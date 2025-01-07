/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * StorageServiceSessionCache.h
 *
 * StorageService-based SessionCache implementation header.
 */

#ifndef __shibsp_sscache_h__
#define __shibsp_sscache_h__

#include "SessionCache.h"
#include "io/HTTPResponse.h"

#include <ctime>
#include <boost/scoped_ptr.hpp>

namespace xmltooling {
    class CondWait;
    class RWLock;
    class Thread;
}

namespace shibsp {

    class IPRange;
    class StoredSession;
    class SHIBSP_DLLLOCAL SSCache : public SessionCache
    {
    public:
        SSCache(const xercesc::DOMElement* e, bool deprecationSupport);
        virtual ~SSCache();

#ifndef SHIBSP_LITE
        void receive(DDF& in, std::ostream& out);

        void insert(
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
            );
        std::vector<std::string>::size_type logout(
            const char* bucketID,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions
            ) {
            return _logout(bucketID, issuer, nameid, indexes, expires, sessions, 0);
        }
        bool matches(
            const SPRequest& request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes
            );
#endif
        std::string active(const SPRequest& request);
        Session* find(SPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr);

        void remove(SPRequest& request, time_t revocationExp=0);

        Session* find(const char* bucketID, const char* key) {
            return _find(bucketID, key, nullptr, nullptr, nullptr);
        }
        void remove(const char* bucketID, const char* key, time_t revocationExp=0);
        void test();

        unsigned long getCacheTimeout(const SPRequest& request) const;

    private:
        // internal delegates of external methods
        Session * _find(
            const char* bucketID,
            const char* key,
            const char* recovery,
            const char* client_addr,
            time_t* timeout);
#ifndef SHIBSP_LITE
        std::vector<std::string>::size_type _logout(
            const char* bucketID,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions,
            short attempts
        );

        // maintain back-mappings of NameID/SessionIndex -> session key
        void insert(const char* key, time_t expires, const char* name, const char* index, short attempts=0);
        bool stronglyMatches(const XMLCh* idp, const XMLCh* sp, const opensaml::saml2::NameID& n1, const opensaml::saml2::NameID& n2) const;

        xmltooling::StorageService* m_storage;
        xmltooling::StorageService* m_storage_lite;
        bool m_cacheAssertions,m_reverseIndex,m_softRevocation;
        unsigned long m_reverseIndexMaxSize;
        std::set<xmltooling::xstring> m_excludedNames;
        std::set<std::string> m_persistedAttributeIds;
#endif
        const xercesc::DOMElement* m_root;         // Only valid during initialization
        unsigned long m_inprocTimeout,m_cacheTimeout,m_cacheAllowance;
        std::string m_inboundHeader,m_outboundHeader;
        std::vector<IPRange> m_unreliableNetworks;

        // inproc means we buffer sessions in memory
        boost::scoped_ptr<xmltooling::RWLock> m_lock;
        std::map<std::string,StoredSession*> m_hashtable;

        // handle potentially inexact address comparisons
        bool compareAddresses(const char* client_addr, const char* session_addr) const;

        HTTPResponse::samesite_t getSameSitePolicy(const SPRequest& request) const;
        std::string getCookieName(const SPRequest& request, const char* prefix, time_t* lifetime=nullptr) const;


        // management of buffered sessions
        void dormant(const char* key);
        static void* cleanup_fn(void*);

        Category& m_log;
        bool inproc;
        bool shutdown;
        boost::scoped_ptr<xmltooling::CondWait> shutdown_wait;
        boost::scoped_ptr<xmltooling::Thread> cleanup_thread;

        friend class StoredSession;
    };

}
#endif /* __shibsp_sscache_h__ */
