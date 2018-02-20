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

#include <shibsp/SessionCache.h>
#include <shibsp/remoting/ListenerService.h>

#include <ctime>
#include <boost/shared_ptr.hpp>

namespace xmltooling {
    class CondWait;
    class RWLock;
    class Thread;
}

#ifndef SHIBSP_LITE
namespace opensaml {
    class Assertion;

    namespace saml2 {
        class NameID;
    };

    namespace saml2md {
        class EntityDescriptor;
    };
};
#endif

namespace shibsp {

    class StoredSession;
    class SSCache : public shibsp::SessionCache
#ifndef SHIBSP_LITE
        ,public virtual shibsp::Remoted
#endif
    {
    public:
        SSCache(const xercesc::DOMElement* e);
        virtual ~SSCache();

#ifndef SHIBSP_LITE
        void receive(shibsp::DDF& in, std::ostream& out);

        void insert(
            std::string& sessionID,
            const shibsp::Application& app,
            const xmltooling::HTTPRequest& httpRequest,
            xmltooling::HTTPResponse& httpResponse,
            time_t expires,
            const opensaml::saml2md::EntityDescriptor* issuer=nullptr,
            const XMLCh* protocol=nullptr,
            const opensaml::saml2::NameID* nameid=nullptr,
            const XMLCh* authn_instant=nullptr,
            const XMLCh* session_index=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const std::vector<const opensaml::Assertion*>* tokens=nullptr,
            const std::vector<shibsp::Attribute*>* attributes=nullptr
            );
        std::vector<std::string>::size_type logout(
            const shibsp::Application& app,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions
            ) {
            return _logout(app, issuer, nameid, indexes, expires, sessions, 0);
        }
        bool matches(
            const shibsp::Application& app,
            const xmltooling::HTTPRequest& request,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes
            );
#endif
        shibsp::Session* find(const shibsp::Application& app, const char* key, const char* client_addr=nullptr, time_t* timeout=nullptr);
        void remove(const shibsp::Application& app, const char* key);
        void test();

        std::string active(const shibsp::Application& app, const xmltooling::HTTPRequest& request);
        shibsp::Session* find(const shibsp::Application& app, const xmltooling::HTTPRequest& request, const char* client_addr = nullptr, time_t* timeout = nullptr);
        shibsp::Session* find(const shibsp::Application& app, xmltooling::HTTPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr);
        void remove(const shibsp::Application& app, const xmltooling::HTTPRequest& request, xmltooling::HTTPResponse* response=nullptr);

        unsigned long getCacheTimeout(const shibsp::Application& app) const;

        xmltooling::logging::Category& m_log;
        bool inproc;
#ifndef SHIBSP_LITE
        xmltooling::StorageService* m_storage;
        xmltooling::StorageService* m_storage_lite;
#endif

    private:
#ifndef SHIBSP_LITE
        // maintain back-mappings of NameID/SessionIndex -> session key
        void insert(const char* key, time_t expires, const char* name, const char* index, short attempts=0);
        std::vector<std::string>::size_type _logout(
            const shibsp::Application& app,
            const opensaml::saml2md::EntityDescriptor* issuer,
            const opensaml::saml2::NameID& nameid,
            const std::set<std::string>* indexes,
            time_t expires,
            std::vector<std::string>& sessions,
            short attempts
            );
        bool stronglyMatches(const XMLCh* idp, const XMLCh* sp, const opensaml::saml2::NameID& n1, const opensaml::saml2::NameID& n2) const;
        shibsp::LogoutEvent* newLogoutEvent(const shibsp::Application& app) const;

        bool m_cacheAssertions,m_reverseIndex;
        std::set<xmltooling::xstring> m_excludedNames;
#endif
        const xercesc::DOMElement* m_root;         // Only valid during initialization
        unsigned long m_inprocTimeout,m_cacheTimeout,m_cacheAllowance;
        std::string m_inboundHeader,m_outboundHeader;

        // inproc means we buffer sessions in memory
        boost::scoped_ptr<xmltooling::RWLock> m_lock;
        std::map<std::string,StoredSession*> m_hashtable;

        // management of buffered sessions
        void dormant(const char* key);
        static void* cleanup_fn(void*);

        bool shutdown;
        boost::scoped_ptr<xmltooling::CondWait> shutdown_wait;
        boost::scoped_ptr<xmltooling::Thread> cleanup_thread;
    };

}
#endif /* __shibsp_sscache_h__ */
