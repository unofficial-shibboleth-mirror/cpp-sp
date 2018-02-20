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
 * StoredSession.h
 *
 * Internal declaration of Session subclass used by StorageService-backed SessionCache.
 */

#ifndef __shibsp_storedsession_h__
#define __shibsp_storedsession_h__

#include <shibsp/SessionCache.h>
#include <shibsp/remoting/ddf.h>

#include <ctime>
#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

namespace xmltooling {
    class Mutex;
};

#ifndef SHIBSP_LITE
namespace opensaml {
    class Assertion;

    namespace saml2 {
        class NameID;
    };
};
#endif

namespace shibsp {

    class SSCache;

    class StoredSession : public virtual shibsp::Session
    {
    public:
        StoredSession(SSCache* cache, shibsp::DDF& obj);

        virtual ~StoredSession();

        xmltooling::Lockable* lock();
        void unlock();

        const char* getID() const {
            return m_obj.name();
        }
        const char* getApplicationID() const {
            return m_obj["application_id"].string();
        }
        const char* getClientAddress() const {
            return m_obj["client_addr"].first().string();
        }

        const char* getClientAddress(const char* family) const {
            if (family)
                return m_obj["client_addr"][family].string();
            return nullptr;
        }
        void setClientAddress(const char* client_addr) {
            shibsp::DDF obj = m_obj["client_addr"];
            if (!obj.isstruct())
                obj = m_obj.addmember("client_addr").structure();
            obj.addmember(getAddressFamily(client_addr)).string(client_addr);
        }

        const char* getEntityID() const {
            return m_obj["entity_id"].string();
        }
        const char* getProtocol() const {
            return m_obj["protocol"].string();
        }
        const char* getAuthnInstant() const {
            return m_obj["authn_instant"].string();
        }
#ifndef SHIBSP_LITE
        const opensaml::saml2::NameID* getNameID() const {
            return m_nameid.get();
        }
#endif
        const char* getSessionIndex() const {
            return m_obj["session_index"].string();
        }
        const char* getAuthnContextClassRef() const {
            return m_obj["authncontext_class"].string();
        }
        const char* getAuthnContextDeclRef() const {
            return m_obj["authncontext_decl"].string();
        }
        const std::vector<shibsp::Attribute*>& getAttributes() const {
            if (m_attributes.empty())
                unmarshallAttributes();
            return m_attributes;
        }
        const std::multimap<std::string, const shibsp::Attribute*>& getIndexedAttributes() const;

        const std::vector<const char*>& getAssertionIDs() const;

        void validate(const shibsp::Application& application, const char* client_addr, time_t* timeout);

#ifndef SHIBSP_LITE
        void addAttributes(const std::vector<shibsp::Attribute*>& attributes);
        const opensaml::Assertion* getAssertion(const char* id) const;
        void addAssertion(opensaml::Assertion* assertion);
#endif

        time_t getExpiration() const { return m_expires; }
        time_t getLastAccess() const { return m_lastAccess; }

        // Allows the cache to bind sessions to multiple client address
        // families based on whatever this function returns.
        static const char* getAddressFamily(const char* addr);

    private:
        void unmarshallAttributes() const;

        shibsp::DDF m_obj;
#ifndef SHIBSP_LITE
        boost::scoped_ptr<opensaml::saml2::NameID> m_nameid;
        mutable std::map< std::string,boost::shared_ptr<opensaml::Assertion> > m_tokens;
#endif
        mutable std::vector<shibsp::Attribute*> m_attributes;
        mutable std::multimap<std::string,const shibsp::Attribute*> m_attributeIndex;
        mutable std::vector<const char*> m_ids;

        SSCache* m_cache;
        time_t m_expires,m_lastAccess;
        boost::scoped_ptr<xmltooling::Mutex> m_lock;
    };

}

#endif /* __shibsp_storedsession_h__ */
