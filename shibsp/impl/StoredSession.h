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
 * impl/StoredSession.h
 *
 * Internal declaration of Session subclass used by StorageService-backed SessionCache.
 */

#ifndef __shibsp_storedsession_h__
#define __shibsp_storedsession_h__

#include "Application.h"
#include "SessionCache.h"
#include "remoting/ddf.h"

#include <mutex>

namespace shibsp {

    class SSCache;

    class SHIBSP_DLLLOCAL StoredSession : public virtual Session
    {
    public:
        StoredSession(SSCache* cache, DDF& obj);

        virtual ~StoredSession();

        void lock();
        bool try_lock();
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
            DDF obj = m_obj["client_addr"];
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
        time_t getAuthnInstant() const {
            return m_obj["authn_instant"].longinteger();
        }
        const char* getAuthnContextClassRef() const {
            return m_obj["authncontext_class"].string();
        }
        const std::vector<std::unique_ptr<Attribute>>& getAttributes() const {
            if (m_attributes.empty())
                unmarshallAttributes();
            return m_attributes;
        }
        const std::multimap<std::string, const Attribute*>& getIndexedAttributes() const;

        void validate(const Application& application, const char* client_addr, time_t* timeout);

        time_t getExpiration() const { return m_expires; }
        time_t getLastAccess() const { return m_lastAccess; }

        // Allows the cache to bind sessions to multiple client address
        // families based on whatever this function returns.
        static const char* getAddressFamily(const char* addr);

    private:
        void unmarshallAttributes() const;

        DDF m_obj;
        mutable std::vector<std::unique_ptr<Attribute>> m_attributes;
        mutable std::multimap<std::string,const Attribute*> m_attributeIndex;

        SSCache* m_cache;
        time_t m_expires,m_lastAccess;
        // TODO: possibly convert to a shared lock where possible?
        // I used exclusive because it avoided lock "upgrades"
        // when mutating or deleting sessions.
        std::mutex m_lock;
    };

}

#endif /* __shibsp_storedsession_h__ */
