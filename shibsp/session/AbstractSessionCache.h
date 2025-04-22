/**
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
 * @file session/AbstractSessionCache.h
 *
 * Base class for SessionCache implementations.
 */

#ifndef __shibsp_abssessioncache_h__
#define __shibsp_abssessioncache_h__

#include <logging/Category.h>
#include <remoting/ddf.h>
#include <session/SessionCache.h>

#include <mutex>

namespace shibsp {

    class SHIBSP_API AbstractSessionCache;
    class SHIBSP_API Attribute;

    class SHIBSP_API BasicSession : public virtual Session
    {
    public:
        BasicSession(AbstractSessionCache& cache, DDF& obj);
        virtual ~BasicSession();

        void lock();
        bool try_lock();
        void unlock();

        const char* getID() const;
        const char* getApplicationID() const;
        const char* getClientAddress(const char* family) const;
        void setClientAddress(const char* client_addr);
        const std::map<std::string,DDF>& getAttributes() const;
        time_t getCreation() const;
        time_t getLastAccess() const;

        void validate(const char* applicationId, const char* client_addr, time_t* timeout);

        // Allows the cache to bind sessions to multiple client address
        // families based on whatever this function returns.
        static const char* getAddressFamily(const char* addr);

    private:
        DDF m_obj;
        std::map<std::string,DDF> m_attributes;

        AbstractSessionCache& m_cache;
        time_t m_creation,m_lastAccess;
        // TODO: possibly convert to a shared lock where possible?
        // I used exclusive because it avoided lock "upgrades"
        // when mutating or deleting sessions.
        std::mutex m_lock;
    };

    class SHIBSP_API AbstractSessionCache : public virtual SessionCache {
        protected:
            /** Constructor. */
            AbstractSessionCache();
            virtual ~AbstractSessionCache();
    
            Category& m_log;
    
        public:
            bool start();

        friend class BasicSession;
        };    
};

#endif /** __shibsp_abssessioncache_h__ */