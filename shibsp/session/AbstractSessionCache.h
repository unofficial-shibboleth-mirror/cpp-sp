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
#include <util/BoostPropertySet.h>

#include <condition_variable>
#include <mutex>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif
#include <thread>
#include <boost/property_tree/ptree_fwd.hpp>

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

    class SHIBSP_API AbstractSessionCache : public virtual SessionCache, public virtual BoostPropertySet {
        public:
            /**
             * Starts background cleanup thread for in-memory hashtable of sessions.
             * 
             * @return true iff the thread was successfully started
             */
            bool start();

            static const char CLEANUP_INTERVAL_PROP_NAME[];
            static const char INPROC_TIMEOUT_PROP_NAME[];

            static unsigned int CLEANUP_INTERVAL_PROP_DEFAULT;
            static unsigned int INPROC_TIMEOUT_PROP_DEFAULT;

        protected:
            /**
             * Constructor.
             * 
             * @param pt root of property tree to load
             */
            AbstractSessionCache(const boost::property_tree::ptree& pt);

            /** Destructor. */
            virtual ~AbstractSessionCache();
    
            /**
             * Get logging object.
             * 
             * @return logging object
             */
            Category& log() const;

        private:
            static void* cleanup_fn(void*);
            void dormant(const std::string& key);

            Category& m_log;
#if defined(HAVE_CXX17)
            std::shared_mutex m_lock;
#elif defined(HAVE_CXX14)
            std::shared_timed_mutex m_lock;
#else
            std::mutex m_lock;
#endif
            std::map<std::string,std::unique_ptr<BasicSession>> m_hashtable;

            bool m_shutdown;
            std::condition_variable m_shutdown_wait;
            std::thread m_cleanup_thread;
                
        friend class BasicSession;
        };    
};

#endif /** __shibsp_abssessioncache_h__ */