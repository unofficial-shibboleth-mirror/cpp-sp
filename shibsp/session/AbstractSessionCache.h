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
#include <session/SessionCacheSPI.h>
#include <util/BoostPropertySet.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif
#include <thread>
#include <vector>

#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

    class SHIBSP_API AbstractSessionCache;
    class SHIBSP_API Attribute;
    class SHIBSP_API CookieManager;
    class SHIBSP_API IPRange;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    class SHIBSP_API BasicSession : public virtual Session
    {
    public:
        BasicSession(AbstractSessionCache& cache, DDF& obj);
        virtual ~BasicSession();

        void lock();
        bool try_lock();
        void unlock();

        const char* getID() const;
        unsigned int getVersion() const;
        const char* getApplicationID() const;
        const char* getClientAddress(const char* fanily) const;
        const std::map<std::string,DDF>& getAttributes() const;
        DDF getOpaqueData() const;
        time_t getCreation() const;
        time_t getLastAccess() const;

        /**
         * Returns a clone of the underlying data in the session.
         * 
         * @return a clone of the session's data, owned by caller
         */
        DDF cloneData() const;

        /**
         * Replace the session's data with an updated version.
         * 
         * <p>This must be called while holding the exclusive lock on the object.
         * Ownership of the input object is transferred to this object and the
         * original data will be freed.</p>
         * 
         * @param data new data
         */
        void updateData(DDF& data);

        /**
         * Perform validation of a local session based on policy and checks for revocation.
         * 
         * @param request optional session carrying request if available
         * @param lifetime session lifetime policy, 0 if none
         * @param timeout session timeout policy, 0 if none
         * 
         * @return true iff the session remains valid
         */
        bool isValid(SPRequest* request, unsigned int lifetime, unsigned int timeout);

    private:
        DDF m_obj;
        std::map<std::string,DDF> m_attributes;

        AbstractSessionCache& m_cache;
        time_t m_lastAccess,m_lastAccessReported;
        // TODO: possibly convert to a shared lock where possible?
        // I used exclusive because it avoided lock "upgrades"
        // when mutating or deleting sessions.
        std::mutex m_lock;
    };

    class SHIBSP_API AbstractSessionCache : public virtual SessionCache, public SessionCacheSPI, public virtual BoostPropertySet {
        public:
            /**
             * Starts background cleanup thread for in-memory hashtable of sessions.
             * 
             * @return true iff the thread was successfully started
             */
            bool start();

            /**
             * Triggers shutdown flag, signals background thread(s), and joins with ours.
             */
            void stop();

            // SessionCache API
            std::string create(SPRequest& request, DDF& data);
            std::unique_lock<Session> find(SPRequest& request, bool checkTimeout, bool ignoreAddress);
            std::unique_lock<Session> find(const char* applicationId, const char* key, unsigned int version=1);
            bool update(SPRequest& request, std::unique_lock<Session>& session, DDF& data, const char* reason=nullptr);
            void remove(SPRequest& request);
            void remove(const char* key);

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
            Category& logger() const;

            /**
             * Access the shutdown state.
             */
            bool isShutdown() const;

            /**
             * Tests the validity of a session's data structures.
             * 
             * <p>Note that this is not a policy evaluation of the data in the session but only
             * of the structure/content to fit the underlying assumptions built into the code.</p>
             * 
             * @param sessionData the data to examine
             * 
             * @return true iff the data is valid
             */
            static bool isSessionDataValid(DDF& sessionData);
            /**
             * Compares two addresses, allowing for the unreliableNetworks fuzzy match option.
             * 
             * @param one   first address
             * @param two   second address
             * 
             * @return true iff the addresses are "equivalent" for session purposes
             */
            bool isAddressMatch(const char* one, const char* two) const;

            /**
             * Returns a string signifying the network address family of the input address.
             * 
             * @param addr address to evaluate
             * 
             * @return the address family (or a default value, so null is never returned)
             */
            static const char* getAddressFamily(const std::string& addr);

            /**
             * Generates version-specific filenames and cookie values by modifying a string in place.
             * 
             * @param path base string to append version to
             * @param version version to append
             */
            static void computeVersionedFilename(std::string& path, unsigned int version);

            /**
             * Conditionally logs to request API or directly depending on existence of request.
             * 
             * @param request request if available
             * @param log fallback logger
             * @param level logging level
             * @param formatString format string
             */
            static void log(const SPRequest* request, Category& log, Priority::Value level, const char* formatString, ...);
        private:
            // Split session key and version from cookie values.
            static std::pair<std::string,unsigned int> parseCookieValue(const char* value);

            static void* cleanup_fn(void*);
            void dormant(const SPRequest* request, const std::string& key);
            // Wrapper for finding sessions via varied inputs.
            std::unique_lock<Session> _find(
                SPRequest* request,
                const char* applicationID,
                const char* key,
                unsigned int version,
                unsigned int lifetime,
                unsigned int timeout,
                const char* client_addr
                );

            Category& m_log;
#if defined(HAVE_CXX17)
            std::shared_mutex m_lock;
#elif defined(HAVE_CXX14)
            std::shared_timed_mutex m_lock;
#else
            std::mutex m_lock;
#endif
            std::map<std::string,std::unique_ptr<BasicSession>> m_hashtable;
            std::unique_ptr<CookieManager> m_cookieManager;
            std::vector<IPRange> m_unreliableNetworks;
            std::condition_variable m_shutdown_wait;
            std::thread m_cleanup_thread;
            std::string m_issuerAttribute;
            bool m_shutdown;
            unsigned int m_storageAccessInterval;
            
            friend class BasicSession;
        };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /** __shibsp_abssessioncache_h__ */