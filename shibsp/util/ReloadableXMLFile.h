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
 * @file shibsp/util/ReloadableXMLFile.h
 * 
 * Base class for reloadable file-based XML configuration.
 */

#ifndef __shibsp_reloadablexml_h__
#define __shibsp_reloadablexml_h__

#include <shibsp/base.h>

#include <ctime>
#include <memory>
#include <string>
#include <boost/property_tree/ptree_fwd.hpp>

#ifdef HAVE_CXX14
#include <shared_mutex>
#endif

namespace shibsp {

    class SHIBSP_API Category;

    /**
     * Base class for file-based XML configuration.
     */
    class SHIBSP_API ReloadableXMLFile
    {
    MAKE_NONCOPYABLE(ReloadableXMLFile);
    protected:
        /**
         * Base class constructor.
         * 
         * @param path                  path to file to use
         * @param log                   logging object to use
         * @param reloadChanges         whether to monitor for changes
         * @param deprecationSupport    true iff deprecated options and settings should be accepted
         */
        ReloadableXMLFile(
            const std::string& path,
            Category& log,
            bool reloadChanges=false,
            bool deprecationSupport=true
            );
    
        virtual ~ReloadableXMLFile();

        /**
         * Loads configuration material.
         * 
         * <p>This method is called to load configuration material
         * initially and any time a change is detected. The base version
         * performs basic parsing duties and returns the result.</p>
         *
         * <p>This method is not called with the object locked, so actual
         * modification of implementation state requires explicit locking within
         * the method override.</p>
         * 
         * <p>This method should NOT throw exceptions.</p>
         * 
         * @return a possibly empty smart pointer holding the replacement tree
         */
        virtual std::unique_ptr<boost::property_tree::ptree> load();
        
        /** The owned property tree. */
        std::unique_ptr<boost::property_tree::ptree> m_tree;

        /** Logging object. */
        Category& m_log;

        /** Resource path. */
        std::string m_source;

        /** Last modification of local resource. */
        time_t m_filestamp;

        /** Shared lock for guarding reloads. */
#ifdef HAVE_CXX17
        std::unique_ptr<std::shared_mutex> m_lock;
#elif HAVE_CXX14
        std::unique_ptr<std::shared_timed_mutex> m_lock;
#endif

    public:
        // SharedLockable
        void lock_shared();
        bool try_lock_shared();
        void unlock_shared();
        // BasicLockable
        void lock();
        bool try_lock();
        void unlock();
    };

};

#endif /* __shibsp_reloadablexml_h__ */
