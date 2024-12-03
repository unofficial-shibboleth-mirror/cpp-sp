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
 * @file shibsp/util/ReloadableFile.h
 * 
 * Base class for reloadable file-based configuration.
 */

#ifndef __shibsp_reloadablefile_h__
#define __shibsp_reloadablefile_h__

#include <shibsp/base.h>

#include <ctime>
#include <memory>
#include <string>

#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

namespace shibsp {

    class SHIBSP_API Category;

    /**
     * Base class for file-based configuration, provides locking and reload semantics.
     */
    class SHIBSP_API ReloadableFile
    {
    MAKE_NONCOPYABLE(ReloadableFile);
    protected:
        /**
         * Base class constructor.
         * 
         * @param path                  path to file to use
         * @param log                   logging object to use
         * @param reloadChanges         whether to monitor for changes
         */
        ReloadableFile(const std::string& path, Category& log, bool reloadChanges=false);
    
        virtual ~ReloadableFile();

        /**
         * Loads (or reloads) configuration material.
         * 
         * <p>This method is called to load configuration material
         * initially and any time a change is detected. The base class version
         * assumes success and calls the updateModificationTime method.</p>
         *
         * <p>This method is not called with the object locked, so actual
         * modification of implementation state requires explicit locking within
         * the method override, and the method should return with the object
         * unlocked.</p>
         * 
         * <p>This method should NOT throw exceptions.</p>
         */
        virtual bool load();

        /**
         * Gets the source path for the configuration.
         * 
         * @return source path
         */
        const std::string& getSource() const;

        /**
         * Returns the last successful load of this configuration resource.
         * 
         * @return last successful load time
         */
        time_t getLastModified() const;

        /**
         * Determines whether the source file has been modified since it was last
         * loaded, or returns false in the event of an error accessing the file.
         * 
         * <p>This method must be called with the object locked, shared or exclusively.</p>
         * 
         * @return true iff the source has been modified
         */
        bool isUpdated() const;

        /**
         * Updates the time of last modification of the source, assigning a future fence
         * value in the event of an error to discontinue checking.
         * 
         * <p>This method must be called with the object locked exclusively.</p>
         */
        void updateModificationTime();

    private:
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

#endif /* __shibsp_reloadablefile_h__ */
