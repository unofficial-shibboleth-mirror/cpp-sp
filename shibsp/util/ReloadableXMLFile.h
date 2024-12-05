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
 * Base class for reloadable XML file-based configuration.
 */

#ifndef __shibsp_ReloadableXMLFile_h__
#define __shibsp_ReloadableXMLFile_h__

#include <shibsp/util/Lockable.h>

#include <ctime>
#include <memory>
#include <string>

#include <boost/property_tree/ptree_fwd.hpp>

#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

namespace shibsp {

    class SHIBSP_API Category;

    /**
     * Base class for file-based XML configuration, provides locking and reload semantics.
     * 
     * <p>Also supports "inliine" configuration that short-circuits most of this logic
     * allowing for unified handling of the two cases by implementing classes and the
     * consumers of a configuration interface.</p>
     */
    class SHIBSP_API ReloadableXMLFile : public virtual BasicLockable, public virtual SharedLockable
    {
        MAKE_NONCOPYABLE(ReloadableXMLFile);

    public:
        static const char PATH_PROP_NAME[];
        static const char RELOAD_CHANGES_PROP_NAME[];

        // BasicLockable
        void lock();
        bool try_lock();
        void unlock();
        // SharedLockable
        void lock_shared();
        bool try_lock_shared();
        void unlock_shared();

    protected:
        /**
         * Base class constructor.
         * 
         * <p>The supported property keys for an "out of band" file-backed instance
         * of whatever the underlying configuration is are "path" and "reloadChanges"
         * (the latter a boolean flag)</p>
         * 
         * <p>In the absence of a "path" key, the configuration is assumed to be
         * inline as the content of the supplied tree and the base class essentially
         * performs no activity, stubs out locking, etc.</p>
         * 
         * <p>Note that the root element name specified applies to the content of the
         * configuration itself and not the element that may be carrying the "path" key
         * specifying an external file (i.e., in that case it's the external content whose
         * root element would be expected to match).</p>
         * 
         * @param pt                    root of property tree defining resource
         * @param rootElementName       name of expexcted root element of XML configuration
         * @param log                   logging object to use
         */
        ReloadableXMLFile(const std::string& rootElementName, const boost::property_tree::ptree& pt, Category& log);
    
        virtual ~ReloadableXMLFile();

        /**
         * Loads (or reloads) configuration material.
         * 
         * <p>This method is called to load configuration material
         * initially and any time a change is detected but is not called
         * initially unless by a subclass.</p>
         *
         * <p>This method is not intended to throw.</p>
         * 
         * <p>This method is not called with the object locked, and it does
         * not modify implementation state. Subclasses are expected to override
         * this method to lock and modify state as required.</p>
         * 
         * @return a pair containing a (possibly null) pointer to the property tree
         *  loaded and a flag indicating whether the subclass should retain ownership
         *  of the tree and free it when done with it
         */
        virtual std::pair<bool,boost::property_tree::ptree*> load() noexcept;

        /**
         * Gets the last time the configuration was updated.
         * 
         * <p>This method must be called with the object locked, shared or exclusively.</p>
         * 
         * @return the last configuration update
         */
        time_t getLastModified() const;

        /**
         * Determines whether the source file has been modified since it was last
         * loaded, or returns false in the event of an error accessing the file.
         * 
         * <p>This method must be called with the object locked, shared or exclusively.</p>
         * 
         * <p>The method is virtual primarily to facilitate alternative control over reload
         * events.</p>
         * 
         * @return true iff the source has been modified
         */
        virtual bool isUpdated() const;

        /**
         * Updates the time of last modification of the source, assigning a future fence
         * value in the event of an error to discontinue checking.
         * 
         * <p>This method must be called with the object locked exclusively.</p>
         * 
         * <p>The method is virtual primarily to facilitate alternative control over reload
         * events.</p>
         */
        void updateModificationTime();

        /**
         * Updates the time of last modification to an explicitly input time.
         * 
         * <p>This method must be called with the object locked exclusively.</p>
         * 
         * <p>The method is primarily to facilitate alternative control over reload
         * events.</p>
         */
        void updateModificationTime(time_t t);

    private:
        /** Root of configuration or of the pointer to the configuration. */
        const boost::property_tree::ptree& m_root;

        /** Logging object. */
        Category& m_log;

        /** Resource path. */
        std::string m_source;

        /** Expected name of root element, i.e. subtree, after parsing. */
        std::string m_rootElementName;

        /** Last modification of local resource. */
        time_t m_filestamp;

        /** Shared lock for guarding reloads. */
#ifdef HAVE_CXX17
        std::unique_ptr<std::shared_mutex> m_lock;
#elif HAVE_CXX14
        std::unique_ptr<std::shared_timed_mutex> m_lock;
#endif
    };

};

#endif /* __shibsp_ReloadableXMLFile_h__ */
