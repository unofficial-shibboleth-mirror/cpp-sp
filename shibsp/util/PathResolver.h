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
 * @file shibsp/util/PathResolver.h
 *
 * Resolves local filenames into absolute pathnames.
 */

#ifndef __shibsp_pathres_h__
#define __shibsp_pathres_h__

#include <shibsp/base.h>

#include <string>

namespace shibsp {

#if defined (_MSC_VER)
#    pragma warning( push )
#    pragma warning( disable : 4251 )
#endif

    /**
     * Resolves local filenames into absolute pathnames.
     */
    class SHIBSP_API PathResolver
    {
        MAKE_NONCOPYABLE(PathResolver);
    public:
        PathResolver();
        virtual ~PathResolver();

        /** Types of file resources to resolve. */
        enum file_type_t {
            SHIBSP_LIB_FILE,
            SHIBSP_LOG_FILE,
            SHIBSP_RUN_FILE,
            SHIBSP_CFG_FILE,
            SHIBSP_CACHE_FILE
        };

        /**
         * Set the default package to use when resolving files.
         *
         * @param pkgname name of default package to use
         */
        void setDefaultPackageName(const char* pkgname);

        /**
         * Set the default installation prefix to use when resolving files.
         *
         * @param prefix name of default prefix to use
         */
        void setDefaultPrefix(const char* prefix);

        /**
         * Set the lib directory to use when resolving files.
         * <p>If relative, the default prefix will be prepended.
         *
         * @param dir    the library directory to use
         */
        void setLibDir(const char* dir);

        /**
         * Set the log directory to use when resolving files.
         * <p>If relative, the default prefix will be prepended.
         *
         * @param dir    the log directory to use
         */
        void setLogDir(const char* dir);

        /**
         * Set the run directory to use when resolving files.
         * <p>If relative, the default prefix will be prepended.
         *
         * @param dir    the run directory to use
         */
        void setRunDir(const char* dir);

        /**
         * Set the config directory to use when resolving files.
         * <p>If relative, the default prefix will be prepended.
         *
         * @param dir    the config directory to use
         */
        void setCfgDir(const char* dir);

        /**
         * Set the cache directory to use when resolving files.
         * <p>If relative, the default prefix will be prepended.
         *
         * @param dir    the cache directory to use
         */
        void setCacheDir(const char* dir);

        /**
         * Changes the input filename into an absolute pathname to the same file.
         *
         * @param s         filename to resolve
         * @param filetype  type of file being resolved
         * @param pkgname   application package name to use in resolving the file (or nullptr for the default)
         * @param prefix    installation prefix to use in resolving the file (or nullptr for the default)
         *
         * @return a const reference to the input string
         */
        const std::string& resolve(std::string& s, file_type_t filetype, const char* pkgname=nullptr, const char* prefix=nullptr) const;

    private:
        bool isAbsolute(const char* s) const;

        std::string m_defaultPackage,m_defaultPrefix,m_lib,m_log,m_run,m_cfg,m_cache;
    };

#if defined (_MSC_VER)
#   pragma warning( pop )
#endif
};

#endif /* __shibsp_pathres_h__ */
