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
 * @file shibsp/util/DirectoryWalker.h
 *
 * Iterates over directory entries.
 */

#if !defined(__shibsp_dirwalk_h__)
#define __shibsp_dirwalk_h__

#include <logging/Category.h>

#include <string>
#include <sys/stat.h>

namespace shibsp {

#if defined (_MSC_VER)
#    pragma warning( push )
#    pragma warning( disable : 4251 )
#endif

    /**
     * Portable directory walker that invokes a callback function for every file in a
     * directory, optionally doing depth-first recursion of nested directories.
     */
    class SHIBSP_API DirectoryWalker
    {
        MAKE_NONCOPYABLE(DirectoryWalker);
    public:

        /**
         * Constructor.
         *
         * @param log log category
         * @param path directory path to walk
         * @param recurse true iff nested directories should be processed
         */
        DirectoryWalker(Category& log, const char* path, bool recurse=false);

        virtual ~DirectoryWalker();

        /** Callback function, passed the path and file names, stat buffer, and optional callback data. */
        typedef void (*DirectoryWalkerCallback)(const char* pathname, const char* filename, struct stat& stat_buf, void* data);

        /**
         * Perform a depth-first traversal of the directory.
         *
         * @param callback_fn   callback function to invoke for each match
         * @param callback_data optional pointer to pass to callback
         * @param startsWith    optional prefix matching, skipping non-matching entries
         * @param endsWith      optional suffix matching, skipping non-matching entries
         */
        void walk(
            const DirectoryWalkerCallback& callback_fn,
            void* callback_data = nullptr,
            const char* startsWith = nullptr,
            const char* endsWith = nullptr
            ) const {
            _walk(m_path.c_str(), callback_fn, callback_data, startsWith, endsWith);
        }

    private:
        void _walk(
            const char* path,
            const DirectoryWalkerCallback& callback_fn,
            void* callback_data = nullptr,
            const char* startsWith = nullptr,
            const char* endsWith = nullptr
        ) const;

        Category& m_log;
        std::string m_path;
        bool m_recurse;
    };

#if defined (_MSC_VER)
#   pragma warning( pop )
#endif
};

#endif /* __shibsp_dirwalk_h__ */
