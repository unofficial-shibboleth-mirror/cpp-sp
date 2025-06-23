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
 * util/DirectoryWalker.cpp
 *
 * Iterates over directory entries.
 */

#include "internal.h"
#include "exceptions.h"
#include "util/DirectoryWalker.h"

#ifdef WIN32
# include <windows.h>
#else
# include <boost/algorithm/string.hpp>
# if defined(HAVE_SYS_TYPES_H) && defined(HAVE_DIRENT_H)
#  include <dirent.h>
#  include <sys/types.h>
# else
#  error Unsupported directory library headers.
# endif
#endif

using namespace shibsp;
using namespace std;

DirectoryWalker::DirectoryWalker(Category& log, const char* path, bool recurse)
    : m_log(log), m_path(path), m_recurse(recurse)
{
}

DirectoryWalker::~DirectoryWalker()
{
}

void DirectoryWalker::_walk(
    const char* path, const DirectoryWalkerCallback& callback_fn, void* callback_data, const char* startsWith, const char* endsWith
    ) const
{
#ifdef WIN32
    string searchpath = string(path) + '/';
    if (startsWith)
        searchpath += startsWith;
    searchpath += '*';
    if (endsWith)
        searchpath += endsWith;
    m_log.debug("searching path (%s)", searchpath.c_str());

    WIN32_FIND_DATA f;
    HANDLE h = FindFirstFile(searchpath.c_str(), &f);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            m_log.warn("Unable to open directory (%s)", path);
        else
            m_log.debug("no matching entries in directory (%s)", path);
        return;
    }
    do {
        if (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!strcmp(f.cFileName, ".") || !strcmp(f.cFileName, ".."))
                continue;
            if (m_recurse) {
                m_log.debug("processing nested directory (%s)", f.cFileName);
                string nested = string(path) + '/' + f.cFileName;
                _walk(nested.c_str(), callback_fn, callback_data, startsWith, endsWith);
            }
            else {
                m_log.debug("recursion disabled, skipping nested directory (%s)", f.cFileName);
            }
        }
        else {
            string fullname = string(path) + '/' + f.cFileName;
            struct stat stat_buf;
            if (stat(fullname.c_str(), &stat_buf) == 0) {
                m_log.debug("invoking callback for file (%s)", fullname.c_str());
                callback_fn(fullname.c_str(), stat_buf, callback_data);
            }
            else {
                m_log.warn("unable to access (%s)", fullname.c_str());
            }
        }
    } while (FindNextFile(h, &f));
    FindClose(h);
#else
    DIR* d = opendir(path);
    if (!d) {
        m_log.warn("Unable to open directory (%s)", path);
        return;
    }
    char dir_buf[sizeof(struct dirent) + PATH_MAX];
    struct dirent* ent = (struct dirent*)dir_buf;
    struct dirent* entptr = nullptr;
    while (readdir_r(d, ent, &entptr) == 0 && entptr) {
        if (!strcmp(entptr->d_name, ".") || !strcmp(entptr->d_name, ".."))
            continue;
        else if (startsWith || endsWith) {
            string fname(entptr->d_name);
            if ((startsWith && !boost::algorithm::starts_with(fname, startsWith)) ||
                (endsWith && !boost::algorithm::ends_with(fname, endsWith))) {
                continue;
            }
        }

        string fullname = string(path) + '/' + entptr->d_name;
        struct stat stat_buf;
        if (stat(fullname.c_str(), &stat_buf) != 0) {
            m_log.warn("unable to access (%s)", fullname.c_str());
        }
        else if (S_ISDIR(stat_buf.st_mode)) {
            if (m_recurse) {
                m_log.debug("processing nested directory (%s)", entptr->d_name);
                _walk(fullname.c_str(), callback_fn, callback_data, startsWith, endsWith);
            }
            else {
                m_log.debug("recursion disabled, skipping nested directory (%s)", entptr->d_name);
            }
        }
        else {
            m_log.debug("invoking callback for file (%s)", fullname.c_str());
            callback_fn(fullname.c_str(), stat_buf, callback_data);
        }
    }
    closedir(d);
#endif
    }
