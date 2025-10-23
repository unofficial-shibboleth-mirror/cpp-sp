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
 * util/Misc.cpp
 * 
 * Utility function implementations.
 */

#include "internal.h"
#include "util/Date.h"
#include "util/Misc.h"

#include <ctime>
#include <set>
#include <sstream>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include <sys/stat.h>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex.hpp>
namespace regexp = boost;
#else
# include <regex>
namespace regexp = std;
#endif

using namespace shibsp;
using namespace std;

vector<string>::size_type shibsp::split_to_container(vector<string>& container, const char* s)
{
    if (s) {
        string dup(s);
        boost::trim(dup);
        boost::split(container, dup, boost::is_space(), boost::token_compress_on);
    }
    return container.size();
}

set<string>::size_type shibsp::split_to_container(set<string>& container, const char* s)
{
    if (s) {
        string dup(s);
        boost::trim(dup);
        boost::split(container, dup, boost::is_space(), boost::token_compress_on);
    }
    return container.size();
}

time_t shibsp::parseISODuration(const string& s)
{
    // If solving a problem with a regex gives you two problems, any estimates on these?
    static regexp::regex notime_parser("P([[:d:]]+Y)?([[:d:]]+M)?([[:d:]]+D)?");
    static regexp::regex full_parser("P([[:d:]]+Y)?([[:d:]]+M)?([[:d:]]+D)?T([[:d:]]+H)?([[:d:]]+M)?([[:d:]]+S|[[:d:]]+\\.[[:d:]]+S)?");
    
    if (s.empty()) {
        return -1;
    }

    regexp::smatch match;

    try {
        if (strchr(s.c_str(), 'T')) {
            regexp::regex_search(s, match, full_parser);
        }
        else {
            regexp::regex_search(s, match, notime_parser);
        }
    }
    catch (const regexp::regex_error& e) {
        return -1;
    }

    if (match.empty()) {
        return -1;
    }

    vector<double> vec = {0,0,0,0,0,0}; // years, months, days, hours, minutes, seconds

    for (size_t i = 1; i < match.size(); ++i) {

        if (match[i].matched) {
            string str = match[i];
            str.pop_back(); // remove last character.
            try {
                vec[i-1] = boost::lexical_cast<long>(str);
            }
            catch (const boost::bad_lexical_cast& e) {
                return 0;
            }
        }
    }

    time_t duration =   31556926   * vec[0] +  // years  
                        2629743.83 * vec[1] +  // months
                        86400      * vec[2] +  // days
                        3600       * vec[3] +  // hours
                        60         * vec[4] +  // minutes
                        1          * vec[5];   // seconds    

    return duration;
}

time_t shibsp::parseISODateTime(const string& s)
{
    tm tmStruct = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, nullptr};
    char* ret = strptime(s.c_str(), "%Y-%m-%dT%TZ", &tmStruct);
    if (!ret || *ret) {
        return -1;
    }
    return timegm(&tmStruct);
}

bool FileSupport::exists(const char* path)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(path, &stat_buf) == 0) {
        return true;
    }
#else
    struct stat stat_buf;
    if (stat(path, &stat_buf) == 0) {
        return true;
    }
#endif
    return false;
}

time_t FileSupport::getModificationTime(const char* path)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(path, &stat_buf) == 0) {
        return stat_buf.st_mtime;
    }
#else
    struct stat stat_buf;
    if (stat(path, &stat_buf) == 0) {
        return stat_buf.st_mtime;
    }
#endif
    return 0;
}

#ifdef WIN32
time_t FileSupport::getModificationTime(const wchar_t* path)
{
    struct _stat stat_buf;
    if (_wstat(path, &stat_buf) == 0) {
        return stat_buf.st_mtime;
    }
    return 0;
}
#endif
