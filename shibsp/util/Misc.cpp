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
#include "util/Misc.h"

#include <set>
#include <vector>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace std;

vector<string>::size_type split_to_container(vector<string>& container, const char* s)
{
    if (s) {
        string dup(s);
        boost::trim(dup);
        boost::split(container, dup, boost::is_space(), boost::token_compress_on);
    }
    return container.size();
}

set<string>::size_type split_to_container(set<string>& container, const char* s)
{
    if (s) {
        string dup(s);
        boost::trim(dup);
        boost::split(container, dup, boost::is_space(), boost::token_compress_on);
    }
    return container.size();
}
