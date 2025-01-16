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
 * @file shibsp/util/Misc.h
 * 
 * Miscellaneous inline functions and classes.
 */

#include <shibsp/base.h>

#include <set>
#include <string>
#include <vector>
#include <boost/optional.hpp>

namespace shibsp {

    /**
     * Internal utility used for decoding %XX escapes in various places.
     */
    static char x2c(const char* what) {
        char digit;

        digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
        digit *= 16;
        digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
        return(digit);
    }

    /**
     * Used with the Boost property_tree package to perform string to boolean conversions
     * in a consistent way.
     */
    struct string_to_bool_translator {
        typedef std::string internal_type;
        typedef bool external_type;

        boost::optional<bool> get_value(const std::string &s) {
            if (s == "true" || s == "1") {
                return boost::make_optional(true);
            } else if (s == "false" || s == "0") {
                return boost::make_optional(false);
            } else {
                return boost::none;
            }
        }
    };

    /**
     * Splitter functions that trim the input and split on whitespace into a container.
     */
    SHIBSP_API std::vector<std::string>::size_type split_to_container(std::vector<std::string>& container, const char* s);
    SHIBSP_API std::set<std::string>::size_type split_to_container(std::set<std::string>& container, const char* s);
};