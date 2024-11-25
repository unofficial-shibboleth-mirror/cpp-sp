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

#ifndef __shibsp_logging_stringutil_h__
#define __shibsp_logging_stringutil_h__

#include "internal.h"

#include <string>
#include <vector>
#include <climits>
#include <cstdarg>

namespace shibsp {

    /**
     * Utility class ported from log4shib.
     */
    class StringUtil {
    private:
        StringUtil() {}
        MAKE_NONCOPYABLE(StringUtil);

    public:
        /**
         * Returns a string contructed from the a format specifier
         * and a va_list of arguments, analogously to vprintf(3).
         * 
         * @param format the format specifier.
         * @param args the va_list of arguments.
         */
        static std::string vform(const char* format, va_list args);
    };

}

#endif // __shibsp_logging_stringutil_h__
