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

#include "StringUtil.h"

#include <cstdio>

using namespace shibsp;

#if defined(_MSC_VER)
    #define VSNPRINTF _vsnprintf
#else
    #define VSNPRINTF vsnprintf
#endif // _MSC_VER

std::string StringUtil::vform(const char* format, va_list args) {
    size_t size = 256;
    char* buffer = new char[size];
        
    while (true) {
        va_list args_copy;

        va_copy(args_copy, args);
        int n = VSNPRINTF(buffer, size, format, args_copy);

        va_end(args_copy);

        // If that worked, return a string.
        if ((n > -1) && (static_cast<size_t>(n) < size)) {
            std::string s(buffer);
            delete [] buffer;
            return s;
        }

        // Else try again with more space.
            size = (n > -1) ?
                n + 1 :   // ISO/IEC 9899:1999
                size * 2; // twice the old size

        delete [] buffer;
        buffer = new char[size];
    }

}
