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
  * Program to output the 4 didgit version derived from the versions file
  * amd suitable for inputting the build of our installers.
  */
#include <iostream>
#include <shibsp\version.h>

int main()
{
    if (SHIBSP_VERSION_PATCH != 0) {
        std::cerr << "SHIB_VERESION_PATCH SHOUKLD BE ZERO" << std::endl; 
        return 1;
    }
    int version = (SHIBSP_VERSION_MAJOR << 24) | (SHIBSP_VERSION_MINOR << 16) | SHIBSP_VERSION_REVISION;
    std::cout << version << std::endl;
}
