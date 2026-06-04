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
 * io/impl/HTTPRequest.cpp
 * 
 * Interface to HTTP requests handled by agents.
 */

#include "internal.h"

#include "io/HTTPRequest.h"

#include <cstring>
#include <algorithm>
#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

HTTPRequest::HTTPRequest()
{
}

HTTPRequest::~HTTPRequest()
{
}

bool HTTPRequest::isSecure() const
{
    return strcmp(getScheme(),"https")==0;
}

bool HTTPRequest::isDefaultPort() const
{
    if (isSecure())
        return getPort() == 443;
    else
        return getPort() == 80;
}
