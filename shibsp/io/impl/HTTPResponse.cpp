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
 * io/impl/HTTPResponse.cpp
 * 
 * Interface to HTTP responses issued by agents.
 */

#include "internal.h"
#include "io/HTTPResponse.h"

#include <cstring>
#include <stdexcept>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif


using namespace shibsp;
using namespace std;

HTTPResponse::HTTPResponse()
{
}

HTTPResponse::~HTTPResponse()
{
}

void HTTPResponse::setContentType(const char* type)
{
    setResponseHeader("Content-Type", type);
}

void HTTPResponse::setResponseHeader(const char* name, const char* value, bool)
{
    if (name) {
        for (const char* ch=name; *ch; ++ch) {
            if (iscntrl(*ch))
                throw domain_error("Response header name contained a control character.");
        }
    }

    if (value) {
        for (const char* ch=value; *ch; ++ch) {
            if (iscntrl(*ch))
                throw domain_error("Value for response header contained a control character.");
        }
    }
}

long HTTPResponse::sendError(istream& inputStream)
{
    return sendResponse(inputStream, SHIBSP_HTTP_STATUS_ERROR);
}
