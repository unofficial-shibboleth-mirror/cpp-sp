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

#include <stdexcept>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif


using namespace shibsp;
using namespace std;

GenericResponse::GenericResponse()
{
}

GenericResponse::~GenericResponse()
{
}

vector<string> HTTPResponse::m_allowedSchemes;

vector<string>& HTTPResponse::getAllowedSchemes()
{
    return m_allowedSchemes;
}

void HTTPResponse::sanitizeURL(const char* url)
{
    const char* ch;
    for (ch=url; *ch; ++ch) {
        if (iscntrl((unsigned char)(*ch)))  // convert to unsigned to allow full range from 00-FF
            throw domain_error("URL contained a control character.");
    }

    ch = strchr(url, ':');
    if (!ch)
        throw domain_error("URL is missing a colon where expected; improper URL encoding?");
    string s(url, ch - url);

    for (const string& scheme : m_allowedSchemes) {
        if (strcasecmp(s.c_str(), scheme.c_str()) == 0) {
            return;
        }
    }

    throw domain_error("URL contains invalid scheme.");
}

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

long HTTPResponse::sendRedirect(const char* url)
{
    sanitizeURL(url);
    return SHIBSP_HTTP_STATUS_MOVED;
}

long HTTPResponse::sendError(istream& inputStream)
{
    return sendResponse(inputStream, SHIBSP_HTTP_STATUS_ERROR);
}

long HTTPResponse::sendResponse(istream& inputStream)
{
    return sendResponse(inputStream, SHIBSP_HTTP_STATUS_OK);
}
