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
#include <boost/algorithm/string.hpp>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

using namespace shibsp;
using namespace boost;
using namespace std;

GenericRequest::GenericRequest()
{
}

GenericRequest::~GenericRequest()
{
}

bool GenericRequest::isDefaultPort() const
{
    return false;
}

void GenericRequest::absolutize(string& url) const
{
    if (url.empty())
        url = '/';
    if (url[0] == '/') {
        // Compute a URL to the root of the site.
        const char* scheme = getScheme();
        string root = string(scheme) + "://" + getHostname();
        if (!isDefaultPort())
            root += ":" + lexical_cast<string>(getPort());
        url = root + url;
    }
}

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

namespace {
    void handle_cookie_fn(map<string,string>& cookieMap, vector<string>& nvpair, const string& s) {
        nvpair.clear();
        split(nvpair, s, is_any_of("="));
        if (nvpair.size() == 2) {
            trim(nvpair[0]);
            if (ends_with(nvpair[0], "_fgwars")) {
                nvpair[0].erase(nvpair[0].end() - 7, nvpair[0].end());
            }
            cookieMap[nvpair[0]] = nvpair[1];
        }
    }
}

const map<string,string>& HTTPRequest::getCookies() const
{
    if (m_cookieMap.empty()) {
        string cookies=getHeader("Cookie");
        vector<string> nvpair;
        tokenizer< char_separator<char> > nvpairs(cookies, char_separator<char>(";"));
        for_each(nvpairs.begin(), nvpairs.end(),
            boost::bind(handle_cookie_fn, boost::ref(m_cookieMap), boost::ref(nvpair), _1));
    }
    return m_cookieMap;
}

const char* HTTPRequest::getCookie(const char* name) const
{
    return getCookie(name, false);
}

const char* HTTPRequest::getCookie(const char* name, bool) const
{
    // The fallback support is implemented via the getCookies() load above
    // so we ignore it here.

    map<string,string>::const_iterator lookup = getCookies().find(name);
    if (lookup != m_cookieMap.end()) {
        return lookup->second.c_str();
    }

    return nullptr;
}
