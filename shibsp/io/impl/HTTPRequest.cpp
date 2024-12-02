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
#include <boost/algorithm/string.hpp>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/Threads.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

bool GenericRequest::m_langFromClient = true;
GenericRequest::langrange_t GenericRequest::m_defaultRange;

GenericRequest::GenericRequest() : m_langRangeIter(m_langRange.rend())
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

void GenericRequest::setLangDefaults(bool langFromClient, const XMLCh* defaultRange)
{
    m_langFromClient = langFromClient;
    m_defaultRange.clear();
    if (!defaultRange)
        return;
    float q = 0.0f;
    XMLStringTokenizer tokens(defaultRange);
    while (tokens.hasMoreTokens()) {
        const XMLCh* t = tokens.nextToken();
        if (t && *t) {
            vector<xstring> tagArray;
            static const XMLCh delims[] = {chDash, chNull};
            XMLStringTokenizer tags(t, delims);
            while (tags.hasMoreTokens())
                tagArray.push_back(tags.nextToken());
            m_defaultRange.insert(langrange_t::value_type(q, tagArray));
            q -= 0.0001f;
        }
    }
}

bool GenericRequest::startLangMatching() const
{
    // This is a no-op except on the first call, to populate the
    // range information to use in matching.
    if (m_langRange.empty()) {
        if (m_langFromClient) {
            string hdr(getLanguageRange());
            char_separator<char> sep1(", "); // tags are split by commas or spaces
            char_separator<char> sep2("; "); // quality is separated by semicolon
            tokenizer< char_separator<char> > tokens(hdr, sep1);
            for (tokenizer< char_separator<char> >::iterator t = tokens.begin(); t != tokens.end(); ++t) {
                string tag = trim_copy(*t);   // handle any surrounding ws
                tokenizer< char_separator<char> > subtokens(tag, sep2);
                tokenizer< char_separator<char> >::iterator s = subtokens.begin();
                if (s != subtokens.end() && *s != "*") {
                    float q = 1.0f;
                    auto_ptr_XMLCh lang((s++)->c_str());

                    // Check for quality tag
                    if (s != subtokens.end() && starts_with(*s, "q=")) {
                        try {
                            q = lexical_cast<float,string>(s->c_str() + 2);
                        }
                        catch (bad_lexical_cast&) {
                            q = 0.0f;
                        }
                    }

                    // Split range into tokens.
                    vector<xstring> tagArray;
                    static const XMLCh delims[] = {chDash, chNull};
                    XMLStringTokenizer tags(lang.get(), delims);
                    const XMLCh* tag;
                    while (tags.hasMoreTokens()) {
                        tag = tags.nextToken();
                        if (*tag != chAsterisk)
                            tagArray.push_back(tag);
                    }

                    if (tagArray.empty())
                        continue;

                    // Adjust q using the server priority list. As long as the supplied q deltas are larger than
                    // factors like .0001, the client settings will always trump ours.
                    if (!m_defaultRange.empty()) {
                        float adj = (m_defaultRange.size() + 1) * 0.0001f;
                        for (langrange_t::const_iterator prio = m_defaultRange.begin(); prio != m_defaultRange.end(); ++prio) {
                            if (prio->second == tagArray) {
                                adj = prio->first;
                                break;
                            }
                        }
                        q -= adj;
                    }
                    m_langRange.insert(langrange_t::value_type(q, tagArray));
                }
            }
        }
        else {
            m_langRange = m_defaultRange;
        }
    }
    
    m_langRangeIter = m_langRange.rbegin();
    return (m_langRangeIter != const_cast<const langrange_t&>(m_langRange).rend());
}

bool GenericRequest::continueLangMatching() const
{
    return (++m_langRangeIter != const_cast<const langrange_t&>(m_langRange).rend());
}

bool GenericRequest::matchLang(const XMLCh* tag) const
{
    if (m_langRangeIter == const_cast<const langrange_t&>(m_langRange).rend())
        return false;

    // To match against a given range, the range has to be built up and then
    // truncated segment by segment to look for a match against the tag.
    // That allows more specific ranges like en-US to match the tag en.
    // The "end" fence tells us how much of the original range to recompose
    // into a hyphenated string, and we stop on a match, or when the fence
    // moves back to the beginning of the array.
    bool match = false;
    vector<xstring>::size_type end = m_langRangeIter->second.size();
    do {
        // Skip single-character private extension separators.
        while (end > 1 && m_langRangeIter->second[end-1].length() <= 1)
            --end;
        // Build a range from 0 to end - 1 of segments.
        xstring compareTo(m_langRangeIter->second[0]);
        for (vector<xstring>::size_type ix = 1; ix <= end - 1; ++ix)
            compareTo = compareTo + chDash + m_langRangeIter->second[ix];
        match = (compareTo.length() > 1 && XMLString::compareIStringASCII(compareTo.c_str(), tag) == 0);
    } while (!match && --end > 0);
    return match;
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

string HTTPRequest::getLanguageRange() const
{
    return getHeader("Accept-Language");
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
