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
 * io/impl/CookieManager.cpp
 * 
 * Manages reading and writing HTTP cookies.
 */

#include "internal.h"

#include "Agent.h"
#include "SPRequest.h"
#include "RequestMapper.h"
#include "io/CookieManager.h"
#include "util/Misc.h"
#include "util/PropertySet.h"

#include <boost/lexical_cast.hpp>
#include <string.h>

using namespace shibsp;
using namespace std;

#ifndef HAVE_STRCASECMP
# define strncasecmp _strnicmp
# define strcasecmp _stricmp
#endif

CookieManager::CookieManager(const char* defaultName)
    : m_defaultName(defaultName),
        m_appSpecific(false),
        m_path("/"),
        m_maxAge(-1),
        m_secure(true),
        m_httpOnly(true),
        m_sameSiteValue(SAMESITE_ABSENT)
{
}

CookieManager::~CookieManager()
{
}

void CookieManager::setCookieNamePolicy(const char* overridePropertyName, bool appSpecific)
{
    m_overrideProperty = overridePropertyName ? overridePropertyName : nullptr;
    m_appSpecific = appSpecific;
}

void CookieManager::setPath(const char* path)
{
    m_path = path ? path : "";
}

void CookieManager::setDomain(const char* domain)
{
    m_domain = domain ? domain : "";
}

void CookieManager::setMaxAge(int maxAge)
{
    m_maxAge = maxAge;
}

void CookieManager::setSecure(bool secure)
{
    m_secure = secure;
}

void CookieManager::setHttpOnly(bool httpOnly)
{
    m_httpOnly = httpOnly;
}

void CookieManager::setSameSite(const char* value)
{
    if (value) {
        if (!strcasecmp(value, "None")) {
            setSameSite(SAMESITE_NONE);
        }
        else if (!strcasecmp(value, "Lax")) {
            setSameSite(SAMESITE_LAX);
        }
        else if (!strcasecmp(value, "Strict")) {
            setSameSite(SAMESITE_STRICT);
        }
        else {
            setSameSite(SAMESITE_ABSENT);
        }
    }
    else {
        setSameSite(SAMESITE_ABSENT);
    }
}

void CookieManager::setSameSite(samesite_t value)
{
    m_sameSiteValue = value;
}

string CookieManager::computeCookieName(const SPRequest& request) const
{
    // If not app-specific, return the overridden or default name unadorned.
    if (!m_appSpecific) {
        if (m_overrideProperty.empty()) {
            return m_defaultName;
        }
        const char* overridden = request.getRequestSettings().first->getString(m_overrideProperty.c_str());
        return overridden ? string(overridden) : m_defaultName;
    }

    // Otherwise, the base name is the default or the overridden name.
    string cookieName(request.getRequestSettings().first->getString(m_overrideProperty.c_str(), m_defaultName.c_str()));

    // This is just a hex-encode to avoid a dependency on a hashing API.
    string decoration = request.getRequestSettings().first->getString(
        RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT);

    return cookieName + '_' + hex_encode(decoration);
}

void CookieManager::outputHeader(SPRequest& request, const char* value, int maxAge) const
{
    string header(computeCookieName(request));
    header += '=';
    if (value) {
        header += value;
    }
    if (maxAge >= 0) {
        try {
            string s = boost::lexical_cast<string>(maxAge);
            header += "; Max-Age=" + s;
        }
        catch (boost::bad_lexical_cast&) {
        }
    }
    if (!m_path.empty()) {
        header += "; Path=";
        header += m_path;
    }
    if (!m_domain.empty()) {
        header += "; Domain=";
        header += m_domain;
    }
    if (m_secure) {
        header += "; Secure=1";
    }
    if (m_httpOnly) {
        header += "; HttpOnly=1";
    }
    if (m_sameSiteValue != SAMESITE_ABSENT) {
        switch (m_sameSiteValue) {
            case SAMESITE_NONE:
                header += "; SameSite=None";
                break;
            case SAMESITE_LAX:
                header += "; SameSite=Lax";
                break;
            case SAMESITE_STRICT:
                header += "; SameSite=Strict";
                break;
            default:
                break;
        }
    }

    request.setResponseHeader("Set-Cookie", header.c_str());
}

const char* CookieManager::getCookieValue(const SPRequest& request) const
{
    const auto& cookies = request.getCookies();
    const auto& entry = cookies.find(computeCookieName(request));
    return entry == cookies.end() ? nullptr : entry->second.c_str();
}

void CookieManager::setCookie(SPRequest& request, const char* value) const
{
    outputHeader(request, value, request.getRequestSettings().first->getInt(RequestMapper::COOKIE_MAXAGE_PROP_NAME, m_maxAge));
}

void CookieManager::unsetCookie(SPRequest& request) const
{
    outputHeader(request, nullptr, 0);
}
