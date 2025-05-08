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
#include "util/PropertySet.h"

#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

CookieManager::CookieManager(const char* defaultName)
    : m_defaultName(defaultName),
        m_overrideProperty(nullptr),
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
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    string encode(request.getAgent().getID());
    encode += request.getRequestSettings().first->getString("applicationId", "default");
    cookieName += '_';
    for (const char* ch = encode.c_str(); *ch; ++ch) {
        cookieName += (DIGITS[((unsigned char)(0xF0 & *ch)) >> 4 ]);
        cookieName += (DIGITS[0x0F & *ch]);
    }
    
    return cookieName;
}

void CookieManager::outputHeader(SPRequest& request, int maxAge) const
{
    string header(computeCookieName(request));
    header += "; max-age=";
    try {
        header += boost::lexical_cast<string>(maxAge);
    }
    catch (boost::bad_lexical_cast&) {
        header += "-1";
    }
    if (!m_path.empty()) {
        header += "; path=";
        header += m_path;
    }
    if (!m_domain.empty()) {
        header += "; domain=";
        header += m_domain;
    }
    if (m_secure) {
        header += "; secure=1";
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
    outputHeader(request, request.getRequestSettings().first->getInt("cookieMaxAge", m_maxAge));
}

void CookieManager::unsetCookie(SPRequest& request) const
{
    outputHeader(request, 0);
}
