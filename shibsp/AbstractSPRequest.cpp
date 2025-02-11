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
 * AbstractSPRequest.cpp
 *
 * Abstract base for SPRequest implementations.
 */

#include "internal.h"
#include "exceptions.h"
#include "AbstractSPRequest.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "util/CGIParser.h"
#include "util/Misc.h"

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#ifndef HAVE_STRCASECMP
# define strncasecmp _strnicmp
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace std;

SPRequest::SPRequest()
{
}

SPRequest::~SPRequest()
{
}


AbstractSPRequest::AbstractSPRequest(const char* category)
    : m_log(Category::getInstance(category)),
        m_agent(AgentConfig::getConfig().getAgent()),
        m_mapper(nullptr), m_sessionTried(false), m_session(nullptr)
{
}

AbstractSPRequest::~AbstractSPRequest()
{
    if (m_session)
        m_session->unlock();
    if (m_mapper)
        m_mapper->unlock_shared();
}

const Agent& AbstractSPRequest::getAgent() const
{
    return m_agent;
}

RequestMapper::Settings AbstractSPRequest::getRequestSettings() const
{
    if (!m_mapper) {
        // Map request to application and content settings.
        m_mapper = m_agent.getRequestMapper();
        m_mapper->lock_shared();
        m_settings = m_mapper->getSettings(*this);

        if (m_log.isDebugEnabled()) {
            m_log.debug("mapped %s to %s", getRequestURL(), m_settings.first->getString("applicationId", ""));
        }
    }
    return m_settings;
}

Session* AbstractSPRequest::getSession(bool checkTimeout, bool ignoreAddress, bool cache)
{
    // Only attempt this once.
    if (cache && m_sessionTried)
        return m_session;
    else if (cache)
        m_sessionTried = true;

    // Need address checking and timeout settings.
    time_t timeout = 3600;
    if (checkTimeout || !ignoreAddress) {
        if (checkTimeout) {
            timeout = getRequestSettings().first->getUnsignedInt("timeout", 3600);
        }
        ignoreAddress = !getRequestSettings().first->getBool("consistentAddress", true);
    }

    // The cache will either silently pass a session or nullptr back, or throw an exception out.
    Session* session = getAgent().getSessionCache()->find(
        *this, (ignoreAddress ? nullptr : getRemoteAddr().c_str()), (checkTimeout ? &timeout : nullptr)
        );
    if (cache)
        m_session = session;
    return session;
}

void AbstractSPRequest::setRequestURI(const char* uri)
{
    if (uri)
        m_uri = uri;
    else
        m_uri.clear();
}

const char* AbstractSPRequest::getRequestURI() const
{
    return m_uri.c_str();
}

const char* AbstractSPRequest::getRequestURL() const
{
    if (m_url.empty()) {
        // Compute the full target URL
        int port = getPort();
        const char* scheme = getScheme();
        m_url = string(scheme) + "://" + getHostname();
        if (!isDefaultPort())
            m_url += ":" + boost::lexical_cast<string>(port);
        m_url += m_uri;
    }
    return m_url.c_str();
}

string AbstractSPRequest::getRemoteAddr() const
{
    const char* addr = getRequestSettings().first->getString("REMOTE_ADDR");
    return addr ? getHeader(addr) : "";
}

const char* AbstractSPRequest::getParameter(const char* name) const
{
    if (!m_parser.get())
        m_parser.reset(new CGIParser(*this));

    pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
    return (bounds.first==bounds.second) ? nullptr : bounds.first->second;
}

vector<const char*>::size_type AbstractSPRequest::getParameters(const char* name, vector<const char*>& values) const
{
    if (!m_parser.get())
        m_parser.reset(new CGIParser(*this));

    pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
    while (bounds.first != bounds.second) {
        values.push_back(bounds.first->second);
        ++bounds.first;
    }
    return values.size();
}

string AbstractSPRequest::getCookieName(const char* prefix, time_t* lifetime) const
{
    if (lifetime) {
        *lifetime = getRequestSettings().first->getUnsignedInt("cookieLifetime", 0);
    }

    if (!prefix)
        prefix = "";

    const char* p = getRequestSettings().first->getString("cookieName");
    if (p) {
        return string(prefix) + p;
    }

    return string(prefix); // + getHash(); TODO: uniqueify the cookie name
}

pair<string,const char*> AbstractSPRequest::getCookieNameProps(const char* prefix, time_t* lifetime) const
{
    static const char* defProps="; path=/; HttpOnly";
    static const char* sslProps="; path=/; secure; HttpOnly";

    if (lifetime) {
        *lifetime = getRequestSettings().first->getUnsignedInt("cookieLifetime", 0);
    }

    if (!prefix)
        prefix = "";

    const char* cookieProps = getRequestSettings().first->getString("cookieProps");
    if (!cookieProps || !strcasecmp(cookieProps, "http")) {
        cookieProps = defProps;
    }
    else if (!strcasecmp(cookieProps, "https")) {
        cookieProps = sslProps;
    }

    const char* cookieName = getRequestSettings().first->getString("cookieName");
    if (cookieName) {
        return make_pair(string(prefix) + cookieName, cookieProps);
    }

    // TODO: uniqueify the cookie name
    return make_pair(string(prefix) /* + getHash() */, cookieProps);
}

const char* AbstractSPRequest::getHandlerURL(const char* resource) const
{
    if (!resource)
        resource = getRequestURL();

    if (!m_handlerURL.empty() && resource && !strcmp(getRequestURL(), resource))
        return m_handlerURL.c_str();

    // Check for relative URL.
    string stackresource;
    if (resource && *resource == '/') {
        // Compute a URL to the root of the site and point resource at constructed string.
        int port = getPort();
        const char* scheme = getScheme();
        stackresource = string(scheme) + "://" + getHostname();
        if (!isDefaultPort())
            stackresource += ":" + boost::lexical_cast<string>(port);
        stackresource += resource;
        resource = stackresource.c_str();
    }

    if (!resource || (strncasecmp(resource,"http://",7) && strncasecmp(resource,"https://",8))) {
        throw ConfigurationException("Target resource was not an absolute URL.");
    }

    bool ssl_only = getRequestSettings().first->getBool("handlerSSL", true);
    const char* handler = getRequestSettings().first->getString("handlerURL", "/Shibboleth.sso");

    if (*handler != '/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)) {
        throw ConfigurationException(string("Invalid handlerURL property: ") + handler);
    }

    // The "handlerURL" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler
    //
    // note: if ssl_only is true, make sure the protocol is https

    const char* path = nullptr;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon = strchr(prot, ':');
    colon += 3;
    const char* slash = strchr(colon, '/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store in member.
    if (ssl_only)
        m_handlerURL.assign("https://");
    else
        m_handlerURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the handler URL
    m_handlerURL += host + path;
    return m_handlerURL.c_str();
}

string AbstractSPRequest::getNotificationURL(bool front, unsigned int index) const
{
    // We have to process the underlying setting each call to this method unfortunately.
    const char* rawlocs = getRequestSettings().first->getString(front ? "frontNotifyURLs" : "backNotifyURLs");
    vector<string> locs;
    split_to_container(locs, rawlocs);

    if (index >= locs.size())
        return string();

    const char* resource = getRequestURL();
    if (!resource || (strncasecmp(resource,"http://", 7) && strncasecmp(resource,"https://", 8))) {
        throw ConfigurationException("Request URL was not absolute.");
    }

    const char* handler = locs[index].c_str();

    // Should never happen...
    if (!handler || (*handler!='/' && strncasecmp(handler, "http:", 5) && strncasecmp(handler, "https:", 6))) {
        throw ConfigurationException("Invalid Location property in Notify element");
    }

    // The "Location" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler

    const char* path = nullptr;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store.
    string notifyURL(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the URL
    notifyURL += host + path;
    return notifyURL;
}

void AbstractSPRequest::limitRedirect(const char* url) const
{
    if (!url || *url == '/')
        return;

    enum {
        REDIRECT_LIMIT_NONE,
        REDIRECT_LIMIT_EXACT,
        REDIRECT_LIMIT_HOST,
        REDIRECT_LIMIT_ALLOW,
        REDIRECT_LIMIT_EXACT_ALLOW,
        REDIRECT_LIMIT_HOST_ALLOW
    } redirectLimit;

    // Derive the active rule.
    vector<string> redirectAllow;
    const char* prop = getRequestSettings().first->getString("redirectLimit", "exact");
    if (!strcmp(prop, "none")) {
        redirectLimit = REDIRECT_LIMIT_NONE;
    }
    else if (!strcmp(prop, "exact")) {
        redirectLimit = REDIRECT_LIMIT_EXACT;
    }
    else if (!strcmp(prop, "host")) {
        redirectLimit = REDIRECT_LIMIT_HOST;
    }
    else {
        if (!strcmp(prop, "exact+allow")) {
            redirectLimit = REDIRECT_LIMIT_EXACT_ALLOW;
        }
        else if (!strcmp(prop, "host+allow")) {
            redirectLimit = REDIRECT_LIMIT_HOST_ALLOW;
        }
        else if (!strcmp(prop, "allow")) {
            redirectLimit = REDIRECT_LIMIT_ALLOW;
        }
        else {
            m_log.error("unrecognized redirectLimit setting (%s), falling back to 'exact' ", prop);
        }
        prop = getRequestSettings().first->getString("redirectAllow");
        if (prop) {
            split_to_container(redirectAllow, prop);
        }
    }

    if (redirectLimit != REDIRECT_LIMIT_NONE) {

        // This is ugly, but the purpose is to prevent blocking legitimate redirects
        // that lack a trailing slash after the hostname. If there are fewer than 3
        // slashes, we assume the hostname wasn't terminated.
        string urlcopy(url);
        if (count(urlcopy.begin(), urlcopy.end(), '/') < 3) {
            urlcopy += '/';
        }

        vector<string> allowlist;
        if (redirectLimit == REDIRECT_LIMIT_EXACT || redirectLimit == REDIRECT_LIMIT_EXACT_ALLOW) {
            // Scheme and hostname have to match.
            if (isDefaultPort()) {
                allowlist.push_back(string(getScheme()) + "://" + getHostname() + '/');
            }
            allowlist.push_back(string(getScheme()) + "://" + getHostname() + ':' + boost::lexical_cast<string>(getPort()) + '/');
        }
        else if (redirectLimit == REDIRECT_LIMIT_HOST || redirectLimit == REDIRECT_LIMIT_HOST_ALLOW) {
            // Allow any scheme or port.
            allowlist.push_back(string("https://") + getHostname() + '/');
            allowlist.push_back(string("http://") + getHostname() + '/');
            allowlist.push_back(string("https://") + getHostname() + ':');
            allowlist.push_back(string("http://") + getHostname() + ':');
        }

        if (!allowlist.empty()) {
            for (const string& s : allowlist) {
                if (boost::istarts_with(urlcopy, s)) {
                    return;
                }
            }
        }

        if (!redirectAllow.empty()) {
            for (const string& s : redirectAllow) {
                if (boost::istarts_with(urlcopy, s)) {
                    return;
                }
            }
        }

        m_log.warn("redirectLimit policy enforced, blocked redirect to (%s)", url);
        throw AgentException("Blocked unacceptable redirect location.");
    }
}

string AbstractSPRequest::getSecureHeader(const char* name) const
{
    return getHeader(name);
}

void AbstractSPRequest::setAuthType(const char* authtype)
{

}

const char* AbstractSPRequest::getCookie(const char* name) const
{
    bool sameSiteFallback = getRequestSettings().first->getBool("sameSiteFallback", false);
    return HTTPRequest::getCookie(name, sameSiteFallback);
}

void AbstractSPRequest::setCookie(const char* name, const char* value, time_t expires, samesite_t sameSite)
{
    bool sameSiteFallback = false;
    if (sameSite == SAMESITE_NONE) {
        sameSiteFallback = getRequestSettings().first->getBool("sameSiteFallback", false);
    }

    static const char* defProps="; path=/; HttpOnly";
    static const char* sslProps="; path=/; secure; HttpOnly";

    const char* cookieProps = getRequestSettings().first->getString("cookieProps", defProps);
    if (!strcmp(cookieProps, "https"))
        cookieProps = sslProps;
    else if (!strcmp(cookieProps, "http"))
        cookieProps = defProps;

    string decoratedValue(value ? value : "");
    if (!value) {
        decoratedValue += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
    }
    decoratedValue += cookieProps;
    HTTPResponse::setCookie(name, decoratedValue.c_str(), expires, sameSite, sameSiteFallback);
}

void AbstractSPRequest::log(Priority::Value level, const std::string& msg) const
{
    m_log.log(level, msg);
}

bool AbstractSPRequest::isPriorityEnabled(Priority::Value level) const
{
    return m_log.isPriorityEnabled(level);
}
