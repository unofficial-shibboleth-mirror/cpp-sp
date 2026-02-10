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
#include "logging/impl/StringUtil.h"
#include "session/SessionCache.h"
#include "util/CGIParser.h"
#include "util/Misc.h"

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>

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
        m_mapper(nullptr)
{
}

AbstractSPRequest::~AbstractSPRequest()
{
    // TODO: wrap this in a proper lock wrapper?
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

bool AbstractSPRequest::isUseHeaders() const {
    return getRequestSettings().first->getBool(
        RequestMapper::USE_HEADERS_PROP_NAME, RequestMapper::USE_HEADERS_PROP_DEFAULT);
}
bool AbstractSPRequest::isUseVariables() const {
    return getRequestSettings().first->getBool(
        RequestMapper::USE_VARIABLES_PROP_NAME, RequestMapper::USE_VARIABLES_PROP_DEFAULT);
}

unique_lock<Session> AbstractSPRequest::getSession(bool checkTimeout, bool ignoreAddress)
{
    return getAgent().getSessionCache()->find(*this, checkTimeout, ignoreAddress);
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
    const char* addr = getRequestSettings().first->getString(RequestMapper::REMOTE_ADDR_PROP_NAME);
    return addr ? getHeader(addr) : "";
}

const char* AbstractSPRequest::getParameter(const char* name) const
{
    if (!m_parser) {
        m_parser.reset(new CGIParser(*this));
    }

    pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
    return (bounds.first==bounds.second) ? nullptr : bounds.first->second;
}

vector<const char*>::size_type AbstractSPRequest::getParameters(const char* name, vector<const char*>& values) const
{
    if (!m_parser) {
        m_parser.reset(new CGIParser(*this));
    }

    pair<CGIParser::walker,CGIParser::walker> bounds = m_parser->getParameters(name);
    while (bounds.first != bounds.second) {
        values.push_back(bounds.first->second);
        ++bounds.first;
    }
    return values.size();
}

const std::map<std::string,std::string>& AbstractSPRequest::getCookies() const
{
    if (m_cookieMap.empty()) {
        // Split cookie name/value pairs on semicolon using tokenizer for iteration.
        string cookies = getHeader("Cookie");
        if (!cookies.empty()) {
            boost::tokenizer<boost::char_separator<char>> nvpairs(cookies, boost::char_separator<char>(";"));

            // Holds each cookie name/value pair while splitting.
            vector<string> nvpair;

            for (const auto& cookie : nvpairs) {
                // Split on '=' to separate name/value.
                nvpair.clear();
                boost::split(nvpair, cookie, boost::is_any_of("="));

                if (nvpair.size() == 2) {
                    boost::trim(nvpair[0]);
                    m_cookieMap[nvpair[0]] = nvpair[1];
                }
            }
        }
    }
    return m_cookieMap;
}

const char* AbstractSPRequest::getHandlerURL(const char* resource) const
{
    if (!resource) {
        resource = getRequestURL();
    }

    if (!m_handlerURL.empty() && resource && !strcmp(getRequestURL(), resource)) {
        return m_handlerURL.c_str();
    }

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

    bool ssl_only = getRequestSettings().first->getBool(
        RequestMapper::HANDLER_SSL_PROP_NAME, RequestMapper::HANDLER_SSL_PROP_DEFAULT);
    const char* handler = getRequestSettings().first->getString(
        RequestMapper::HANDLER_URL_PROP_NAME, RequestMapper::HANDLER_URL_PROP_DEFAULT);

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
    if (!path) {
        path = slash;
    }

    // Compute the actual protocol and store in member.
    if (ssl_only) {
        m_handlerURL.assign("https://");
    }
    else {
        m_handlerURL.assign(prot, colon-prot);
    }

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
    // We have to process the underlying setting each call to this method for now.
    // Given how rarely it would be used, not a big issue.
    vector<string> locs;
    split_to_container(locs, getRequestSettings().first->getString(RequestMapper::LOGOUT_NOTIFY_PROP_NAME));

    if (index >= locs.size()) {
        return string();
    }

    const char* resource = getRequestURL();
    if (!resource || (strncasecmp(resource,"http://", 7) && strncasecmp(resource,"https://", 8))) {
        throw ConfigurationException("Request URL was not absolute.");
    }

    const char* handler = locs[index].c_str();

    // Should never happen...
    if (!handler || (*handler!='/' && strncasecmp(handler, "http:", 5) && strncasecmp(handler, "https:", 6))) {
        throw ConfigurationException("Invalid URL in logoutNotify setting.");
    }

    // The location can be in one of three formats:
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
    if (!path) {
        path = slash;
    }

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
    // TODO: come up with some way to optmize/cache this if possible.

    if (!url || *url == '/') {
        return;
    }

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
    const char* prop = getRequestSettings().first->getString(
        RequestMapper::REDIRECT_LIMIT_PROP_NAME, RequestMapper::REDIRECT_LIMIT_PROP_DEFAULT);
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
            error("unrecognized redirectLimit setting (%s), falling back to 'exact' ", prop);
        }
        prop = getRequestSettings().first->getString(RequestMapper::REDIRECT_ALLOW_PROP_NAME);
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

        warn("%s policy enforced, blocked redirect to (%s)", RequestMapper::REDIRECT_LIMIT_PROP_NAME, url);
        throw AgentException("Blocked unacceptable redirect location.");
    }
}

string AbstractSPRequest::getSecureHeader(const char* name) const
{
    return getHeader(name);
}

string AbstractSPRequest::getCGINameForHeader(const char* name) const
{
    string cgiversion("HTTP_");
    const char* pch = name;
    while (*pch) {
        cgiversion += (isalnum(*pch) ? toupper(*pch) : '_');
        pch++;
    }
    return cgiversion;
}

void AbstractSPRequest::setAuthType(const char* authtype)
{
}

const char* AbstractSPRequest::getLogContext() const{
    return nullptr;
}

void AbstractSPRequest::log(Priority::Value level, const exception& e) const
{
    const AgentException* rich_ex = dynamic_cast<const AgentException*>(&e);
    if (rich_ex) {
        ostringstream msg;
        msg << e.what() << " [";

        // Dump properties and status code.
        if (rich_ex->getStatusCode() != 0) {
            msg << "status=" << rich_ex->getStatusCode();
        }

        for (const auto& prop : rich_ex->getProperties()) {
            msg << ", " << prop.first << '=' << prop.second;
        }

        msg << ']';

        log(level, msg.str());
    }
    else {
        log(level, e.what());
    }
}

void AbstractSPRequest::log(Priority::Value level, const std::string& msg) const
{
    if (isPriorityEnabled(level)) {
        const char* ctx = getLogContext();
        if (ctx) {
            m_log.log(level, "%s %s", ctx, msg.c_str());
        }
        else {
            m_log.log(level, msg);
        }
    }
}

void AbstractSPRequest::log(Priority::Value level, const char* formatString, va_list args) const
{
    if (isPriorityEnabled(level)) {
        const char* ctx = getLogContext();
        if (ctx) {
            string msg = StringUtil::vform(formatString, args);
            m_log.log(level, "%s %s", ctx, msg.c_str());
        }
        else {
            m_log.logva(level, formatString, args);
        }
    }
}

bool AbstractSPRequest::isPriorityEnabled(Priority::Value level) const
{
    return m_log.isPriorityEnabled(level);
}

void SPRequest::debug(const string& msg) const
{
    log(Priority::SHIB_DEBUG, msg);
}

void SPRequest::info(const string& msg) const
{
    log(Priority::SHIB_INFO, msg);
}

void SPRequest::warn(const string& msg) const
{
    log(Priority::SHIB_WARN, msg);
}

void SPRequest::error(const string& msg) const
{
    log(Priority::SHIB_ERROR, msg);
}

void SPRequest::crit(const string& msg) const
{
    log(Priority::SHIB_CRIT, msg);
}

void SPRequest::debug(const char* formatString, ...) const
{
    if (isPriorityEnabled(Priority::SHIB_DEBUG)) {
        va_list va;
        va_start(va, formatString);
        log(Priority::SHIB_DEBUG, formatString, va);
        va_end(va);
    }
}

void SPRequest::info(const char* formatString, ...) const
{
    if (isPriorityEnabled(Priority::SHIB_INFO)) {
        va_list va;
        va_start(va, formatString);
        log(Priority::SHIB_INFO, formatString, va);
        va_end(va);
    }
}

void SPRequest::warn(const char* formatString, ...) const
{
    if (isPriorityEnabled(Priority::SHIB_WARN)) {
        va_list va;
        va_start(va, formatString);
        log(Priority::SHIB_WARN, formatString, va);
        va_end(va);
    }
}

void SPRequest::error(const char* formatString, ...) const
{
    if (isPriorityEnabled(Priority::SHIB_ERROR)) {
        va_list va;
        va_start(va, formatString);
        log(Priority::SHIB_ERROR, formatString, va);
        va_end(va);
    }
}

void SPRequest::crit(const char* formatString, ...) const
{
    if (isPriorityEnabled(Priority::SHIB_CRIT)) {
        va_list va;
        va_start(va, formatString);
        log(Priority::SHIB_CRIT, formatString, va);
        va_end(va);
    }
}
