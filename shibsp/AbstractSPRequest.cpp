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
#include "Application.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "logging/Category.h"
#include "util/CGIParser.h"

#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

SPRequest::SPRequest()
{
}

SPRequest::~SPRequest()
{
}


AbstractSPRequest::AbstractSPRequest(const char* category)
    : m_log(Category::getInstance(category)), m_sp(SPConfig::getConfig().getServiceProvider()),
        m_mapper(nullptr), m_app(nullptr), m_sessionTried(false), m_session(nullptr)
{
    if (m_sp)
        m_sp->lock();
}

AbstractSPRequest::~AbstractSPRequest()
{
    if (m_session)
        m_session->unlock();
    if (m_mapper)
        m_mapper->unlock_shared();
    if (m_sp)
        m_sp->unlock();
}

const ServiceProvider& AbstractSPRequest::getServiceProvider() const
{
    return *m_sp;
}

RequestMapper::Settings AbstractSPRequest::getRequestSettings() const
{
    if (!m_mapper) {
        // Map request to application and content settings.
        m_mapper = m_sp->getRequestMapper();
        m_mapper->lock_shared();
        m_settings = m_mapper->getSettings(*this);

/*
        if (reinterpret_cast<Category*>(m_log)->isDebugEnabled()) {
            reinterpret_cast<Category*>(m_log)->debug(
                "mapped %s to %s", getRequestURL(), m_settings.first->getString("applicationId").second
                );
        }
    */
    }
    return m_settings;
}

const Application& AbstractSPRequest::getApplication() const
{
    if (!m_app) {
        // Now find the application from the URL settings
        m_app = m_sp->getApplication(getRequestSettings().first->getString("applicationId"));
        if (!m_app)
            throw ConfigurationException("Unable to map non-default applicationId to an ApplicationOverride, check configuration.");
    }
    return *m_app;
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
        const PropertySet* props = getApplication().getPropertySet("Sessions");
        if (props) {
            if (checkTimeout) {
                pair<bool,unsigned int> p = props->getUnsignedInt("timeout");
                if (p.first)
                    timeout = p.second;
            }
            pair<bool,bool> pcheck = props->getBool("consistentAddress");
            if (pcheck.first)
                ignoreAddress = !pcheck.second;
        }
    }

    // The cache will either silently pass a session or nullptr back, or throw an exception out.
    Session* session = getServiceProvider().getSessionCache()->find(
        getApplication(), *this, (ignoreAddress ? nullptr : getRemoteAddr().c_str()), (checkTimeout ? &timeout : nullptr)
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

#ifdef HAVE_STRCASECMP
    if (!resource || (strncasecmp(resource,"http://",7) && strncasecmp(resource,"https://",8)))
#else
    if (!resource || (strnicmp(resource,"http://",7) && strnicmp(resource,"https://",8)))
#endif
        throw ConfigurationException("Target resource was not an absolute URL.");

    bool ssl_only = true;
    const char* handler = nullptr;
    const PropertySet* props = getApplication().getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> p = props->getBool("handlerSSL");
        if (p.first)
            ssl_only = p.second;
        pair<bool,const char*> p2 = props->getString("handlerURL");
        if (p2.first)
            handler = p2.second;
    }

    if (!handler) {
        handler = "/Shibboleth.sso";
    }
    else if (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)) {
        throw ConfigurationException(
            string("Invalid handlerURL property in <Sessions> element for Application ") + m_app->getId()
            );
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

string AbstractSPRequest::getSecureHeader(const char* name) const
{
    return getHeader(name);
}

void AbstractSPRequest::setAuthType(const char* authtype)
{

}

const char* AbstractSPRequest::getCookie(const char* name) const
{
    pair<bool, bool> sameSiteFallback = pair<bool, bool>(false, false);
    const PropertySet* props = getApplication().getPropertySet("Sessions");
    if (props) {
        sameSiteFallback = props->getBool("sameSiteFallback");
    }
    return HTTPRequest::getCookie(name, sameSiteFallback.first && sameSiteFallback.second);
}

void AbstractSPRequest::setCookie(const char* name, const char* value, time_t expires, samesite_t sameSite)
{
    static const char* defProps="; path=/; HttpOnly";
    static const char* sslProps="; path=/; secure; HttpOnly";

    const char* cookieProps = defProps;
    pair<bool,bool> sameSiteFallback = pair<bool,bool>(false, false);

    const PropertySet* props = getApplication().getPropertySet("Sessions");
    if (props) {
        if (sameSite == SAMESITE_NONE) {
            sameSiteFallback = props->getBool("sameSiteFallback");
        }

        pair<bool, const char*> p = props->getString("cookieProps");
        if (p.first) {
            if (!strcmp(p.second, "https"))
                cookieProps = sslProps;
            else if (strcmp(p.second, "http"))
                cookieProps = p.second;
        }
    }

    if (cookieProps) {
        string decoratedValue(value ? value : "");
        if (!value) {
            decoratedValue += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
        }
        decoratedValue += cookieProps;
        HTTPResponse::setCookie(name, decoratedValue.c_str(), expires, sameSite,
            sameSiteFallback.first && sameSiteFallback.second);
    }
    else {
        HTTPResponse::setCookie(name, value, expires, sameSite,
            sameSiteFallback.first && sameSiteFallback.second);
    }
}

void AbstractSPRequest::log(Priority::Value level, const std::string& msg) const
{
    m_log.log(level, msg);
}

bool AbstractSPRequest::isPriorityEnabled(Priority::Value level) const
{
    return m_log.isPriorityEnabled(level);
}
