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
 * handler/impl/RemotedHandler.cpp
 * 
 * Base class for handlers that need SP request/response layer to be remoted. 
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/RemotedHandler.h"

#include <algorithm>
#include <sstream>

using namespace shibsp;
using namespace std;

#ifndef SHIBSP_LITE

void RemotedResponse::setCookie(const char* name, const char* value, time_t expires, samesite_t sameSite)
{
    static const char* defProps="; path=/; HttpOnly";
    static const char* sslProps="; path=/; secure; HttpOnly";

    const char* cookieProps = defProps;
    pair<bool,bool> sameSiteFallback = pair<bool,bool>(false, false);

    const PropertySet* props = m_app ? m_app->getPropertySet("Sessions") : nullptr;
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

#endif

set<string> RemotedHandler::m_remotedHeaders;

RemotedHandler::RemotedHandler()
{
}

RemotedHandler::~RemotedHandler()
{
}

void RemotedHandler::addRemotedHeader(const char* header)
{
    m_remotedHeaders.insert(header);
}

DDF RemotedHandler::send(const SPRequest& request, DDF& in) const
{
    // Capture and forward entityIDSelf content setting, if set.
    const char* entityID = request.getRequestSettings().first->getString("entityIDSelf");
    if (entityID) {
        string s(entityID);
        string::size_type pos = s.find("$hostname");
        if (pos != string::npos)
            s.replace(pos, 9, request.getHostname());
        in.addmember("_mapped.entityID").string(s.c_str());
    }

    //return request.getServiceProvider().getListenerService()->send(in);
}

DDF RemotedHandler::wrap(const SPRequest& request, const vector<string>* headers, bool certs) const
{
    DDF in = DDF(m_address.c_str()).structure();
    in.addmember("scheme").string(request.getScheme());
    in.addmember("hostname").unsafe_string(request.getHostname());
    in.addmember("port").integer(request.getPort());
    in.addmember("content_type").string(request.getContentType().c_str());
    in.addmember("body").string(request.getRequestBody());
    in.addmember("content_length").integer(request.getContentLength());
    in.addmember("remote_user").string(request.getRemoteUser().c_str());
    in.addmember("client_addr").string(request.getRemoteAddr().c_str());
    in.addmember("method").string(request.getMethod());
    in.addmember("uri").unsafe_string(request.getRequestURI());
    in.addmember("url").unsafe_string(request.getRequestURL());
    in.addmember("query").string(request.getQueryString());

    if (headers || !m_remotedHeaders.empty()) {
        string hdr;
        DDF hin = in.addmember("headers").structure();
        if (headers) {
            for (vector<string>::const_iterator h = headers->begin(); h != headers->end(); ++h) {
                hdr = request.getHeader(h->c_str());
                if (!hdr.empty())
                    hin.addmember(h->c_str()).unsafe_string(hdr.c_str());
            }
        }
        for (set<string>::const_iterator hh = m_remotedHeaders.begin(); hh != m_remotedHeaders.end(); ++hh) {
            hdr = request.getHeader(hh->c_str());
            if (!hdr.empty())
                hin.addmember(hh->c_str()).unsafe_string(hdr.c_str());
        }
    }

    return in;
}

pair<bool,long> RemotedHandler::unwrap(SPRequest& request, DDF& out) const
{
    DDF h = out["headers"];
    DDF hdr = h.first();
    while (hdr.isstring()) {
#ifdef HAVE_STRCASECMP
        if (!strcasecmp(hdr.name(), "Content-Type"))
#else
        if (!stricmp(hdr.name(), "Content-Type"))
#endif
            request.setContentType(hdr.string());
        else
            request.setResponseHeader(hdr.name(), hdr.string());
        hdr = h.next();
    }
    h = out["redirect"];
    if (h.isstring())
        return make_pair(true, request.sendRedirect(h.string()));
    h = out["response"];
    if (h.isstruct()) {
        const char* data = h["data"].string();
        if (data) {
            istringstream s(data);
            return make_pair(true, request.sendResponse(s, h["status"].integer()));
        }
    }
    return make_pair(false, 0L);
}
