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
 * handler/impl/LogoutHandler.cpp
 *
 * Base class for logout-related handlers.
 */

#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/LogoutHandler.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "util/PathResolver.h"
#include "util/URLEncoder.h"

#include <fstream>
#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

LogoutHandler::LogoutHandler() : m_initiator(true)
{
}

LogoutHandler::~LogoutHandler()
{
}

pair<bool,long> LogoutHandler::run(SPRequest& request, bool isHandler) const
{
    // If this isn't a LogoutInitiator, we only "continue" a notification loop, rather than starting one.
    if (!m_initiator && !request.getParameter("notifying"))
        return make_pair(false,0L);

    // Try another front-channel notification. No extra parameters and the session is implicit.
    return notifyFrontChannel(request);
}

/*
void LogoutHandler::receive(DDF& in, ostream& out)
{
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    if (in["notify"].integer() != 1)
        throw RemotintgException("Unsupported operation.");

    vector<string> sessions;
    DDF s = in["sessions"];
    DDF temp = s.first();
    while (temp.isstring()) {
        sessions.push_back(temp.string());
        temp = s.next();
        //if (notifyBackChannel(*app, in["url"].string(), sessions, in["local"].integer()==1))
            //ret.integer(1);
    }

    out << ret;
}
*/

pair<bool,long> LogoutHandler::notifyFrontChannel(
    SPRequest& request,
    const map<string,string>* params
    ) const
{
    // Index of notification point starts at 0.
    unsigned int index = 0;
    const char* param = request.getParameter("index");
    if (param)
        index = atoi(param);

    // "return" is a backwards-compatible "eventual destination" to go back to after logout completes.
    param = request.getParameter("return");

    // Fetch the next front notification URL and bump the index for the next round trip.
    string loc = request.getNotificationURL(true, index++);
    if (loc.empty())
        return make_pair(false,0L);

    const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();

    // Start with an "action" telling the application what this is about.
    loc = loc + (strchr(loc.c_str(),'?') ? '&' : '?') + "action=logout";

    // Now we create a second URL representing the return location back to us.
    const char* start = request.getRequestURL();
    const char* end = strchr(start, '?');
    string locstr(start, end ? end - start : strlen(start));

    // Add a signal that we're coming back from notification and the next index.
    locstr = locstr + "?notifying=1&index=" + boost::lexical_cast<string>(index);

    // Add return if set.
    if (param)
        locstr = locstr + "&return=" + encoder.encode(param);

    // We preserve anything we're instructed to directly.
    if (params) {
        for (map<string,string>::const_iterator p = params->begin(); p!=params->end(); ++p)
            locstr = locstr + '&' + p->first + '=' + encoder.encode(p->second.c_str());
    }
    else {
        for (vector<string>::const_iterator q = m_preserve.begin(); q!=m_preserve.end(); ++q) {
            param = request.getParameter(q->c_str());
            if (param)
                locstr = locstr + '&' + *q + '=' + encoder.encode(param);
        }
    }

    // Add the notifier's return parameter to the destination location and redirect.
    // This is NOT the same as the return parameter that might be embedded inside it ;-)
    loc = loc + "&return=" + encoder.encode(locstr.c_str());
    return make_pair(true, request.sendRedirect(loc.c_str()));
}

bool LogoutHandler::notifyBackChannel(const SPRequest& request, const vector<string>& sessions, bool local) const
{
    if (sessions.empty()) {
        Category::getInstance(SHIBSP_LOGCAT ".Logout").error("no sessions supplied to back channel notification method");
        return false;
    }

    unsigned int index = 0;
    string endpoint = request.getNotificationURL(false, index++);
    if (endpoint.empty())
        return true;

    if (false) {
#ifndef SHIBSP_LITE
        scoped_ptr<Envelope> env(EnvelopeBuilder::buildEnvelope());
        Body* body = BodyBuilder::buildBody();
        env->setBody(body);
        ElementProxy* msg = new AnyElementImpl(shibspconstants::SHIB2SPNOTIFY_NS, LogoutNotification);
        body->getUnknownXMLObjects().push_back(msg);
        msg->setAttribute(xmltooling::QName(nullptr, _type), local ? _local : _global);
        for (vector<string>::const_iterator s = sessions.begin(); s != sessions.end(); ++s) {
            auto_ptr_XMLCh temp(s->c_str());
            ElementProxy* child = new AnyElementImpl(shibspconstants::SHIB2SPNOTIFY_NS, SessionID);
            child->setTextContent(temp.get());
            msg->getUnknownXMLObjects().push_back(child);
        }

        bool result = true;
        SOAPNotifier soaper;
        while (!endpoint.empty()) {
            try {
                soaper.send(*env, SOAPTransport::Address(application.getId(), application.getId(), endpoint.c_str()));
                delete soaper.receive();
            }
            catch (std::exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT ".Logout").error("error notifying application of logout event: %s", ex.what());
                result = false;
            }
            soaper.reset();
            endpoint = application.getNotificationURL(requestURL, false, index++);
        }
        return result;
#else
        return false;
#endif
    }

/*
    // When not out of process, we remote the back channel work.
    // TODO: remove anyway....
    DDF out,in(m_address.c_str());
    DDFJanitor jin(in), jout(out);
    in.addmember("notify").integer(1);
    //in.addmember("application_id").string(application.getId());
    in.addmember("url").string(request.getRequestURL());
    if (local)
        in.addmember("local").integer(1);
    DDF s = in.addmember("sessions").list();
    for (vector<string>::const_iterator i = sessions.begin(); i!=sessions.end(); ++i) {
        DDF temp = DDF(nullptr).string(i->c_str());
        s.add(temp);
    }
    //out = application.getServiceProvider().getListenerService()->send(in);
    return (out.integer() == 1);
*/
return false;
}
