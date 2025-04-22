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
 * handler/impl/SessionHandler.cpp
 *
 * Handler for dumping information about an active session.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "attribute/AttributeConfiguration.h"
#include "handler/SecuredHandler.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "util/Date.h"

#include <ctime>
#include <sstream>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    class SHIBSP_API SessionHandler : public SecuredHandler
    {
    public:
        SessionHandler(const ptree& pt);
        virtual ~SessionHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        pair<bool,long> doHTML(SPRequest& request) const;
        pair<bool,long> doJSON(SPRequest& request) const;

        bool m_values;
        string m_contentType;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL SessionHandlerFactory(const pair<ptree&,const char*>& p, bool)
    {
        return new SessionHandler(p.first);
    }

};

SessionHandler::SessionHandler(const ptree& pt)
    : SecuredHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".Handler.Session")), m_values(false)
{
    m_contentType = getString("contentType", "");
    if (!m_contentType.empty() && m_contentType != "application/json" && m_contentType != "text/html")
        throw ConfigurationException("Unsupported contentType property in Session Handler configuration.");

    m_values = getBool("showAttributeValues", false);
}

namespace {
    static ostream& json_safe(ostream& os, const char* buf)
    {
        os << '"';
        for (; *buf; ++buf) {
            switch (*buf) {
                case '\\':
                case '"':
                    os << '\\';
                    os << *buf;
                    break;
                case '\b':
                    os << "\\b";
                    break;
                case '\t':
                    os << "\\t";
                    break;
                case '\n':
                    os << "\\n";
                    break;
                case '\f':
                    os << "\\f";
                    break;
                case '\r':
                    os << "\\r";
                    break;
                default:
                    os << *buf;
            }
        }
        os << '"';
        return os;
    }
};

pair<bool,long> SessionHandler::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");

    if (m_contentType == "application/json") {
        request.setContentType(m_contentType.c_str());
        return doJSON(request);
    }
    request.setContentType("text/html; charset=UTF-8");
    return doHTML(request);
}

pair<bool,long> SessionHandler::doJSON(SPRequest& request) const
{
    stringstream s;

    Session* session = nullptr;
    try {
        session = request.getSession(); // caches the locked session in the request so it's unlocked automatically
        if (!session) {
            s << "{}" << endl;
            return make_pair(true, request.sendResponse(s));
        }
    }
    catch (exception& ex) {
        m_log.info("exception accessing user session: %s", ex.what());
        s << "{}" << endl;
        return make_pair(true, request.sendError(s));
    }

    s << "{ ";
    s << "\"expiration\": ";
    s << ((session->getCreation() + request.getRequestSettings().first->getUnsignedInt("lifetime", 28800) - time(nullptr)) / 60);

    /*
        attributes: [ { "name": "foo", "values" : count } ]

        attributes: [
            { "name": "foo", "values": [ "val", "val" ] }
        ]
    */

    const map<string,DDF>& attributes = session->getAttributes();
    if (!attributes.empty()) {
        s << ", \"attributes\": [ ";
        string key;
        int count=0;
        for (map<string,DDF>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
            if (a->first != key) {
                // We're starting a new attribute.
                if (a != attributes.begin()) {
                    // Need to close out the previous.
                    if (m_values) {
                        s << " ] }, ";
                    }
                    else {
                        s << ", \"values\": " << count << " }, ";
                        count = 0;
                    }
                }
                s << "{ \"name\": ";
                json_safe(s, a->first.c_str());
            }

            if (m_values) {
                bool first = true;
                DDF val = const_cast<DDF&>(a->second).first();
                while (!val.isnull()) {
                    if (!first || a->first == key) {
                        s << ", ";
                    }
                    else {
                        s << ", \"values\": [ ";
                    }
                    json_safe(s, val.string());

                    val = const_cast<DDF&>(a->second).next();
                    first = false;
                }
            }
            else {
                count += a->second.integer();
            }
            key = a->first;
        }

        if (m_values)
            s << " ] } ";
        else
            s << ", \"values\": " << count << " }";
        s << " ]";
    }

    s << " }" << endl;
    return make_pair(true, request.sendResponse(s));
}

pair<bool,long> SessionHandler::doHTML(SPRequest& request) const
{
    // Default delimiter is semicolon but is configurable.
    const char* delim = request.getAgent().getAttributeConfiguration(
        request.getRequestSettings().first->getString("attributeConfigID")
        ).getString("attributeValueDelimiter", ";");
    size_t delim_len = strlen(delim);

    stringstream s;
    s << "<html><head><title>Session Summary</title></head><body><pre>" << endl;

    Session* session = nullptr;
    try {
        session = request.getSession(); // caches the locked session in the request so it's unlocked automatically
        if (!session) {
            s << "A valid session was not found.</pre></body></html>" << endl;
            return make_pair(true, request.sendResponse(s));
        }
    }
    catch (exception& ex) {
        s << "Exception while retrieving active session:" << endl
            << '\t' << ex.what() << "</pre></body></html>" << endl;
        return make_pair(true, request.sendResponse(s));
    }

    s << "<u>Miscellaneous</u>" << endl;

    s << "<strong>Session Expiration (barring inactivity):</strong> ";
    s << ((session->getCreation() + request.getRequestSettings().first->getUnsignedInt("lifetime", 28800) - time(nullptr)) / 60) << " minute(s)" << endl;
    s << endl << "<u>Attributes</u>" << endl;

    string key;
    int count=0;
    const map<string,DDF>& attributes = session->getAttributes();
    for (map<string,DDF>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
        if (a->first != key) {
            if (a != attributes.begin()) {
                if (m_values)
                    s << endl;
                else {
                    s << count << " value(s)" << endl;
                    count = 0;
                }
            }
            s << "<strong>" << a->first << "</strong>: ";
        }

        if (m_values) {
            bool first = true;
            DDF val = const_cast<DDF&>(a->second).first();
            while (!val.isnull()) {
                if (!first || a->first == key) {
                    s << delim;
                }
                string serialized(val.string());
                string::size_type pos = serialized.find(delim, string::size_type(0));
                if (pos != string::npos) {
                    for (; pos != string::npos; pos = serialized.find(delim, pos)) {
                        serialized.insert(pos, "\\");
                        pos += delim_len + 1;
                    }
                    s << serialized;
                }
                else {
                    s << val.string();
                }

                val = const_cast<DDF&>(a->second).next();
                first = false;
            }
        }
        else {
            count += a->second.integer();
        }
        key = a->first;
    }

    if (!m_values && !attributes.empty())
        s << count << " value(s)" << endl;

    s << "</pre></body></html>";
    return make_pair(true, request.sendResponse(s));
}
