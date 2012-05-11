/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * SessionHandler.cpp
 *
 * Handler for dumping information about an active session.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/SecuredHandler.h"

#include <ctime>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API SessionHandler : public SecuredHandler
    {
    public:
        SessionHandler(const DOMElement* e, const char* appId);
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

    Handler* SHIBSP_DLLLOCAL SessionHandlerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SessionHandler(p.first, p.second);
    }

};

SessionHandler::SessionHandler(const DOMElement* e, const char* appId)
    : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionHandler")), m_values(false)
{
    pair<bool,const char*> prop = getString("contentType");
    if (prop.first)
        m_contentType = prop.second;
    if (!m_contentType.empty() && m_contentType != "application/json" && m_contentType != "text/html")
        throw ConfigurationException("Unsupported contentType property in Session Handler configuration.");

    pair<bool,bool> flag = getBool("showAttributeValues");
    if (flag.first)
        m_values = flag.second;
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
    catch (std::exception& ex) {
        m_log.info("exception accessing user session: %s", ex.what());
        s << "{}" << endl;
        return make_pair(true, request.sendError(s));
    }

    s << "{ ";
    s << "\"expiration\": ";
    if (session->getExpiration())
        s << ((session->getExpiration() - time(nullptr)) / 60);
    else
        s << 0;

    if (session->getClientAddress()) {
        s << ", \"client_address\": ";
        json_safe(s, session->getClientAddress());
    }

    if (session->getProtocol()) {
        s << ", \"protocol\": ";
        json_safe(s, session->getProtocol());
    }

    pair<bool,bool> stdvars = request.getRequestSettings().first->getBool("exportStdVars");
    if (!stdvars.first || stdvars.second) {
        if (session->getEntityID()) {
            s << ", \"identity_provider\": ";
            json_safe(s, session->getEntityID());
        }

        if (session->getAuthnInstant()) {
            s << ", \"authn_instant\": ";
            json_safe(s, session->getAuthnInstant());
        }

        if (session->getAuthnContextClassRef()) {
            s << ", \"authncontext_class\": ";
            json_safe(s, session->getAuthnContextClassRef());
        }

        if (session->getAuthnContextDeclRef()) {
            s << ", \"authncontext_decl\": ";
            json_safe(s, session->getAuthnContextDeclRef());
        }

    }

    /*
        attributes: [ { "name": "foo", "values" : count } ]

        attributes: [
            { "name": "foo", "values": [ "val", "val" ] }
        ]
    */

    const multimap<string,const Attribute*>& attributes = session->getIndexedAttributes();
    if (!attributes.empty()) {
        s << ", \"attributes\": [ ";
        string key;
        vector<string>::size_type count=0;
        for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
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
                const vector<string>& vals = a->second->getSerializedValues();
                for (vector<string>::const_iterator v = vals.begin(); v!=vals.end(); ++v) {
                    if (v != vals.begin() || a->first == key) {
                        s << ", ";
                    }
                    else {
                        s << ", \"values\": [ ";
                    }
                    json_safe(s, v->c_str());
                }
            }
            else {
                count += a->second->getSerializedValues().size();
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
    catch (std::exception& ex) {
        s << "Exception while retrieving active session:" << endl
            << '\t' << ex.what() << "</pre></body></html>" << endl;
        return make_pair(true, request.sendResponse(s));
    }

    s << "<u>Miscellaneous</u>" << endl;

    s << "<strong>Session Expiration (barring inactivity):</strong> ";
    if (session->getExpiration())
        s << ((session->getExpiration() - time(nullptr)) / 60) << " minute(s)" << endl;
    else
        s << "Infinite" << endl;

    s << "<strong>Client Address:</strong> " << (session->getClientAddress() ? session->getClientAddress() : "(none)") << endl;
    s << "<strong>SSO Protocol:</strong> " << (session->getProtocol() ? session->getProtocol() : "(none)") << endl;

    pair<bool,bool> stdvars = request.getRequestSettings().first->getBool("exportStdVars");
    if (!stdvars.first || stdvars.second) {
        s << "<strong>Identity Provider:</strong> " << (session->getEntityID() ? session->getEntityID() : "(none)") << endl;
        s << "<strong>Authentication Time:</strong> " << (session->getAuthnInstant() ? session->getAuthnInstant() : "(none)") << endl;
        s << "<strong>Authentication Context Class:</strong> " << (session->getAuthnContextClassRef() ? session->getAuthnContextClassRef() : "(none)") << endl;
        s << "<strong>Authentication Context Decl:</strong> " << (session->getAuthnContextDeclRef() ? session->getAuthnContextDeclRef() : "(none)") << endl;
    }

    s << endl << "<u>Attributes</u>" << endl;

    string key;
    vector<string>::size_type count=0;
    const multimap<string,const Attribute*>& attributes = session->getIndexedAttributes();
    for (multimap<string,const Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a) {
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
            const vector<string>& vals = a->second->getSerializedValues();
            for (vector<string>::const_iterator v = vals.begin(); v!=vals.end(); ++v) {
                if (v != vals.begin() || a->first == key)
                    s << ';';
                string::size_type pos = v->find_first_of(';',string::size_type(0));
                if (pos!=string::npos) {
                    string value(*v);
                    for (; pos != string::npos; pos = value.find_first_of(';',pos)) {
                        value.insert(pos, "\\");
                        pos += 2;
                    }
                    s << value;
                }
                else {
                    s << *v;
                }
            }
        }
        else {
            count += a->second->getSerializedValues().size();
        }
        key = a->first;
    }

    if (!m_values && !attributes.empty())
        s << count << " value(s)" << endl;

    s << "</pre></body></html>";
    return make_pair(true, request.sendResponse(s));
}
