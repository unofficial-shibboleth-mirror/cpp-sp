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
#include "handler/AbstractHandler.h"
#include "util/IPRange.h"

#include <ctime>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Blocker : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL Blocker g_Blocker;

    class SHIBSP_API SessionHandler : public AbstractHandler
    {
    public:
        SessionHandler(const DOMElement* e, const char* appId);
        virtual ~SessionHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        void parseACL(const string& acl) {
            try {
                m_acl.push_back(IPRange::parseCIDRBlock(acl.c_str()));
            }
            catch (std::exception& ex) {
                m_log.error("invalid CIDR block (%s): %s", acl.c_str(), ex.what());
            }
        }

        bool m_values;
        vector<IPRange> m_acl;
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
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionHandler"), &g_Blocker), m_values(false)
{
    pair<bool,const char*> acl = getString("acl");
    if (acl.first) {
        string aclbuf=acl.second;
        vector<string> aclarray;
        split(aclarray, aclbuf, is_space(), algorithm::token_compress_on);
        for_each(aclarray.begin(), aclarray.end(), boost::bind(&SessionHandler::parseACL, this, _1));
        if (m_acl.empty()) {
            m_log.warn("invalid CIDR range(s) in Session handler acl property, allowing 127.0.0.1 as a fall back");
            m_acl.push_back(IPRange::parseCIDRBlock("127.0.0.1"));
        }
    }

    pair<bool,bool> flag = getBool("showAttributeValues");
    if (flag.first)
        m_values = flag.second;
}

pair<bool,long> SessionHandler::run(SPRequest& request, bool isHandler) const
{
    if (!m_acl.empty()) {
        static bool (IPRange::* contains)(const char*) const = &IPRange::contains;
        if (find_if(m_acl.begin(), m_acl.end(), boost::bind(contains, _1, request.getRemoteAddr().c_str())) == m_acl.end()) {
            m_log.error("session handler request blocked from invalid address (%s)", request.getRemoteAddr().c_str());
            istringstream msg("Session Handler Blocked");
            return make_pair(true,request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_FORBIDDEN));
        }
    }

    stringstream s;
    s << "<html><head><title>Session Summary</title></head><body><pre>" << endl;

    Session* session = nullptr;
    try {
        session = request.getSession(); // caches the locked session in the request so it's unlocked automatically
        if (!session) {
            s << "A valid session was not found.</pre></body></html>" << endl;
            request.setContentType("text/html");
            request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
            request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");
            return make_pair(true, request.sendResponse(s));
        }
    }
    catch (std::exception& ex) {
        s << "Exception while retrieving active session:" << endl
            << '\t' << ex.what() << "</pre></body></html>" << endl;
        request.setContentType("text/html");
        request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
        request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");
        return make_pair(true, request.sendResponse(s));
    }

    s << "<u>Miscellaneous</u>" << endl;

    s << "<strong>Client Address:</strong> " << (session->getClientAddress() ? session->getClientAddress() : "(none)") << endl;
    s << "<strong>Identity Provider:</strong> " << (session->getEntityID() ? session->getEntityID() : "(none)") << endl;
    s << "<strong>SSO Protocol:</strong> " << (session->getProtocol() ? session->getProtocol() : "(none)") << endl;
    s << "<strong>Authentication Time:</strong> " << (session->getAuthnInstant() ? session->getAuthnInstant() : "(none)") << endl;
    s << "<strong>Authentication Context Class:</strong> " << (session->getAuthnContextClassRef() ? session->getAuthnContextClassRef() : "(none)") << endl;
    s << "<strong>Authentication Context Decl:</strong> " << (session->getAuthnContextDeclRef() ? session->getAuthnContextDeclRef() : "(none)") << endl;
    s << "<strong>Session Expiration (barring inactivity):</strong> ";
    if (session->getExpiration())
        s << ((session->getExpiration() - time(nullptr)) / 60) << " minute(s)" << endl;
    else
        s << "Infinite" << endl;

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
    }

    if (!m_values && !attributes.empty())
        s << count << " value(s)" << endl;

    s << "</pre></body></html>";
    request.setContentType("text/html; charset=UTF-8");
    request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");
    return make_pair(true, request.sendResponse(s));
}
