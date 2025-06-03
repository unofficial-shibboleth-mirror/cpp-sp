/*
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
 * session/impl/MemorySessionCacheTests.cpp
 *
 * Unit tests for in-memory SessionCache back-end.
 */

#include "AbstractSPRequest.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "exceptions.h"
#include "remoting/ddf.h"
#include "session/SessionCache.h"

#include <map>
#include <memory>
#include <string>
#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ini_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/session/impl/"

namespace {

class DummyRequest : public AbstractSPRequest {
public:
    DummyRequest(const char* uri=nullptr) : AbstractSPRequest(SHIBSP_LOGCAT ".DummyRequest"), m_addr("192.168.0.1") {
        setRequestURI(uri);
    }
    const char* getMethod() const { return nullptr; }
    const char* getScheme() const { return m_scheme.c_str(); }
    const char* getHostname() const { return m_hostname.c_str(); }
    int getPort() const { return m_port; }
    string getContentType() const { return ""; }
    long getContentLength() const { return -1; }
    const char* getQueryString() const { return m_query.c_str(); }
    const char* getRequestBody() const { return nullptr; }
    string getHeader(const char* name) const {
        return m_requestHeaders.find(name) == m_requestHeaders.end() ? "" : m_requestHeaders.find(name)->second;
    }
    string getRemoteUser() const { return m_user.c_str(); }
    string getRemoteAddr() const { return m_addr.c_str(); }
    string getAuthType() const { return nullptr; }
    long sendResponse(istream&, long status) { return status; }
    void clearHeader(const char* name) {}
    void setHeader(const char* name, const char* value) {}
    void setResponseHeader(const char* name, const char* value, bool replace=false) {
        HTTPResponse::setResponseHeader(name, value, replace);
        m_responseHeaders[name] = value ? value : "";
    }
    void setRemoteUser(const char*) {}
    long returnDecline() { return 200; }
    long returnOK() { return 200; }

    bool isUseHeaders() const {return true;}
    bool isUseVariables() const { return false; }
    
    string m_scheme;
    string m_hostname;
    int m_port;
    string m_query;
    string m_user;
    string m_addr;
    map<string,string> m_requestHeaders;
    map<string,string> m_responseHeaders;
};

struct MemoryFixture
{
    MemoryFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "memory-shibboleth.ini").c_str(), true);
    }
    ~MemoryFixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
};

/////////////

BOOST_FIXTURE_TEST_CASE(MemorySessionCache_tests, MemoryFixture)
{
    bool started = AgentConfig::getConfig().start();
    BOOST_CHECK(started);

    DDF obj(nullptr);
    DDFJanitor janitor(obj);

    obj.addmember("session.opaque").string("foo");
    DDF attrs = obj.addmember("session.attributes").list();

    DDF issuer("Shib-Identity-Provider");
    issuer.list();
    issuer.add(DDF(nullptr).string("https://idp.example.org"));
    attrs.add(issuer);

    DDF affiliation("affiliation");
    affiliation.list();
    affiliation.add(DDF(nullptr).string("member"));
    affiliation.add(DDF(nullptr).string("student"));
    attrs.add(affiliation);

    DummyRequest request("https://sp.example.org/secure/index.html");
    DDF child = obj["session"];

    SessionCache* cache = AgentConfig::getConfig().getAgent().getSessionCache();

    string key = cache->create(request, child);

    BOOST_CHECK(obj["session"].isnull());
    BOOST_CHECK_EQUAL(key.c_str(), child.name());
    string cookieName("__Host-shibsession_73702e6578616d706c652e6f7267637573746f6d");
    string header(cookieName);
    header += '=' + key;
    header += "; max-age=-1; path=/; secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);

    string cookie(cookieName);
    cookie += '=' + key;
    request.m_requestHeaders["Cookie"] = cookie;

    unique_lock<Session> session = cache->find(request, true, false);
    BOOST_CHECK(session);
}

}
