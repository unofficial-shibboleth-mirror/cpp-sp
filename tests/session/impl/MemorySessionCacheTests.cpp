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

#include "Agent.h"
#include "AgentConfig.h"
#include "exceptions.h"
#include "remoting/ddf.h"
#include "session/SessionCache.h"

#include "DummyRequest.h"

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

struct MemoryFixture
{
    MemoryFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "memory-agent.ini").c_str(), true);
    }
    ~MemoryFixture() {
        AgentConfig::getConfig().term();
    }

    DDF createTestData(const char* opaque) {
        DDF obj(nullptr);
        obj.addmember("session.opaque").string(opaque);
        DDF attrs = obj.addmember("session.attributes").list();

        DDF issuer("Shib-Identity-Provider");
        issuer.list();
        issuer.add(DDF(nullptr).string("https://idp.example.org"));
        attrs.add(issuer);

        DDF authts("Shib-Authentication-Instant");
        authts.list();
        authts.add(DDF(nullptr).longinteger(1765202451));
        attrs.add(authts);

        DDF affiliation("affiliation");
        affiliation.list();
        affiliation.add(DDF(nullptr).string("member"));
        affiliation.add(DDF(nullptr).string("student"));
        attrs.add(affiliation);

        return obj;
    }

    string data_path;
};

/////////////

BOOST_FIXTURE_TEST_CASE(MemorySessionCache_tests, MemoryFixture)
{
    bool started = AgentConfig::getConfig().start();
    BOOST_CHECK(started);

    DDF obj = createTestData("foo");
    DDFJanitor janitor(obj);

    DummyRequest request("https://sp.example.org/secure/index.html");
    DDF child = obj["session"];

    SessionCache* cache = AgentConfig::getConfig().getAgent().getSessionCache();

    string key = cache->create(request, child);

    BOOST_CHECK(obj["session"].isnull());
    BOOST_CHECK_EQUAL(key.c_str(), child.name());
    string cookieName("__Host-shibsession_637573746f6d");
    string header(cookieName);
    header = header + '=' + key + ".1"; 
    header += "; Path=/; Secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);

    string cookie(cookieName);
    cookie = cookie + '=' + key + ".1";
    request.m_requestHeaders["Cookie"] = cookie;

    unique_lock<Session> session = cache->find(request, true, false);
    BOOST_CHECK(session);
    if (session) {
        const DDF& attr = session.mutex()->getAttributes().at("Shib-Authentication-Instant");
        DDF val = const_cast<DDF&>(attr).first();
        BOOST_CHECK(val.isstring());
        BOOST_CHECK_EQUAL(val.string(), "1765202451");
        session.unlock();
    }

    // Clear old response headers.
    request.m_responseHeaders.clear();

    // Force an address re-bind, which should revise the session version.
    request.m_addr = "::1";

    session = cache->find(request, true, false);
    BOOST_CHECK(session);
    if (session) {
        BOOST_CHECK_EQUAL(session.mutex()->getVersion(), 2);
        header = cookieName + '=' + key + ".2"; 
        header += "; Path=/; Secure=1; HttpOnly=1; SameSite=None";
        BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);
        session.unlock();
    }

    cache->remove(request);

    header = cookieName;
    header += "=; Max-Age=0; Path=/; Secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);
    
    session = cache->find("custom", key.c_str());
    BOOST_CHECK(!session);
}

BOOST_FIXTURE_TEST_CASE(MemorySessionCache_testUpdate, MemoryFixture)
{
    bool started = AgentConfig::getConfig().start();
    BOOST_CHECK(started);

    DDF obj = createTestData("foo");
    DDFJanitor janitor(obj);

    DummyRequest request("https://sp.example.org/secure/index.html");
    DDF child = obj["session"];

    SessionCache* cache = AgentConfig::getConfig().getAgent().getSessionCache();

    string key = cache->create(request, child);

    BOOST_CHECK(obj["session"].isnull());
    BOOST_CHECK_EQUAL(key.c_str(), child.name());

    // Bind session to request with cookie.
    string cookieName("__Host-shibsession_637573746f6d");
    string cookie(cookieName);
    cookie = cookie + '=' + key + ".1";
    request.m_requestHeaders["Cookie"] = cookie;

    unique_lock<Session> session = cache->find(request, true, false);
    BOOST_CHECK(session);

    // Clear old response headers.
    request.m_responseHeaders.clear();

    if (session) {
        BOOST_CHECK_EQUAL(session.mutex()->getVersion(), 1);
        DDF opaque = session.mutex()->getOpaqueData();
        BOOST_CHECK_EQUAL(opaque.string(), "foo");

        // Explicit update.
        DDF obj2 = createTestData("bar");
        DDFJanitor janitor2(obj2);

        child = obj2["session"];
        BOOST_CHECK(cache->update(request, session, child));

        opaque = session.mutex()->getOpaqueData();
        BOOST_CHECK_EQUAL(opaque.string(), "bar");
        BOOST_CHECK_EQUAL(session.mutex()->getVersion(), 2);

        session.unlock();
    }

    session = cache->find(request, true, false);
    BOOST_CHECK(session);
    if (session) {
        BOOST_CHECK_EQUAL(session.mutex()->getVersion(), 2);
        string header = cookieName + '=' + key + ".2"; 
        header += "; Path=/; Secure=1; HttpOnly=1; SameSite=None";
        BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);
        session.unlock();
    }

    cache->remove(request);

    string header = cookieName;
    header += "=; Max-Age=0; Path=/; Secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);
    
    session = cache->find("custom", key.c_str());
    BOOST_CHECK(!session);
}

}
