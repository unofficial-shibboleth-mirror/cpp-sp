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

class exceptionCheck {
public:
    exceptionCheck(const string& msg) : m_msg(msg) {}
    bool check_message(const exception& e) {
        return m_msg.compare(e.what()) == 0;
    }
private:
    string m_msg;
};

/////////////

BOOST_AUTO_TEST_CASE(BogusFilesystemSessionCache)
{
    exceptionCheck checker("Configured session cache directory was inaccessible to agent process.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (string(DATA_PATH) + "bogus-filesystem-shibboleth.ini").c_str(), true),
            ConfigurationException, checker.check_message);
}

/////////////

struct FilesystemFixture
{
    FilesystemFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "filesystem-shibboleth.ini").c_str(), true);
    }
    ~FilesystemFixture() {
        AgentConfig::getConfig().term();
        string trackingfile = data_path + "shibsp_cache_cleanup";
        std::remove(trackingfile.c_str());
    }

    string data_path;
};

BOOST_FIXTURE_TEST_CASE(FilesystemSessionCache_invalid_attributes, FilesystemFixture)
{
    bool started = AgentConfig::getConfig().start();
    BOOST_CHECK(started);

    DDF obj(nullptr);
    DDFJanitor janitor(obj);

    obj.addmember("session.attributes");    // not a list

    DummyRequest request("https://sp.example.org/secure/index.html");
    DDF child = obj["session"];

    SessionCache* cache = AgentConfig::getConfig().getAgent().getSessionCache();

    exceptionCheck checker("Error while processing session attributes for storage.");
    BOOST_CHECK_EXCEPTION(cache->create(request, child), SessionException, checker.check_message);
}

BOOST_FIXTURE_TEST_CASE(FilesystemSessionCache_tests, FilesystemFixture)
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
    header += "; Path=/; Secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);

    string cookie(cookieName);
    cookie += '=' + key;
    request.m_requestHeaders["Cookie"] = cookie;

    unique_lock<Session> session = cache->find(request, true, false);
    BOOST_CHECK(session);
    if (session) {
        session.unlock();
    }

    // Clear old response headers.
    request.m_responseHeaders.clear();

    cache->remove(request);

    header = cookieName;
    header += "=; Max-Age=0; Path=/; Secure=1; HttpOnly=1; SameSite=None";
    BOOST_CHECK_EQUAL(request.m_responseHeaders["Set-Cookie"], header);
    
    session = cache->find("custom", key.c_str());
    BOOST_CHECK(!session);
}

}
