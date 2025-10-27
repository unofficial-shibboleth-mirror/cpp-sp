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
 * TimeAccessControlTests.cpp
 *
 * Unit tests for Time AccessControl implementation.
 */

#include "exceptions.h"
#include "AbstractSPRequest.h"
#include "AccessControl.h"
#include "AgentConfig.h"
#include "logging/Category.h"
#include "remoting/ddf.h"
#include "session/SessionCache.h"
#include "util/BoostPropertySet.h"

#include "DummyRequest.h"

#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/impl/acl/time/"

namespace {

/** Open structure for testing manipulation. */
struct DummySession : public Session, public NoOpBasicLockable {
public:
    DummySession() {}
    ~DummySession() {
        for (auto& a : m_attributes) {
            a.second.destroy();
        }
    }

    const char* getID() const {
        return nullptr;
    }
    unsigned int getVersion() const {
        return 1;
    }
    const char* getApplicationID() const {
        return nullptr;
    }
    time_t getCreation() const {
        return 0;
    }
    time_t getLastAccess() const {
        return 0;
    }
    const map<string,DDF>& getAttributes() const {
        return m_attributes;
    }
    DDF getOpaqueData() const {
        return DDF();
    }

    map<string,DDF> m_attributes;
};

class MappableDummyRequest : public DummyRequest {
public:
    MappableDummyRequest() {}
    ~MappableDummyRequest() {}
    RequestMapper::Settings getRequestSettings() const { return make_pair(&m_map, nullptr); }

    BoostPropertySet m_map;
};

class exceptionCheck {
public:
    exceptionCheck(const string& msg) : m_msg(msg) {}
    bool check_message(const exception& e) {
        if (m_msg.compare(e.what()) == 0) {
            return true;
        }
        else {
            cout << "Non-matching message: " << e.what() << endl;
            return false;
        }
    }
private:
    string m_msg;
};

struct TimeAccessControlFixture
{
    TimeAccessControlFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "../../console-agent.ini").c_str(), true);
    }
    ~TimeAccessControlFixture() {
        AgentConfig::getConfig().term();
    }

    void parse(const string& filename) {
        xml_parser::read_xml(data_path + filename, tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }

    ptree tree;
    string data_path;
};

/////////////
// File pointing to external ACL file that's invalid XML.
/////////////

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_external_invalid, TimeAccessControlFixture)
{
    parse("external-acl-badxml.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL content that has a bad internal element.
/////////////

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_invalid_internal, TimeAccessControlFixture)
{
    parse("internal-acl-invalid2.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Time-based rule requires element content of the form \"LT|LE|EQ|GE|GT value\".");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL test for TimeSinceAuthn rule.
/////////////

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_TimeSinceAuthn, TimeAccessControlFixture)
{
    parse("inline-timesinceauth.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    // No attribute available.
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    DDF ac("Shib-Authentication-Instant");
    ac.list();
    ac.add(DDF(nullptr).longinteger(time(nullptr) - 300));
    session.m_attributes[ac.name()] = ac;
    
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);

    ac.first().longinteger(time(nullptr) - 7200);
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);
}

/////////////
// Inline ACL tests for absolute Time rule.
/////////////

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_OldTimeValid, TimeAccessControlFixture)
{
    parse("inline-old-time-valid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_OldTimeInvalid, TimeAccessControlFixture)
{
    parse("inline-old-time-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);
}

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_NewTimeValid, TimeAccessControlFixture)
{
    parse("inline-new-time-valid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_NewTimeInvalid, TimeAccessControlFixture)
{
    parse("inline-new-time-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);
}

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_YearValid, TimeAccessControlFixture)
{
    parse("inline-year-valid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

BOOST_FIXTURE_TEST_CASE(TimeAccessControl_inline_YearInvalid, TimeAccessControlFixture)
{
    parse("inline-year-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    MappableDummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);
}

};
