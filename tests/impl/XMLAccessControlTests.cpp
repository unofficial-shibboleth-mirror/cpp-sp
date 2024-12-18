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
 * XMLAccessControlTests.cpp
 *
 * Unit tests for XML AccessControl implementation.
 */

#include "exceptions.h"
#include "AccessControl.h"
#include "AgentConfig.h"
#include "SessionCache.h"
#include "attribute/Attribute.h"
#include "logging/Category.h"

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/impl/"

namespace {

/** Open structure for testing manipulation. */
struct DummySession : public Session
{
public:
    DummySession() {}
    ~DummySession() {}

    const char* getID() const {
        return nullptr;
    }
    const char* getApplicationID() const {
        return nullptr;
    }
    time_t getExpiration() const {
        return 0;
    }
    time_t getLastAccess() const {
        return 0;
    }
    const char* getClientAddress() const {
        return nullptr;
    }
    const char* getEntityID() const {
        return nullptr;
    }
    const char* getProtocol() const {
        return nullptr;
    }
    time_t getAuthnInstant() const {
        return m_authInstant;
    }
    const char* getSessionIndex() const {
        return nullptr;
    }
    const char* getAuthnContextClassRef() const {
        return m_ac.c_str();
    }
    const vector<unique_ptr<Attribute>>& getAttributes() const {
    }

    const multimap<string,const Attribute*>& getIndexedAttributes() const {
        if (m_attributeIndex.empty()) {
            for (const unique_ptr<Attribute>& a : m_attributes) {
                const vector<string>& aliases = a->getAliases();
                for (const string& alias : a->getAliases()) {
                    m_attributeIndex.insert(multimap<string, const Attribute*>::value_type(alias, a.get()));
                }
            }
        }
        return m_attributeIndex;
    }

    time_t m_authInstant;
    string m_ac;
    vector<unique_ptr<Attribute>> m_attributes;
    mutable multimap<string,const Attribute*> m_attributeIndex;
};

class exceptionCheck {
public:
    exceptionCheck(const string& msg) : m_msg(msg) {}
    bool check_message(const exception& e) {
        cout << e.what() << endl;
        return m_msg.compare(e.what()) == 0;
    }
private:
    string m_msg;
};

struct BaseFixture
{
    BaseFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "console-shibboleth.ini").c_str(), true);
    }
    ~BaseFixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
};

/////////////
// File pointing to external ACL file that's invalid XML.
/////////////

struct External_Invalid_Fixture : public BaseFixture
{
    External_Invalid_Fixture() {
        xml_parser::read_xml(data_path + "external-acl-badxml.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~External_Invalid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_external_invalid, External_Invalid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL content that has the wrong child element.
/////////////

struct Inline_Invalid_Fixture : public BaseFixture
{
    Inline_Invalid_Fixture() {
        xml_parser::read_xml(data_path + "internal-acl-invalid.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~Inline_Invalid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_invalid, Inline_Invalid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////

/*

struct Inline_Valid_Fixture : public BaseFixture
{
    Inline_Valid_Fixture() {
        xml_parser::read_xml(data_path + "inline.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~Inline_Valid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_valid, Inline_Valid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts1, 0);
    dummy.unlock();

    // No-op since there's no locking internally.
    dummy.forceReload();
    sleep(2);

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts2, 0);
    dummy.unlock();
}

struct External_Valid_Fixture : public BaseFixture
{
    External_Valid_Fixture() {
        xml_parser::read_xml(data_path + "external.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~External_Valid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_external_valid, External_Valid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_GT(ts1, 0);
    dummy.unlock();

    dummy.forceReload();
    sleep(2);

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_GT(ts2, ts1);
    dummy.unlock();
}

*/

};