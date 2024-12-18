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
#include "AbstractSPRequest.h"
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
struct DummySession : public Session, public NoOpBasicLockable
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

class DummyRequest : public AbstractSPRequest {
public:
    DummyRequest() : AbstractSPRequest(SHIBSP_LOGCAT ".DummyRequest") {}
    const char* getMethod() const { return nullptr; }
    const char* getScheme() const { return nullptr; }
    const char* getHostname() const { return nullptr; }
    int getPort() const { return 0; }
    string getContentType() const { return ""; }
    long getContentLength() const { return -1; }
    const char* getQueryString() const { return nullptr; }
    const char* getRequestBody() const { return nullptr; }
    string getHeader(const char*) const { return nullptr; }
    string getRemoteUser() const { return nullptr; }
    string getAuthType() const { return nullptr; }
    long sendResponse(istream&, long status) { return status; }
    void clearHeader(const char*, const char*) {}
    void setHeader(const char*, const char*) {}
    void setRemoteUser(const char*) {}
    long returnDecline() { return 200; }
    long returnOK() { return 200; }
};

class exceptionCheck {
public:
    exceptionCheck(const string& msg) : m_msg(msg) {}
    bool check_message(const exception& e) {
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
// Inline ACL content that has a bad internal element.
/////////////

struct Inline_InvalidInternal_Fixture : public BaseFixture
{
    Inline_InvalidInternal_Fixture() {
        xml_parser::read_xml(data_path + "internal-acl-invalid2.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_invalid_internal, Inline_InvalidInternal_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL test for authnContextClassRef rule.
/////////////

struct Inline_ACRule_Fixture : public BaseFixture
{
    Inline_ACRule_Fixture() {
        xml_parser::read_xml(data_path + "inline-ac-acl.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_ACRule, Inline_ACRule_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    acl->lock_shared();

    DummyRequest request;
    DummySession session;
    session.m_ac = "Foo";

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    session.m_ac = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);

    acl->unlock_shared();
}

/*
struct External_Valid_Fixture : public BaseFixture
{
    External_Valid_Fixture() {
        xml_parser::read_xml(data_path + "external.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
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