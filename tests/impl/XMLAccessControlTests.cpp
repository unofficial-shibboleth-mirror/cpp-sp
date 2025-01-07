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
#include "attribute/Attribute.h"
#include "attribute/SimpleAttribute.h"
#include "logging/Category.h"
#include "session/SessionCache.h"

#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/impl/acl/"

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
    const char* getBucketID() const {
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
        return m_attributes;
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
    string getRemoteUser() const { return m_user; }
    string getAuthType() const { return nullptr; }
    long sendResponse(istream&, long status) { return status; }
    void clearHeader(const char*, const char*) {}
    void setHeader(const char*, const char*) {}
    void setRemoteUser(const char*) {}
    long returnDecline() { return 200; }
    long returnOK() { return 200; }

    string m_user;
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

struct XMLAccessControlFixture
{
    XMLAccessControlFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "../console-shibboleth.ini").c_str(), true);
    }
    ~XMLAccessControlFixture() {
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

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_external_invalid, XMLAccessControlFixture)
{
    parse("external-acl-badxml.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL content that has the wrong child element.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_invalid, XMLAccessControlFixture)
{
    parse("internal-acl-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL content that has a bad internal element.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_invalid_internal, XMLAccessControlFixture)
{
    parse("internal-acl-invalid2.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL test for NOT operator with 2 rules.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_NOT_multiple, XMLAccessControlFixture)
{
    parse("inline-not-multiple-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial AccessControl configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline ACL test for valid-user rule.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_ValidUserRule, XMLAccessControlFixture)
{
    parse("inline-valid-user-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    BOOST_CHECK_EQUAL(acl->authorized(request, nullptr), AccessControl::shib_acl_false);
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// Inline ACL test for user rule.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_UserRule, XMLAccessControlFixture)
{
    parse("inline-user-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    request.m_user = "smith";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    request.m_user = "jdoe";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// Inline ACL test for user regex rule.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_UserRegexRule, XMLAccessControlFixture)
{
    parse("inline-user-regex-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    request.m_user = "smith";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    request.m_user = "jdoe";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// Inline ACL test for authnContextClassRef rule.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_ACRule, XMLAccessControlFixture)
{
    parse("inline-ac-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    session.m_ac = "Foo";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    session.m_ac = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// Inline ACL test for attribute rule.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_inline_AttrRule, XMLAccessControlFixture)
{
    parse("inline-attr-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    session.m_attributes.push_back(unique_ptr<Attribute>(new SimpleAttribute({"affiliation"})));
    SimpleAttribute& attr = dynamic_cast<SimpleAttribute&>(*(session.m_attributes.back()));

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    attr.getValues().push_back("staff");
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    attr.getValues().push_back("student");
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// External ACL test for OR operator
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_external_OR, XMLAccessControlFixture)
{
    parse("external-or-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    session.m_attributes.push_back(unique_ptr<Attribute>(new SimpleAttribute({"affiliation"})));
    SimpleAttribute& attr = dynamic_cast<SimpleAttribute&>(*(session.m_attributes.back()));

    request.m_user = "jdoe";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);

    request.m_user = "smith";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    attr.getValues().push_back("student");
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// External ACL test for AND operator
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_external_AND, XMLAccessControlFixture)
{
    parse("external-and-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    session.m_attributes.push_back(unique_ptr<Attribute>(new SimpleAttribute({"affiliation"})));
    SimpleAttribute& attr = dynamic_cast<SimpleAttribute&>(*(session.m_attributes.back()));

    request.m_user = "jdoe";
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);

    attr.getValues().push_back("student");
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);
}

/////////////
// External ACL test for NOT operator
/////////////

BOOST_FIXTURE_TEST_CASE(XMLAccessControl_external_NOT, XMLAccessControlFixture)
{
    parse("external-not-acl.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<AccessControl> acl(AgentConfig::getConfig().AccessControlManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

#ifdef HAVE_CXX14
    shared_lock locker(*acl);
#endif

    DummyRequest request;
    DummySession session;

    session.m_attributes.push_back(unique_ptr<Attribute>(new SimpleAttribute({"affiliation"})));
    SimpleAttribute& attr = dynamic_cast<SimpleAttribute&>(*(session.m_attributes.back()));

    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_true);

    attr.getValues().push_back("student");
    BOOST_CHECK_EQUAL(acl->authorized(request, &session), AccessControl::shib_acl_false);
}

};