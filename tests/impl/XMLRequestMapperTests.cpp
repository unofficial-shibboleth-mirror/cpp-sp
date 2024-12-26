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
 * XMLRequestMapperTests.cpp
 *
 * Unit tests for XML RequestMapper implementation.
 */

#include "exceptions.h"
#include "AbstractSPRequest.h"
#include "AccessControl.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "logging/Category.h"
#include "util/PropertySet.h"

#ifdef HAVE_CXX14
# include <shared_mutex>
#endif

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/impl/reqmap/"

namespace {

class DummyRequest : public AbstractSPRequest {
public:
    DummyRequest(const char* uri=nullptr) : AbstractSPRequest(SHIBSP_LOGCAT ".DummyRequest") {
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
    string getHeader(const char*) const { return nullptr; }
    string getRemoteUser() const { return nullptr; }
    string getAuthType() const { return nullptr; }
    long sendResponse(istream&, long status) { return status; }
    void clearHeader(const char*, const char*) {}
    void setHeader(const char*, const char*) {}
    void setRemoteUser(const char*) {}
    long returnDecline() { return 200; }
    long returnOK() { return 200; }

    string m_scheme;
    string m_hostname;
    int m_port;
    string m_query;
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

struct XMLRequestMapperFixture
{
    XMLRequestMapperFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "../console-shibboleth.ini").c_str(), true);
    }
    ~XMLRequestMapperFixture() {
        AgentConfig::getConfig().term();
    }

    void parse(const string& filename) {
        xml_parser::read_xml(data_path + filename, tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }

    ptree tree;
    string data_path;
};

/////////////
// File pointing to external file that's invalid XML.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_external_invalid, XMLRequestMapperFixture)
{
    parse("external-badxml.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial RequestMapper configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline content that has the wrong child element.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_invalid, XMLRequestMapperFixture)
{
    parse("internal-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial RequestMapper configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline content that has a bad internal element.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_invalid_internal, XMLRequestMapperFixture)
{
    parse("internal-invalid2.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Initial RequestMapper configuration was invalid.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true),
            ConfigurationException, checker.check_message);
}

/////////////
// Inline test to check for applicationId defaulting.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_defaultingId, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request;
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "sp.example.org");
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
}

/////////////
// Inline test to check for applicationId non-defaulting.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_customId, XMLRequestMapperFixture)
{
    parse("inline-with-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request;
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "sp.example.org");
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "custom");
}

/////////////
// Inline test to check for unsuccessful mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_no_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request;
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 80;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), nullptr);
}

/////////////
// Inline tests to check for HostRegex mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_HostRegex_mapping_failed, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "spa.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("regex"), nullptr);
    BOOST_CHECK(!settings.first->getBool("requireSession", false));
    BOOST_CHECK(!settings.first->getBool("isPassive", false));
}

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_HostRegex_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "sp4.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("regex"), "https\\://sp\\d\\.example\\.org\\:443");
    BOOST_CHECK(!settings.first->getBool("requireSession", false));
    BOOST_CHECK(settings.first->getBool("isPassive", false));
}

/////////////
// Inline test to check for Path mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_Path_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "secure");
    BOOST_CHECK(settings.first->getBool("requireSession", false));
    BOOST_CHECK(!settings.first->getBool("forceAuthn", false));
}

/////////////
// Inline test to check for nested Path mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_nested_Path_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/foo/bar/baz/baf");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "baz");
    BOOST_CHECK(!settings.first->getBool("requireSession", false));
    BOOST_CHECK(settings.first->getBool("forceAuthn", false));
}

/////////////
// Inline tests to check for PathRegex mapping behavior.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_PathRegex_mapping_failed, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/folderx");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "sp.example.org");
    BOOST_CHECK_EQUAL(settings.first->getString("regex"), nullptr);
    BOOST_CHECK(!settings.first->getBool("requireSession", false));
    BOOST_CHECK_EQUAL(settings.first->getString("requireSessionWith"), nullptr);
}

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_PathRegex_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/folder1");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("regex"), "FoLdEr\\d");
    BOOST_CHECK(!settings.first->getBool("requireSession", false));
    BOOST_CHECK_EQUAL(settings.first->getString("requireSessionWith"), "custom");
}

/////////////
// Inline test to check for Query mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_Query_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;
    request.m_query = "foo=jdoe&bar=baz";

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "foo");
    BOOST_CHECK(settings.first->getBool("requireSession", false));
    BOOST_CHECK_EQUAL(settings.first->getString("entityId"), "https://idp.example.org/foo");
}

/////////////
// Inline tests to check for Query regex mapping.
/////////////

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_Query_regex_mapping_failed, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;
    request.m_query = "baz=jdoe";

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "secure");
    BOOST_CHECK(settings.first->getBool("requireSession", false));
    BOOST_CHECK_EQUAL(settings.first->getString("entityId"), nullptr);
}

BOOST_FIXTURE_TEST_CASE(XMLRequestMapper_inline_Query_regex_mapping, XMLRequestMapperFixture)
{
    parse("inline-no-applicationId.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    unique_ptr<RequestMapper> mapper(AgentConfig::getConfig().RequestMapperManager.newPlugin(
        tree.front().second.get<string>("<xmlattr>.type").c_str(), tree.front().second, true));

    DummyRequest request("/secure");
    request.m_scheme = "https";
    request.m_hostname = "sp.example.org";
    request.m_port = 443;
    request.m_query = "baz=jdoe&bar=baz";

#ifdef HAVE_CXX14
    shared_lock locker(*mapper);
#endif

    const RequestMapper::Settings settings = mapper->getSettings(request);
    BOOST_CHECK_EQUAL(settings.second, nullptr);
    BOOST_CHECK_EQUAL(settings.first->getString("applicationId"), "default");
    BOOST_CHECK_EQUAL(settings.first->getString("name"), "bar");
    BOOST_CHECK(settings.first->getBool("requireSession", false));
    BOOST_CHECK_EQUAL(settings.first->getString("entityId"), "https://idp.example.org/bar");
}
};