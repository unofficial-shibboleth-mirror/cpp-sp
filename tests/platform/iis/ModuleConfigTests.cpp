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
 * platform/iis/ModuleConfigTests.cpp
 *
 * Unit tests for IIS ModuleConfig class.
 */

#include "exceptions.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "platform/iis/ModuleConfig.h"

#include <memory>

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/test/unit_test.hpp>

using namespace shibsp::iis;
using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/platform/iis/"

namespace {

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

struct ModuleConfigFixture
{
    ModuleConfigFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "./console-agent.ini").c_str(), true);
    }
    ~ModuleConfigFixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
};

BOOST_FIXTURE_TEST_CASE(ModuleConfigTest_ini_invalid, ModuleConfigFixture)
{
    exceptionCheck checker(data_path + "iis-bad.ini(4): unmatched '['");
    BOOST_CHECK_EXCEPTION(ModuleConfig::newModuleConfig(string(data_path + "iis-bad.ini").c_str()),
            ini_parser_error, checker.check_message);
}

BOOST_FIXTURE_TEST_CASE(ModuleConfigTest_xml_invalid, ModuleConfigFixture)
{
    exceptionCheck checker(data_path + "iis-bad.xml(3): unexpected end of data");
    BOOST_CHECK_EXCEPTION(ModuleConfig::newModuleConfig(string(data_path + "iis-bad.xml").c_str()),
            xml_parser_error, checker.check_message);
}

void validateSites(const ModuleConfig* config)
{
    // Bad site should be absent.
    BOOST_CHECK(!config->getSiteConfig("bad"));

    const PropertySet* one = config->getSiteConfig("1");
    BOOST_CHECK(one);
    BOOST_CHECK_EQUAL(one->getString(ModuleConfig::SITE_NAME_PROP_NAME), "sp.example.org");
    BOOST_CHECK(!one->getString(ModuleConfig::SITE_SCHEME_PROP_NAME));
    BOOST_CHECK_EQUAL(one->getUnsignedInt(ModuleConfig::SITE_PORT_PROP_NAME, 0), 0);
    BOOST_CHECK(!one->getString(ModuleConfig::SITE_ALIASES_PROP_NAME));
    BOOST_CHECK(!one->getBool(RequestMapper::USE_HEADERS_PROP_NAME, true));

    const PropertySet* two = config->getSiteConfig("2");
    BOOST_CHECK(two);
    BOOST_CHECK_EQUAL(two->getString(ModuleConfig::SITE_NAME_PROP_NAME), "sp2.example.org");
    BOOST_CHECK_EQUAL(two->getString(ModuleConfig::SITE_SCHEME_PROP_NAME), "https");
    BOOST_CHECK_EQUAL(two->getUnsignedInt(ModuleConfig::SITE_PORT_PROP_NAME, 0), 443);
    BOOST_CHECK(!two->getString(ModuleConfig::SITE_ALIASES_PROP_NAME));

    const PropertySet* three = config->getSiteConfig("3");
    BOOST_CHECK(three);
    BOOST_CHECK_EQUAL(three->getString(ModuleConfig::SITE_NAME_PROP_NAME), "sp3.example.org");
    BOOST_CHECK(!three->getString(ModuleConfig::SITE_SCHEME_PROP_NAME));
    BOOST_CHECK_EQUAL(three->getUnsignedInt(ModuleConfig::SITE_PORT_PROP_NAME, 0), 0);
    BOOST_CHECK_EQUAL(three->getString(ModuleConfig::SITE_ALIASES_PROP_NAME), "alt.example.org alt2.example.org");
}

BOOST_FIXTURE_TEST_CASE(ModuleConfigTest_ini, ModuleConfigFixture)
{
    unique_ptr<ModuleConfig> config(ModuleConfig::newModuleConfig(string(data_path + "iis.ini").c_str()));
    
    BOOST_CHECK(config->getBool(RequestMapper::USE_VARIABLES_PROP_NAME, true));
    BOOST_CHECK(config->getBool(RequestMapper::USE_HEADERS_PROP_NAME, false));
    
    validateSites(config.get());
}

BOOST_FIXTURE_TEST_CASE(ModuleConfigTest_xml, ModuleConfigFixture)
{
    unique_ptr<ModuleConfig> config(ModuleConfig::newModuleConfig(string(data_path + "iis.xml").c_str()));
    
    BOOST_CHECK(!config->getBool(RequestMapper::USE_VARIABLES_PROP_NAME, true));
    BOOST_CHECK(config->getBool(RequestMapper::USE_HEADERS_PROP_NAME, false));
    BOOST_CHECK(!config->getString(ModuleConfig::AUTHENTICATED_ROLE_PROP_NAME));
    BOOST_CHECK_EQUAL(config->getString(ModuleConfig::ROLE_ATTRIBUTES_PROP_NAME), "foo bar");

    validateSites(config.get());
}

};