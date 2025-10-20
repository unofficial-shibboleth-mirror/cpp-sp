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
#include "attribute/AttributeConfiguration.h"

#include <iostream>
#include <memory>

#include <boost/property_tree/ini_parser.hpp>
#include <boost/test/unit_test.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/attribute/impl/"

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

struct AttributeConfigFixture
{
    AttributeConfigFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "./console-agent.ini").c_str(), true);
    }
    ~AttributeConfigFixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
};

BOOST_FIXTURE_TEST_CASE(AttributeConfigTest_ini_invalid, AttributeConfigFixture)
{
    exceptionCheck checker(data_path + "attributes-bad.ini(1): unmatched '['");
    BOOST_CHECK_EXCEPTION(AttributeConfiguration::newAttributeConfiguration(string(data_path + "attributes-bad.ini").c_str()),
            ini_parser_error, checker.check_message);
}

BOOST_FIXTURE_TEST_CASE(AttributeConfigTest_ini, AttributeConfigFixture)
{
    unique_ptr<AttributeConfiguration> config(AttributeConfiguration::newAttributeConfiguration(string(data_path + "attributes.ini").c_str()));
    
    BOOST_CHECK_EQUAL(config->getString("scopeDelimiter"), "/");
    BOOST_CHECK(!config->getBool("exportDuplicateValues", true));
    BOOST_CHECK_EQUAL(config->getString("caseInsensitiveAttributes"), "foo bar");
    BOOST_CHECK_EQUAL(config->getString("encoding"), "URL");
    BOOST_CHECK_EQUAL(config->getString(AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_NAME,
            AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT),
        AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT);
}

};