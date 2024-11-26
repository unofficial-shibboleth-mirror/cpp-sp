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
 * AgentConfigTests.cpp
 *
 * Unit tests for agent config machinery and logging.
 */

#include <stdexcept>

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include "AgentConfig.h"

using namespace boost::property_tree::ini_parser;
using namespace shibsp;
using namespace std;

// The ./ bypasses the usual path resolution for relative paths.
#define DATA_PATH "./data/"

struct AC_Fixture {
    AC_Fixture() : data_path(DATA_PATH) {}
    string data_path;
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

BOOST_FIXTURE_TEST_CASE(AgentConfig_init_bad_path, AC_Fixture)
{
    BOOST_CHECK(!AgentConfig::getConfig().init(nullptr, (data_path + "missing.ini").c_str(), false));

    exceptionCheck checker("./data/missing.ini: cannot open file");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "missing.ini").c_str(), true),
        ini_parser_error, checker.check_message);
}

BOOST_FIXTURE_TEST_CASE(AgentConfig_init_bad_format, AC_Fixture)
{
    exceptionCheck checker_unmatched("./data/unmatched_shibboleth.ini(1): unmatched '['");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "unmatched_shibboleth.ini").c_str(), true),
        ini_parser_error, checker_unmatched.check_message);

    exceptionCheck checker_dupsection("./data/dupsection_shibboleth.ini(4): duplicate section name");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "dupsection_shibboleth.ini").c_str(), true),
        ini_parser_error, checker_dupsection.check_message);

    exceptionCheck checker_noequals("./data/noequals_shibboleth.ini(2): '=' character not found in line");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "noequals_shibboleth.ini").c_str(), true),
        ini_parser_error, checker_noequals.check_message);

    exceptionCheck checker_dupproperty("./data/dupproperty_shibboleth.ini(3): duplicate key name");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "dupproperty_shibboleth.ini").c_str(), true),
        ini_parser_error, checker_dupproperty.check_message);

    exceptionCheck checker_nokey("./data/nokey_shibboleth.ini(2): key expected");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().init(nullptr, (data_path + "nokey_shibboleth.ini").c_str(), true),
        ini_parser_error, checker_nokey.check_message);
}

BOOST_AUTO_TEST_CASE(AgentConfig_term_without_init)
{
    exceptionCheck checker_term("Library terminated without initialization.");
    BOOST_CHECK_EXCEPTION(AgentConfig::getConfig().term(),
        runtime_error, checker_term.check_message);
}

BOOST_FIXTURE_TEST_CASE(AgentConfig_init_success, AC_Fixture)
{
    BOOST_CHECK(AgentConfig::getConfig().init(nullptr, (data_path + "shibboleth.ini").c_str(), true));
    AgentConfig::getConfig().term();
}
