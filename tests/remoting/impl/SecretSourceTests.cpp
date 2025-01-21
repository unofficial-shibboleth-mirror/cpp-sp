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
 * remoting/impl/SecretSourceTests.cpp
 *
 * Unit tests for SecretSource implementations.
 */

#include "AgentConfig.h"
#include "exceptions.h"
#include "remoting/SecretSource.h"

#include <memory>
#include <string>
#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ini_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/remoting/impl/"

namespace {

struct SecretSourceFixture
{
    SecretSourceFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "../../console-shibboleth.ini").c_str(), true);
    }
    ~SecretSourceFixture() {
        AgentConfig::getConfig().term();
    }

    void parse(const string& filename) {
        ini_parser::read_ini(data_path + filename, tree);
    }

    ptree tree;
    string data_path;
};

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_file_invalid, SecretSourceFixture)
{
    parse("invalid.ini");

    BOOST_CHECK_THROW(
        AgentConfig::getConfig().SecretSourceManager.newPlugin(FILE_SECRET_SOURCE, tree, false),
        ConfigurationException);
}

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_file_missing, SecretSourceFixture)
{
    parse("file-missing.ini");

    BOOST_CHECK_THROW(
        AgentConfig::getConfig().SecretSourceManager.newPlugin(FILE_SECRET_SOURCE, tree, false),
        IOException);
}

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_file, SecretSourceFixture)
{
    parse("file.ini");

    unique_ptr<SecretSource> source(AgentConfig::getConfig().SecretSourceManager.newPlugin(FILE_SECRET_SOURCE, tree, false));
    BOOST_CHECK_EQUAL(source->getSecret(), string("password!"));
}

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_env_invalid, SecretSourceFixture)
{
    parse("invalid.ini");

    BOOST_CHECK_THROW(
        AgentConfig::getConfig().SecretSourceManager.newPlugin(ENV_SECRET_SOURCE, tree, false),
        ConfigurationException);
}

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_env_missing, SecretSourceFixture)
{
    parse("env.ini");

    BOOST_CHECK_THROW(
        AgentConfig::getConfig().SecretSourceManager.newPlugin(ENV_SECRET_SOURCE, tree, false),
        IOException);
}

/////////////

BOOST_FIXTURE_TEST_CASE(SecretSourceTest_env, SecretSourceFixture)
{
    parse("env.ini");

    setenv("SHIB_SECRET", "password!", true);

    unique_ptr<SecretSource> source(AgentConfig::getConfig().SecretSourceManager.newPlugin(ENV_SECRET_SOURCE, tree, false));
    BOOST_CHECK_EQUAL(source->getSecret(), string("password!"));
}
};