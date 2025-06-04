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
    }

    string data_path;
};

BOOST_FIXTURE_TEST_CASE(FilesystemSessionCache_tests, FilesystemFixture)
{
}

}
