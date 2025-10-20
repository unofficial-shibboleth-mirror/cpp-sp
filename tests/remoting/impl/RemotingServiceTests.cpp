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
 * remoting/impl/RemotingServiceTests.cpp
 *
 * Unit tests for RemotingService implementations.
 */

#include "Agent.h"
#include "AgentConfig.h"
#include "exceptions.h"
#include "remoting/RemotingService.h"

#include <memory>
#include <string>
#include <boost/test/unit_test.hpp>


using namespace shibsp;
using namespace std;

#if defined (_MSC_VER)
#define setenv(name, value, overwrite) _putenv_s(name, value)
#define unsetenv(name) _putenv_s(name, "")
#endif

#define DATA_PATH "./data/remoting/impl/"

namespace {

#ifdef HAVE_CXX14
// Used as test decorator for any tests requiring testbed.
struct testbedRunning {
    boost::test_tools::assertion_result operator()(boost::unit_test::test_unit_id) {
        const char* var = getenv("SHIBSP_TESTBED_RUNNING");
        return var && *var == '1';
    }
};
#endif

struct RemotingFixture
{
    RemotingFixture() : data_path(DATA_PATH) {
        setenv("SHIBSP_AGENT_SECRET", "foo", true);
        AgentConfig::getConfig().init(nullptr, (data_path + "./agent.ini").c_str(), true);
    }
    ~RemotingFixture() {
        AgentConfig::getConfig().term();
        unsetenv("SHIBSP_AGENT_SECRET");
    }

    string data_path;
};

/////////////

#ifdef HAVE_CXX14

BOOST_FIXTURE_TEST_CASE(RemotingService_startup, RemotingFixture)
{
    AgentConfig::getConfig().getAgent().getRemotingService();
}

BOOST_FIXTURE_TEST_CASE(RemotingService_wrong_path, RemotingFixture, * boost::unit_test::precondition(testbedRunning()))
{
    const RemotingService* service = AgentConfig::getConfig().getAgent().getRemotingService();
    DDF input("/missing");
    DDFJanitor injanitor(input);
    BOOST_CHECK_THROW(service->send(input), RemotingException);
}

BOOST_FIXTURE_TEST_CASE(RemotingService_ping, RemotingFixture, * boost::unit_test::precondition(testbedRunning()))
{
    const RemotingService* service = AgentConfig::getConfig().getAgent().getRemotingService();
    DDF input("ping");
    DDFJanitor injanitor(input);

    DDF output = service->send(input);
    DDFJanitor outjanitor(output);
    BOOST_CHECK_LE(output.getmember("epoch").longinteger(), time(nullptr));

    DDF output2 = service->send(input);
    DDFJanitor outjanitor2(output2);
    BOOST_CHECK_LE(output2.getmember("epoch").longinteger(), time(nullptr));
}

#endif

};