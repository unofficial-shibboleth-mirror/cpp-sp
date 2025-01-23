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
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/remoting/impl/"

namespace {

struct RemotingFixture
{
    RemotingFixture() : data_path(DATA_PATH) {
        setenv("SHIBSP_AGENT_SECRET", "foo", true);
        AgentConfig::getConfig().init(nullptr, (data_path + "./shibboleth.ini").c_str(), true);
    }
    ~RemotingFixture() {
        AgentConfig::getConfig().term();
        unsetenv("SHIBSP_AGENT_SECRET");
    }

    string data_path;
};

/////////////

BOOST_FIXTURE_TEST_CASE(RemotingService_test, RemotingFixture)
{
    AgentConfig::getConfig().getAgent().getRemotingService();
}

};