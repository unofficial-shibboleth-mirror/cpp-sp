/**
* Licensed to the University Corporation for Advanced Internet
* Development, Inc. (UCAID) under one or more contributor license
* agreements. See the NOTICE file distributed with this work for
* additional information regarding copyright ownership.
*
* UCAID licenses this file to you under the Apache License,
* Version 2.0 (the "License"); you may not use this file except
* in compliance with the License. You may obtain a copy of the
* License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
*/

#include <fstream>

#include <cxxtest/TestSuite.h>
#include <cxxtest/GlobalFixture.h>

#include <shibsp/SPConfig.h>
#include <shibsp/metadata/MetadataExt.h>
#include <shibsp/ServiceProvider.h>

using namespace shibsp;

std::string data_path = "../unittests/data/";
std::string config_path = "../unittests/config";

class ToolingFixture : public CxxTest::GlobalFixture
{
public:
    bool setUpWorld() {
        SPConfig& conf = SPConfig::getConfig();
        // Initialize the SP library.
        conf.setFeatures(
            SPConfig::Metadata |
            SPConfig::Logging);

        if (!conf.init(nullptr, config_path.c_str())) {
            fprintf(stderr, "configuration is invalid, see console for specific problems\n");
            return false;
        }

        if (!conf.instantiate("../configs/shibboleth3.xml")) {
            fprintf(stderr, "configuration is invalid, see console for specific problems\n");
            return false;
        }

        registerMetadataExtClasses();

        return true;
    }
    bool tearDownWorld() {
        SPConfig::getConfig().term();
        SPConfig::getConfig().getServiceProvider();
        return true;
    }
};

static ToolingFixture globalFixture;


class GlobalTest : public CxxTest::TestSuite
{
public:
    void testssrf(void) {
        TS_ASSERT(true);
    }
};
