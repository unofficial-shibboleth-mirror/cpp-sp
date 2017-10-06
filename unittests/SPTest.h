#include <fstream>
#include "BaseTestCase.h"
#include <shibsp/SPConfig.h>
#include <cxxtest/GlobalFixture.h>
#include <shibsp\metadata\MetadataExt.h>
#include <shibsp\ServiceProvider.h>

using namespace shibsp;

std::string data_path = "unittests/data/";
std::string config_path = "unittests/config";

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

        registerMetadataExtClasses();

        return true;
    }
    bool tearDownWorld() {
        SPConfig::getConfig().term();
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