#include <fstream>
#include "BaseTestCase.h"
#include <cxxtest/GlobalFixture.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>

using namespace xmltooling;
using namespace xercesc;
using namespace std;


string data_path = "../xmltoolingtest/data/";

class ToolingFixture : public CxxTest::GlobalFixture
{
public:
    bool setUpWorld() {
        return true;
    }
    bool tearDownWorld() {
        return true;
    }
    //bool setUp() { printf( "</test>" ); return true; }
    //bool tearDown() { printf( "</test>" ); return true; }
};


class GlobalTest : public CxxTest::TestSuite
{
public:
    void testssrf(void) {
        TS_ASSERT(true);
    }
};