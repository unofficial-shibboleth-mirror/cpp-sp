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

        if (!conf.instantiate("./configs/shibboleth2.xml")) /*
            
            (std::string("<SPConfig type='XML' xmlns='urn:mace:shibboleth:2.0:native:sp:config' xmlns:conf='urn:mace:shibboleth:2.0:native:sp:config'\n") +
                              std::string("xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol'\n") +
                              std::string("xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' clockSkew='180'> \n") +
                              std::string("<conf:SecurityPolicyProvider type='XML' validate='true' path='..\cpp-sp\configs\security-policy.xml' /> </SPConfig>\n")).c_str()))/*
        "<SecurityPolicyProvider xmlns='urn:mace:shibboleth:2.0:native:sp:config' type='XML' validate='true' path='../cpp-sp/configs/security-policy.xml' />"))*/ {
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