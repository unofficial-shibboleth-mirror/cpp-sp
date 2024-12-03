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
 * ReloadableFileTests.cpp
 *
 * Unit tests for reloadable file usage.
 */

#include "AgentConfig.h"
#include "logging/Category.h"
#include "util/ReloadableFile.h"

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/util/reloadablefile/"

struct RF_Fixture {
    RF_Fixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "console-shibboleth.ini").c_str(), true);
    }
    ~RF_Fixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
};

class DummyXMLFile : virtual public ReloadableFile
{
public:
    DummyXMLFile(const string& source, bool reloadable)
        : ReloadableFile(source, Category::getInstance("DummyXMLFile"), reloadable),
            m_log(Category::getInstance("DummyXMLFile")), m_tree(nullptr) {
        if (!load()) {
            m_log.error("initial configuration was invalid");
        }
    }
    ~DummyXMLFile() {}

    time_t getLastModified() const {
        return ReloadableFile::getLastModified();
    }

protected:
    bool load();

private:
    Category& m_log;
    unique_ptr<ptree> m_tree;
};

bool DummyXMLFile::load()
{
#ifdef HAVE_CXX14
    unique_lock<ReloadableFile> locker(*this);
#endif
    try {
        unique_ptr<ptree> newtree = unique_ptr<ptree>(new ptree());
        xml_parser::read_xml(getSource(), *newtree, xml_parser::no_comments|xml_parser::trim_whitespace);
        m_tree.swap(newtree);
        return ReloadableFile::load();
    } catch (const bad_alloc& e) {
        m_log.crit("out of memory parsing XML configuration (%s)", getSource().c_str());
    } catch (const xml_parser_error& e) {
        m_log.error("failed to process XML configuration (%s): %s", getSource().c_str(), e.what());
    }
    return false;
}

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_noreload, RF_Fixture)
{
    DummyXMLFile dummy(data_path + "requestmap1.xml", false);

    time_t ts = dummy.getLastModified();
    BOOST_CHECK_GT(ts, 0);
}
