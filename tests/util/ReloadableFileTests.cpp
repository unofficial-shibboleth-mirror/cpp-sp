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

struct Inline_Fixture {
    Inline_Fixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "console-shibboleth.ini").c_str(), true);
        xml_parser::read_xml(data_path + "inline.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~Inline_Fixture() {
        AgentConfig::getConfig().term();
    }

    string data_path;
    ptree tree;
};

class DummyXMLFile : virtual public ReloadableFile
{
public:
    DummyXMLFile(const ptree& pt)
        : ReloadableFile(pt, Category::getInstance("DummyXMLFile")),
            m_log(Category::getInstance("DummyXMLFile")), m_tree(nullptr), m_forceReload(false) {

        load();
    }
    ~DummyXMLFile() {}

    bool isUpdated() const {
        return m_forceReload;
    }

    void forceReload() {
        m_forceReload = true;
    }

    time_t getLastModified() const {
        return ReloadableFile::getLastModified();
    }

protected:
    pair<bool,ptree*> load();

private:
    Category& m_log;
    unique_ptr<ptree> m_tree;
    bool m_forceReload;
};

pair<bool,ptree*> DummyXMLFile::load()
{
    pair<bool,ptree*> ret = ReloadableFile::load();
    if (ret.second) {
        if (ret.first) {
            m_log.debug("external config is valid");
        } else {
            m_log.debug("inline config is valid");
            return ret;
        }
    } else {
        m_log.error("initial configuration was invalid");
        return ret;
    }

    // Swap in external config and update timestamp.

#ifdef HAVE_CXX14
    unique_lock<ReloadableFile> locker(*this);
#endif
    unique_ptr<ptree> newtree(ret.second);
    m_tree.swap(newtree);
    updateModificationTime(time(nullptr));

    return ret;
}

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_no_reload, Inline_Fixture)
{
    DummyXMLFile dummy(tree);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts1, 0);
    dummy.unlock();

    // No-op since there's no locking internally.
    dummy.forceReload();
    sleep(2);

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts2, 0);
    dummy.unlock();
}
