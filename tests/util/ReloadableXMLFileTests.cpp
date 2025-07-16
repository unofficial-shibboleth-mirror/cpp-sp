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
#include "util/ReloadableXMLFile.h"

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

#ifdef WIN32
#include <Windows.h>
#endif // WIN32

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/util/reloadablefile/"

namespace {

class DummyXMLFile : virtual public ReloadableXMLFile
{
public:
    DummyXMLFile(ptree& pt)
        : ReloadableXMLFile("RequestMap", pt, Category::getInstance("DummyXMLFile")),
            m_log(Category::getInstance("DummyXMLFile")), m_tree(nullptr), m_forceReload(false) {
        if (!load().second) {
            throw domain_error("Invalid configuration.");
        }
    }
    ~DummyXMLFile() {}

    bool isUpdated() const {
        return m_forceReload;
    }

    void forceReload() {
        m_forceReload = true;
    }

    time_t getLastModified() const {
        return ReloadableXMLFile::getLastModified();
    }

protected:
    pair<bool,ptree*> load() noexcept;

private:
    Category& m_log;
    unique_ptr<ptree> m_tree;
    bool m_forceReload;
};

pair<bool,ptree*> DummyXMLFile::load() noexcept
{
    pair<bool,ptree*> ret = ReloadableXMLFile::load();
    if (ret.second) {

        // For test-sake, re-verify the child element.
        const boost::optional<ptree&> child = ret.second->get_child_optional("RequestMap");
        if (!child) {
            return make_pair(false, nullptr);
        }

        if (ret.first) {
            m_log.debug("external config is valid");
        } else {
            m_log.debug("inline config is valid");
            return ret;
        }
    } else {
        return make_pair(false, nullptr);
    }

    // Swap in external config and update timestamp.

#ifdef HAVE_CXX14
    unique_lock<ReloadableXMLFile> locker(*this);
#endif
    unique_ptr<ptree> newtree(ret.second);
    m_tree.swap(newtree);
    updateModificationTime(time(nullptr));

    return ret;
}

class exceptionCheck {
public:
    exceptionCheck(const string& msg) : m_msg(msg) {}
    bool check_message(const exception& e) {
        return m_msg.compare(e.what()) == 0;
    }
private:
    string m_msg;
};

struct ReloadableXMLFileFixture
{
    ReloadableXMLFileFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "console-agent.ini").c_str(), true);
    }
    ~ReloadableXMLFileFixture() {
        AgentConfig::getConfig().term();
    }

    void parse(const string& filename) {
        xml_parser::read_xml(data_path + filename, tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }

    string data_path;
    ptree tree;
};

/////////////

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_external_invalid, ReloadableXMLFileFixture)
{
    parse("external-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Invalid configuration.");
    BOOST_CHECK_EXCEPTION(DummyXMLFile dummy(tree.front().second), domain_error, checker.check_message);
}

/////////////

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_invalid, ReloadableXMLFileFixture)
{
    parse("inline-invalid.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Invalid configuration.");
    BOOST_CHECK_EXCEPTION(DummyXMLFile dummy(tree.front().second), domain_error, checker.check_message);
}

/////////////

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_valid, ReloadableXMLFileFixture)
{
    parse("inline.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts1, 0);
    dummy.unlock_shared();

    // No-op since there's no locking internally.
    dummy.forceReload();
#ifdef WIN32
    Sleep(2);
#else
    sleep(2);
#endif // WIN32

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_EQUAL(ts2, 0);
    dummy.unlock_shared();
}

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_external_valid, ReloadableXMLFileFixture)
{
    parse("external.xml");
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_GT(ts1, 0);
    dummy.unlock_shared();
    dummy.forceReload();
#ifdef WIN32
    Sleep(2000);
#else
    sleep(2);
#endif // WIN32

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_GT(ts2, ts1);
    dummy.unlock_shared();
}

};
