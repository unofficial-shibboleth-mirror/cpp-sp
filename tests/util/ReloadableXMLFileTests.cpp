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

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#define DATA_PATH "./data/util/reloadablefile/"

namespace {

class DummyXMLFile : virtual public ReloadableXMLFile
{
public:
    DummyXMLFile(const ptree& pt)
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

struct BaseFixture
{
    BaseFixture() : data_path(DATA_PATH) {
        AgentConfig::getConfig().init(nullptr, (data_path + "console-shibboleth.ini").c_str(), true);
    }
    ~BaseFixture() {
        AgentConfig::getConfig().term();
    }
    string data_path;
};

/////////////

struct External_Invalid_Fixture : public BaseFixture
{
    External_Invalid_Fixture() {
        xml_parser::read_xml(data_path + "external-invalid.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~External_Invalid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_external_invalid, External_Invalid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Invalid configuration.");
    BOOST_CHECK_EXCEPTION(DummyXMLFile dummy(tree.front().second), domain_error, checker.check_message);
}

/////////////

struct Inline_Invalid_Fixture : public BaseFixture
{
    Inline_Invalid_Fixture() {
        xml_parser::read_xml(data_path + "inline-invalid.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~Inline_Invalid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_invalid, Inline_Invalid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);

    exceptionCheck checker("Invalid configuration.");
    BOOST_CHECK_EXCEPTION(DummyXMLFile dummy(tree.front().second), domain_error, checker.check_message);
}

/////////////

struct Inline_Valid_Fixture : public BaseFixture
{
    Inline_Valid_Fixture() {
        xml_parser::read_xml(data_path + "inline.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~Inline_Valid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_inline_valid, Inline_Valid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

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

struct External_Valid_Fixture : public BaseFixture
{
    External_Valid_Fixture() {
        xml_parser::read_xml(data_path + "external.xml", tree, xml_parser::no_comments|xml_parser::trim_whitespace);
    }
    ~External_Valid_Fixture() {
    }

    ptree tree;
};

BOOST_FIXTURE_TEST_CASE(ReloadableFileTest_external_valid, External_Valid_Fixture)
{
    BOOST_CHECK_EQUAL(tree.size(), 1);
    DummyXMLFile dummy(tree.front().second);

    dummy.lock_shared();
    time_t ts1 = dummy.getLastModified();
    BOOST_CHECK_GT(ts1, 0);
    dummy.unlock();

    dummy.forceReload();
    sleep(2);

    dummy.lock_shared();
    time_t ts2 = dummy.getLastModified();
    BOOST_CHECK_GT(ts2, ts1);
    dummy.unlock();
}

};