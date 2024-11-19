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
 * BoostPropertySetTests.cpp
 *
 * Unit tests for BoostPropertySet usage.
 */

#include "util/BoostPropertySet.h"

#include <memory>
#include <vector>
#include <boost/test/unit_test.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace std;
namespace pt = boost::property_tree;

#define DATA_PATH "data/util/boostpropset/"

struct BPS_Fixture {
    BPS_Fixture() : data_path(DATA_PATH) {}
    string data_path;
};

BOOST_FIXTURE_TEST_CASE(BoostPropertySet_ini, BPS_Fixture)
{
    pt::ptree tree;
    pt::read_ini(data_path + "attributes.ini", tree);

    BoostPropertySet props;
    props.load(tree);

    BOOST_CHECK_EQUAL(props.getBool("config.UseEnvironment", false), true);
    BOOST_CHECK_EQUAL(props.getBool("config.UseHeaders", false), false);

    BOOST_CHECK_EQUAL(props.getString("mappings.foo"), "bar");
    BOOST_CHECK_EQUAL(props.getString("mappings.bar"), "baz");

    // Test invalid conversions.
    BOOST_CHECK_EQUAL(props.getInt("mappings.foo", 42), 42);
    BOOST_CHECK_EQUAL(props.getUnsignedInt("mappings.bar", 42), 42);
}

// Exposes setParent as public method for test.
class TestBoostPropertySet : public virtual BoostPropertySet {
public:
    TestBoostPropertySet() {} 
    virtual ~TestBoostPropertySet() {}

    void setParent(const PropertySet2* parent) {
        BoostPropertySet::setParent(parent);
    }
};

BOOST_FIXTURE_TEST_CASE(BoostPropertySet_tree, BPS_Fixture)
{
    pt::ptree tree;
    pt::read_xml(data_path + "tree.xml", tree);

    // Holds the heap objects, and provides simple access to them.
    // In a real scenario, there would be a mesh of "real" objects connected
    // while exposing a PropertySet interface.
    vector<unique_ptr<TestBoostPropertySet>> ones;
    vector<unique_ptr<TestBoostPropertySet>> twos;

    // Set up nested tree of PropertySets wrapped around each layer's <xmlattr> node.

    const pt::ptree& root = tree.get_child("root");
    TestBoostPropertySet rootset;
    const boost::optional<const pt::ptree&> xmlattr = root.get_child_optional("<xmlattr>");
    if (xmlattr) {
        rootset.load(xmlattr.get(), "unset");
    }

    for (const pair<const string,pt::ptree>& child : root) {
        if (child.first == "one") {
            ones.push_back(make_unique<TestBoostPropertySet>());
            const auto& one = ones.back();
            const boost::optional<const pt::ptree&> xmlattr = child.second.get_child_optional("<xmlattr>");
            if (xmlattr) {
                one->load(xmlattr.get(), "unset");
            }
            one->setParent(&rootset);

            for (const pair<const string,pt::ptree>& child2 : child.second) {
                if (child2.first == "two") {
                    twos.push_back(make_unique<TestBoostPropertySet>());
                    const auto& two = twos.back();
                    const boost::optional<const pt::ptree&> xmlattr = child2.second.get_child_optional("<xmlattr>");
                    if (xmlattr) {
                        two->load(xmlattr.get(), "unset");
                    }
                    two->setParent(one.get());
                }
            }
        }
    }

    BOOST_CHECK_EQUAL(ones.size(), 2);
    BOOST_CHECK_EQUAL(twos.size(), 2);
    BOOST_CHECK_EQUAL(rootset.getString("foo"), "bar");
    BOOST_CHECK_EQUAL(rootset.getString("zork"), "frobnitz");
    BOOST_CHECK_EQUAL(rootset.getString("<xmlattr>"), nullptr);
    BOOST_CHECK_EQUAL(rootset.getString("one"), nullptr);

    BOOST_CHECK_EQUAL(ones[0]->getString("foo"), "baz");
    BOOST_CHECK_EQUAL(ones[0]->getString("zork"), "frobnitz");
    BOOST_CHECK_EQUAL(ones[0]->getString("<xmlattr>"), nullptr);
    BOOST_CHECK_EQUAL(ones[0]->getString("two"), nullptr);

    BOOST_CHECK_EQUAL(ones[1]->getString("foo", "zork"), "zork");
    BOOST_CHECK_EQUAL(ones[1]->getString("zork"), nullptr);
    BOOST_CHECK_EQUAL(ones[1]->getString("<xmlattr>"), nullptr);
    BOOST_CHECK_EQUAL(ones[1]->getString("two"), nullptr);

    BOOST_CHECK_EQUAL(twos[0]->getString("foo"), "baz");
    BOOST_CHECK_EQUAL(twos[0]->getString("zork"), "frobnitz");
    BOOST_CHECK_EQUAL(twos[0]->getString("<xmlattr>"), nullptr);

    BOOST_CHECK_EQUAL(twos[1]->getString("unset"), "foo zork");
    BOOST_CHECK_EQUAL(twos[1]->getString("foo"), nullptr);
    BOOST_CHECK_EQUAL(twos[1]->getString("zork"), "zorkmid");
    BOOST_CHECK_EQUAL(twos[1]->getString("<xmlattr>"), nullptr);
}
