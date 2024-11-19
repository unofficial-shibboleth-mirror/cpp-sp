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
 * PropertyTreeTests.cpp
 *
 * Unit tests for property tree usage.
 */

#include <boost/test/unit_test.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace std;
namespace pt = boost::property_tree;

#define DATA_PATH "data/util/propertytree/"

struct PT_Fixture {
    PT_Fixture() : data_path(DATA_PATH) {}
    string data_path;
};

BOOST_FIXTURE_TEST_CASE(PropertyTree_RequestMap_simple, PT_Fixture)
{
    pt::ptree tree;
    pt::read_xml(data_path + "requestmap1.xml", tree);

    BOOST_CHECK_EQUAL(tree.size(), 1);

    const pt::ptree& requestMap = tree.get_child("RequestMap");
    BOOST_CHECK_EQUAL(requestMap.size(), 2);

    for (const pair<const string,pt::ptree>& child : requestMap) {
        BOOST_CHECK_EQUAL(child.first, "Host");

        BOOST_CHECK_GE(child.second.size(), 1);
        const pt::ptree& attrs = child.second.get_child("<xmlattr>");
        string name = attrs.get<string>("name");
        if (name == "sp.example.org") {
            BOOST_CHECK_EQUAL(child.second.size(), 2);
            BOOST_CHECK_EQUAL(attrs.size(), 1);
            BOOST_CHECK_EQUAL(child.second.get<string>("Path.<xmlattr>.name"), "secure");
            BOOST_CHECK_EQUAL(child.second.get<string>("Path.<xmlattr>.requireSession"), "true");
        } else if (name == "admin.example.org") {
            // Nothing in Host element except the <xmlattr> tree.
            BOOST_CHECK_EQUAL(child.second.size(), 1);
            // Three XML attributes, including name.
            BOOST_CHECK_EQUAL(attrs.size(), 3);
            BOOST_CHECK_EQUAL(attrs.get<string>("applicationId"), "admin");
            BOOST_CHECK_EQUAL(attrs.get<string>("requireSession"), "true");
        } else {
            BOOST_ERROR("Unexpected Host name: " << name);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(PropertyTree_RequestMap_utf8, PT_Fixture)
{
    pt::ptree tree;
    pt::read_xml(data_path + "requestmap2.xml", tree);

    BOOST_CHECK_EQUAL(tree.size(), 1);

    const pt::ptree& requestMap = tree.get_child("RequestMap");
    BOOST_CHECK_EQUAL(requestMap.size(), 1);

    for (const pair<string,pt::ptree>& child : requestMap) {
        BOOST_CHECK_EQUAL(child.first, "Host");

        BOOST_CHECK_EQUAL(child.second.size(), 2);
        const pt::ptree& attrs = child.second.get_child("<xmlattr>");
        string name = attrs.get<string>("name");
        if (name == "sp.example.org") {
            BOOST_CHECK_EQUAL(attrs.size(), 1);
            BOOST_CHECK_EQUAL(child.second.get<string>("Path.<xmlattr>.name"), "secure/☯️");
            BOOST_CHECK_EQUAL(child.second.get<string>("Path.<xmlattr>.requireSession"), "true");
        } else {
            BOOST_ERROR("Unexpected Host name: " << name);
        }
    }
}
