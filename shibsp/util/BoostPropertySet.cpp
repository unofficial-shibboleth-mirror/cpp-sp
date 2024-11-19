/**
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
 * BoostPropertySet.cpp
 * 
 * DOM-based property set implementation.
 */

#include "internal.h"
#include "util/BoostPropertySet.h"

#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace boost;
using namespace std;

PropertySet::PropertySet()
{
}

PropertySet::~PropertySet()
{
}

PropertySet2::PropertySet2()
{
}

PropertySet2::~PropertySet2()
{
}

BoostPropertySet::BoostPropertySet() : m_parent(nullptr)
{
}

BoostPropertySet::~BoostPropertySet()
{
}

const PropertySet2* BoostPropertySet::getParent() const
{
    return m_parent;
}

void BoostPropertySet::setParent(const PropertySet2* parent)
{
    m_parent = parent;
}

void BoostPropertySet::load(const property_tree::ptree& pt, const char* unsetter)
{
    m_pt = &pt;

    // Check for unsetter, pull out and split.
    if (unsetter) {
        const optional<string> val = pt.get_optional<string>(unsetter);
        if (val) {
            split(m_unset, val.get(), is_space(), algorithm::token_compress_on);
        }
    }
}

bool BoostPropertySet::getBool(const char* name, bool defaultValue) const
{
    if (m_pt) {
        // Check for a child node with the target name and return its value as a bool.
        const optional<const property_tree::ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            const string& val = child->data();
            return val == "1" || val == "true";
        }
    }

    // If we have a parent and the setting isn't "unset" at this layer, return its copy.
    if (m_parent && m_unset.find(name) == m_unset.end()) {
        return m_parent->getBool(name, defaultValue);
    }

    // Else return the default.
    return defaultValue;
}

const char* BoostPropertySet::getString(const char* name, const char* defaultValue) const
{
    if (m_pt) {
        // Check for a child node with the target name and return its value as a C string.
        const optional<const property_tree::ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            return child->data().c_str();
        }
    }

    // If we have a parent and the setting isn't "unset" at this layer, return its copy.
    if (m_parent && m_unset.find(name) == m_unset.end()) {
        return m_parent->getString(name, defaultValue);
    }

    // Else return the default.
    return defaultValue;
}

unsigned int BoostPropertySet::getUnsignedInt(const char* name, unsigned int defaultValue) const
{
    if (m_pt) {
        // Check for a child node with the target name and return its value as a C string.
        const optional<const property_tree::ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            try {
                return lexical_cast<unsigned int>(child->data());
            }
            catch (const bad_lexical_cast&) {
            }
        }
    }

    // If we have a parent and the setting isn't "unset" at this layer, return its copy.
    if (m_parent && m_unset.find(name) == m_unset.end()) {
        return m_parent->getUnsignedInt(name, defaultValue);
    }

    // Else return the default.
    return defaultValue;
}

int BoostPropertySet::getInt(const char* name, int defaultValue) const
{
    if (m_pt) {
        // Check for a child node with the target name and return its value as a C string.
        const optional<const property_tree::ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            try {
                return lexical_cast<int>(child->data());
            }
            catch (const bad_lexical_cast&) {
            }
        }
    }

    // If we have a parent and the setting isn't "unset" at this layer, return its copy.
    if (m_parent && m_unset.find(name) == m_unset.end()) {
        return m_parent->getInt(name, defaultValue);
    }

    // Else return the default.
    return defaultValue;
}
