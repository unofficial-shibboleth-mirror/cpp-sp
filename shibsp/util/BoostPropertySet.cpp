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
 * util/BoostPropertySet.cpp
 * 
 * Boost propertytree-based property set implementation.
 */

#include "internal.h"
#include "util/BoostPropertySet.h"
#include "util/Misc.h"

#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

PropertySet::PropertySet()
{
}

PropertySet::~PropertySet()
{
}

const char BoostPropertySet::XMLATTR_NODE_NAME[] = "<xmlattr>";

BoostPropertySet::BoostPropertySet() : m_parent(nullptr), m_pt(nullptr)
{
}

BoostPropertySet::~BoostPropertySet()
{
}

const PropertySet* BoostPropertySet::getParent() const
{
    return m_parent;
}

void BoostPropertySet::setParent(const PropertySet* parent)
{
    m_parent = parent;
}

void BoostPropertySet::load(const ptree& pt, const char* unsetter)
{
    // Check for <xmlattr> in case this was an XML-based tree.
    const boost::optional<const ptree&> xmlattr = pt.get_child_optional(XMLATTR_NODE_NAME);
    if (xmlattr) {
        m_pt = &xmlattr.get();
    }
    else {
        m_pt = &pt;
    }

    // Check for unsetter, pull out and split.
    if (unsetter) {
        const boost::optional<string> val = m_pt->get_optional<string>(unsetter);
        if (val) {
            split_to_container(m_unset, val.get().c_str());
        }
    }
}

bool BoostPropertySet::hasProperty(const char* name) const
{
    if (m_pt) {
        bool ret = m_pt->get_child_optional(name).has_value();
        if (ret) {
            return ret;
        }
    }

    if (m_parent && m_unset.find(name) == m_unset.end()) {
        return m_parent->hasProperty(name);
    }
    return false;
}

bool BoostPropertySet::getBool(const char* name, bool defaultValue) const
{
    if (m_pt) {
        // Check for a child node with the target name and return its value as a bool.
        const boost::optional<const ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            static string_to_bool_translator tr;
            return child.get().get_value(defaultValue, tr);
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
        const boost::optional<const ptree&> child = m_pt->get_child_optional(name);
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
        const boost::optional<const ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            try {
                return boost::lexical_cast<unsigned int>(child->data());
            }
            catch (const boost::bad_lexical_cast&) {
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
        const boost::optional<const ptree&> child = m_pt->get_child_optional(name);
        if (child) {
            try {
                return boost::lexical_cast<int>(child->data());
            }
            catch (const boost::bad_lexical_cast&) {
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
