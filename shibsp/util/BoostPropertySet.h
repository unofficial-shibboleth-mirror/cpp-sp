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
 * @file shibsp/util/DOMPropertySet.h
 * 
 * DOM-based property set implementation.
 */

#ifndef __shibsp_boostpropset_h__
#define __shibsp_boostpropset_h__

#include <shibsp/util/PropertySet.h>

#include <set>
#include <boost/property_tree/ptree.hpp>

namespace shibsp {

    /**
     * Boost property tree-based property set implementation.
     */
    class SHIBSP_API BoostPropertySet : public virtual PropertySet2
    {
    public:
        BoostPropertySet();
        
        virtual ~BoostPropertySet();

        const PropertySet2* getParent() const;
        void setParent(const PropertySet2* parent);
        bool getBool(const char* name, bool defaultValue) const;
        const char* getString(const char* name, const char* defaultValue) const;
        unsigned int getUnsignedInt(const char* name, unsigned int defaultValue) const;
        int getInt(const char* name, int defaultValue) const;

        /**
         * Loads the property set from a ptree owned and managed by the caller.
         * 
         * @param pt        property tree instance to wrap
		 * @param unsetter  optional name of a property containing a list of property names to "unset"
         */
        void load(const boost::property_tree::ptree& pt, const char* unsetter=nullptr);

    private:
        const PropertySet2* m_parent;
        const boost::property_tree::ptree* m_pt;
		std::set<std::string> m_unset;
    };

};

#endif /* __shibsp_boostpropset_h__ */
