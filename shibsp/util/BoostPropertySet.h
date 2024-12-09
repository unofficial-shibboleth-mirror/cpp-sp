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
 * @file shibsp/util/BoostPropertySet.h
 * 
 * Boost propertytree-based property set implementation.
 */

#ifndef __shibsp_boostpropset_h__
#define __shibsp_boostpropset_h__

#include <shibsp/util/PropertySet.h>

#include <set>
#include <boost/property_tree/ptree.hpp>

#if defined (_MSC_VER)
#    pragma warning( push )
#    pragma warning( disable : 4251 )
#endif

namespace shibsp {

    /**
     * Boost property tree-based property set implementation.
     * 
     * <p>This implementation is generally suitable only for trees created
     * by hand or that are parsed via one of the non-XML parsing methods.</p>
     * 
     * <p>The XML-based representation uses special "reserved" property node
     * names for attributes and element content and can therefore not be used
     * directly as a means of exposing the properties via this interface.</p>
     */
    class SHIBSP_API BoostPropertySet : public virtual PropertySet2
    {
    public:
        BoostPropertySet();
        virtual ~BoostPropertySet();

        bool getBool(const char* name, bool defaultValue) const;
        const char* getString(const char* name, const char* defaultValue=nullptr) const;
        unsigned int getUnsignedInt(const char* name, unsigned int defaultValue) const;
        int getInt(const char* name, int defaultValue) const;

        /**
         * Loads the property set from a ptree owned and managed by the caller.
         * 
         * @param pt        property tree instance to wrap
		 * @param unsetter  optional name of a property containing a list of property names to "unset"
         */
        void load(const boost::property_tree::ptree& pt, const char* unsetter=nullptr);

    protected:
        /**
         * Returns the parent PropertySet.
         * 
         * @return parent PropertySet
         */
        const PropertySet2* getParent() const;

        /**
         * Installs a parent PropertySet to allow an inheritance relationship to a different instance.
         * 
         * @param parent the parent PropertySet to install
         */
        void setParent(const PropertySet2* parent);

    private:
        const PropertySet2* m_parent;
        const boost::property_tree::ptree* m_pt;
		std::set<std::string> m_unset;
    };

#if defined (_MSC_VER)
#   pragma warning( pop )
#endif

};

#endif /* __shibsp_boostpropset_h__ */
