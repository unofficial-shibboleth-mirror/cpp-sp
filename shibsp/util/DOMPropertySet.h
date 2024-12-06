/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file shibsp/util/DOMPropertySet.h
 * 
 * DOM-based property set implementation.
 */

#ifndef __shibsp_dompropset_h__
#define __shibsp_dompropset_h__

#include <shibsp/util/PropertySet.h>

#include <set>
#include <boost/shared_ptr.hpp>

#if defined (_MSC_VER)
#    pragma warning( push )
#    pragma warning( disable : 4251 )
#endif

namespace xmltooling {
	class QName;
}

namespace shibsp {

    /**
     * DOM-based property set implementation.
     */
    class SHIBSP_API DOMPropertySet : public virtual PropertySet
    {
    public:
        DOMPropertySet();
        
        virtual ~DOMPropertySet();

        const PropertySet* getParent() const;
        void setParent(const PropertySet* parent);
        std::pair<bool,bool> getBool(const char* name) const;
        std::pair<bool,const char*> getString(const char* name) const;
        std::pair<bool,unsigned int> getUnsignedInt(const char* name) const;
        std::pair<bool,int> getInt(const char* name) const;
        const PropertySet* getPropertySet(const char* name) const;

        /**
         * Interface that remaps property names for legacy support.
         */
        class SHIBSP_API Remapper {
            MAKE_NONCOPYABLE(Remapper);
        protected:
            /** Constructor. */
            Remapper();

        public:
            /** Destructor. */
            virtual ~Remapper();

            /**
             * Remap a name (or return it unchanged).
             *
             * @param src original name
             * @param log logger to use
             *
             * @return the name to use
             */
            virtual const char* remap(const char* src, Category& log) const=0;
        };

        /**
         * Concrete remapper that relies on an STL map.
         */
        class SHIBSP_API STLRemapper : public Remapper {
        public:
            /**
             * Constructor.
             *
             * @param rules remapping rules
             */
            STLRemapper(const std::map<std::string,std::string>& rules);
            virtual ~STLRemapper();

            const char* remap(const char* src, Category& log) const;

        private:
            const std::map<std::string, std::string>& m_rules;
        };

        /**
         * Loads the property set from a DOM element.
         * 
         * @param e         root element of property set
         * @param log       optional log object for tracing
         * @param filter    optional filter controls what child elements to include as nested PropertySets
         * @param remapper  optional mapper of property rename rules for legacy property support
		 * @param unsetter  optional name of a property containing a list of property names to "unset"
         */
        void load(
            const xercesc::DOMElement* e,
            Category* log=nullptr,
            xercesc::DOMNodeFilter* filter=nullptr,
            const Remapper* remapper=nullptr,
			const xmltooling::QName* unsetter=nullptr
            );

    protected:
        /**
         * Post-load injection of a property, for use by subclasses.
         *
         * @param name  property name
         * @param val   property value
         * @param ns    property namespace
         * @return  true iff the property was successfully set
         */
        bool setProperty(const char* name, const char* val);

    private:
        const PropertySet* m_parent;
        const xercesc::DOMElement* m_root;
        std::map<std::string,std::pair<char*,const XMLCh*> > m_map;
		std::set<std::string> m_unset;
        std::map< std::string,boost::shared_ptr<DOMPropertySet> > m_nested;
        std::vector<xmltooling::xstring> m_injected;
    };

};

#if defined (_MSC_VER)
#   pragma warning( pop )
#endif

#endif /* __shibsp_dompropset_h__ */
