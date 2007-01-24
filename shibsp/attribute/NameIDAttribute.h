/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file shibsp/attribute/NameIDAttribute.h
 * 
 * An Attribute whose values are relations of a value and a scope.
 */

#ifndef __shibsp_nameidattr_h__
#define __shibsp_nameidattr_h__

#include <shibsp/attribute/Attribute.h>
#include <xmltooling/exceptions.h>

namespace shibsp {

    /** Default serialization format for NameIDs */
    #define DEFAULT_NAMEID_FORMATTER    "$Name!!$NameQualifier!!$SPNameQualifier"

    /**
     * An Attribute whose values are derived from or mappable to a SAML NameID.
     */
    class SHIBSP_API NameIDAttribute : public Attribute
    {
    public:
        /**
         * Constructor
         * 
         * @param id    Attribute identifier
         */
        NameIDAttribute(const char* id, const char* formatter=DEFAULT_NAMEID_FORMATTER)
            : Attribute(id), m_formatter(formatter) {
        }
        
        virtual ~NameIDAttribute() {}
        
        /**
         * Holds all the fields associated with a NameID.
         */
        struct SHIBSP_API Value
        {
            std::string m_Name;
            std::string m_Format;
            std::string m_NameQualifier;
            std::string m_SPNameQualifier;
            std::string m_SPProvidedID;
        };
        
        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * <p>Each compound value is a pair containing the simple value and the scope. 
         * 
         * @return  a mutable vector of the values
         */
        std::vector<Value>& getValues() {
            return m_values;
        }
        
        size_t valueCount() const {
            return m_values.size();
        }
        
        void clearSerializedValues() {
            m_serialized.clear();
        }
        
        const std::vector<std::string>& getSerializedValues() const {
            if (m_serialized.empty()) {
                for (std::vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
                    // This is kind of a hack, but it's a good way to reuse some code.
                    xmltooling::XMLToolingException e(
                        m_formatter,
                        xmltooling::namedparams(
                            5,
                            "Name", i->m_Name,
                            "Format", i->m_Format,
                            "NameQualifier", i->m_NameQualifier,
                            "SPNameQualifier", i->m_SPNameQualifier,
                            "SPProvidedID", i->m_SPProvidedID
                            )
                        );
                    m_serialized.push_back(e.what());
                }
            }
            return Attribute::getSerializedValues();
        }
    
        DDF marshall() const {
            DDF ddf = Attribute::marshall();
            ddf.name("NameIDAttribute");
            DDF vlist = ddf.addmember("values").list();
            for (std::vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
                DDF val = DDF(NULL).structure();
                val.addmember("Name").string(i->m_Name.c_str());
                if (!i->m_Format.empty())
                    val.addmember("Format").string(i->m_Format.c_str());
                if (!i->m_NameQualifier.empty())
                    val.addmember("NameQualifier").string(i->m_NameQualifier.c_str());
                if (!i->m_SPNameQualifier.empty())
                    val.addmember("SPNameQualifier").string(i->m_SPNameQualifier.c_str());
                if (!i->m_SPProvidedID.empty())
                    val.addmember("SPProvidedID").string(i->m_SPProvidedID.c_str());
                vlist.add(val);
            }
            return ddf;
        }
    
    private:
        std::vector<Value> m_values;
        std::string m_formatter;
    };

};

#endif /* __shibsp_nameidattr_h__ */
