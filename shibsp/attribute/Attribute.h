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
 * @file shibsp/attribute/Attribute.h
 * 
 * A resolved attribute.
 */

#ifndef __shibsp_attribute_h__
#define __shibsp_attribute_h__

#include <shibsp/remoting/ddf.h>

#include <string>
#include <vector>

namespace shibsp {

    /**
     * A resolved attribute.
     * 
     * <p>Resolved attributes are a neutral construct that represent both simple and
     * complex attribute data structures that might be found in SAML assertions
     * or obtained from other sources.
     * 
     * <p>Attributes consist of an id/name that is locally unique (that is, unique to a
     * configuration at any given point in time) and zero or more values. Values can
     * be of any type or structure, but will generally be made available to applications
     * only if a serialized string form exists. More complex values can be used with
     * access control plugins that understand them, however. 
     */
    class SHIBSP_API Attribute
    {
        MAKE_NONCOPYABLE(Attribute);
    protected:
        /**
         * Constructor
         * 
         * @param id    Attribute identifier 
         */
        Attribute(const char* id) : m_id(id) {}

        /**
         * Maintains a copy of serialized attribute values, when possible.
         * 
         * <p>Implementations should maintain the array when values are added or removed.
         */
        mutable std::vector<std::string> m_serialized;

    public:
        virtual ~Attribute() {}
        
        /**
         * Returns the Attribute identifier.
         * 
         * @return Attribute identifier
         */
        const char* getId() const {
            return m_id.c_str();
        }
        
        /**
         * Returns serialized attribute values encoded as UTF-8 strings.
         * 
         * @return  an immutable vector of values
         */
        virtual const std::vector<std::string>& getSerializedValues() const {
            return m_serialized;
        }
        
        /**
         * Informs the attribute that values have changed and any serializations
         * must be cleared. 
         */
        virtual void clearSerializedValues()=0;
        
        /**
         * Marshalls an Attribute for remoting.
         * 
         * This allows Attribute objects to be communicated across process boundaries
         * without excess XML parsing. The DDF returned must be a struct containing
         * a string member called "id" and a list called "values". The name of the struct
         * should contain the registered name of the Attribute implementation.  
         */
        virtual DDF marshall() const {
            DDF ddf(NULL);
            ddf.structure().addmember("id").string(m_id.c_str());
            return ddf;
        }
        
    private:
        std::string m_id;
    };

};

#endif /* __shibsp_attribute_h__ */
