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
 * @file shibsp/attribute/BinaryAttribute.h
 * 
 * An Attribute whose values are binary data.
 */

#ifndef __shibsp_binattr_h__
#define __shibsp_binattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * An Attribute whose values are binary data.
     * 
     * <p>Binary attributes use base64 encoding to serialize their values.
     * The original binary values are accessible in the underlying value
     * collection.
     */
    class SHIBSP_API BinaryAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids   array with primary identifier in first position, followed by any aliases
         */
        BinaryAttribute(const std::vector<std::string>& ids);

        /**
         * Constructs based on a remoted BinaryAttribute.
         * 
         * @param in    input object containing marshalled BinaryAttribute
         */
        BinaryAttribute(DDF& in);
        
        virtual ~BinaryAttribute();

        /**
         * Returns the set of raw binary values.
         * 
         * @return  a mutable vector of the values
         */
        std::vector<std::string>& getValues();

        /**
         * Returns the set of raw binary values.
         * 
         * @return  an immutable vector of the values
         */
        const std::vector<std::string>& getValues() const;

        // Virtual function overrides.
        size_t valueCount() const;
        void clearSerializedValues();
        const char* getString(size_t index) const;
        void removeValue(size_t index);
        const std::vector<std::string>& getSerializedValues() const;
        DDF marshall() const;
    
    private:
        std::vector<std::string> m_values;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_scopedattr_h__ */
