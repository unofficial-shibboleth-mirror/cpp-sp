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
 * @file shibsp/util/PropertySet.h
 * 
 * Interface to a generic set of typed properties.
 */

#ifndef __shibsp_propset_h__
#define __shibsp_propset_h__

#include <shibsp/base.h>

#include <utility>

namespace shibsp {

    /**
     * Interface to a generic set of typed properties.
     */
    class SHIBSP_API PropertySet
    {
        MAKE_NONCOPYABLE(PropertySet);
    protected:
        PropertySet();
    public:
        virtual ~PropertySet();

        /**
         * Gets whether a matching property exists.
         * 
         * @param name  property name
         * @return true iff the named property exists
         */
        virtual bool hasProperty(const char* name) const=0;

        /**
         * Returns a boolean-valued property.
         * 
         * @param name  property name
         * @param defaultValue  default value if property is unset
         * @return effective property value
         */
        virtual bool getBool(const char* name, bool defaultValue) const=0;

        /**
         * Returns a string-valued property.
         * 
         * @param name  property name
         * @param defaultValue  default value if property is unset
         * @return effective property value
         */
        virtual const char* getString(const char* name, const char* defaultValue=nullptr) const=0;

        /**
         * Returns an unsigned integer-valued property.
         * 
         * @param name  property name
         * @param defaultValue  default value if property is unset
         * @return effective property value
         */
        virtual unsigned int getUnsignedInt(const char* name, unsigned int defaultValue) const=0;

        /**
         * Returns an integer-valued property.
         * 
         * @param name  property name
         * @param defaultValue  default value if property is unset
         * @return effective property value
         */
        virtual int getInt(const char* name, int defaultValue) const=0;
    };

};

#endif /* __shibsp_propset_h__ */
