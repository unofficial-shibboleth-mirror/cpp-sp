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
 * @file shibsp/util/TemplateParameters.h
 * 
 * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet. 
 */

#ifndef __shibsp_tempparams_h__
#define __shibsp_tempparams_h__

#include <shibsp/base.h>

#include <xmltooling/util/TemplateEngine.h>

namespace shibsp {

    class SHIBSP_API PropertySet;

    /**
     * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet.
     */
    class SHIBSP_API TemplateParameters : public xmltooling::TemplateEngine::TemplateParameters
    {
    public:
        /**
         * Constructor
         * 
         * @param e     an exception to supply additional parameters
         * @param props a PropertySet to supply additional parameters
         */
        TemplateParameters(const std::exception* e=nullptr, const PropertySet* props=nullptr);

        virtual ~TemplateParameters();
        
        /**
         * Sets a PropertySet to supply additional parameters.
         *  
         * @param props a PropertySet to supply additional parameters
         */
        void setPropertySet(const PropertySet* props);
        
        /**
         * Returns the exception passed to the object, if it contains rich information.
         *
         * @return  an exception, or nullptr
         */
        const xmltooling::XMLToolingException* getRichException() const;

        const char* getParameter(const char* name) const;
        
        /**
         * Returns a set of query string name/value pairs, URL-encoded,
         * representing all known parameters. If an exception is
         * present, it's type, message, and parameters will be included.
         *
         * @return  the query string representation
         */
        std::string toQueryString() const;

    private:
        const PropertySet* m_props;
        const std::exception* m_exception;
        const xmltooling::XMLToolingException* m_toolingException;
    };
};

#endif /* __shibsp_tempparams_h__ */
