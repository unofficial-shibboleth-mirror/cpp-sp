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
 * @file shibsp/util/TemplateParameters.h
 * 
 * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet. 
 */

#ifndef __shibsp_tempparams_h__
#define __shibsp_tempparams_h__

#include <shibsp/util/PropertySet.h>
#include <xmltooling/util/TemplateEngine.h>

namespace shibsp {

    /**
     * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet.
     */
    class SHIBSP_API TemplateParameters : public xmltooling::TemplateEngine::TemplateParameters
    {
    public:
        /**
         * Constructor
         * 
         * @param props a PropertySet to supply additional parameters
         */
        TemplateParameters(const PropertySet* props=NULL) {
            setPropertySet(props);
        }

        virtual ~TemplateParameters() {}
        
        /**
         * Sets a PropertySet to supply additional parameters.
         *  
         * @param props a PropertySet to supply additional parameters
         */
        void setPropertySet(const PropertySet* props);
        
        const char* getParameter(const char* name) const;

    private:
        const PropertySet* m_props;
    };
};

#endif /* __shibsp_tempparams_h__ */
