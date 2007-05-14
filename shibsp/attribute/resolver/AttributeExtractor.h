/*
 *  Copyright 2001-2007 Internet2
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
 * @file shibsp/attribute/resolver/AttributeExtractor.h
 * 
 * A service that extracts and decodes attributes from XML objects.
 */

#ifndef __shibsp_extractor_h__
#define __shibsp_extractor_h__

#include <shibsp/base.h>

#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/Lockable.h>

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Attribute;
    class SHIBSP_API SPRequest;

    /**
     * A service that extracts and decodes attributes from XML objects.
     */
    class SHIBSP_API AttributeExtractor : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(AttributeExtractor);
    protected:
        AttributeExtractor() {}
    public:
        virtual ~AttributeExtractor() {}

        /**
         * Extracts the attributes found in an XMLObject.
         * 
         * @param application   Application performing the extraction
         * @param issuer        source of object, if known
         * @param xmlObject     object to extract
         * @param attributes    a map to populate with the extracted attributes, keyed by id
         * 
         * @throws AttributeExtractionException thrown if there is a problem extracting attributes
         */
        virtual void extractAttributes(
            const Application& application,
            const opensaml::saml2md::RoleDescriptor* issuer,
            const xmltooling::XMLObject& xmlObject,
            std::multimap<std::string,Attribute*>& attributes
            ) const=0;

        /**
         * Clears possible HTTP request headers that might be populated
         * during attribute export.
         *
         * @param request   the SP request being processed
         */
        virtual void clearHeaders(SPRequest& request) const=0;
    };

    /**
     * Registers AttributeExtractor classes into the runtime.
     */
    void SHIBSP_API registerAttributeExtractors();

    /** AttributeExtractor based on an XML mapping schema. */
    #define XML_ATTRIBUTE_EXTRACTOR "XML"
};

#endif /* __shibsp_extractor_h__ */
