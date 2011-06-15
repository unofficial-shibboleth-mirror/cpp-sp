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
 * @file shibsp/attribute/resolver/AttributeExtractor.h
 *
 * A service that extracts and decodes attributes from XML objects.
 */

#ifndef __shibsp_extractor_h__
#define __shibsp_extractor_h__

#include <shibsp/base.h>

#include <string>
#include <vector>
#include <xmltooling/Lockable.h>

namespace xmltooling {
    class XMLTOOL_API XMLObject;
};

namespace opensaml {
    namespace saml2md {
        class SAML_API RoleDescriptor;
        class SAML_API SPSSODescriptor;
    };
};

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Attribute;

    /**
     * A service that extracts and decodes attributes from XML objects.
     */
    class SHIBSP_API AttributeExtractor : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(AttributeExtractor);
    protected:
        AttributeExtractor();
    public:
        virtual ~AttributeExtractor();

        /**
         * Extracts the attributes found in an XMLObject.
         *
         * @param application   Application performing the extraction
         * @param issuer        source of object, if known
         * @param xmlObject     object to extract
         * @param attributes    an array to populate with the extracted attributes
         *
         * @throws AttributeExtractionException thrown if there is a problem extracting attributes
         */
        virtual void extractAttributes(
            const Application& application,
            const opensaml::saml2md::RoleDescriptor* issuer,
            const xmltooling::XMLObject& xmlObject,
            std::vector<Attribute*>& attributes
            ) const=0;

        /**
         * Populates an array with the set of Attribute IDs that might be generated.
         *
         * @param attributes    array to populate
         */
        virtual void getAttributeIds(std::vector<std::string>& attributes) const=0;

        /**
         * Generates and/or modifies metadata reflecting the extractor,
         * typically attribute-related requirements.
         *
         * <p>The default implementation does nothing.
         *
         * @param role          metadata role to decorate
         */
        virtual void generateMetadata(opensaml::saml2md::SPSSODescriptor& role) const;
    };

    /**
     * Registers AttributeExtractor classes into the runtime.
     */
    void SHIBSP_API registerAttributeExtractors();

    /** AttributeExtractor based on an XML mapping schema. */
    #define XML_ATTRIBUTE_EXTRACTOR "XML"

    /** AttributeExtractor for DelegationRestriction information. */
    #define DELEGATION_ATTRIBUTE_EXTRACTOR "Delegation"

    /** AttributeExtractor for KeyInfo information. */
    #define KEYDESCRIPTOR_ATTRIBUTE_EXTRACTOR "KeyDescriptor"

    /** AttributeExtractor based on chaining together other extractors. */
    #define CHAINING_ATTRIBUTE_EXTRACTOR "Chaining"
};

#endif /* __shibsp_extractor_h__ */
