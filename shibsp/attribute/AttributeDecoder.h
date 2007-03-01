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
 * @file shibsp/attribute/AttributeDecoder.h
 * 
 * Decodes SAML NameID/Attribute objects into resolved Attributes.
 */

#ifndef __shibsp_attrdecoder_h__
#define __shibsp_attrdecoder_h__

#include <shibsp/attribute/Attribute.h>
#include <xmltooling/XMLObject.h>

namespace shibsp {

    /**
     * Decodes XML objects into resolved Attributes.
     */
    class SHIBSP_API AttributeDecoder
    {
        MAKE_NONCOPYABLE(AttributeDecoder);
    protected:
        AttributeDecoder() {}
    public:
        virtual ~AttributeDecoder() {}
        
        /**
         * Decodes an XMLObject into a resolved Attribute.
         * 
         * @param id                ID of resolved attribute
         * @param xmlObject         XMLObject to decode
         * @param assertingParty    name of the party asserting the attribute
         * @param relyingParty      name of the party relying on the attribute
         * @return a resolved Attribute
         */
        virtual Attribute* decode(
            const char* id, const xmltooling::XMLObject* xmlObject, const char* assertingParty=NULL, const char* relyingParty=NULL
            ) const=0;
    };

    /** Decodes SimpleAttributes */
    #define SIMPLE_ATTRIBUTE_DECODER "Simple"
    
    /** Decodes ScopedAttributes */
    #define SCOPED_ATTRIBUTE_DECODER "Scoped"

    /** Decodes NameIDAttributes */
    #define NAMEID_ATTRIBUTE_DECODER "NameID"

    /** Registers built-in AttributeDecoders into the runtime. */
    void registerAttributeDecoders();
};

#endif /* __shibsp_attrdecoder_h__ */
