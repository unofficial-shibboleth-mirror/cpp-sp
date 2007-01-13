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
 * @file shibsp/Application.h
 * 
 * Interface to a Shibboleth Application instance.
 */

#ifndef __shibsp_app_h__
#define __shibsp_app_h__

#include <shibsp/util/PropertySet.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/TrustEngine.h>

namespace shibsp {

    /**
     * Interface to a Shibboleth Application instance.
     * 
     * <p>An Application is a logical set of resources that act as a unit
     * of session management and policy.
     */
    class SHIBSP_API Application : public virtual PropertySet
    {
        MAKE_NONCOPYABLE(Application);
    protected:
        Application() {}
    public:
        virtual ~Application() {}

        /**
         * Returns the Application's ID.
         * 
         * @return  the ID
         */        
        virtual const char* getId() const=0;

        /**
         * Returns a unique hash for the Application.
         * 
         * @return a value resulting from a hash of the Application's ID  
         */
        virtual const char* getHash() const=0;

        /**
         * Returns the name and cookie properties to use for this Application.
         * 
         * @param prefix    a value to prepend to the base cookie name
         * @return  a pair containing the cookie name and the string to append to the cookie value
         */
        virtual std::pair<std::string,const char*> getCookieNameProps(const char* prefix) const;

        /**
         * Returns a MetadataProvider for use with this Application.
         * 
         * @return  a MetadataProvider instance, or NULL
         */
        virtual opensaml::saml2md::MetadataProvider* getMetadataProvider() const=0;
        
        /**
         * Returns a TrustEngine for use with this Application.
         * 
         * @return  a TrustEngine instance, or NULL
         */
        virtual xmltooling::TrustEngine* getTrustEngine() const=0;
        
        /**
         * Returns configuration properties governing security interactions with a peer entity.
         * 
         * @param provider  a peer entity's metadata
         * @return  the applicable PropertySet
         */
        virtual const shibsp::PropertySet* getCredentialUse(const opensaml::saml2md::EntityDescriptor* provider) const=0;
    };
};

#endif /* __shibsp_app_h__ */
