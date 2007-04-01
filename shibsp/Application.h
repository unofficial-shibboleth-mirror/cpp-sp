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
 * @file shibsp/Application.h
 * 
 * Interface to a Shibboleth Application instance.
 */

#ifndef __shibsp_app_h__
#define __shibsp_app_h__

#include <shibsp/util/PropertySet.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/TrustEngine.h>

namespace shibsp {
    
    class SHIBSP_API AttributeResolver;
    class SHIBSP_API Handler;
    class SHIBSP_API ServiceProvider;

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
         * Returns the owning ServiceProvider instance.
         *
         * @return a locked ServiceProvider
         */
        virtual const ServiceProvider& getServiceProvider() const=0;

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
         * Returns an AttributeResolver for use with this Application.
         * 
         * @return  an AttributeResolver, or NULL
         */
        virtual AttributeResolver* getAttributeResolver() const=0;

        /**
         * Returns a set of attribute IDs to resolve for the Application.
         *
         * @return  a set of attribute IDs, or an empty set
         */
        virtual const std::set<std::string>* getAttributeIds() const=0;

        /**
         * Returns the CredentialResolver instance associated with this Application.
         * 
         * @return  a CredentialResolver, or NULL
         */
        virtual xmltooling::CredentialResolver* getCredentialResolver() const=0;

        /**
         * Returns configuration properties governing security interactions with a peer.
         * 
         * @param provider  a peer entity's metadata
         * @return  the applicable PropertySet
         */
        virtual const PropertySet* getRelyingParty(const opensaml::saml2md::EntityDescriptor* provider) const=0;

        /**
         * Returns the default SessionInitiator Handler when automatically
         * requesting a session.
         * 
         * @return the default SessionInitiator, or NULL
         */
        virtual const Handler* getDefaultSessionInitiator() const=0;
        
        /**
         * Returns a SessionInitiator Handler with a particular ID when automatically
         * requesting a session.
         * 
         * @param id    an identifier unique to the Application
         * @return the designated SessionInitiator, or NULL
         */
        virtual const Handler* getSessionInitiatorById(const char* id) const=0;
        
        /**
         * Returns the default AssertionConsumerService Handler
         * for use in AuthnRequest messages.
         * 
         * @return the default AssertionConsumerService, or NULL
         */
        virtual const Handler* getDefaultAssertionConsumerService() const=0;

        /**
         * Returns an AssertionConsumerService Handler with a particular index
         * for use in AuthnRequest messages.
         * 
         * @param index an index unique to an application
         * @return the designated AssertionConsumerService, or NULL
         */
        virtual const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const=0;

        /**
         * Returns one or more AssertionConsumerService Handlers that support
         * a particular protocol binding.
         * 
         * @param binding   a protocol binding identifier
         * @return a set of qualifying AssertionConsumerServices
         */
        virtual const std::vector<const Handler*>& getAssertionConsumerServicesByBinding(const XMLCh* binding) const=0;
        
        /**
         * Returns the Handler associated with a particular path/location.
         * 
         * @param path  the PATH_INFO appended to the end of a base Handler location
         *              that invokes the Handler
         * @return the mapped Handler, or NULL 
         */
        virtual const Handler* getHandler(const char* path) const=0;

        /**
         * Returns the set of audience values associated with this Application.
         * 
         * @return set of audience values associated with the Application
         */
        virtual const std::vector<const XMLCh*>& getAudiences() const=0;
    };
};

#endif /* __shibsp_app_h__ */
