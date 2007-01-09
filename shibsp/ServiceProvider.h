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
 * @file shibsp/ServiceProvider.h
 * 
 * Interface to a Shibboleth ServiceProvider instance.
 */

#ifndef __shibsp_sp_h__
#define __shibsp_sp_h__

#include <shibsp/PropertySet.h>
#include <xmltooling/signature/CredentialResolver.h>

namespace shibsp {

    class ListenerService;

    /**
     * Interface to a Shibboleth ServiceProvider instance.
     * 
     * <p>A ServiceProvider exposes configuration and infrastructure services required
     * by the SP implementation, allowing a flexible configuration format.
     */
    class SHIBSP_API ServiceProvider : public virtual xmltooling::Lockable, public virtual PropertySet
    {
        MAKE_NONCOPYABLE(ServiceProvider);
    protected:
        ServiceProvider() {}
    public:
        virtual ~ServiceProvider() {}
        
        /**
         * Loads a configuration and prepares the instance for use.
         * 
         * <p>Implemented as a separate method so that services can rely on
         * other services while they initialize by accessing the ServiceProvider
         * from the SPConfig singleton.
         */
        virtual void init()=0;
        
        /**
         * Returns a ListenerService instance.
         * 
         * @param required  true iff an exception should be thrown if no ListenerService is available
         * @return  a ListenerService if available, or NULL
         */
        virtual ListenerService* getListenerService(bool required=true) const=0;
        
        /**
         * Returns a CredentialResolver instance mapped to a key.
         * 
         * @param id    a NULL-terminated key identifying the CredentialResolver to the configuration 
         * @return  a CredentialResolver if available, or NULL
         */
        virtual xmlsignature::CredentialResolver* getCredentialResolver(const char* id) const=0;

        //virtual ISessionCache* getSessionCache() const=0;
        
        //virtual IRequestMapper* getRequestMapper() const=0;
        
        //virtual const IApplication* getApplication(const char* applicationId) const=0;
    };

    /**
     * Registers ServiceProvider classes into the runtime.
     */
    void SHIBSP_API registerServiceProviders();

    /** SP based on integrated XML and native server configuration. */
    #define XML_SERVICE_PROVIDER "edu.internet2.middleware.shibboleth.sp.provider.XMLServiceProvider"
};

#endif /* __shibsp_sp_h__ */
