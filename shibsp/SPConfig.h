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
 * @file shibsp/SPConfig.h
 * 
 * Library configuration 
 */

#ifndef __shibsp_config_h__
#define __shibsp_config_h__

#include <shibsp/base.h>
#include <xmltooling/PluginManager.h>
#include <xercesc/dom/DOM.hpp>

/**
 * @namespace shibsp
 * Shibboleth Service Provider Library
 */
namespace shibsp {

    class SHIBSP_API ListenerService;
    class SHIBSP_API ServiceProvider;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * Singleton object that manages library startup/shutdown.
     */
    class SHIBSP_API SPConfig
    {
    MAKE_NONCOPYABLE(SPConfig);
    public:
        virtual ~SPConfig() {}

        /**
         * Returns the global configuration object for the library.
         * 
         * @return reference to the global library configuration object
         */
        static SPConfig& getConfig();

        /**
         * Bitmask values representing subsystems of the library.
         */
        enum components_t {
            Listener = 1,
            Caching = 2,
            Metadata = 4,
            Trust = 8,
            Credentials = 16,
            AAP = 32,
            RequestMapper = 64,
            OutOfProcess = 128,
            InProcess = 256,
            Logging = 512
        };
        
        /**
         * Set a bitmask of subsystems to activate.
         * 
         * @param enabled   bitmask of component constants
         */
        void setFeatures(unsigned long enabled) {
            m_features = enabled;
        }

        /**
         * Test whether a subsystem is enabled.
         * 
         * @param feature   subsystem/component to test
         * @return true iff feature is enabled
         */
        bool isEnabled(components_t feature) {
            return (m_features & feature)>0;
        }
        
        /**
         * Initializes library
         * 
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         * 
         * @param catalog_path  delimited set of schema catalog files to load
         * @return true iff initialization was successful 
         */
        virtual bool init(const char* catalog_path)=0;
        
        /**
         * Shuts down library
         * 
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself.
         */
        virtual void term()=0;
        
        /**
         * Sets the global ServiceProvider instance.
         * This method must be externally synchronized with any code that uses the object.
         * Any previously set object is destroyed.
         * 
         * @param serviceProvider   new ServiceProvider instance to store
         */
        void setServiceProvider(ServiceProvider* serviceProvider);
        
        /**
         * Returns the global ServiceProvider instance.
         * 
         * @return  global ServiceProvider or NULL
         */
        ServiceProvider* getServiceProvider() const {
            return m_serviceProvider;
        }

        /**
         * Manages factories for ListenerService plugins.
         */
        xmltooling::PluginManager<ListenerService,const xercesc::DOMElement*> ListenerServiceManager;

    protected:
        SPConfig() : m_serviceProvider(NULL) {}
        
        /** Global ServiceProvider instance. */
        ServiceProvider* m_serviceProvider;

    private:
        unsigned long m_features;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_config_h__ */