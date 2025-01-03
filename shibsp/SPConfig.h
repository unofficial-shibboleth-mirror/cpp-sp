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
 * @file shibsp/SPConfig.h
 *
 * Library configuration.
 */

#ifndef __shibsp_config_h__
#define __shibsp_config_h__

#include <shibsp/base.h>
#include <shibsp/logging/Category.h>
#include <shibsp/util/PluginManager.h>

#include <string>
#include <xmltooling/QName.h>
#include <xercesc/dom/DOM.hpp>

/**
 * @namespace shibsp
 * Shibboleth Service Provider Library
 */
namespace shibsp {

    class SHIBSP_API AccessControl;
    class SHIBSP_API Handler;
    class SHIBSP_API ListenerService;
    class SHIBSP_API RequestMapper;
    class SHIBSP_API ServiceProvider;
    class SHIBSP_API SessionCache;
    class SHIBSP_API SessionInitiator;

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
        SPConfig();

        virtual ~SPConfig();

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
            RequestMapping = 64,
            OutOfProcess = 128,
            InProcess = 256,
            Logging = 512,
            Handlers = 1024
        };

        /**
         * Set a bitmask of subsystems to activate.
         *
         * @param enabled   bitmask of component constants
         */
        void setFeatures(unsigned long enabled);


        /**
         * Gets the bitmask of subsystems being activated.
         *
         * @return bitmask of component constants
         */
        unsigned long getFeatures() const;

        /**
         * Test whether a subsystem is enabled.
         *
         * @param feature   subsystem/component to test
         * @return true iff feature is enabled
         */
        bool isEnabled(components_t feature) const;

        /**
         * Initializes library
         *
         * Each process using the library MUST call this function exactly once
         * before using any library classes.
         *
         * @param catalog_path  delimited set of schema catalog files to load
         * @param inst_prefix   installation prefix for software
         * @return true iff initialization was successful
         */
        virtual bool init(const char* catalog_path=nullptr, const char* inst_prefix=nullptr);

        /**
         * Shuts down library
         *
         * Each process using the library SHOULD call this function exactly once
         * before terminating itself.
         */
        virtual void term();

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
         * @return  global ServiceProvider or nullptr
         */
        ServiceProvider* getServiceProvider() const;

        /**
         * Instantiates and installs a ServiceProvider instance based on an XML configuration string
         * or a configuration pathname.
         *
         * @param config    a snippet of XML to parse (it <strong>MUST</strong> contain a type attribute) or a pathname
         * @param rethrow   true iff caught exceptions should be rethrown instead of just returning the status
         * @return true iff instantiation was successful
         */
        virtual bool instantiate(const char* config=nullptr, bool rethrow=false);

        /**
          * Separator for serialized values of multi-valued attributes.
          *
          * <p>This is deprecated, and was never actually read within the code.</p>
          *
          * @deprecated
          */
        char attribute_value_delimeter;

        /**
         * Manages factories for AccessControl plugins.
         */
        PluginManager<AccessControl,std::string,const xercesc::DOMElement*> AccessControlManager;

        /**
         * Manages factories for Handler plugins that implement AssertionConsumerService functionality.
         */
        PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > AssertionConsumerServiceManager;

        /**
         * Manages factories for Handler plugins that implement customized functionality.
         */
        PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > HandlerManager;

        /**
         * Manages factories for Handler plugins that implement LogoutInitiator functionality.
         */
        PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > LogoutInitiatorManager;

        /**
         * Manages factories for RequestMapper plugins.
         */
        PluginManager<RequestMapper,std::string,const xercesc::DOMElement*> RequestMapperManager;

        /**
         * Manages factories for ServiceProvider plugins.
         */
        PluginManager<ServiceProvider,std::string,const xercesc::DOMElement*> ServiceProviderManager;

        /**
         * Manages factories for SessionCache plugins.
         */
        PluginManager<SessionCache,std::string,const xercesc::DOMElement*> SessionCacheManager;

        /**
         * Manages factories for Handler plugins that implement SessionInitiator functionality.
         */
        PluginManager< SessionInitiator,std::string,std::pair<const xercesc::DOMElement*,const char*> > SessionInitiatorManager;

        /**
         * Manages factories for Handler plugins that implement SingleLogoutService functionality.
         */
        PluginManager< Handler,std::string,std::pair<const xercesc::DOMElement*,const char*> > SingleLogoutServiceManager;

        /**
         * Helper for deprecation warnings about an at-risk feature or setting.
         */
        Category& deprecation() const;

    protected:
        /** Global ServiceProvider instance. */
        ServiceProvider* m_serviceProvider;

    private:
        unsigned long m_features;
        xercesc::DOMDocument* m_configDoc;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_config_h__ */
