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
 * XMLApplication.h
 *
 * Internal declaration of Application subclass used by XML-based configurator.
 */

#ifndef __shibsp_xmlserviceprov_h__
#define __shibsp_xmlserviceprov_h__

#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "remoting/ListenerService.h"
#include "util/DOMPropertySet.h"

#include <xmltooling/logging.h>
#include <xmltooling/PluginManager.h>
#include <xmltooling/util/ReloadableXMLFile.h>

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

namespace xmltooling {
    class Mutex;
    class RWLock;
}

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    // Top-level configuration implementation
    class SHIBSP_DLLLOCAL XMLConfig;
    class SHIBSP_DLLLOCAL XMLConfigImpl : public DOMPropertySet, public xercesc::DOMNodeFilter
    {
    public:
        XMLConfigImpl(const xercesc::DOMElement* e, bool first, XMLConfig* outer, xmltooling::logging::Category& log);
        ~XMLConfigImpl() {
            if (m_document)
                m_document->release();
        }

        std::map<std::string,Remoted*> m_listenerMap;
        boost::scoped_ptr<RequestMapper> m_requestMapper;
        boost::scoped_ptr<xmltooling::Mutex> m_appMapLock;
        std::map< std::string, boost::shared_ptr<Application> > m_appmap;
        std::vector<std::string> m_externalAppPaths;

        boost::shared_ptr<Application> findExternalOverride(const char*, const XMLConfig*);

        // Provides filter to exclude special config elements.
        xercesc::DOMNodeFilter::FilterAction acceptNode(const xercesc::DOMNode* node) const;

        void setDocument(xercesc::DOMDocument* doc) {
            m_document = doc;
        }

    private:
        void doExtensions(const xercesc::DOMElement*, const char*, xmltooling::logging::Category&);
        void doListener(const xercesc::DOMElement*, XMLConfig*, xmltooling::logging::Category&);
        void doCaching(const xercesc::DOMElement*, XMLConfig*, xmltooling::logging::Category&);

        xercesc::DOMDocument* m_document;
        const XMLApplication* m_defaultApplication;
        bool m_deprecationSupport;
    };

    class SHIBSP_DLLLOCAL XMLConfig : public ServiceProvider, public xmltooling::ReloadableXMLFile
    {
    public:
        XMLConfig(const xercesc::DOMElement* e, bool deprecationSupport=true);
        virtual ~XMLConfig();

        void init() {
            background_load();
        }

        const XMLCh* getConfigurationNamespace() const {
            return m_impl ? m_impl->getElement()->getNamespaceURI() : nullptr;
        }

        // PropertySet
        const PropertySet* getParent() const { return m_impl->getParent(); }
        void setParent(const PropertySet* parent) { return m_impl->setParent(parent); }
        std::pair<bool, bool> getBool(const char* name, const char* ns = nullptr) const { return m_impl->getBool(name, ns); }
        std::pair<bool, const char*> getString(const char* name, const char* ns = nullptr) const { return m_impl->getString(name, ns); }
        std::pair<bool, const XMLCh*> getXMLString(const char* name, const char* ns = nullptr) const { return m_impl->getXMLString(name, ns); }
        std::pair<bool, unsigned int> getUnsignedInt(const char* name, const char* ns = nullptr) const { return m_impl->getUnsignedInt(name, ns); }
        std::pair<bool, int> getInt(const char* name, const char* ns = nullptr) const { return m_impl->getInt(name, ns); }
        const PropertySet* getPropertySet(const char* name, const char* ns = shibspconstants::ASCII_SHIBSPCONFIG_NS) const { return m_impl->getPropertySet(name, ns); }
        const xercesc::DOMElement* getElement() const { return m_impl->getElement(); }

        // ServiceProvider
        ListenerService* getListenerService(bool required = true) const {
            if (required && !m_listener)
                throw ConfigurationException("No ListenerService available.");
            return m_listener.get();
        }

        SessionCache* getSessionCache(bool required = true) const {
            if (required && !m_sessionCache)
                throw ConfigurationException("No SessionCache available.");
            return m_sessionCache.get();
        }

        RequestMapper* getRequestMapper(bool required = true) const {
            if (required && !m_impl->m_requestMapper)
                throw ConfigurationException("No RequestMapper available.");
            return m_impl->m_requestMapper.get();
        }

        const Application* getApplication(const char* applicationId) const;

        void regListener(const char* address, Remoted* svc);
        bool unregListener(const char* address, Remoted* current);
        Remoted* lookupListener(const char* address) const;

    protected:
        std::pair<bool,xercesc::DOMElement*> background_load();

    private:
        friend class XMLConfigImpl;

        boost::scoped_ptr<xmltooling::RWLock> m_listenerLock;
        std::map< std::string,std::pair<Remoted*,Remoted*> > m_listenerMap;

        // The order of these members actually matters. If we want to rely on auto-destruction, then
        // anything dependent on anything else has to come later in the object so it will pop first.
        // Remoring is the lowest, then the cache, and finally the rest.
        boost::scoped_ptr<ListenerService> m_listener;
        boost::scoped_ptr<SessionCache> m_sessionCache;
        boost::scoped_ptr<XMLConfigImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

}

#endif /* __shibsp_xmlserviceprov_h__ */
