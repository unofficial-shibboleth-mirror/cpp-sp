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

#ifndef __shibsp_xmlapplication_h__
#define __shibsp_xmlapplication_h__

#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/Handler.h"
#include "util/DOMPropertySet.h"
#include "util/PluginManager.h"

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

namespace xmltooling {
    class CredentialResolver;
    class TrustEngine;
};

namespace shibsp {

    class LogoutInitiator;
    class ServiceProvider;
    class SessionInitiator;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL XMLApplication
        : public Application, public DOMPropertySet, public xercesc::DOMNodeFilter
    {
    public:
        XMLApplication(
            const ServiceProvider*,
            xercesc::DOMElement*,
            bool deprecationSupport,
            const XMLApplication* base=nullptr,
            xercesc::DOMDocument* doc=nullptr);
        virtual ~XMLApplication();

        const char* getHash() const {
            return m_hash.c_str();
        }

        std::string getNotificationURL(const char* resource, bool front, unsigned int index) const;

        const std::vector<std::string>& getRemoteUserAttributeIds() const {
            return (m_remoteUsers.empty() && m_base) ? m_base->getRemoteUserAttributeIds() : m_remoteUsers;
        }

        void clearHeader(SPRequest& request, const char* rawname, const char* cginame) const;
        void setHeader(SPRequest& request, const char* name, const char* value) const;
        std::string getSecureHeader(const SPRequest& request, const char* name) const;

        const SessionInitiator* getDefaultSessionInitiator() const;
        const SessionInitiator* getSessionInitiatorById(const char* id) const;
        const Handler* getDefaultAssertionConsumerService() const;
        const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        const Handler* getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding=nullptr) const;
        const Handler* getHandler(const char* path) const;
        void getHandlers(std::vector<const Handler*>& handlers) const;
        void limitRedirect(const GenericRequest& request, const char* url) const;

        // Provides filter to exclude special config elements.
        xercesc::DOMNodeFilter::FilterAction acceptNode(const xercesc::DOMNode* node) const;

    private:
        template <class T> T* doChainedPlugins(
            const PluginManager<T, std::string, const xercesc::DOMElement*>& pluginMgr,
            const char* pluginType,
            const char* chainingType,
            const XMLCh* localName,
            xercesc::DOMElement* e,
            Category& log,
            const char* dummyType = nullptr
        );
        void doAttributeInfo(Category&);
        void doHandlers(const xercesc::DOMElement*, Category&);
        void doSSO(std::set<std::string>&, xercesc::DOMElement*, Category&);
        void doLogout(std::set<std::string>&, xercesc::DOMElement*, Category&);
        void doNameIDMgmt(std::set<std::string>&, xercesc::DOMElement*, Category&);
        void doArtifactResolution(const char*, xercesc::DOMElement*, Category&);
        const XMLApplication* m_base;
        std::string m_hash;
        std::pair<std::string, std::string> m_attributePrefix;

        std::vector<std::string> m_remoteUsers, m_frontLogout, m_backLogout;

        // manage handler objects
        std::vector< boost::shared_ptr<Handler> > m_handlers;

        // maps location (path info) to applicable handlers
        std::map<std::string, const Handler*> m_handlerMap;

        // maps unique indexes to consumer services
        std::map<unsigned int, const Handler*> m_acsIndexMap;

        // pointer to default consumer service
        const Handler* m_acsDefault;

        // maps protocol strings to supporting consumer service(s)
        typedef std::map< xmltooling::xstring, std::vector<const Handler*> > ACSProtocolMap;
        ACSProtocolMap m_acsProtocolMap;

        // pointer to default session initiator
        const SessionInitiator* m_sessionInitDefault;

        // maps unique ID strings to session initiators
        std::map<std::string, const SessionInitiator*> m_sessionInitMap;

        // pointer to default artifact resolution service
        const Handler* m_artifactResolutionDefault;

        std::pair<bool,int> getArtifactEndpointIndex() const {
            if (m_artifactResolutionDefault) return m_artifactResolutionDefault->getInt("index");
            return m_base ? m_base->getArtifactEndpointIndex() : std::make_pair(false, 0);
        }

        enum {
            REDIRECT_LIMIT_INHERIT,
            REDIRECT_LIMIT_NONE,
            REDIRECT_LIMIT_EXACT,
            REDIRECT_LIMIT_HOST,
            REDIRECT_LIMIT_ALLOW,
            REDIRECT_LIMIT_EXACT_ALLOW,
            REDIRECT_LIMIT_HOST_ALLOW
        } m_redirectLimit;

        std::vector<std::string> m_redirectAllow;
        bool m_deprecationSupport;
        xercesc::DOMDocument* m_doc;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

}

#endif /* __shibsp_xmlapplication_h__ */
