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
#include "remoting/ListenerService.h"
#include "util/DOMPropertySet.h"

#include <xmltooling/logging.h>
#include <xmltooling/PluginManager.h>

#include <boost/scoped_ptr.hpp>
#include <boost/shared_ptr.hpp>

namespace xmltooling {
    class CredentialResolver;
    class TrustEngine;
};

#ifndef SHIBSP_LITE
namespace opensaml {
    class SAMLArtifact;

    namespace saml2p {
        class SAML2Artifact;
    };

    namespace saml2md {
        class EntityDescriptor;
        class EntityMatcher;
        class MetadataProvider;
    };
};
#endif

namespace shibsp {

    class LogoutInitiator;
    class ProtocolProvider;
    class ServiceProvider;
    class SessionInitiator;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL XMLApplication
        : public Application, public Remoted, public DOMPropertySet, public xercesc::DOMNodeFilter
    {
    public:
        XMLApplication(
            const ServiceProvider*,
            const ProtocolProvider*,
            xercesc::DOMElement*,
            bool deprecationSupport,
            const XMLApplication* base=nullptr,
            xercesc::DOMDocument* doc=nullptr);
        virtual ~XMLApplication();

        const char* getHash() const {
            return m_hash.c_str();
        }

#ifndef SHIBSP_LITE
        opensaml::SAMLArtifact* generateSAML1Artifact(const opensaml::saml2md::EntityDescriptor* relyingParty) const;
        opensaml::saml2p::SAML2Artifact* generateSAML2Artifact(const opensaml::saml2md::EntityDescriptor* relyingParty) const;

        opensaml::saml2md::MetadataProvider* getMetadataProvider(bool required=true) const {
            if (required && !m_base && !m_metadata)
                throw ConfigurationException("No MetadataProvider available.");
            return (!m_metadata && m_base) ? m_base->getMetadataProvider(required) : m_metadata.get();
        }
        xmltooling::TrustEngine* getTrustEngine(bool required = true) const {
            if (required && !m_base && !m_trust)
                throw ConfigurationException("No TrustEngine available.");
            return (!m_trust && m_base) ? m_base->getTrustEngine(required) : m_trust.get();
        }
        AttributeExtractor* getAttributeExtractor() const {
            return (!m_attrExtractor && m_base) ? m_base->getAttributeExtractor() : m_attrExtractor.get();
        }
        AttributeFilter* getAttributeFilter() const {
            return (!m_attrFilter && m_base) ? m_base->getAttributeFilter() : m_attrFilter.get();
        }
        AttributeResolver* getAttributeResolver() const {
            return (!m_attrResolver && m_base) ? m_base->getAttributeResolver() : m_attrResolver.get();
        }
        xmltooling::CredentialResolver* getCredentialResolver() const {
            return (!m_credResolver && m_base) ? m_base->getCredentialResolver() : m_credResolver.get();
        }
        const PropertySet* getRelyingParty(const opensaml::saml2md::EntityDescriptor* provider) const;
        const PropertySet* getRelyingParty(const XMLCh* entityID) const;

        const std::vector<const XMLCh*>* getAudiences() const {
            return (m_audiences.empty() && m_base) ? m_base->getAudiences() : &m_audiences;
        }

        // PropertySet overrides.
        std::pair<bool, const char*> getString(const char* name, const char* ns = nullptr) const;
        std::pair<bool, const XMLCh*> getXMLString(const char* name, const char* ns = nullptr) const;
#endif
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
        void limitRedirect(const xmltooling::GenericRequest& request, const char* url) const;

        void receive(DDF& in, std::ostream& out);

        // Provides filter to exclude special config elements.
        xercesc::DOMNodeFilter::FilterAction acceptNode(const xercesc::DOMNode* node) const;

    private:
        template <class T> T* doChainedPlugins(
            const xmltooling::PluginManager<T, std::string, const xercesc::DOMElement*>& pluginMgr,
            const char* pluginType,
            const char* chainingType,
            const XMLCh* localName,
            xercesc::DOMElement* e,
            xmltooling::logging::Category& log,
            const char* dummyType = nullptr
        );
        void doAttributeInfo();
        void doHandlers(const ProtocolProvider*, const xercesc::DOMElement*, xmltooling::logging::Category&);
        void doSSO(const ProtocolProvider&, std::set<std::string>&, xercesc::DOMElement*, xmltooling::logging::Category&);
        void doLogout(const ProtocolProvider&, std::set<std::string>&, xercesc::DOMElement*, xmltooling::logging::Category&);
        void doNameIDMgmt(const ProtocolProvider&, std::set<std::string>&, xercesc::DOMElement*, xmltooling::logging::Category&);
        void doArtifactResolution(const ProtocolProvider&, const char*, xercesc::DOMElement*, xmltooling::logging::Category&);
        const XMLApplication* m_base;
        std::string m_hash;
        std::pair<std::string, std::string> m_attributePrefix;
#ifndef SHIBSP_LITE
        void doAttributePlugins(xercesc::DOMElement*, xmltooling::logging::Category&);
        boost::scoped_ptr<opensaml::saml2md::MetadataProvider> m_metadata;
        boost::scoped_ptr<xmltooling::TrustEngine> m_trust;
        boost::scoped_ptr<AttributeExtractor> m_attrExtractor;
        boost::scoped_ptr<AttributeFilter> m_attrFilter;
        boost::scoped_ptr<AttributeResolver> m_attrResolver;
        boost::scoped_ptr<xmltooling::CredentialResolver> m_credResolver;
        std::vector<const XMLCh*> m_audiences;

        // RelyingParty properties
        std::map< xmltooling::xstring, boost::shared_ptr<PropertySet> > m_partyMap;   // name-based matching
        std::vector< std::pair< boost::shared_ptr<opensaml::saml2md::EntityMatcher>, boost::shared_ptr<PropertySet> > > m_partyVec;  // plugin-based matching
#endif
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
            REDIRECT_LIMIT_WHITELIST,
            REDIRECT_LIMIT_EXACT_WHITELIST,
            REDIRECT_LIMIT_HOST_WHITELIST
        } m_redirectLimit;

        std::vector<std::string> m_redirectWhitelist;
        bool m_deprecationSupport;
        xercesc::DOMDocument* m_doc;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

}

#endif /* __shibsp_xmlapplication_h__ */
