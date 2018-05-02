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

#include <shibsp/SPConfig.h>
#include <shibsp/Application.h>
#include <shibsp/util/DOMPropertySet.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/binding/SAMLArtifact.h>
#include <saml/saml2/binding/SAML2Artifact.h>

#if defined (_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4250 )
#endif

namespace ta {

    using namespace std;
    using namespace shibsp;
    using namespace opensaml::saml2md;
    using namespace opensaml;

    class TestApplication : public Application  {
    public:
        TestApplication(const ServiceProvider *sp, MetadataProvider* provider);

        // Application
        virtual const char* getHash() const;
        virtual MetadataProvider* getMetadataProvider(bool required=true) const;
        virtual xmltooling::TrustEngine* getTrustEngine(bool required=true) const;
        virtual AttributeExtractor* getAttributeExtractor() const;
        virtual AttributeFilter* getAttributeFilter() const;
        virtual AttributeResolver* getAttributeResolver() const;
        virtual xmltooling::CredentialResolver* getCredentialResolver() const;
        virtual const PropertySet* getRelyingParty(const EntityDescriptor* provider) const;
        virtual const PropertySet* getRelyingParty(const XMLCh* entityID) const;
        virtual const  vector<const XMLCh*>* getAudiences() const;
        virtual string getNotificationURL(const char* request, bool front, unsigned int index) const;
        virtual const vector<string>& getRemoteUserAttributeIds() const;
        virtual const SessionInitiator* getDefaultSessionInitiator() const;
        virtual const SessionInitiator* getSessionInitiatorById(const char* id) const;
        virtual const Handler* getDefaultAssertionConsumerService() const;
        virtual const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        virtual const Handler* getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding=nullptr) const;
        virtual const Handler* getHandler(const char* path) const;
        virtual void getHandlers(vector<const Handler*>& handlers) const;
        virtual SAMLArtifact* generateSAML1Artifact(const EntityDescriptor* relyingParty) const;
        virtual saml2p::SAML2Artifact* generateSAML2Artifact(const EntityDescriptor* relyingParty) const;

        // PropertySet
        virtual const PropertySet* getParent() const;
        virtual void setParent(const PropertySet* parent);
        virtual pair<bool, bool> getBool(const char* name, const char* ns=nullptr) const;
        virtual pair<bool, const char*> getString(const char* name, const char* ns=nullptr) const;
        virtual pair<bool, const XMLCh*> getXMLString(const char* name, const char* ns=nullptr) const;
        virtual pair<bool, unsigned int> getUnsignedInt(const char* name, const char* ns=nullptr) const;
        virtual pair<bool, int> getInt(const char* name, const char* ns=nullptr) const;
        virtual void getAll(std::map<std::string, const char*>& properties) const;
        virtual const PropertySet* getPropertySet(const char* name, const char* ns=shibspconstants::ASCII_SHIBSPCONFIG_NS) const;
        virtual const xercesc::DOMElement* getElement() const;

    private:
        MetadataProvider* m_provider;
    };

}

#if defined (_MSC_VER)
#pragma warning( pop )
#endif
