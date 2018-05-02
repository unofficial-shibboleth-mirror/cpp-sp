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

#include <xmltooling/unicode.h>
#include <shibsp/Application.h>
#include <shibsp/util/DOMPropertySet.h>

#include "TestApplication.h"

using namespace std;
using namespace shibsp;
using namespace opensaml;
using namespace opensaml::saml2md;

namespace ta {
    TestApplication::TestApplication(const ServiceProvider *sp, MetadataProvider* provider) : Application(sp), m_provider(provider)
    {};

    const char* TestApplication::getHash() const
    {
        return "";
    }

    MetadataProvider* TestApplication::getMetadataProvider(bool required) const
    {
        return m_provider;
    }

    xmltooling::TrustEngine* TestApplication::getTrustEngine(bool required) const
    {
        return nullptr;
    }


    AttributeExtractor* TestApplication::getAttributeExtractor() const
    {
        return nullptr;
    }

    AttributeFilter* TestApplication::getAttributeFilter() const
    {
        return nullptr;
    }

    AttributeResolver* TestApplication::getAttributeResolver() const
    {
        return nullptr;
    }

    xmltooling::CredentialResolver* TestApplication::getCredentialResolver() const
    {
        return nullptr;
    }

    const PropertySet* TestApplication::getRelyingParty(const opensaml::saml2md::EntityDescriptor* provider) const
    {
        return nullptr;
    }


    const PropertySet* TestApplication::getRelyingParty(const XMLCh* entityID) const
    {
        return this;
    }


    const vector<const XMLCh*>* TestApplication::getAudiences() const
    {
        return nullptr;
    }

    string TestApplication::getNotificationURL(const char* request, bool front, unsigned int index) const
    {
        return "";
    }

    const vector<string>& TestApplication::getRemoteUserAttributeIds() const
    {
        static const vector<string> retVal(0);
        return retVal;
    }

    const SessionInitiator* TestApplication::getDefaultSessionInitiator() const
    {
        return nullptr;
    }

    const SessionInitiator* TestApplication::getSessionInitiatorById(const char* id) const
    {
        return nullptr;
    }

    const Handler* TestApplication::getDefaultAssertionConsumerService() const
    {
        return nullptr;
    }

    const Handler* TestApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
    {
        return nullptr;
    }

    const Handler* TestApplication::getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding) const
    {
        return nullptr;
    }

    const Handler* TestApplication::getHandler(const char* path) const
    {
        return nullptr;
    }

    void TestApplication::getHandlers(vector<const Handler*>& handlers) const
    {
        return;
    }

    SAMLArtifact* TestApplication::generateSAML1Artifact(const EntityDescriptor* relyingParty) const
    {
        return nullptr;
    }

    saml2p::SAML2Artifact* TestApplication::generateSAML2Artifact(const EntityDescriptor* relyingParty) const
    {
        return nullptr;
    }


    const PropertySet* TestApplication::getParent() const
    {
        return nullptr;
    }
    void TestApplication::setParent(const PropertySet* parent)
    {
        return;
    }
    pair<bool, bool> TestApplication::getBool(const char* name, const char* ns) const
    {
        static const pair<bool, bool> retVal(false, false);
        return retVal;
    }
    pair<bool, const char*> TestApplication::getString(const char* name, const char* ns) const
    {
        if (!strcmp(name, "entityID")) {
            return pair<bool, const char*>(true, "http://localhost/Shibboleth");
        }
        if (!strcmp(name, "authType")) {
            return pair<bool, const char*>(true, "NONE");
        }
        return pair<bool, const char*>(false, "");
    }
    pair<bool, const XMLCh*> TestApplication::getXMLString(const char* name, const char* ns) const
    {
        static const pair<bool, const XMLCh*> retVal(false, nullptr);
        return retVal;
    }
    pair<bool, unsigned int> TestApplication::getUnsignedInt(const char* name, const char* ns) const
    {
        static const pair<bool, unsigned int> retVal(false, 1);
        return retVal;
    }
    pair<bool, int> TestApplication::getInt(const char* name, const char* ns) const
    {
        static const pair<bool, int> retVal(false, -1);
        return retVal;
    }
    void TestApplication::getAll(std::map<std::string, const char*>& properties) const
    {
    }
    const PropertySet* TestApplication::getPropertySet(const char* name, const char* ns) const
    {
        return nullptr;
    }
    const xercesc::DOMElement* TestApplication::getElement() const
    {
        return nullptr;
    }

}
