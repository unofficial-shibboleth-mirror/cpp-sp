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
#include <fstream>

#include "BaseTestCase.h"

#include <xercesc/dom/DOMDocument.hpp>

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/security/SecurityHelper.h>

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/binding/SAML2ArtifactType0004.h>
#include <saml/saml2/binding/SAML2Artifact.h>
#include <saml/saml2/metadata/Metadata.h>

#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>
#include <shibsp/util/DOMPropertySet.h>
#include <TestApplication.h>

using namespace xmltooling;
using namespace xercesc;
using namespace std;
using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace shibsp;

extern string data_path;

class DynamicMetadataTest : public CxxTest::TestSuite {
 private:
    const string m_entityId;
    auto_ptr<SAML2ArtifactType0004> m_artifact;
public:
    DynamicMetadataTest() : CxxTest::TestSuite(), m_entityId("https://idp.shibboleth.net/idp/shibboleth"), m_artifact(nullptr)
    {}

    void setUp()
    {
        if (!m_artifact.get()) {
            m_artifact.reset(new SAML2ArtifactType0004(SecurityHelper::doHash("SHA1", m_entityId.data(), m_entityId.length(), false), 666));
        }
    }

private:

    void performTest(string fileName, bool artifactOnly, const string type =  DYNAMIC_METADATA_PROVIDER)
    {
        const string config(data_path + fileName);
        ifstream in(config.c_str());
        const XMLToolingConfig& xcf = XMLToolingConfig::getConfig();
        ParserPool& pool = xcf.getParser();
        XercesJanitor<DOMDocument> janitor(pool.parse(in));
        auto_ptr<MetadataProvider> metadataProvider(
            opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(type, janitor.get()->getDocumentElement())
        );

        ta::TestApplication testApp(SPConfig::getConfig().getServiceProvider(), metadataProvider.get());
        try {
            metadataProvider->init();
            if (!artifactOnly) {
                MetadataProviderCriteria crit(testApp, m_entityId.c_str());
                pair<const EntityDescriptor*, const RoleDescriptor*>  thePair = metadataProvider->getEntityDescriptor(crit);
                TS_ASSERT(nullptr != thePair.first);
            }

            MetadataProviderCriteria artifactCrit(testApp, m_artifact.get());
            pair<const EntityDescriptor*, const RoleDescriptor*>  artifactPair = metadataProvider->getEntityDescriptor(artifactCrit);
            TS_ASSERT(nullptr != artifactPair.first);
        } catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }

    }

public:
    void testTemplateFromRepo() {
        performTest("templateFromRepo.xml", false);
    }

    void testTemplateFromRepoArtifactOnly ()
    {
        
        performTest("templateFromRepo.xml", true);
    }


    void testTemplateFromFile()
    {
        performTest("templateFromFile.xml", false);
    }

    void testTemplateFromFileArtifactOnly()
    {
        // The template *IGNORES* the input and joint points at /idp.shibboleth.net.xml 
        performTest("templateFromFile.xml", true);
    }


    void testRegexFromFile()
    {
        performTest("regexFromFile.xml", false);
    }

    void testRegexFromFileArtifactOnly()
    {
        performTest("regexFromFile.xml", true);
    }


    void testTestFromStaticFile()
    {
        performTest("staticFromFile.xml", false, XML_METADATA_PROVIDER);
    }

    void testTestFromStaticFileArtefactOnly()
    {
        performTest("staticFromFile.xml", true, XML_METADATA_PROVIDER);
    }

/* WIP

    void MDQ() {
        string config = data_path + "fromMDQ.xml";
        ifstream in(config.c_str());
        XMLToolingConfig& xcf = XMLToolingConfig::getConfig();
        ParserPool& pool = xcf.getParser();
        XercesJanitor<DOMDocument> janitor(pool.parse(in));
        auto_ptr<MetadataProvider> metadataProvider(
            opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(DYNAMIC_METADATA_PROVIDER, janitor.get()->getDocumentElement())
        );

        ta::TestApplication testApp(SPConfig::getConfig().getServiceProvider(), metadataProvider.get());
        MetadataProviderCriteria crit(testApp, m_entityId.c_str());
        try {
            metadataProvider->init();
            pair<const EntityDescriptor*, const RoleDescriptor*>  thePair = metadataProvider->getEntityDescriptor(crit);
            TS_ASSERT(nullptr != thePair.first);

            MetadataProviderCriteria artifactCrit(testApp, m_artifact.get());
            pair<const EntityDescriptor*, const RoleDescriptor*>  artefactPair = metadataProvider->getEntityDescriptor(artifactCrit);
            TS_ASSERT(nullptr != artefactPair.first);
            if (nullptr != artefactPair.first)
                fprintf(stderr, "ei : %s\n", (artefactPair.first)->getEntityID());
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }
    */

};
