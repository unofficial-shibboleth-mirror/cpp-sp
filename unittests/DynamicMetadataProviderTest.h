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
#include <xercesc\dom\DOMDocument.hpp>
#include <cpp-xmltooling\xmltooling\XMLToolingConfig.h>
#include <cpp-xmltooling\xmltooling\util\XMLHelper.h>
#include <cpp-xmltooling\xmltooling\util\ParserPool.h>

#include <cpp-opensaml\saml\SAMLConfig.h>
#include <cpp-opensaml\saml\saml2\metadata\MetadataProvider.h>


using namespace xmltooling;
using namespace xercesc;
using namespace std;
using namespace opensaml::saml2md;

extern string data_path;

class DynamicMetadataTest : public CxxTest::TestSuite {
public:
    void setUp()
    {}

    void tearDown()
    {}

    void testTemplateFromRepo() {
        string config = data_path + "templateFromRepo.xml";
        ifstream in(config.c_str());
        XMLToolingConfig& xcf = XMLToolingConfig::getConfig();
        ParserPool& pool = xcf.getParser();
        DOMDocument* doc = pool.parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr<MetadataProvider> metadataProvider(
            opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(DYNAMIC_METADATA_PROVIDER, doc->getDocumentElement())
        );
        try {
            metadataProvider->init();
            pair<const EntityDescriptor*, const RoleDescriptor*>  pair = metadataProvider->getEntityDescriptor( opensaml::saml2md::MetadataProvider::Criteria("https://www.example.org/sp"));
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
    }

};


