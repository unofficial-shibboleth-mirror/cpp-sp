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
 * ChainingAttributeExtractor.cpp
 *
 * Chains together multiple AttributeExtractor plugins.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <boost/ptr_container/ptr_vector.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL ChainingAttributeExtractor : public AttributeExtractor
    {
    public:
        ChainingAttributeExtractor(const DOMElement* e, bool deprecationSupport=true);
        virtual ~ChainingAttributeExtractor() {}

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

        void extractAttributes(
            const Application& application,
            const GenericRequest* request,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<Attribute*>& attributes
            ) const {
            for (ptr_vector<AttributeExtractor>::iterator i = m_extractors.begin(); i != m_extractors.end(); ++i) {
                Locker locker(&(*i));
                i->extractAttributes(application, request, issuer, xmlObject, attributes);
            }
        }

        void getAttributeIds(vector<string>& attributes) const {
            for (ptr_vector<AttributeExtractor>::iterator i = m_extractors.begin(); i != m_extractors.end(); ++i) {
                Locker locker(&(*i));
                i->getAttributeIds(attributes);
            }
        }

        void generateMetadata(SPSSODescriptor& role) const {
            for (ptr_vector<AttributeExtractor>::iterator i = m_extractors.begin(); i != m_extractors.end(); ++i) {
                Locker locker(&(*i));
                i->generateMetadata(role);
            }
        }

    private:
        mutable ptr_vector<AttributeExtractor> m_extractors;
    };

    static const XMLCh _AttributeExtractor[] =  UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,E,x,t,r,a,c,t,o,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory AssertionAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory MetadataAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory DelegationAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory KeyDescriptorAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory XMLAttributeExtractorFactory;

    AttributeExtractor* SHIBSP_DLLLOCAL ChainingExtractorFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new ChainingAttributeExtractor(e, deprecationSupport);
    }
};

void SHIBSP_API shibsp::registerAttributeExtractors()
{
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(ASSERTION_ATTRIBUTE_EXTRACTOR, AssertionAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(METADATA_ATTRIBUTE_EXTRACTOR, MetadataAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(DELEGATION_ATTRIBUTE_EXTRACTOR, DelegationAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(KEYDESCRIPTOR_ATTRIBUTE_EXTRACTOR, KeyDescriptorAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(XML_ATTRIBUTE_EXTRACTOR, XMLAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(CHAINING_ATTRIBUTE_EXTRACTOR, ChainingExtractorFactory);
}

AttributeExtractor::AttributeExtractor()
{
}

AttributeExtractor::~AttributeExtractor()
{
}

void AttributeExtractor::generateMetadata(SPSSODescriptor& role) const
{
}

ChainingAttributeExtractor::ChainingAttributeExtractor(const DOMElement* e, bool deprecationSupport)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = XMLHelper::getFirstChildElement(e, _AttributeExtractor);
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (!t.empty()) {
            try {
                Category::getInstance(SHIBSP_LOGCAT ".AttributeExtractor.Chaining").info(
                    "building AttributeExtractor of type (%s)...", t.c_str()
                    );
                auto_ptr<AttributeExtractor> np(conf.AttributeExtractorManager.newPlugin(t.c_str(), e, deprecationSupport));
                m_extractors.push_back(np.get());
                np.release();
            }
            catch (const exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT ".AttributeExtractor.Chaining").error(
                    "caught exception processing embedded AttributeExtractor element: %s", ex.what()
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeExtractor);
    }
}
