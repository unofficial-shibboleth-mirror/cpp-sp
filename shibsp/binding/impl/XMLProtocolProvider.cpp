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
 * XMLProtocolProvider.cpp
 *
 * XML-based protocol provider.
 */

#include "internal.h"
#include "exceptions.h"
#include "binding/ProtocolProvider.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <map>
#include <fstream>
#include <boost/shared_ptr.hpp>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using shibspconstants::SHIB2SPPROTOCOLS_NS;
using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {
    static const XMLCh _id[] =          UNICODE_LITERAL_2(i,d);
    static const XMLCh Binding[] =      UNICODE_LITERAL_7(B,i,n,d,i,n,g);
    static const XMLCh Initiator[] =    UNICODE_LITERAL_9(I,n,i,t,i,a,t,o,r);
    static const XMLCh Protocol[] =     UNICODE_LITERAL_8(P,r,o,t,o,c,o,l);
    static const XMLCh Protocols[] =    UNICODE_LITERAL_9(P,r,o,t,o,c,o,l,s);
    static const XMLCh Service[] =      UNICODE_LITERAL_7(S,e,r,v,i,c,e);

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL XMLProtocolProviderImpl : public DOMNodeFilter, DOMPropertySet
    {
    public:
        XMLProtocolProviderImpl(const DOMElement* e, Category& log);
        ~XMLProtocolProviderImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        FilterAction acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }

    private:
        DOMDocument* m_document;
        // Map of protocol/service pair to an Initiator propset plus an array of Binding propsets.
        typedef map< pair<string,string>, pair< const PropertySet*,vector<const PropertySet*> > > protmap_t;
        protmap_t m_map;
        vector< boost::shared_ptr<PropertySet> > m_propsetJanitor;  // needed to maintain vector API

        friend class SHIBSP_DLLLOCAL XMLProtocolProvider;
    };

    class XMLProtocolProvider : public ProtocolProvider, public ReloadableXMLFile
    {
    public:
        XMLProtocolProvider(const DOMElement* e, bool deprecationSupport=true)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT ".ProtocolProvider.XML"), true, deprecationSupport) {
            background_load(); // guarantees an exception or the policy is loaded
        }

        ~XMLProtocolProvider() {
            shutdown();
        }

        const PropertySet* getInitiator(const char* protocol, const char* service) const {
            XMLProtocolProviderImpl::protmap_t::const_iterator i = m_impl->m_map.find(pair<string,string>(protocol,service));
            return (i != m_impl->m_map.end()) ? i->second.first : nullptr;
        }

        const vector<const PropertySet*>& getBindings(const char* protocol, const char* service) const {
            XMLProtocolProviderImpl::protmap_t::const_iterator i = m_impl->m_map.find(pair<string,string>(protocol,service));
            return (i != m_impl->m_map.end()) ? i->second.second : m_noBindings;
        }

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        static vector<const PropertySet*> m_noBindings;
        scoped_ptr<XMLProtocolProviderImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    ProtocolProvider* SHIBSP_DLLLOCAL XMLProtocolProviderFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new XMLProtocolProvider(e, deprecationSupport);
    }
}

void SHIBSP_API shibsp::registerProtocolProviders()
{
    SPConfig::getConfig().ProtocolProviderManager.registerFactory(XML_PROTOCOL_PROVIDER, XMLProtocolProviderFactory);
}

ProtocolProvider::ProtocolProvider()
{
}

ProtocolProvider::~ProtocolProvider()
{
}

vector<const PropertySet*> XMLProtocolProvider::m_noBindings;

XMLProtocolProviderImpl::XMLProtocolProviderImpl(const DOMElement* e, Category& log) : m_document(nullptr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLProtocolProviderImpl");
#endif
    if (!XMLHelper::isNodeNamed(e, SHIB2SPPROTOCOLS_NS, Protocols))
        throw ConfigurationException("XML ProtocolProvider requires prot:Protocols at root of configuration.");

    e = XMLHelper::getFirstChildElement(e, SHIB2SPPROTOCOLS_NS, Protocol);
    while (e) {
        string id = XMLHelper::getAttrString(e, nullptr, _id);
        if (!id.empty()) {
            const DOMElement* svc = XMLHelper::getFirstChildElement(e, SHIB2SPPROTOCOLS_NS, Service);
            while (svc) {
                string svcid = XMLHelper::getAttrString(svc, nullptr, _id);
                if (!svcid.empty() && m_map.count(make_pair(id,svcid)) == 0) {
                    pair< const PropertySet*,vector<const PropertySet*> >& entry = m_map[make_pair(id,svcid)];
                    // Wrap the Initiator in a propset, if any.
                    const DOMElement* child = XMLHelper::getFirstChildElement(svc, SHIB2SPPROTOCOLS_NS, Initiator);
                    if (child) {
                        boost::shared_ptr<DOMPropertySet> initprop(new DOMPropertySet());
                        initprop->load(child, nullptr, this);
                        m_propsetJanitor.push_back(initprop);
                        entry.first = initprop.get();
                    }
                    else {
                        entry.first = nullptr;
                    }

                    // Walk the Bindings.
                    child = XMLHelper::getFirstChildElement(svc, SHIB2SPPROTOCOLS_NS, Binding);
                    while (child) {
                        boost::shared_ptr<DOMPropertySet> bindprop(new DOMPropertySet());
                        bindprop->load(child, nullptr, this);
                        m_propsetJanitor.push_back(bindprop);
                        entry.second.push_back(bindprop.get());
                        child = XMLHelper::getNextSiblingElement(child, SHIB2SPPROTOCOLS_NS, Binding);
                    }
                }
                svc = XMLHelper::getNextSiblingElement(svc, SHIB2SPPROTOCOLS_NS, Service);
            }
        }
        e = XMLHelper::getNextSiblingElement(e, SHIB2SPPROTOCOLS_NS, Protocol);
    }
}

pair<bool,DOMElement*> XMLProtocolProvider::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<XMLProtocolProviderImpl> impl(new XMLProtocolProviderImpl(raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}
