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
 * XMLSecurityPolicyProvider.cpp
 *
 * XML-based security policy provider.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "security/SecurityPolicy.h"
#include "security/SecurityPolicyProvider.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <map>
#include <saml/SAMLConfig.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using shibspconstants::SHIB2SPCONFIG_NS;
using opensaml::SAMLConfig;
using opensaml::SecurityPolicyRule;
using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL XMLSecurityPolicyProviderImpl
    {
    public:
        XMLSecurityPolicyProviderImpl(const DOMElement* e, Category& log);
        ~XMLSecurityPolicyProviderImpl() {
            for (map< string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::iterator i = m_policyMap.begin(); i != m_policyMap.end(); ++i) {
                delete i->second.first;
                for_each(i->second.second.begin(), i->second.second.end(), xmltooling::cleanup<SecurityPolicyRule>());
            }
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

    private:
        DOMDocument* m_document;
        vector<xstring> m_whitelist,m_blacklist;
        map< string,pair< PropertySet*,vector<const SecurityPolicyRule*> > > m_policyMap;
        map< string,pair< PropertySet*,vector<const SecurityPolicyRule*> > >::const_iterator m_defaultPolicy;

        friend class SHIBSP_DLLLOCAL XMLSecurityPolicyProvider;
    };

    class XMLSecurityPolicyProvider : public SecurityPolicyProvider, public ReloadableXMLFile
    {
    public:
        XMLSecurityPolicyProvider(const DOMElement* e)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".SecurityPolicyProvider.XML")), m_impl(nullptr) {
            background_load(); // guarantees an exception or the policy is loaded
        }

        ~XMLSecurityPolicyProvider() {
            shutdown();
            delete m_impl;
        }

        const PropertySet* getPolicySettings(const char* id=nullptr) const {
            if (!id || !*id)
                return m_impl->m_defaultPolicy->second.first;
            map<string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::const_iterator i = m_impl->m_policyMap.find(id);
            if (i != m_impl->m_policyMap.end())
                return i->second.first;
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }

        const vector<const SecurityPolicyRule*>& getPolicyRules(const char* id=nullptr) const {
            if (!id || !*id)
                return m_impl->m_defaultPolicy->second.second;
            map<string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::const_iterator i = m_impl->m_policyMap.find(id);
            if (i != m_impl->m_policyMap.end())
                return i->second.second;
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }
        const vector<xstring>& getAlgorithmBlacklist() const {
            return m_impl->m_blacklist;
        }
        const vector<xstring>& getAlgorithmWhitelist() const {
            return m_impl->m_whitelist;
        }
        
    protected:
        pair<bool,DOMElement*> load(bool backup);
        pair<bool,DOMElement*> background_load();

    private:
        XMLSecurityPolicyProviderImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SecurityPolicyProvider* SHIBSP_DLLLOCAL XMLSecurityPolicyProviderFactory(const DOMElement* const & e)
    {
        return new XMLSecurityPolicyProvider(e);
    }

    class SHIBSP_DLLLOCAL PolicyNodeFilter : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh AlgorithmBlacklist[] =   UNICODE_LITERAL_18(A,l,g,o,r,i,t,h,m,B,l,a,c,k,l,i,s,t);
    static const XMLCh AlgorithmWhitelist[] =   UNICODE_LITERAL_18(A,l,g,o,r,i,t,h,m,W,h,i,t,e,l,i,s,t);
    static const XMLCh Policy[] =               UNICODE_LITERAL_6(P,o,l,i,c,y);
    static const XMLCh PolicyRule[] =           UNICODE_LITERAL_10(P,o,l,i,c,y,R,u,l,e);
    static const XMLCh Rule[] =                 UNICODE_LITERAL_4(R,u,l,e);
    static const XMLCh SecurityPolicies[] =     UNICODE_LITERAL_16(S,e,c,u,r,i,t,y,P,o,l,i,c,i,e,s);
}

void SHIBSP_API shibsp::registerSecurityPolicyProviders()
{
    SPConfig::getConfig().SecurityPolicyProviderManager.registerFactory(XML_SECURITYPOLICY_PROVIDER, XMLSecurityPolicyProviderFactory);
}

SecurityPolicyProvider::SecurityPolicyProvider()
{
}

SecurityPolicyProvider::~SecurityPolicyProvider()
{
}

SecurityPolicy* SecurityPolicyProvider::createSecurityPolicy(
    const Application& application, const xmltooling::QName* role, const char* policyId
    ) const
{
    pair<bool,bool> validate = getPolicySettings(policyId ? policyId : application.getString("policyId").second)->getBool("validate");
    return new SecurityPolicy(application, role, (validate.first && validate.second), policyId);
}

XMLSecurityPolicyProviderImpl::XMLSecurityPolicyProviderImpl(const DOMElement* e, Category& log)
    : m_document(nullptr), m_defaultPolicy(m_policyMap.end())
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLSecurityPolicyProviderImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, SHIB2SPCONFIG_NS, SecurityPolicies))
        throw ConfigurationException("XML SecurityPolicyProvider requires conf:SecurityPolicies at root of configuration.");

    const XMLCh* algs = nullptr;
    const DOMElement* alglist = XMLHelper::getLastChildElement(e, AlgorithmBlacklist);
    if (alglist && alglist->hasChildNodes()) {
        algs = alglist->getFirstChild()->getNodeValue();
    }
    else if ((alglist = XMLHelper::getLastChildElement(e, AlgorithmWhitelist)) && alglist->hasChildNodes()) {
        algs = alglist->getFirstChild()->getNodeValue();
    }
    if (algs) {
        const XMLCh* token;
        XMLStringTokenizer tokenizer(algs);
        while (tokenizer.hasMoreTokens()) {
            token = tokenizer.nextToken();
            if (token) {
                if (XMLString::equals(alglist->getLocalName(), AlgorithmBlacklist))
                    m_blacklist.push_back(token);
                else
                    m_whitelist.push_back(token);
            }
        }
    }

    PolicyNodeFilter filter;
    SAMLConfig& samlConf = SAMLConfig::getConfig();
    e = XMLHelper::getFirstChildElement(e, Policy);
    while (e) {
        string id(XMLHelper::getAttrString(e, nullptr, _id));
        pair< PropertySet*,vector<const SecurityPolicyRule*> >& rules = m_policyMap[id];
        rules.first = nullptr;
        auto_ptr<DOMPropertySet> settings(new DOMPropertySet());
        settings->load(e, nullptr, &filter);
        rules.first = settings.release();

        // Set default policy if not set, or id is "default".
        if (m_defaultPolicy == m_policyMap.end() || id == "default")
            m_defaultPolicy = m_policyMap.find(id);

        // Process PolicyRule elements.
        const DOMElement* rule = XMLHelper::getFirstChildElement(e, PolicyRule);
        while (rule) {
            string t(XMLHelper::getAttrString(rule, nullptr, _type));
            if (!t.empty()) {
                try {
                    rules.second.push_back(samlConf.SecurityPolicyRuleManager.newPlugin(t.c_str(), rule));
                }
                catch (exception& ex) {
                    log.crit("error instantiating policy rule (%s) in policy (%s): %s", t.c_str(), id.c_str(), ex.what());
                }
            }
            rule = XMLHelper::getNextSiblingElement(rule, PolicyRule);
        }

        if (rules.second.size() == 0) {
            // Process Rule elements.
            log.warn("detected legacy Policy configuration, please convert to new PolicyRule syntax");
            rule = XMLHelper::getFirstChildElement(e, Rule);
            while (rule) {
                string t(XMLHelper::getAttrString(rule, nullptr, _type));
                if (!t.empty()) {
                    try {
                        rules.second.push_back(samlConf.SecurityPolicyRuleManager.newPlugin(t.c_str(), rule));
                    }
                    catch (exception& ex) {
                        log.crit("error instantiating policy rule (%s) in policy (%s): %s", t.c_str(), id.c_str(), ex.what());
                    }
                }
                rule = XMLHelper::getNextSiblingElement(rule, Rule);
            }

            // Manually add a basic Conditions rule.
            log.info("installing a default Conditions rule in policy (%s) for compatibility with legacy configuration", id.c_str());
            rules.second.push_back(samlConf.SecurityPolicyRuleManager.newPlugin(CONDITIONS_POLICY_RULE, nullptr));
        }

        e = XMLHelper::getNextSiblingElement(e, Policy);
    }

    if (m_defaultPolicy == m_policyMap.end())
        throw ConfigurationException("XML SecurityPolicyProvider requires at least one Policy.");
}

pair<bool,DOMElement*> XMLSecurityPolicyProvider::load(bool backup)
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load(backup);

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    XMLSecurityPolicyProviderImpl* impl = new XMLSecurityPolicyProviderImpl(raw.second, m_log);

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    delete m_impl;
    m_impl = impl;


    return make_pair(false,(DOMElement*)nullptr);
}

pair<bool,DOMElement*> XMLSecurityPolicyProvider::background_load()
{
    try {
        return load(false);
    }
    catch (long& ex) {
        if (ex == HTTPResponse::XMLTOOLING_HTTP_STATUS_NOTMODIFIED)
            m_log.info("remote resource (%s) unchanged", m_source.c_str());
        if (!m_loaded && !m_backing.empty())
            return load(true);
        throw;
    }
    catch (exception&) {
        if (!m_loaded && !m_backing.empty())
            return load(true);
        throw;
    }
}
