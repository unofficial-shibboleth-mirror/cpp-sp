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
#include <boost/shared_ptr.hpp>
#include <saml/SAMLConfig.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xsec/dsig/DSIGConstants.hpp>

using opensaml::SAMLConfig;
using opensaml::SecurityPolicyRule;
using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh excludeDefaults[] =      UNICODE_LITERAL_15(e,x,c,l,u,d,e,D,e,f,a,u,l,t,s);
    static const XMLCh includeDefaultBlacklist[] = UNICODE_LITERAL_23(i,n,c,l,u,d,e,D,e,f,a,u,l,t,B,l,a,c,k,l,i,s,t);
    static const XMLCh AlgorithmBlacklist[] =   UNICODE_LITERAL_18(A,l,g,o,r,i,t,h,m,B,l,a,c,k,l,i,s,t);
    static const XMLCh AlgorithmWhitelist[] =   UNICODE_LITERAL_18(A,l,g,o,r,i,t,h,m,W,h,i,t,e,l,i,s,t);
    static const XMLCh ExcludedAlgorithms[] =   UNICODE_LITERAL_18(E,x,c,l,u,d,e,d,A,l,g,o,r,i,t,h,m,s);
    static const XMLCh IncludedAlgorithms[] =   UNICODE_LITERAL_18(I,n,c,l,u,d,e,d,A,l,g,o,r,i,t,h,m,s);
    static const XMLCh Policy[] =               UNICODE_LITERAL_6(P,o,l,i,c,y);
    static const XMLCh PolicyRule[] =           UNICODE_LITERAL_10(P,o,l,i,c,y,R,u,l,e);
    static const XMLCh Rule[] =                 UNICODE_LITERAL_4(R,u,l,e);
    static const XMLCh SecurityPolicies[] =     UNICODE_LITERAL_16(S,e,c,u,r,i,t,y,P,o,l,i,c,i,e,s);

    static vector<xstring> EMPTY_VECTOR;

    class SHIBSP_DLLLOCAL XMLSecurityPolicyProviderImpl
    {
    public:
        XMLSecurityPolicyProviderImpl(const DOMElement*, Category&);
        ~XMLSecurityPolicyProviderImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

    private:
        DOMDocument* m_document;
        bool m_excludeDefaults;
        vector<xstring> m_includes,m_excludes;
        vector< boost::shared_ptr<SecurityPolicyRule> > m_ruleJanitor;   // need this to maintain vector type in API
        typedef map< string,pair< boost::shared_ptr<PropertySet>,vector<const SecurityPolicyRule*> > > policymap_t;
        policymap_t m_policyMap;
        policymap_t::const_iterator m_defaultPolicy;

        friend class SHIBSP_DLLLOCAL XMLSecurityPolicyProvider;
    };

    class XMLSecurityPolicyProvider : public SecurityPolicyProvider, public ReloadableXMLFile
    {
    public:
        XMLSecurityPolicyProvider(const DOMElement* e, bool deprecationSupport=true)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT ".SecurityPolicyProvider.XML"), true, deprecationSupport) {
            background_load(); // guarantees an exception or the policy is loaded
        }

        ~XMLSecurityPolicyProvider() {
            shutdown();
        }

        const PropertySet* getPolicySettings(const char* id=nullptr) const {
            if (!id || !*id)
                return m_impl->m_defaultPolicy->second.first.get();
            XMLSecurityPolicyProviderImpl::policymap_t::const_iterator i = m_impl->m_policyMap.find(id);
            if (i != m_impl->m_policyMap.end())
                return i->second.first.get();
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }

        const vector<const SecurityPolicyRule*>& getPolicyRules(const char* id=nullptr) const {
            if (!id || !*id)
                return m_impl->m_defaultPolicy->second.second;
            XMLSecurityPolicyProviderImpl::policymap_t::const_iterator i = m_impl->m_policyMap.find(id);
            if (i != m_impl->m_policyMap.end())
                return i->second.second;
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }
        const vector<xstring>& getDefaultExcludedAlgorithms() const {
            return m_impl->m_excludeDefaults ? m_defaultBlacklist : EMPTY_VECTOR;
        }
        const vector<xstring>& getExcludedAlgorithms() const {
            return m_impl->m_excludes;
        }
        const vector<xstring>& getIncludedAlgorithms() const {
            return m_impl->m_includes;
        }
        const vector<xstring>& getDefaultAlgorithmBlacklist() const {
            return getDefaultExcludedAlgorithms();
        }
        const vector<xstring>& getAlgorithmBlacklist() const {
            return getExcludedAlgorithms();
        }
        const vector<xstring>& getAlgorithmWhitelist() const {
            return getIncludedAlgorithms();
        }

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        scoped_ptr<XMLSecurityPolicyProviderImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SecurityPolicyProvider* SHIBSP_DLLLOCAL XMLSecurityPolicyProviderFactory(const DOMElement* const & e, bool deprecationSupport)
    {
        return new XMLSecurityPolicyProvider(e, deprecationSupport);
    }

    class SHIBSP_DLLLOCAL PolicyNodeFilter : public DOMNodeFilter
    {
    public:
        FilterAction acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };
}

void SHIBSP_API shibsp::registerSecurityPolicyProviders()
{
    SPConfig::getConfig().SecurityPolicyProviderManager.registerFactory(XML_SECURITYPOLICY_PROVIDER, XMLSecurityPolicyProviderFactory);
}

SecurityPolicyProvider::SecurityPolicyProvider()
{
    m_defaultBlacklist.push_back(DSIGConstants::s_unicodeStrURIRSA_MD5);
    m_defaultBlacklist.push_back(DSIGConstants::s_unicodeStrURIMD5);
    m_defaultBlacklist.push_back(DSIGConstants::s_unicodeStrURIRSA_1_5);
}

SecurityPolicyProvider::~SecurityPolicyProvider()
{
}

const vector<xstring>& SecurityPolicyProvider::getDefaultExcludedAlgorithms() const
{
    return m_defaultBlacklist;
}

const vector<xstring>& SecurityPolicyProvider::getExcludedAlgorithms() const {
    return getAlgorithmBlacklist();
}

const vector<xstring>& SecurityPolicyProvider::getIncludedAlgorithms() const {
    return getAlgorithmWhitelist();
}

const vector<xstring>& SecurityPolicyProvider::getDefaultAlgorithmBlacklist() const
{
    return getDefaultExcludedAlgorithms();
}

const vector<xstring>& SecurityPolicyProvider::getAlgorithmBlacklist() const {
    return EMPTY_VECTOR;
}

const vector<xstring>& SecurityPolicyProvider::getAlgorithmWhitelist() const {
    return EMPTY_VECTOR;
}

SecurityPolicy* SecurityPolicyProvider::createSecurityPolicy(
    const Application& application, const xmltooling::QName* role, const char* policyId
    ) const
{
    pair<bool,bool> validate = getPolicySettings(policyId ? policyId : application.getString("policyId").second)->getBool("validate");
    return new SecurityPolicy(application, role, (validate.first && validate.second), policyId);
}

SecurityPolicy* SecurityPolicyProvider::createSecurityPolicy(
    const char* profile, const Application& application, const xmltooling::QName* role, const char* policyId
    ) const
{
    SecurityPolicy* policy = createSecurityPolicy(application, role, policyId);
    policy->setProfile(profile);
    return policy;
}

XMLSecurityPolicyProviderImpl::XMLSecurityPolicyProviderImpl(const DOMElement* e, Category& log)
    : m_document(nullptr), m_excludeDefaults(true), m_defaultPolicy(m_policyMap.end())
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLSecurityPolicyProviderImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2SPCONFIG_NS, SecurityPolicies) &&
        !XMLHelper::isNodeNamed(e, shibspconstants::SHIB3SPCONFIG_NS, SecurityPolicies)) {
        throw ConfigurationException("XML SecurityPolicyProvider requires conf:SecurityPolicies at root of configuration.");
    }

    bool deprecationSupport = false;
    if (XMLString::equals(e->getNamespaceURI(), shibspconstants::SHIB2SPCONFIG_NS)) {
        SPConfig::getConfig().deprecation().warn("legacy V2 configuration");
        deprecationSupport = true;
    }

    const XMLCh* algs = nullptr;
    const DOMElement* alglist = XMLHelper::getLastChildElement(e, AlgorithmBlacklist);
    if (alglist) {
        SPConfig::getConfig().deprecation().warn("<AlgorithmBlacklist> and includeDefaultBlacklist replaced by <ExcludedAlgorithms> and excludeDefaults");
        m_excludeDefaults = XMLHelper::getAttrBool(alglist, true, includeDefaultBlacklist);
        if (alglist->hasChildNodes()) {
            algs = alglist->getFirstChild()->getNodeValue();
        }
    }
    else {
        alglist = XMLHelper::getLastChildElement(e, AlgorithmWhitelist);
        if (alglist) {
            SPConfig::getConfig().deprecation().warn("<AlgorithmWhitelist> replaced by <IncludedAlgorithms>");
            if (alglist->hasChildNodes()) {
                algs = alglist->getFirstChild()->getNodeValue();
            }
            m_excludeDefaults = false;
        }
        else {
            const DOMElement* alglist = XMLHelper::getLastChildElement(e, ExcludedAlgorithms);
            if (alglist) {
                m_excludeDefaults = XMLHelper::getAttrBool(alglist, true, excludeDefaults);
                if (alglist->hasChildNodes()) {
                    algs = alglist->getFirstChild()->getNodeValue();
                }
            }
            else {
                alglist = XMLHelper::getLastChildElement(e, IncludedAlgorithms);
                if (alglist && alglist->hasChildNodes()) {
                    algs = alglist->getFirstChild()->getNodeValue();
                }
                m_excludeDefaults = false;
            }
        }
    }

    if (algs) {
        const XMLCh* token;
        XMLStringTokenizer tokenizer(algs);
        while (tokenizer.hasMoreTokens()) {
            token = tokenizer.nextToken();
            if (token) {
                if (XMLString::equals(alglist->getLocalName(), AlgorithmBlacklist) ||
                    XMLString::equals(alglist->getLocalName(), ExcludedAlgorithms)) {
                    m_excludes.push_back(token);
                }
                else {
                    m_includes.push_back(token);
                }
            }
        }
    }

    PolicyNodeFilter filter;
    SAMLConfig& samlConf = SAMLConfig::getConfig();
    e = XMLHelper::getFirstChildElement(e, Policy);
    while (e) {
        string id(XMLHelper::getAttrString(e, nullptr, _id));
        policymap_t::mapped_type& rules = m_policyMap[id];
        boost::shared_ptr<DOMPropertySet> settings(new DOMPropertySet());
        settings->load(e, nullptr, &filter);
        rules.first = settings;

        // Set default policy if not set, or id is "default".
        if (m_defaultPolicy == m_policyMap.end() || id == "default")
            m_defaultPolicy = m_policyMap.find(id);

        // Process PolicyRule elements.
        const DOMElement* rule = XMLHelper::getFirstChildElement(e, PolicyRule);
        while (rule) {
            string t(XMLHelper::getAttrString(rule, nullptr, _type));
            if (!t.empty()) {
                try {
                    boost::shared_ptr<SecurityPolicyRule> ptr(samlConf.SecurityPolicyRuleManager.newPlugin(t.c_str(), rule, deprecationSupport));
                    m_ruleJanitor.push_back(ptr);
                    rules.second.push_back(ptr.get());
                }
                catch (std::exception& ex) {
                    log.crit("error instantiating policy rule (%s) in policy (%s): %s", t.c_str(), id.c_str(), ex.what());
                }
            }
            rule = XMLHelper::getNextSiblingElement(rule, PolicyRule);
        }

        if (rules.second.size() == 0) {
            // Process Rule elements.
            SPConfig::getConfig().deprecation().warn("Rule elements detected, convert to PolicyRule syntax");
            rule = XMLHelper::getFirstChildElement(e, Rule);
            while (rule) {
                string t(XMLHelper::getAttrString(rule, nullptr, _type));
                if (!t.empty()) {
                    try {
                        boost::shared_ptr<SecurityPolicyRule> ptr(samlConf.SecurityPolicyRuleManager.newPlugin(t.c_str(), rule, deprecationSupport));
                        m_ruleJanitor.push_back(ptr);
                        rules.second.push_back(ptr.get());
                    }
                    catch (std::exception& ex) {
                        log.crit("error instantiating policy rule (%s) in policy (%s): %s", t.c_str(), id.c_str(), ex.what());
                    }
                }
                rule = XMLHelper::getNextSiblingElement(rule, Rule);
            }

            // Manually add a basic Conditions rule.
            log.warn("installing a default Conditions rule in policy (%s) for compatibility with legacy configuration", id.c_str());
            boost::shared_ptr<SecurityPolicyRule> cptr(samlConf.SecurityPolicyRuleManager.newPlugin(CONDITIONS_POLICY_RULE, nullptr, deprecationSupport));
            m_ruleJanitor.push_back(cptr);
            rules.second.push_back(cptr.get());
        }

        e = XMLHelper::getNextSiblingElement(e, Policy);
    }

    if (m_defaultPolicy == m_policyMap.end())
        throw ConfigurationException("XML SecurityPolicyProvider requires at least one Policy.");
}

pair<bool,DOMElement*> XMLSecurityPolicyProvider::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<XMLSecurityPolicyProviderImpl> impl(new XMLSecurityPolicyProviderImpl(raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}
