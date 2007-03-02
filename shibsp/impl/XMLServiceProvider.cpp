/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * XMLServiceProvider.cpp
 *
 * XML-based SP configuration and mgmt
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "Application.h"
#include "RequestMapper.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "SPRequest.h"
#include "TransactionLog.h"
#include "attribute/resolver/AttributeResolver.h"
#include "handler/Handler.h"
#include "remoting/ListenerService.h"
#include "security/PKIXTrustEngine.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <saml/SAMLConfig.h>
#include <saml/binding/ArtifactMap.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/metadata/ChainingMetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/ChainingTrustEngine.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/ReplayCache.h>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL TokenValidator : public Validator
    {
    public:
        TokenValidator(const Application& app, time_t ts=0, const RoleDescriptor* role=NULL) : m_app(app), m_ts(ts), m_role(role) {}
        void validate(const XMLObject*) const;

    private:
        const Application& m_app;
        time_t m_ts;
        const RoleDescriptor* m_role;
    };

    static vector<const Handler*> g_noHandlers;

    // Application configuration wrapper
    class SHIBSP_DLLLOCAL XMLApplication : public virtual Application, public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLApplication(const ServiceProvider*, const DOMElement* e, const XMLApplication* base=NULL);
        ~XMLApplication() { cleanup(); }
    
        // PropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:sp:config:2.0") const;

        // Application
        const ServiceProvider& getServiceProvider() const {return *m_sp;}
        const char* getId() const {return getString("id").second;}
        const char* getHash() const {return m_hash.c_str();}

        MetadataProvider* getMetadataProvider() const {
            return (!m_metadata && m_base) ? m_base->getMetadataProvider() : m_metadata;
        }
        TrustEngine* getTrustEngine() const {
            return (!m_trust && m_base) ? m_base->getTrustEngine() : m_trust;
        }
        AttributeResolver* getAttributeResolver() const {
            return (!m_attrResolver && m_base) ? m_base->getAttributeResolver() : m_attrResolver;
        }

        const PropertySet* getCredentialUse(const EntityDescriptor* provider) const;

        const Handler* getDefaultSessionInitiator() const;
        const Handler* getSessionInitiatorById(const char* id) const;
        const Handler* getDefaultAssertionConsumerService() const;
        const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        const vector<const Handler*>& getAssertionConsumerServicesByBinding(const XMLCh* binding) const;
        const Handler* getHandler(const char* path) const;

        const vector<const XMLCh*>& getAudiences() const {
            return (m_audiences.empty() && m_base) ? m_base->getAudiences() : m_audiences;
        }
        Validator* getTokenValidator(time_t ts=0, const opensaml::saml2md::RoleDescriptor* role=NULL) const {
            return new TokenValidator(*this, ts, role);
        }

        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;
    
    private:
        void cleanup();
        const ServiceProvider* m_sp;   // this is ok because its locking scope includes us
        const XMLApplication* m_base;
        string m_hash;
        MetadataProvider* m_metadata;
        TrustEngine* m_trust;
        AttributeResolver* m_attrResolver;
        vector<const XMLCh*> m_audiences;

        // manage handler objects
        vector<Handler*> m_handlers;

        // maps location (path info) to applicable handlers
        map<string,const Handler*> m_handlerMap;

        // maps unique indexes to consumer services
        map<unsigned int,const Handler*> m_acsIndexMap;
        
        // pointer to default consumer service
        const Handler* m_acsDefault;

        // maps binding strings to supporting consumer service(s)
#ifdef HAVE_GOOD_STL
        typedef map<xstring,vector<const Handler*> > ACSBindingMap;
#else
        typedef map<string,vector<const Handler*> > ACSBindingMap;
#endif
        ACSBindingMap m_acsBindingMap;

        // maps unique ID strings to session initiators
        map<string,const Handler*> m_sessionInitMap;

        // pointer to default session initiator
        const Handler* m_sessionInitDefault;

        DOMPropertySet* m_credDefault;
#ifdef HAVE_GOOD_STL
        map<xstring,PropertySet*> m_credMap;
#else
        map<const XMLCh*,PropertySet*> m_credMap;
#endif
    };

    // Top-level configuration implementation
    class SHIBSP_DLLLOCAL XMLConfig;
    class SHIBSP_DLLLOCAL XMLConfigImpl : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLConfigImpl(const DOMElement* e, bool first, const XMLConfig* outer);
        ~XMLConfigImpl();
        
        RequestMapper* m_requestMapper;
        map<string,Application*> m_appmap;
        map<string,CredentialResolver*> m_credResolverMap;
        map< string,pair< PropertySet*,vector<const SecurityPolicyRule*> > > m_policyMap;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

    private:
        void doExtensions(const DOMElement* e, const char* label, Category& log);

        const XMLConfig* m_outer;
        DOMDocument* m_document;
    };

    class SHIBSP_DLLLOCAL XMLConfig : public ServiceProvider, public ReloadableXMLFile
    {
    public:
        XMLConfig(const DOMElement* e)
            : ReloadableXMLFile(e), m_impl(NULL), m_listener(NULL), m_sessionCache(NULL), m_tranLog(NULL) {
        }
        
        void init() {
            load();
        }

        ~XMLConfig() {
            delete m_impl;
            delete m_sessionCache;
            delete m_listener;
            delete m_tranLog;
            XMLToolingConfig::getConfig().setReplayCache(NULL);
            SAMLConfig::getConfig().setArtifactMap(NULL);
            for_each(m_storage.begin(), m_storage.end(), cleanup_pair<string,StorageService>());
        }

        // PropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const {return m_impl->getBool(name,ns);}
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const {return m_impl->getString(name,ns);}
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const {return m_impl->getXMLString(name,ns);}
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const {return m_impl->getUnsignedInt(name,ns);}
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const {return m_impl->getInt(name,ns);}
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:sp:config:2.0") const {return m_impl->getPropertySet(name,ns);}
        const DOMElement* getElement() const {return m_impl->getElement();}

        // ServiceProvider
        TransactionLog* getTransactionLog() const {
            if (m_tranLog)
                return m_tranLog;
            throw ConfigurationException("No TransactionLog available.");
        }

        StorageService* getStorageService(const char* id) const {
            if (id) {
                map<string,StorageService*>::const_iterator i=m_storage.find(id);
                if (i!=m_storage.end())
                    return i->second;
            }
            return NULL;
        }

        ListenerService* getListenerService(bool required=true) const {
            if (required && !m_listener)
                throw ConfigurationException("No ListenerService available.");
            return m_listener;
        }

        SessionCache* getSessionCache(bool required=true) const {
            if (required && !m_sessionCache)
                throw ConfigurationException("No SessionCache available.");
            return m_sessionCache;
        }

        RequestMapper* getRequestMapper(bool required=true) const {
            if (required && !m_impl->m_requestMapper)
                throw ConfigurationException("No RequestMapper available.");
            return m_impl->m_requestMapper;
        }

        const Application* getApplication(const char* applicationId) const {
            map<string,Application*>::const_iterator i=m_impl->m_appmap.find(applicationId);
            return (i!=m_impl->m_appmap.end()) ? i->second : NULL;
        }

        CredentialResolver* getCredentialResolver(const char* id) const {
            if (id) {
                map<string,CredentialResolver*>::const_iterator i=m_impl->m_credResolverMap.find(id);
                if (i!=m_impl->m_credResolverMap.end())
                    return i->second;
            }
            return NULL;
        }

        const PropertySet* getPolicySettings(const char* id) const {
            map<string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::const_iterator i = m_impl->m_policyMap.find(id);
            if (i!=m_impl->m_policyMap.end())
                return i->second.first;
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }

        const vector<const SecurityPolicyRule*>& getPolicyRules(const char* id) const {
            map<string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::const_iterator i = m_impl->m_policyMap.find(id);
            if (i!=m_impl->m_policyMap.end())
                return i->second.second;
            throw ConfigurationException("Security Policy ($1) not found, check <SecurityPolicies> element.", params(1,id));
        }

    protected:
        pair<bool,DOMElement*> load();

    private:
        friend class XMLConfigImpl;
        XMLConfigImpl* m_impl;
        mutable ListenerService* m_listener;
        mutable SessionCache* m_sessionCache;
        mutable TransactionLog* m_tranLog;
        mutable map<string,StorageService*> m_storage;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh _Application[] =         UNICODE_LITERAL_11(A,p,p,l,i,c,a,t,i,o,n);
    static const XMLCh Applications[] =         UNICODE_LITERAL_12(A,p,p,l,i,c,a,t,i,o,n,s);
    static const XMLCh _ArtifactMap[] =         UNICODE_LITERAL_11(A,r,t,i,f,a,c,t,M,a,p);
    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh Credentials[] =          UNICODE_LITERAL_11(C,r,e,d,e,n,t,i,a,l,s);
    static const XMLCh CredentialUse[] =        UNICODE_LITERAL_13(C,r,e,d,e,n,t,i,a,l,U,s,e);
    static const XMLCh fatal[] =                UNICODE_LITERAL_5(f,a,t,a,l);
    static const XMLCh _Handler[] =             UNICODE_LITERAL_7(H,a,n,d,l,e,r);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh Implementation[] =       UNICODE_LITERAL_14(I,m,p,l,e,m,e,n,t,a,t,i,o,n);
    static const XMLCh InProcess[] =            UNICODE_LITERAL_9(I,n,P,r,o,c,e,s,s);
    static const XMLCh Library[] =              UNICODE_LITERAL_7(L,i,b,r,a,r,y);
    static const XMLCh Listener[] =             UNICODE_LITERAL_8(L,i,s,t,e,n,e,r);
    static const XMLCh logger[] =               UNICODE_LITERAL_6(l,o,g,g,e,r);
    static const XMLCh MemoryListener[] =       UNICODE_LITERAL_14(M,e,m,o,r,y,L,i,s,t,e,n,e,r);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh OutOfProcess[] =         UNICODE_LITERAL_12(O,u,t,O,f,P,r,o,c,e,s,s);
    static const XMLCh _path[] =                UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh Policy[] =               UNICODE_LITERAL_6(P,o,l,i,c,y);
    static const XMLCh RelyingParty[] =         UNICODE_LITERAL_12(R,e,l,y,i,n,g,P,a,r,t,y);
    static const XMLCh _ReplayCache[] =         UNICODE_LITERAL_11(R,e,p,l,a,y,C,a,c,h,e);
    static const XMLCh _RequestMapper[] =       UNICODE_LITERAL_13(R,e,q,u,e,s,t,M,a,p,p,e,r);
    static const XMLCh Rule[] =                 UNICODE_LITERAL_4(R,u,l,e);
    static const XMLCh SecurityPolicies[] =     UNICODE_LITERAL_16(S,e,c,u,r,i,t,y,P,o,l,i,c,i,e,s);
    static const XMLCh _SessionCache[] =        UNICODE_LITERAL_12(S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh SessionInitiator[] =     UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _StorageService[] =      UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh TCPListener[] =          UNICODE_LITERAL_11(T,C,P,L,i,s,t,e,n,e,r);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh UnixListener[] =         UNICODE_LITERAL_12(U,n,i,x,L,i,s,t,e,n,e,r);

    class SHIBSP_DLLLOCAL PolicyNodeFilter : public DOMNodeFilter
    {
    public:
        short acceptNode(const DOMNode* node) const {
            if (XMLHelper::isNodeNamed(node,shibspconstants::SHIB2SPCONFIG_NS,Rule))
                return FILTER_REJECT;
            return FILTER_ACCEPT;
        }
    };
};

namespace shibsp {
    ServiceProvider* XMLServiceProviderFactory(const DOMElement* const & e)
    {
        return new XMLConfig(e);
    }
};

void TokenValidator::validate(const XMLObject* xmlObject) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".Application");

    const opensaml::RootObject* root = NULL;
    const opensaml::saml2::Assertion* token2 = dynamic_cast<const opensaml::saml2::Assertion*>(xmlObject);
    if (token2) {
        const opensaml::saml2::Conditions* conds = token2->getConditions();
        // First verify the time conditions, using the specified timestamp, if non-zero.
        if (m_ts>0 && conds) {
            unsigned int skew = XMLToolingConfig::getConfig().clock_skew_secs;
            time_t t=conds->getNotBeforeEpoch();
            if (m_ts+skew < t)
                throw ValidationException("Assertion is not yet valid.");
            t=conds->getNotOnOrAfterEpoch();
            if (t <= m_ts-skew)
                throw ValidationException("Assertion is no longer valid.");
        }

        // Now we process conditions. Only audience restrictions at the moment.
        const vector<opensaml::saml2::Condition*>& convec = conds->getConditions();
        for (vector<opensaml::saml2::Condition*>::const_iterator c = convec.begin(); c!=convec.end(); ++c) {
            const opensaml::saml2::AudienceRestriction* ac=dynamic_cast<const opensaml::saml2::AudienceRestriction*>(*c);
            if (!ac) {
                log.error("unrecognized Condition in assertion (%s)",
                    (*c)->getSchemaType() ? (*c)->getSchemaType()->toString().c_str() : (*c)->getElementQName().toString().c_str());
                throw ValidationException("Assertion contains an unrecognized condition.");
            }

            bool found = false;
            const vector<opensaml::saml2::Audience*>& auds1 = ac->getAudiences();
            const vector<const XMLCh*>& auds2 = m_app.getAudiences();
            for (vector<opensaml::saml2::Audience*>::const_iterator a = auds1.begin(); !found && a!=auds1.end(); ++a) {
                for (vector<const XMLCh*>::const_iterator a2 = auds2.begin(); !found && a2!=auds2.end(); ++a2) {
                    found = XMLString::equals((*a)->getAudienceURI(), *a2);
                }
            }

            if (!found) {
                ostringstream os;
                os << *ac;
                log.error("unacceptable AudienceRestriction in assertion (%s)", os.str().c_str());
                throw ValidationException("Assertion contains an unacceptable AudienceRestriction.");
            }
        }

        root = token2;
    }
    else {
        const opensaml::saml1::Assertion* token1 = dynamic_cast<const opensaml::saml1::Assertion*>(xmlObject);
        if (token1) {
            const opensaml::saml1::Conditions* conds = token1->getConditions();
            // First verify the time conditions, using the specified timestamp, if non-zero.
            if (m_ts>0 && conds) {
                unsigned int skew = XMLToolingConfig::getConfig().clock_skew_secs;
                time_t t=conds->getNotBeforeEpoch();
                if (m_ts+skew < t)
                    throw ValidationException("Assertion is not yet valid.");
                t=conds->getNotOnOrAfterEpoch();
                if (t <= m_ts-skew)
                    throw ValidationException("Assertion is no longer valid.");
            }

            // Now we process conditions. Only audience restrictions at the moment.
            const vector<opensaml::saml1::Condition*>& convec = conds->getConditions();
            for (vector<opensaml::saml1::Condition*>::const_iterator c = convec.begin(); c!=convec.end(); ++c) {
                const opensaml::saml1::AudienceRestrictionCondition* ac=dynamic_cast<const opensaml::saml1::AudienceRestrictionCondition*>(*c);
                if (!ac) {
                    log.error("unrecognized Condition in assertion (%s)",
                        (*c)->getSchemaType() ? (*c)->getSchemaType()->toString().c_str() : (*c)->getElementQName().toString().c_str());
                    throw ValidationException("Assertion contains an unrecognized condition.");
                }

                bool found = false;
                const vector<opensaml::saml1::Audience*>& auds1 = ac->getAudiences();
                const vector<const XMLCh*>& auds2 = m_app.getAudiences();
                for (vector<opensaml::saml1::Audience*>::const_iterator a = auds1.begin(); !found && a!=auds1.end(); ++a) {
                    for (vector<const XMLCh*>::const_iterator a2 = auds2.begin(); !found && a2!=auds2.end(); ++a2) {
                        found = XMLString::equals((*a)->getAudienceURI(), *a2);
                    }
                }

                if (!found) {
                    ostringstream os;
                    os << *ac;
                    log.error("unacceptable AudienceRestrictionCondition in assertion (%s)", os.str().c_str());
                    throw ValidationException("Assertion contains an unacceptable AudienceRestrictionCondition.");
                }
            }

            root = token1;
        }
        else {
            throw ValidationException("Unknown object type passed to token validator.");
        }
    }

    if (!m_role || !m_app.getTrustEngine()) {
        log.warn("no issuer role or TrustEngine provided, so no signature validation performed");
        return;
    }

    const PropertySet* policy=m_app.getServiceProvider().getPolicySettings(m_app.getString("policyId").second);
    pair<bool,bool> signedAssertions=policy ? policy->getBool("signedAssertions") : make_pair(false,false);

    if (root->getSignature()) {
        if (!m_app.getTrustEngine()->validate(*(root->getSignature()),*m_role))
            throw ValidationException("Assertion signature did not validate.");
    }
    else if (signedAssertions.first && signedAssertions.second)
        throw ValidationException("Assertion was unsigned, violating policy.");
}

XMLApplication::XMLApplication(
    const ServiceProvider* sp,
    const DOMElement* e,
    const XMLApplication* base
    ) : m_sp(sp), m_base(base), m_metadata(NULL), m_trust(NULL), m_attrResolver(NULL),
        m_credDefault(NULL), m_sessionInitDefault(NULL), m_acsDefault(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLApplication");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".Application");

    try {
        // First load any property sets.
        load(e,log,this);

        SPConfig& conf=SPConfig::getConfig();
        SAMLConfig& samlConf=SAMLConfig::getConfig();
        XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();

        m_hash=getId();
        m_hash+=getString("providerId").second;
        m_hash=samlConf.hashSHA1(m_hash.c_str(), true);

        const PropertySet* sessions = getPropertySet("Sessions");

        // Process handlers.
        Handler* handler=NULL;
        bool hardACS=false, hardSessionInit=false;
        const DOMElement* child = sessions ? XMLHelper::getFirstChildElement(sessions->getElement()) : NULL;
        while (child) {
            try {
                // A handler is based on the Binding property in conjunction with the element name.
                // If it's an ACS or SI, also handle index/id mappings and defaulting.
                if (XMLHelper::isNodeNamed(child,samlconstants::SAML20MD_NS,AssertionConsumerService::LOCAL_NAME)) {
                    auto_ptr_char bindprop(child->getAttributeNS(NULL,EndpointType::BINDING_ATTRIB_NAME));
                    if (!bindprop.get() || !*(bindprop.get())) {
                        log.warn("md:AssertionConsumerService element has no Binding attribute, skipping it...");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    handler=conf.AssertionConsumerServiceManager.newPlugin(bindprop.get(),child);
                    // Map by binding (may be > 1 per binding, e.g. SAML 1.0 vs 1.1)
#ifdef HAVE_GOOD_STL
                    m_acsBindingMap[handler->getXMLString("Binding").second].push_back(handler);
#else
                    m_acsBindingMap[handler->getString("Binding").second].push_back(handler);
#endif
                    m_acsIndexMap[handler->getUnsignedInt("index").second]=handler;
                    
                    if (!hardACS) {
                        pair<bool,bool> defprop=handler->getBool("isDefault");
                        if (defprop.first) {
                            if (defprop.second) {
                                hardACS=true;
                                m_acsDefault=handler;
                            }
                        }
                        else if (!m_acsDefault)
                            m_acsDefault=handler;
                    }
                }
                else if (XMLString::equals(child->getLocalName(),SessionInitiator)) {
                    auto_ptr_char bindprop(child->getAttributeNS(NULL,EndpointType::BINDING_ATTRIB_NAME));
                    if (!bindprop.get() || !*(bindprop.get())) {
                        log.warn("SessionInitiator element has no Binding attribute, skipping it...");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    handler=conf.SessionInitiatorManager.newPlugin(bindprop.get(),child);
                    pair<bool,const char*> si_id=handler->getString("id");
                    if (si_id.first && si_id.second)
                        m_sessionInitMap[si_id.second]=handler;
                    if (!hardSessionInit) {
                        pair<bool,bool> defprop=handler->getBool("isDefault");
                        if (defprop.first) {
                            if (defprop.second) {
                                hardSessionInit=true;
                                m_sessionInitDefault=handler;
                            }
                        }
                        else if (!m_sessionInitDefault)
                            m_sessionInitDefault=handler;
                    }
                }
                else if (XMLHelper::isNodeNamed(child,samlconstants::SAML20MD_NS,SingleLogoutService::LOCAL_NAME)) {
                    auto_ptr_char bindprop(child->getAttributeNS(NULL,EndpointType::BINDING_ATTRIB_NAME));
                    if (!bindprop.get() || !*(bindprop.get())) {
                        log.warn("md:SingleLogoutService element has no Binding attribute, skipping it...");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    handler=conf.SingleLogoutServiceManager.newPlugin(bindprop.get(),child);
                }
                else if (XMLHelper::isNodeNamed(child,samlconstants::SAML20MD_NS,ManageNameIDService::LOCAL_NAME)) {
                    auto_ptr_char bindprop(child->getAttributeNS(NULL,EndpointType::BINDING_ATTRIB_NAME));
                    if (!bindprop.get() || !*(bindprop.get())) {
                        log.warn("md:ManageNameIDService element has no Binding attribute, skipping it...");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    handler=conf.ManageNameIDServiceManager.newPlugin(bindprop.get(),child);
                }
                else {
                    auto_ptr_char type(child->getAttributeNS(NULL,_type));
                    if (!type.get() || !*(type.get())) {
                        log.warn("Handler element has no type attribute, skipping it...");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    handler=conf.HandlerManager.newPlugin(type.get(),child);
                }

                // Save off the objects after giving the property set to the handler for its use.
                m_handlers.push_back(handler);

                // Insert into location map.
                pair<bool,const char*> location=handler->getString("Location");
                if (location.first && *location.second == '/')
                    m_handlerMap[location.second]=handler;
                else if (location.first)
                    m_handlerMap[string("/") + location.second]=handler;

            }
            catch (exception& ex) {
                log.error("caught exception processing handler element: %s", ex.what());
            }
            
            child = XMLHelper::getNextSiblingElement(child);
        }

        DOMNodeList* nlist=e->getElementsByTagNameNS(samlconstants::SAML20_NS,Audience::LOCAL_NAME);
        for (XMLSize_t i=0; nlist && i<nlist->getLength(); i++)
            if (nlist->item(i)->getParentNode()->isSameNode(e) && nlist->item(i)->hasChildNodes())
                m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());

        // Always include our own providerId as an audience.
        m_audiences.push_back(getXMLString("providerId").second);

        if (conf.isEnabled(SPConfig::Metadata)) {
            child = XMLHelper::getFirstChildElement(e,_MetadataProvider);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building MetadataProvider of type %s...",type.get());
                try {
                    auto_ptr<MetadataProvider> mp(samlConf.MetadataProviderManager.newPlugin(type.get(),child));
                    mp->init();
                    m_metadata = mp.release();
                }
                catch (exception& ex) {
                    log.crit("error building/initializing MetadataProvider: %s", ex.what());
                }
            }
        }

        if (conf.isEnabled(SPConfig::Trust)) {
            child = XMLHelper::getFirstChildElement(e,_TrustEngine);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building TrustEngine of type %s...",type.get());
                try {
                    m_trust = xmlConf.TrustEngineManager.newPlugin(type.get(),child);
                }
                catch (exception& ex) {
                    log.crit("error building TrustEngine: %s", ex.what());
                }
            }
        }

        if (conf.isEnabled(SPConfig::AttributeResolution)) {
            child = XMLHelper::getFirstChildElement(e,_AttributeResolver);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building AttributeResolver of type %s...",type.get());
                try {
                    m_attrResolver = conf.AttributeResolverManager.newPlugin(type.get(),child);
                }
                catch (exception& ex) {
                    log.crit("error building AttributeResolver: %s", ex.what());
                }
            }
        }

        // Finally, load credential mappings.
        child = XMLHelper::getFirstChildElement(e,CredentialUse);
        if (child) {
            m_credDefault=new DOMPropertySet();
            m_credDefault->load(child,log,this);
            child = XMLHelper::getFirstChildElement(child,RelyingParty);
            while (child) {
                DOMPropertySet* rp=new DOMPropertySet();
                rp->load(child,log,this);
                m_credMap[child->getAttributeNS(NULL,opensaml::saml2::Attribute::NAME_ATTRIB_NAME)]=rp;
                child = XMLHelper::getNextSiblingElement(child,RelyingParty);
            }
        }
        
        if (conf.isEnabled(SPConfig::OutOfProcess)) {
            // Really finally, build local browser profile and binding objects.
            // TODO: may need some bits here...
        }
    }
    catch (exception&) {
        cleanup();
        throw;
    }
#ifndef _DEBUG
    catch (...) {
        cleanup();
        throw;
    }
#endif
}

void XMLApplication::cleanup()
{
    for_each(m_handlers.begin(),m_handlers.end(),xmltooling::cleanup<Handler>());
    
    delete m_credDefault;
#ifdef HAVE_GOOD_STL
    for_each(m_credMap.begin(),m_credMap.end(),cleanup_pair<xstring,PropertySet>());
#else
    for_each(m_credMap.begin(),m_credMap.end(),cleanup_pair<const XMLCh*,PropertySet>());
#endif

    delete m_attrResolver;
    delete m_trust;
    delete m_metadata;
}

short XMLApplication::acceptNode(const DOMNode* node) const
{
    if (XMLHelper::isNodeNamed(node,samlconstants::SAML20_NS,opensaml::saml2::Attribute::LOCAL_NAME))
        return FILTER_REJECT;
    else if (XMLHelper::isNodeNamed(node,samlconstants::SAML20_NS,Audience::LOCAL_NAME))
        return FILTER_REJECT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,_Application) ||
        XMLString::equals(name,AssertionConsumerService::LOCAL_NAME) ||
        XMLString::equals(name,SingleLogoutService::LOCAL_NAME) ||
        XMLString::equals(name,ManageNameIDService::LOCAL_NAME) ||
        XMLString::equals(name,SessionInitiator) ||
        XMLString::equals(name,CredentialUse) ||
        XMLString::equals(name,RelyingParty) ||
        XMLString::equals(name,_MetadataProvider) ||
        XMLString::equals(name,_TrustEngine) ||
        XMLString::equals(name,_AttributeResolver))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

pair<bool,bool> XMLApplication::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret=DOMPropertySet::getBool(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getBool(name,ns) : ret;
}

pair<bool,const char*> XMLApplication::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret=DOMPropertySet::getString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getString(name,ns) : ret;
}

pair<bool,const XMLCh*> XMLApplication::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret=DOMPropertySet::getXMLString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getXMLString(name,ns) : ret;
}

pair<bool,unsigned int> XMLApplication::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret=DOMPropertySet::getUnsignedInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getUnsignedInt(name,ns) : ret;
}

pair<bool,int> XMLApplication::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret=DOMPropertySet::getInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getInt(name,ns) : ret;
}

const PropertySet* XMLApplication::getPropertySet(const char* name, const char* ns) const
{
    const PropertySet* ret=DOMPropertySet::getPropertySet(name,ns);
    if (ret || !m_base)
        return ret;
    return m_base->getPropertySet(name,ns);
}

const PropertySet* XMLApplication::getCredentialUse(const EntityDescriptor* provider) const
{
    if (!m_credDefault && m_base)
        return m_base->getCredentialUse(provider);
        
#ifdef HAVE_GOOD_STL
    map<xstring,PropertySet*>::const_iterator i=m_credMap.find(provider->getEntityID());
    if (i!=m_credMap.end())
        return i->second;
    const EntitiesDescriptor* group=dynamic_cast<const EntitiesDescriptor*>(provider->getParent());
    while (group) {
        if (group->getName()) {
            i=m_credMap.find(group->getName());
            if (i!=m_credMap.end())
                return i->second;
        }
        group=dynamic_cast<const EntitiesDescriptor*>(group->getParent());
    }
#else
    map<const XMLCh*,PropertySet*>::const_iterator i=m_credMap.begin();
    for (; i!=m_credMap.end(); i++) {
        if (XMLString::equals(i->first,provider->getId()))
            return i->second;
        const EntitiesDescriptor* group=dynamic_cast<const EntitiesDescriptor*>(provider->getParent());
        while (group) {
            if (XMLString::equals(i->first,group->getName()))
                return i->second;
            group=dynamic_cast<const EntitiesDescriptor*>(group->getParent());
        }
    }
#endif
    return m_credDefault;
}

const Handler* XMLApplication::getDefaultSessionInitiator() const
{
    if (m_sessionInitDefault) return m_sessionInitDefault;
    return m_base ? m_base->getDefaultSessionInitiator() : NULL;
}

const Handler* XMLApplication::getSessionInitiatorById(const char* id) const
{
    map<string,const Handler*>::const_iterator i=m_sessionInitMap.find(id);
    if (i!=m_sessionInitMap.end()) return i->second;
    return m_base ? m_base->getSessionInitiatorById(id) : NULL;
}

const Handler* XMLApplication::getDefaultAssertionConsumerService() const
{
    if (m_acsDefault) return m_acsDefault;
    return m_base ? m_base->getDefaultAssertionConsumerService() : NULL;
}

const Handler* XMLApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
{
    map<unsigned int,const Handler*>::const_iterator i=m_acsIndexMap.find(index);
    if (i!=m_acsIndexMap.end()) return i->second;
    return m_base ? m_base->getAssertionConsumerServiceByIndex(index) : NULL;
}

const vector<const Handler*>& XMLApplication::getAssertionConsumerServicesByBinding(const XMLCh* binding) const
{
#ifdef HAVE_GOOD_STL
    ACSBindingMap::const_iterator i=m_acsBindingMap.find(binding);
#else
    auto_ptr_char temp(binding);
    ACSBindingMap::const_iterator i=m_acsBindingMap.find(temp.get());
#endif
    if (i!=m_acsBindingMap.end())
        return i->second;
    return m_base ? m_base->getAssertionConsumerServicesByBinding(binding) : g_noHandlers;
}

const Handler* XMLApplication::getHandler(const char* path) const
{
    string wrap(path);
    map<string,const Handler*>::const_iterator i=m_handlerMap.find(wrap.substr(0,wrap.find('?')));
    if (i!=m_handlerMap.end())
        return i->second;
    return m_base ? m_base->getHandler(path) : NULL;
}

short XMLConfigImpl::acceptNode(const DOMNode* node) const
{
    if (!XMLString::equals(node->getNamespaceURI(),shibspconstants::SHIB2SPCONFIG_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,Applications) ||
        XMLString::equals(name,_ArtifactMap) ||
        XMLString::equals(name,Credentials) ||
        XMLString::equals(name,Extensions::LOCAL_NAME) ||
        XMLString::equals(name,Implementation) ||
        XMLString::equals(name,Listener) ||
        XMLString::equals(name,MemoryListener) ||
        XMLString::equals(name,Policy) ||
        XMLString::equals(name,_RequestMapper) ||
        XMLString::equals(name,_ReplayCache) ||
        XMLString::equals(name,_SessionCache) ||
        XMLString::equals(name,_StorageService) ||
        XMLString::equals(name,TCPListener) ||
        XMLString::equals(name,UnixListener))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void XMLConfigImpl::doExtensions(const DOMElement* e, const char* label, Category& log)
{
    const DOMElement* exts=XMLHelper::getFirstChildElement(e,Extensions::LOCAL_NAME);
    if (exts) {
        exts=XMLHelper::getFirstChildElement(exts,Library);
        while (exts) {
            auto_ptr_char path(exts->getAttributeNS(NULL,_path));
            try {
                if (path.get()) {
                    XMLToolingConfig::getConfig().load_library(path.get(),(void*)exts);
                    log.debug("loaded %s extension library (%s)", label, path.get());
                }
            }
            catch (exception& e) {
                const XMLCh* fatal=exts->getAttributeNS(NULL,fatal);
                if (fatal && (*fatal==chLatin_t || *fatal==chDigit_1)) {
                    log.fatal("unable to load mandatory %s extension library %s: %s", label, path.get(), e.what());
                    throw;
                }
                else {
                    log.crit("unable to load optional %s extension library %s: %s", label, path.get(), e.what());
                }
            }
            exts=XMLHelper::getNextSiblingElement(exts,Library);
        }
    }
}

XMLConfigImpl::XMLConfigImpl(const DOMElement* e, bool first, const XMLConfig* outer) : m_requestMapper(NULL), m_outer(outer), m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLConfigImpl");
#endif
    Category& log=Category::getInstance(SHIBSP_LOGCAT".Config");

    try {
        SPConfig& conf=SPConfig::getConfig();
        SAMLConfig& samlConf=SAMLConfig::getConfig();
        XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
        const DOMElement* SHAR=XMLHelper::getFirstChildElement(e,OutOfProcess);
        const DOMElement* SHIRE=XMLHelper::getFirstChildElement(e,InProcess);

        // Initialize log4cpp manually in order to redirect log messages as soon as possible.
        if (conf.isEnabled(SPConfig::Logging)) {
            const XMLCh* logconf=NULL;
            if (conf.isEnabled(SPConfig::OutOfProcess))
                logconf=SHAR->getAttributeNS(NULL,logger);
            else if (conf.isEnabled(SPConfig::InProcess))
                logconf=SHIRE->getAttributeNS(NULL,logger);
            if (!logconf || !*logconf)
                logconf=e->getAttributeNS(NULL,logger);
            if (logconf && *logconf) {
                auto_ptr_char logpath(logconf);
                log.debug("loading new logging configuration from (%s), check log destination for status of configuration",logpath.get());
                XMLToolingConfig::getConfig().log_config(logpath.get());
            }
            
            if (first)
                m_outer->m_tranLog = new TransactionLog();
        }
        
        // First load any property sets.
        load(e,log,this);

        const DOMElement* child;
        string plugtype;

        // Much of the processing can only occur on the first instantiation.
        if (first) {
            // Set clock skew.
            pair<bool,unsigned int> skew=getUnsignedInt("clockSkew");
            if (skew.first)
                xmlConf.clock_skew_secs=skew.second;

            // Extensions
            doExtensions(e, "global", log);
            if (conf.isEnabled(SPConfig::OutOfProcess))
                doExtensions(SHAR, "out of process", log);

            if (conf.isEnabled(SPConfig::InProcess))
                doExtensions(SHIRE, "in process", log);
            
            // Instantiate the ListenerService and SessionCache objects.
            if (conf.isEnabled(SPConfig::Listener)) {
                child=XMLHelper::getFirstChildElement(SHAR,UnixListener);
                if (child)
                    plugtype=UNIX_LISTENER_SERVICE;
                else {
                    child=XMLHelper::getFirstChildElement(SHAR,TCPListener);
                    if (child)
                        plugtype=TCP_LISTENER_SERVICE;
                    else {
                        child=XMLHelper::getFirstChildElement(SHAR,MemoryListener);
                        if (child)
                            plugtype=MEMORY_LISTENER_SERVICE;
                        else {
                            child=XMLHelper::getFirstChildElement(SHAR,Listener);
                            if (child) {
                                auto_ptr_char type(child->getAttributeNS(NULL,_type));
                                if (type.get())
                                    plugtype=type.get();
                            }
                        }
                    }
                }
                if (child) {
                    log.info("building ListenerService of type %s...", plugtype.c_str());
                    m_outer->m_listener = conf.ListenerServiceManager.newPlugin(plugtype.c_str(),child);
                }
                else {
                    log.fatal("can't build ListenerService, missing conf:Listener element?");
                    throw ConfigurationException("Can't build ListenerService, missing conf:Listener element?");
                }
            }

            if (conf.isEnabled(SPConfig::Caching)) {
                if (conf.isEnabled(SPConfig::OutOfProcess)) {
                    // First build any StorageServices.
                    string inmemID;
                    child=XMLHelper::getFirstChildElement(SHAR,_StorageService);
                    while (child) {
                        auto_ptr_char id(child->getAttributeNS(NULL,_id));
                        auto_ptr_char type(child->getAttributeNS(NULL,_type));
                        try {
                            log.info("building StorageService (%s) of type %s...", id.get(), type.get());
                            m_outer->m_storage[id.get()] = xmlConf.StorageServiceManager.newPlugin(type.get(),child);
                            if (!strcmp(type.get(),MEMORY_STORAGE_SERVICE))
                                inmemID = id.get();
                        }
                        catch (exception& ex) {
                            log.crit("failed to instantiate StorageService (%s): %s", id.get(), ex.what());
                        }
                        child=XMLHelper::getNextSiblingElement(child,_StorageService);
                    }
                
                    child=XMLHelper::getFirstChildElement(SHAR,_SessionCache);
                    if (child) {
                        auto_ptr_char type(child->getAttributeNS(NULL,_type));
                        log.info("building SessionCache of type %s...",type.get());
                        m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(type.get(),child);
                    }
                    else {
                        log.warn("SessionCache unspecified, building SessionCache of type %s...",STORAGESERVICE_SESSION_CACHE);
                        if (inmemID.empty()) {
                            inmemID = "memory";
                            log.info("no StorageServices configured, providing in-memory version for session cache");
                            m_outer->m_storage[inmemID] = xmlConf.StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE,NULL);
                        }
                        child = e->getOwnerDocument()->createElementNS(NULL,_SessionCache);
                        auto_ptr_XMLCh ssid(inmemID.c_str());
                        const_cast<DOMElement*>(child)->setAttributeNS(NULL,_StorageService,ssid.get());
                        m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(STORAGESERVICE_SESSION_CACHE,child);
                    }

                    // Replay cache.
                    StorageService* replaySS=NULL;
                    child=XMLHelper::getFirstChildElement(SHAR,_ReplayCache);
                    if (child) {
                        auto_ptr_char ssid(child->getAttributeNS(NULL,_StorageService));
                        if (ssid.get() && *ssid.get()) {
                            if (m_outer->m_storage.count(ssid.get()))
                                replaySS = m_outer->m_storage[ssid.get()];
                            if (replaySS)
                                log.info("building ReplayCache on top of StorageService (%s)...", ssid.get());
                            else
                                log.crit("unable to locate StorageService (%s) in configuration", ssid.get());
                        }
                    }
                    if (!replaySS) {
                        log.info("building ReplayCache using in-memory StorageService...");
                        if (inmemID.empty()) {
                            inmemID = "memory";
                            log.info("no StorageServices configured, providing in-memory version for legacy config");
                            m_outer->m_storage[inmemID] = xmlConf.StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE,NULL);
                        }
                        replaySS = m_outer->m_storage[inmemID];
                    }
                    xmlConf.setReplayCache(new ReplayCache(replaySS));
                    
                    // ArtifactMap
                    child=XMLHelper::getFirstChildElement(SHAR,_ArtifactMap);
                    if (child) {
                        auto_ptr_char ssid(child->getAttributeNS(NULL,_StorageService));
                        if (ssid.get() && *ssid.get() && m_outer->m_storage.count(ssid.get())) {
                            log.info("building ArtifactMap on top of StorageService (%s)...", ssid.get());
                            samlConf.setArtifactMap(new ArtifactMap(child, m_outer->m_storage[ssid.get()]));
                        }
                    }
                    if (samlConf.getArtifactMap()==NULL) {
                        log.info("building in-memory ArtifactMap...");
                        samlConf.setArtifactMap(new ArtifactMap(child));
                    }
                }
                else {
                    log.info("building in-process SessionCache of type %s...",REMOTED_SESSION_CACHE);
                    m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(REMOTED_SESSION_CACHE,NULL);
                }
            }
        } // end of first-time-only stuff
        
        // Back to the fully dynamic stuff...next up is the RequestMapper.
        if (conf.isEnabled(SPConfig::RequestMapping)) {
            child=XMLHelper::getFirstChildElement(SHIRE,_RequestMapper);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building RequestMapper of type %s...",type.get());
                m_requestMapper=conf.RequestMapperManager.newPlugin(type.get(),child);
            }
        }
        
        // Now we load the credentials map.
        if (conf.isEnabled(SPConfig::Credentials)) {
            child = XMLHelper::getLastChildElement(e,Credentials);
            if (child) {
                // Step down and process resolvers.
                child=XMLHelper::getFirstChildElement(child);
                while (child) {
                    auto_ptr_char id(child->getAttributeNS(NULL,_id));
                    auto_ptr_char type(child->getAttributeNS(NULL,_type));
                    try {
                        CredentialResolver* cr=xmlConf.CredentialResolverManager.newPlugin(type.get(),child);
                        m_credResolverMap[id.get()] = cr;
                    }
                    catch (exception& ex) {
                        log.crit("failed to instantiate CredentialResolver (%s): %s", id.get(), ex.what());
                    }
                    child = XMLHelper::getNextSiblingElement(child);
                }
            }
        }

        // Load security policies.
        child = XMLHelper::getLastChildElement(e,SecurityPolicies);
        if (child) {
            PolicyNodeFilter filter;
            child = XMLHelper::getFirstChildElement(child,Policy);
            while (child) {
                auto_ptr_char id(child->getAttributeNS(NULL,_id));
                pair< PropertySet*,vector<const SecurityPolicyRule*> >& rules = m_policyMap[id.get()];
                rules.first = NULL;
                auto_ptr<DOMPropertySet> settings(new DOMPropertySet());
                settings->load(child, log, &filter);
                rules.first = settings.release();
                const DOMElement* rule = XMLHelper::getFirstChildElement(child,Rule);
                while (rule) {
                    auto_ptr_char type(rule->getAttributeNS(NULL,_type));
                    try {
                        rules.second.push_back(samlConf.SecurityPolicyRuleManager.newPlugin(type.get(),rule));
                    }
                    catch (exception& ex) {
                        log.crit("error instantiating policy rule (%s) in policy (%s): %s", type.get(), id.get(), ex.what());
                    }
                    rule = XMLHelper::getNextSiblingElement(rule,Rule);
                }
                child = XMLHelper::getNextSiblingElement(child,Policy);
            }
        }

        // Load the default application. This actually has a fixed ID of "default". ;-)
        child=XMLHelper::getLastChildElement(e,Applications);
        if (!child) {
            log.fatal("can't build default Application object, missing conf:Applications element?");
            throw ConfigurationException("can't build default Application object, missing conf:Applications element?");
        }
        XMLApplication* defapp=new XMLApplication(m_outer,child);
        m_appmap[defapp->getId()]=defapp;
        
        // Load any overrides.
        child = XMLHelper::getFirstChildElement(child,_Application);
        while (child) {
            auto_ptr<XMLApplication> iapp(new XMLApplication(m_outer,child,defapp));
            if (m_appmap.count(iapp->getId()))
                log.crit("found conf:Application element with duplicate id attribute (%s), skipping it", iapp->getId());
            else
                m_appmap[iapp->getId()]=iapp.release();

            child = XMLHelper::getNextSiblingElement(child,_Application);
        }
    }
    catch (exception&) {
        this->~XMLConfigImpl();
        throw;
    }
#ifndef _DEBUG
    catch (...) {
        this->~XMLConfigImpl();
        throw;
    }
#endif
}

XMLConfigImpl::~XMLConfigImpl()
{
    for_each(m_appmap.begin(),m_appmap.end(),cleanup_pair<string,Application>());
    for_each(m_credResolverMap.begin(),m_credResolverMap.end(),cleanup_pair<string,CredentialResolver>());
    for (map< string,pair<PropertySet*,vector<const SecurityPolicyRule*> > >::iterator i=m_policyMap.begin(); i!=m_policyMap.end(); ++i) {
        delete i->second.first;
        for_each(i->second.second.begin(), i->second.second.end(), xmltooling::cleanup<SecurityPolicyRule>());
    }
    delete m_requestMapper;
    if (m_document)
        m_document->release();
}

pair<bool,DOMElement*> XMLConfig::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLConfigImpl* impl = new XMLConfigImpl(raw.second,(m_impl==NULL),this);
    
    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}
