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

/*
 * shib-ini.h -- config file handling, now XML-based
 *
 * $Id$
 */

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <shibsp/RequestMapper.h>
#include <shibsp/SPConfig.h>
#include <shibsp/TransactionLog.h>
#include <shibsp/security/PKIXTrustEngine.h>
#include <shibsp/util/DOMPropertySet.h>
#include <saml/SAMLConfig.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/metadata/ChainingMetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/ChainingTrustEngine.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/ReplayCache.h>

using namespace shibsp;
using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml1;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;
using xmlsignature::CredentialResolver;

namespace {

    vector<const Handler*> g_noHandlers;

    // Application configuration wrapper
    class XMLApplication : public virtual IApplication, public DOMPropertySet, public DOMNodeFilter
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
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;

        // IApplication
        const char* getId() const {return getString("id").second;}
        const char* getHash() const {return m_hash.c_str();}
        Iterator<IAAP*> getAAPProviders() const;
        MetadataProvider* getMetadataProvider() const;
        TrustEngine* getTrustEngine() const;
        const vector<const XMLCh*>& getAudiences() const;
        const PropertySet* getCredentialUse(const EntityDescriptor* provider) const;

        const SAMLBrowserProfile* getBrowserProfile() const {return m_profile;}
        const SAMLBinding* getBinding(const XMLCh* binding) const
            {return XMLString::compareString(SAMLBinding::SOAP,binding) ? NULL : m_binding;}
        SAMLBrowserProfile::ArtifactMapper* getArtifactMapper() const {return new STArtifactMapper(this);}
        void validateToken(
            SAMLAssertion* token,
            time_t t=0,
            const RoleDescriptor* role=NULL,
            const TrustEngine* trust=NULL
            ) const;
        const Handler* getDefaultSessionInitiator() const;
        const Handler* getSessionInitiatorById(const char* id) const;
        const Handler* getDefaultAssertionConsumerService() const;
        const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        const vector<const Handler*>& getAssertionConsumerServicesByBinding(const XMLCh* binding) const;
        const Handler* getHandler(const char* path) const;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;
    
    private:
        void cleanup();
        const ServiceProvider* m_sp;   // this is ok because its locking scope includes us
        const XMLApplication* m_base;
        string m_hash;
        vector<IAAP*> m_aaps;
        MetadataProvider* m_metadata;
        TrustEngine* m_trust;
        vector<const XMLCh*> m_audiences;
        ShibBrowserProfile* m_profile;
        SAMLBinding* m_binding;
        ShibHTTPHook* m_bindingHook;

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
        typedef map<xmltooling::xstring,vector<const Handler*> > ACSBindingMap;
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
        map<xmltooling::xstring,PropertySet*> m_credMap;
#else
        map<const XMLCh*,PropertySet*> m_credMap;
#endif
    };

    // Top-level configuration implementation
    class XMLConfig;
    class XMLConfigImpl : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLConfigImpl(const DOMElement* e, bool first, const XMLConfig* outer);
        ~XMLConfigImpl();
        
        RequestMapper* m_requestMapper;
        map<string,Application*> m_appmap;
        map<string,CredentialResolver*> m_credResolverMap;
        vector<IAttributeFactory*> m_attrFactories;
        
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

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLConfig : public ServiceProvider, public ReloadableXMLFile
    {
    public:
        XMLConfig(const DOMElement* e)
            : ReloadableXMLFile(e), m_impl(NULL), m_listener(NULL), m_sessionCache(NULL) {
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
            for_each(m_storage.begin(), m_storage.end(), xmltooling::cleanup_pair<string,StorageService>());
        }

        // PropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const {return m_impl->getBool(name,ns);}
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const {return m_impl->getString(name,ns);}
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const {return m_impl->getXMLString(name,ns);}
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const {return m_impl->getUnsignedInt(name,ns);}
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const {return m_impl->getInt(name,ns);}
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const {return m_impl->getPropertySet(name,ns);}
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

    static const XMLCh AAPProvider[] =          UNICODE_LITERAL_11(A,A,P,P,r,o,v,i,d,e,r);
    static const XMLCh _Application[] =         UNICODE_LITERAL_11(A,p,p,l,i,c,a,t,i,o,n);
    static const XMLCh Applications[] =         UNICODE_LITERAL_12(A,p,p,l,i,c,a,t,i,o,n,s);
    static const XMLCh AttributeFactory[] =     UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,F,a,c,t,o,r,y);
    static const XMLCh Credentials[] =          UNICODE_LITERAL_11(C,r,e,d,e,n,t,i,a,l,s);
    static const XMLCh CredentialsProvider[] =  UNICODE_LITERAL_19(C,r,e,d,e,n,t,i,a,l,s,P,r,o,v,i,d,e,r);
    static const XMLCh CredentialUse[] =        UNICODE_LITERAL_13(C,r,e,d,e,n,t,i,a,l,U,s,e);
    static const XMLCh DiagnosticService[] =    UNICODE_LITERAL_17(D,i,a,g,n,o,s,t,i,c,S,e,r,v,i,c,e);
    static const XMLCh fatal[] =                UNICODE_LITERAL_5(f,a,t,a,l);
    static const XMLCh FileResolver[] =         UNICODE_LITERAL_12(F,i,l,e,R,e,s,o,l,v,e,r);
    static const XMLCh Global[] =               UNICODE_LITERAL_6(G,l,o,b,a,l);
    static const XMLCh Id[] =                   UNICODE_LITERAL_2(I,d);
    static const XMLCh Implementation[] =       UNICODE_LITERAL_14(I,m,p,l,e,m,e,n,t,a,t,i,o,n);
    static const XMLCh InProcess[] =            UNICODE_LITERAL_9(I,n,P,r,o,c,e,s,s);
    static const XMLCh Library[] =              UNICODE_LITERAL_7(L,i,b,r,a,r,y);
    static const XMLCh Listener[] =             UNICODE_LITERAL_8(L,i,s,t,e,n,e,r);
    static const XMLCh Local[] =                UNICODE_LITERAL_5(L,o,c,a,l);
    static const XMLCh logger[] =               UNICODE_LITERAL_6(l,o,g,g,e,r);
    static const XMLCh MemoryListener[] =       UNICODE_LITERAL_14(M,e,m,o,r,y,L,i,s,t,e,n,e,r);
    static const XMLCh MemorySessionCache[] =   UNICODE_LITERAL_18(M,e,m,o,r,y,S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh RelyingParty[] =         UNICODE_LITERAL_12(R,e,l,y,i,n,g,P,a,r,t,y);
    static const XMLCh _ReplayCache[] =         UNICODE_LITERAL_11(R,e,p,l,a,y,C,a,c,h,e);
    static const XMLCh RequestMapProvider[] =   UNICODE_LITERAL_18(R,e,q,u,e,s,t,M,a,p,P,r,o,v,i,d,e,r);
    static const XMLCh _SessionCache[] =        UNICODE_LITERAL_12(S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh SessionInitiator[] =     UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _StorageService[] =      UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh OutOfProcess[] =         UNICODE_LITERAL_12(O,u,t,O,f,P,r,o,c,e,s,s);
    static const XMLCh TCPListener[] =          UNICODE_LITERAL_11(T,C,P,L,i,s,t,e,n,e,r);
    static const XMLCh TrustProvider[] =        UNICODE_LITERAL_13(T,r,u,s,t,P,r,o,v,i,d,e,r);
    static const XMLCh UnixListener[] =         UNICODE_LITERAL_12(U,n,i,x,L,i,s,t,e,n,e,r);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh _path[] =                UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    
}

ServiceProvider* shibtarget::XMLServiceProviderFactory(const DOMElement* const & e)
{
    return new XMLConfig(e);
}

XMLApplication::XMLApplication(
    const ServiceProvider* sp,
    const DOMElement* e,
    const XMLApplication* base
    ) : m_sp(sp), m_base(base), m_metadata(NULL), m_trust(NULL), m_profile(NULL), m_binding(NULL), m_bindingHook(NULL),
        m_credDefault(NULL), m_sessionInitDefault(NULL), m_acsDefault(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLApplication");
#endif
    Category& log=Category::getInstance(SHIBT_LOGCAT".Application");

    try {
        // First load any property sets.
        map<string,string> root_remap;
        root_remap["shire"]="session";
        root_remap["shireURL"]="handlerURL";
        root_remap["shireSSL"]="handlerSSL";
        load(e,log,this,&root_remap);

        const PropertySet* propcheck=getPropertySet("Errors");
        if (propcheck && !propcheck->getString("session").first)
            throw ConfigurationException("<Errors> element requires 'session' (or deprecated 'shire') attribute");
        propcheck=getPropertySet("Sessions");
        if (propcheck && !propcheck->getString("handlerURL").first)
            throw ConfigurationException("<Sessions> element requires 'handlerURL' (or deprecated 'shireURL') attribute");

        SPConfig& conf=SPConfig::getConfig();
        XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
        opensaml::SAMLConfig& samlConf=opensaml::SAMLConfig::getConfig();
        SAMLConfig& shibConf=SAMLConfig::getConfig();

        m_hash=getId();
        m_hash+=getString("providerId").second;
        m_hash=samlConf.hashSHA1(m_hash.c_str(), true);

        // Process handlers.
        Handler* handler=NULL;
        bool hardACS=false, hardSessionInit=false;
        const DOMElement* child = XMLHelper::getFirstChildElement(propcheck->getElement());
        while (child) {
            xmltooling::auto_ptr_char bindprop(child->getAttributeNS(NULL,EndpointType::BINDING_ATTRIB_NAME));
            if (!bindprop.get() || !*(bindprop.get())) {
                log.warn("md:AssertionConsumerService element has no Binding attribute, skipping it...");
                child = XMLHelper::getNextSiblingElement(child);
                continue;
            }
            
            try {
                // A handler is based on the Binding property in conjunction with the element name.
                // If it's an ACS or SI, also handle index/id mappings and defaulting.
                if (XMLHelper::isNodeNamed(child,samlconstants::SAML20MD_NS,AssertionConsumerService::LOCAL_NAME)) {
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
                    handler=conf.SingleLogoutServiceManager.newPlugin(bindprop.get(),child);
                }
                else if (XMLHelper::isNodeNamed(child,samlconstants::SAML20MD_NS,ManageNameIDService::LOCAL_NAME)) {
                    handler=conf.ManageNameIDServiceManager.newPlugin(bindprop.get(),child);
                }
                else {
                    handler=conf.HandlerManager.newPlugin(bindprop.get(),child);
                }
            }
            catch (exception& ex) {
                log.error("caught exception processing md:AssertionConsumerService element: %s",ex.what());
            }
            
            // Save off the objects after giving the property set to the handler for its use.
            m_handlers.push_back(handler);

            // Insert into location map.
            pair<bool,const char*> location=handler->getString("Location");
            if (location.first && *location.second == '/')
                m_handlerMap[location.second]=handler;
            else if (location.first)
                m_handlerMap[string("/") + location.second]=handler;

            child = XMLHelper::getNextSiblingElement(child);
        }

        // If no handlers defined at the root, assume a legacy configuration.
        if (!m_base && m_handlers.empty()) {
            // A legacy config installs a SAML POST handler at the root handler location.
            // We use the Sessions element itself as the PropertySet.
            Handler* h1=conf.SessionInitiatorManager.newPlugin(
                shibspconstants::SHIB1_SESSIONINIT_PROFILE_URI,propcheck->getElement()
                );
            m_handlers.push_back(h1);
            m_sessionInitDefault=h1;

            Handler* h2=conf.AssertionConsumerServiceManager.newPlugin(
                samlconstants::SAML1_PROFILE_BROWSER_POST,propcheck->getElement()
                );
            m_handlers.push_back(h2);
            m_handlerMap[""] = h2;
            m_acsDefault=h2;
        }
        
        DOMNodeList* nlist=e->getElementsByTagNameNS(samlconstants::SAML1_NS,Audience::LOCAL_NAME);
        for (XMLSize_t i=0; nlist && i<nlist->getLength(); i++)
            if (nlist->item(i)->getParentNode()->isSameNode(e) && nlist->item(i)->hasChildNodes())
                m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());

        // Always include our own providerId as an audience.
        m_audiences.push_back(getXMLString("providerId").second);

        if (conf.isEnabled(SPConfig::AAP)) {
            child = XMLHelper::getFirstChildElement(e,AAPProvider);
            while (child) {
                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building AAP provider of type %s...",type.get());
                try {
                    IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),child);
                    IAAP* aap=dynamic_cast<IAAP*>(plugin);
                    if (aap)
                        m_aaps.push_back(aap);
                    else {
                        delete plugin;
                        log.crit("plugin was not an AAP provider");
                    }
                }
                catch (exception& ex) {
                    log.crit("error building AAP provider: %s", ex.what());
                }

                child = XMLHelper::getNextSiblingElement(child,AAPProvider);
            }
        }

        if (conf.isEnabled(SPConfig::Metadata)) {
            vector<MetadataProvider*> os2providers;
            child = XMLHelper::getFirstChildElement(e,_MetadataProvider);
            while (child) {
                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building metadata provider of type %s...",type.get());
                try {
                    auto_ptr<MetadataProvider> mp(samlConf.MetadataProviderManager.newPlugin(type.get(),child));
                    mp->init();
                    os2providers.push_back(mp.release());
                }
                catch (exception& ex) {
                    log.crit("error building/initializing metadata provider: %s", ex.what());
                }

                child = XMLHelper::getNextSiblingElement(child,_MetadataProvider);
            }
            
            if (os2providers.size()==1)
                m_metadata=os2providers.front();
            else if (os2providers.size()>1) {
                try {
                    m_metadata = samlConf.MetadataProviderManager.newPlugin(CHAINING_METADATA_PROVIDER,NULL);
                    ChainingMetadataProvider* chainMeta = dynamic_cast<ChainingMetadataProvider*>(m_metadata);
                    while (!os2providers.empty()) {
                        chainMeta->addMetadataProvider(os2providers.back());
                        os2providers.pop_back();
                    }
                }
                catch (exception& ex) {
                    log.crit("error building chaining metadata provider wrapper: %s",ex.what());
                    for_each(os2providers.begin(), os2providers.end(), xmltooling::cleanup<MetadataProvider>());
                }
            }
        }

        if (conf.isEnabled(SPConfig::Trust)) {
            ChainingTrustEngine* chainTrust = NULL;
            child = XMLHelper::getFirstChildElement(e,TrustProvider);
            while (child) {
                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building trust provider of type %s...",type.get());
                try {
                    if (!m_trust) {
                        // For compatibility with old engine types, we're assuming a Shib engine is likely,
                        // which requires chaining, so we'll build that regardless.
                        m_trust = xmlConf.TrustEngineManager.newPlugin(CHAINING_TRUSTENGINE,NULL);
                        chainTrust = dynamic_cast<ChainingTrustEngine*>(m_trust);
                    }
                    if (!strcmp(type.get(),"edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust")) {
                        chainTrust->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE,child));
                        chainTrust->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(SHIBBOLETH_PKIX_TRUSTENGINE,child));
                    }
                    else if (!strcmp(type.get(),"edu.internet2.middleware.shibboleth.common.provider.BasicTrust")) {
                        chainTrust->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE,child));
                    }
                    else {
                        chainTrust->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(type.get(),child));
                    }
                }
                catch (exception& ex) {
                    log.crit("error building trust provider: %s",ex.what());
                }
    
                child = XMLHelper::getNextSiblingElement(child,TrustProvider);
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
            m_profile=new ShibBrowserProfile(this, getMetadataProvider(), getTrustEngine());
            m_bindingHook=new ShibHTTPHook(getTrustEngine());
            m_binding=SAMLBinding::getInstance(SAMLBinding::SOAP);
            SAMLSOAPHTTPBinding* bptr=dynamic_cast<SAMLSOAPHTTPBinding*>(m_binding);
            if (!bptr) {
                log.fatal("binding implementation was not SOAP over HTTP");
                throw UnknownExtensionException("binding implementation was not SOAP over HTTP");
            }
            bptr->addHook(m_bindingHook,m_bindingHook); // the hook is its own global context
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
    delete m_bindingHook;
    delete m_binding;
    delete m_profile;
    for_each(m_handlers.begin(),m_handlers.end(),xmltooling::cleanup<Handler>());
    
    delete m_credDefault;
#ifdef HAVE_GOOD_STL
    for_each(m_credMap.begin(),m_credMap.end(),xmltooling::cleanup_pair<xmltooling::xstring,PropertySet>());
#else
    for_each(m_credMap.begin(),m_credMap.end(),xmltooling::cleanup_pair<const XMLCh*,PropertySet>());
#endif
    for_each(m_aaps.begin(),m_aaps.end(),xmltooling::cleanup<IAAP>());

    delete m_trust;
    delete m_metadata;
}

short XMLApplication::acceptNode(const DOMNode* node) const
{
    if (XMLHelper::isNodeNamed(node,samlconstants::SAML1_NS,AttributeDesignator::LOCAL_NAME))
        return FILTER_REJECT;
    else if (XMLHelper::isNodeNamed(node,samlconstants::SAML20_NS,opensaml::saml1::Attribute::LOCAL_NAME))
        return FILTER_REJECT;
    else if (XMLHelper::isNodeNamed(node,samlconstants::SAML1_NS,Audience::LOCAL_NAME))
        return FILTER_REJECT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,_Application) ||
        XMLString::equals(name,AssertionConsumerService::LOCAL_NAME) ||
        XMLString::equals(name,SingleLogoutService::LOCAL_NAME) ||
        XMLString::equals(name,DiagnosticService) ||
        XMLString::equals(name,SessionInitiator) ||
        XMLString::equals(name,AAPProvider) ||
        XMLString::equals(name,CredentialUse) ||
        XMLString::equals(name,RelyingParty) ||
        XMLString::equals(name,_MetadataProvider) ||
        XMLString::equals(name,TrustProvider))
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

Iterator<IAAP*> XMLApplication::getAAPProviders() const
{
    return (m_aaps.empty() && m_base) ? m_base->getAAPProviders() : m_aaps;
}

MetadataProvider* XMLApplication::getMetadataProvider() const
{
    return (!m_metadata && m_base) ? m_base->getMetadataProvider() : m_metadata;
}

TrustEngine* XMLApplication::getTrustEngine() const
{
    return (!m_trust && m_base) ? m_base->getTrustEngine() : m_trust;
}

const vector<const XMLCh*>& XMLApplication::getAudiences() const
{
    return (m_audiences.empty() && m_base) ? m_base->getAudiences() : m_audiences;
}

const PropertySet* XMLApplication::getCredentialUse(const EntityDescriptor* provider) const
{
    if (!m_credDefault && m_base)
        return m_base->getCredentialUse(provider);
        
#ifdef HAVE_GOOD_STL
    map<xmltooling::xstring,PropertySet*>::const_iterator i=m_credMap.find(provider->getEntityID());
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

void XMLApplication::validateToken(SAMLAssertion* token, time_t ts, const RoleDescriptor* role, const TrustEngine* trust) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validateToken");
#endif
    Category& log=Category::getInstance(SHIBT_LOGCAT".Application");

    // First we verify the time conditions, using the specified timestamp, if non-zero.
    SAMLConfig& config=SAMLConfig::getConfig();
    if (ts>0) {
        const SAMLDateTime* notBefore=token->getNotBefore();
        if (notBefore && ts+config.clock_skew_secs < notBefore->getEpoch())
            throw opensaml::FatalProfileException("Assertion is not yet valid.");
        const SAMLDateTime* notOnOrAfter=token->getNotOnOrAfter();
        if (notOnOrAfter && notOnOrAfter->getEpoch() <= ts-config.clock_skew_secs)
            throw opensaml::FatalProfileException("Assertion is no longer valid.");
    }

    // Now we process conditions. Only audience restrictions at the moment.
    Iterator<SAMLCondition*> conditions=token->getConditions();
    while (conditions.hasNext()) {
        SAMLCondition* cond=conditions.next();
        const SAMLAudienceRestrictionCondition* ac=dynamic_cast<const SAMLAudienceRestrictionCondition*>(cond);
        if (!ac) {
            ostringstream os;
            os << *cond;
            log.error("unrecognized Condition in assertion (%s)",os.str().c_str());
            throw xmltooling::UnknownExtensionException("Assertion contains an unrecognized condition.");
        }
        else if (!ac->eval(getAudiences())) {
            ostringstream os;
            os << *ac;
            log.error("unacceptable AudienceRestrictionCondition in assertion (%s)",os.str().c_str());
            throw opensaml::FatalProfileException("Assertion contains an unacceptable AudienceRestrictionCondition.");
        }
    }

    if (!role || !trust) {
        log.warn("no metadata provided, so no signature validation was performed");
        return;
    }

    const PropertySet* credUse=getCredentialUse(dynamic_cast<const EntityDescriptor*>(role->getParent()));
    pair<bool,bool> signedAssertions=credUse ? credUse->getBool("signedAssertions") : make_pair(false,false);

    if (token->isSigned()) {

        // This will all change, but for fun, we'll port the object from OS1->OS2 for validation.
        stringstream s;
        s << *token;
        DOMDocument* doc = XMLToolingConfig::getConfig().getValidatingParser().parse(s);
        XercesJanitor<DOMDocument> jdoc(doc);
        auto_ptr<Assertion> os2ass(AssertionBuilder::buildAssertion());
        os2ass->unmarshall(doc->getDocumentElement(),true);
        jdoc.release();

        if (!trust->validate(*(os2ass->getSignature()),*role))
            throw xmltooling::XMLSecurityException("Assertion signature did not validate.");
    }
    else if (signedAssertions.first && signedAssertions.second)
        throw xmltooling::XMLSecurityException("Assertion was unsigned, violating policy based on the issuer.");
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
    xmltooling::auto_ptr_char temp(binding);
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
    if (!XMLString::equals(node->getNamespaceURI(),shibspconstants::SHIB1SPCONFIG_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,Applications) ||
        XMLString::equals(name,AttributeFactory) ||
        XMLString::equals(name,Credentials) ||
        XMLString::equals(name,CredentialsProvider) ||
        XMLString::equals(name,Extensions::LOCAL_NAME) ||
        XMLString::equals(name,Implementation) ||
        XMLString::equals(name,Listener) ||
        XMLString::equals(name,MemoryListener) ||
        XMLString::equals(name,MemorySessionCache) ||
        XMLString::equals(name,RequestMapProvider) ||
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
            xmltooling::auto_ptr_char path(exts->getAttributeNS(NULL,_path));
            try {
                if (path.get()) {
                    // TODO: replace with xmltooling extension load...
                    SAMLConfig::getConfig().saml_register_extension(path.get(),(void*)exts);
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

XMLConfigImpl::XMLConfigImpl(const DOMElement* e, bool first, const XMLConfig* outer) : m_outer(outer), m_requestMapper(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLConfigImpl");
#endif
    Category& log=Category::getInstance(SHIBT_LOGCAT".Config");

    try {
        SPConfig& conf=SPConfig::getConfig();
        SAMLConfig& shibConf=SAMLConfig::getConfig();
        XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
        const DOMElement* SHAR=XMLHelper::getFirstChildElement(e,OutOfProcess);
        if (!SHAR)
            SHAR=XMLHelper::getFirstChildElement(e,Global);
        const DOMElement* SHIRE=XMLHelper::getFirstChildElement(e,InProcess);
        if (!SHIRE)
            SHIRE=XMLHelper::getFirstChildElement(e,Local);

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
                xmltooling::auto_ptr_char logpath(logconf);
                log.debug("loading new logging configuration from (%s), check log destination for status of configuration",logpath.get());
                XMLToolingConfig::getConfig().log_config(logpath.get());
            }
            
            if (first)
                m_outer->m_tranLog = new TransactionLog();
        }
        
        // First load any property sets.
        map<string,string> root_remap;
        root_remap["Global"]="OutOfProcess";
        root_remap["Local"]="InProcess";
        load(e,log,this,&root_remap);

        const DOMElement* child;
        string plugtype;

        // Much of the processing can only occur on the first instantiation.
        if (first) {

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
                                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
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
                // TODO: This code's a mess, due to a very bad config layout for the caches...
                // Needs rework with the new config file.
                const DOMElement* container=conf.isEnabled(SPConfig::OutOfProcess) ? SHAR : SHIRE;

                // First build any StorageServices.
                string inmemID;
                child=XMLHelper::getFirstChildElement(container,_StorageService);
                while (child) {
                    xmltooling::auto_ptr_char id(child->getAttributeNS(NULL,Id));
                    xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                    if (id.get() && type.get()) {
                        try {
                            log.info("building StorageService (%s) of type %s...", id.get(), type.get());
                            m_outer->m_storage[id.get()] = xmlConf.StorageServiceManager.newPlugin(type.get(),child);
                            if (!strcmp(type.get(),MEMORY_STORAGE_SERVICE))
                                inmemID = id.get();
                        }
                        catch (exception& ex) {
                            log.crit("failed to instantiate StorageService (%s): %s", id.get(), ex.what());
                        }
                    }
                    child=XMLHelper::getNextSiblingElement(container,_StorageService);
                }
                
                child=XMLHelper::getFirstChildElement(container,_SessionCache);
                if (child) {
                    xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                    log.info("building Session Cache of type %s...",type.get());
                    m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(type.get(),child);
                }
                else if (conf.isEnabled(SPConfig::OutOfProcess)) {
                    log.warn("custom SessionCache unspecified or no longer supported, building SessionCache of type %s...",STORAGESERVICE_SESSION_CACHE);
                    if (inmemID.empty()) {
                        inmemID = "memory";
                        log.info("no StorageServices configured, providing in-memory version for legacy config");
                        m_outer->m_storage[inmemID] = xmlConf.StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE,NULL);
                    }
                    child = container->getOwnerDocument()->createElementNS(NULL,_SessionCache);
                    xmltooling::auto_ptr_XMLCh ssid(inmemID.c_str());
                    const_cast<DOMElement*>(child)->setAttributeNS(NULL,_StorageService,ssid.get());
                    m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(STORAGESERVICE_SESSION_CACHE,child);
                }
                else {
                    log.warn("custom SessionCache unspecified or no longer supported, building SessionCache of type %s...",REMOTED_SESSION_CACHE);
                    m_outer->m_sessionCache=conf.SessionCacheManager.newPlugin(REMOTED_SESSION_CACHE,NULL);
                }
                
                // Replay cache.
                StorageService* replaySS=NULL;
                child=XMLHelper::getFirstChildElement(container,_ReplayCache);
                if (child) {
                    xmltooling::auto_ptr_char ssid(child->getAttributeNS(NULL,_StorageService));
                    if (ssid.get() && *ssid.get()) {
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
            }
        } // end of first-time-only stuff
        
        // Back to the fully dynamic stuff...next up is the RequestMapper.
        if (conf.isEnabled(SPConfig::RequestMapping)) {
            child=XMLHelper::getFirstChildElement(SHIRE,RequestMapProvider);
            if (child) {
                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
                log.info("building RequestMapper of type %s...",type.get());
                m_requestMapper=conf.RequestMapperManager.newPlugin(type.get(),child);
            }
            else {
                log.fatal("can't build RequestMapper, missing conf:RequestMapProvider element?");
                throw ConfigurationException("can't build RequestMapper, missing conf:RequestMapProvider element?");
            }
        }
        
        // Now we load the credentials map.
        if (conf.isEnabled(SPConfig::Credentials)) {
            // Old format was to wrap it in a CredentialsProvider plugin, we're inlining that...
            child = XMLHelper::getFirstChildElement(e,CredentialsProvider);
            child = XMLHelper::getFirstChildElement(child ? child : e,Credentials);
            if (child) {
                // Step down and process resolvers.
                child=XMLHelper::getFirstChildElement(child);
                while (child) {
                    xmltooling::auto_ptr_char id(child->getAttributeNS(NULL,Id));
                    if (!id.get() || !*(id.get())) {
                        log.warn("skipping CredentialsResolver with no Id attribute");
                        child = XMLHelper::getNextSiblingElement(child);
                        continue;
                    }
                    
                    if (XMLString::equals(child->getLocalName(),FileResolver))
                        plugtype=FILESYSTEM_CREDENTIAL_RESOLVER;
                    else {
                        xmltooling::auto_ptr_char c(child->getAttributeNS(NULL,_type));
                        plugtype=c.get();
                    }
                    
                    if (!plugtype.empty()) {
                        try {
                            CredentialResolver* cr=
                                XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(plugtype.c_str(),child);
                            m_credResolverMap[id.get()] = cr;
                        }
                        catch (exception& ex) {
                            log.crit("failed to instantiate CredentialResolver (%s): %s", id.get(), ex.what());
                        }
                    }
                    else {
                        log.error("unknown type of CredentialResolver with Id (%s)", id.get());
                    }
                    
                    child = XMLHelper::getNextSiblingElement(child);
                }
            }
        }

        // Now we load any attribute factories
        child = XMLHelper::getFirstChildElement(e,AttributeFactory);
        while (child) {
            xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,_type));
            log.info("building Attribute factory of type %s...",type.get());
            try {
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),child);
                if (plugin) {
                    IAttributeFactory* fact=dynamic_cast<IAttributeFactory*>(plugin);
                    if (fact) {
                        m_attrFactories.push_back(fact);
                        ShibConfig::getConfig().regAttributeMapping(
                            child->getAttributeNS(NULL,opensaml::saml1::Attribute::ATTRIBUTENAME_ATTRIB_NAME), fact
                            );
                    }
                    else {
                        delete plugin;
                        log.crit("plugin was not an Attribute factory");
                    }
                }
            }
            catch (exception& ex) {
                log.crit("error building Attribute factory: %s", ex.what());
            }

            child = XMLHelper::getNextSiblingElement(child,AttributeFactory);
        }

        // Load the default application. This actually has a fixed ID of "default". ;-)
        child=XMLHelper::getFirstChildElement(e,Applications);
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
            if (m_appmap.find(iapp->getId())!=m_appmap.end())
                log.crit("found conf:Application element with duplicate Id attribute (%s), skipping it", iapp->getId());
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
    for_each(m_appmap.begin(),m_appmap.end(),xmltooling::cleanup_pair<string,Application>());
    ShibConfig::getConfig().clearAttributeMappings();
    for_each(m_attrFactories.begin(),m_attrFactories.end(),xmltooling::cleanup<IAttributeFactory>());
    for_each(m_credResolverMap.begin(),m_credResolverMap.end(),xmltooling::cleanup_pair<string,CredentialResolver>());
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
