/*
 *  Copyright 2001-2005 Internet2
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
#include <shibsp/DOMPropertySet.h>
#include <shibsp/PKIXTrustEngine.h>
#include <shibsp/SPConfig.h>
#include <shibsp/SPConstants.h>
#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/ChainingMetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/ChainingTrustEngine.h>
#include <xmltooling/util/NDC.h>

using namespace shibsp;
using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace shibtarget {

    // Application configuration wrapper
    class XMLApplication : public virtual IApplication, public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLApplication(const IConfig*, const Iterator<ICredentials*>& creds, const DOMElement* e, const XMLApplication* base=NULL);
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
        Iterator<SAMLAttributeDesignator*> getAttributeDesignators() const;
        Iterator<IAAP*> getAAPProviders() const;
        Iterator<IMetadata*> getMetadataProviders() const;
        Iterator<ITrust*> getTrustProviders() const;
        Iterator<const XMLCh*> getAudiences() const;
        const PropertySet* getCredentialUse(const IEntityDescriptor* provider) const;

        const MetadataProvider* getMetadataProvider() const;
        const TrustEngine* getTrustEngine() const;
        
        const SAMLBrowserProfile* getBrowserProfile() const {return m_profile;}
        const SAMLBinding* getBinding(const XMLCh* binding) const
            {return XMLString::compareString(SAMLBinding::SOAP,binding) ? NULL : m_binding;}
        SAMLBrowserProfile::ArtifactMapper* getArtifactMapper() const {return new STArtifactMapper(this);}
        void validateToken(
            SAMLAssertion* token,
            time_t t=0,
            const IRoleDescriptor* role=NULL,
            const Iterator<ITrust*>& trusts=EMPTY(ITrust*)
            ) const;
        const IHandler* getDefaultSessionInitiator() const;
        const IHandler* getSessionInitiatorById(const char* id) const;
        const IHandler* getDefaultAssertionConsumerService() const;
        const IHandler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        Iterator<const IHandler*> getAssertionConsumerServicesByBinding(const XMLCh* binding) const;
        const IHandler* getHandler(const char* path) const;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;
    
    private:
        void cleanup();
        const IConfig* m_ini;   // this is ok because its locking scope includes us
        const XMLApplication* m_base;
        string m_hash;
        vector<SAMLAttributeDesignator*> m_designators;
        vector<IAAP*> m_aaps;
        vector<IMetadata*> m_metadatas;
        vector<ITrust*> m_trusts;
        MetadataProvider* m_metadata;
        TrustEngine* m_trust;
        vector<const XMLCh*> m_audiences;
        ShibBrowserProfile* m_profile;
        SAMLBinding* m_binding;
        ShibHTTPHook* m_bindingHook;

        // vectors manage object life for handlers and their property sets
        vector<IHandler*> m_handlers;
        vector<PropertySet*> m_handlerProps;

        // maps location (path info) to applicable handlers
        map<string,const IHandler*> m_handlerMap;

        // maps unique indexes to consumer services
        map<unsigned int,const IHandler*> m_acsIndexMap;
        
        // pointer to default consumer service
        const IHandler* m_acsDefault;

        // maps binding strings to supporting consumer service(s)
#ifdef HAVE_GOOD_STL
        typedef map<xmltooling::xstring,vector<const IHandler*> > ACSBindingMap;
#else
        typedef map<string,vector<const IHandler*> > ACSBindingMap;
#endif
        ACSBindingMap m_acsBindingMap;

        // maps unique ID strings to session initiators
        map<string,const IHandler*> m_sessionInitMap;

        // pointer to default session initiator
        const IHandler* m_sessionInitDefault;

        DOMPropertySet* m_credDefault;
#ifdef HAVE_GOOD_STL
        map<xmltooling::xstring,PropertySet*> m_credMap;
#else
        map<const XMLCh*,PropertySet*> m_credMap;
#endif
    };

    // Top-level configuration implementation
    class XMLConfig;
    class XMLConfigImpl : public ReloadableXMLFileImpl, public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLConfigImpl(const char* pathname, bool first, const XMLConfig* outer)
            : ReloadableXMLFileImpl(pathname), m_outer(outer), m_requestMapper(NULL) { init(first); }
        XMLConfigImpl(const DOMElement* e, bool first, const XMLConfig* outer)
            : ReloadableXMLFileImpl(e), m_outer(outer), m_requestMapper(NULL) { init(first); }
        ~XMLConfigImpl();
        
        IRequestMapper* m_requestMapper;
        map<string,IApplication*> m_appmap;
        vector<ICredentials*> m_creds;
        vector<IAttributeFactory*> m_attrFactories;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;

    private:
        void init(bool first);
        const XMLConfig* m_outer;
    };
    
    class XMLConfig : public IConfig, public ReloadableXMLFile
    {
    public:
        XMLConfig(const DOMElement* e) : ReloadableXMLFile(e), m_listener(NULL), m_sessionCache(NULL), m_replayCache(NULL) {}
        ~XMLConfig() {
            delete m_impl;
            m_impl=NULL;
            delete m_sessionCache;
            m_sessionCache=NULL;
            delete m_replayCache;
            m_replayCache=NULL;
            delete m_listener;
            m_listener=NULL;
        }

        void init() { getImplementation(); }

        // PropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getBool(name,ns);}
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getString(name,ns);}
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getXMLString(name,ns);}
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getUnsignedInt(name,ns);}
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getInt(name,ns);}
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const {return static_cast<XMLConfigImpl*>(m_impl)->getPropertySet(name,ns);}
        const DOMElement* getElement() const {return static_cast<XMLConfigImpl*>(m_impl)->getElement();}

        // IConfig
        ListenerService* getListener() const {return m_listener;}
        ISessionCache* getSessionCache() const {return m_sessionCache;}
        IReplayCache* getReplayCache() const {return m_replayCache;}
        IRequestMapper* getRequestMapper() const {return static_cast<XMLConfigImpl*>(m_impl)->m_requestMapper;}
        const IApplication* getApplication(const char* applicationId) const {
            map<string,IApplication*>::const_iterator i=static_cast<XMLConfigImpl*>(m_impl)->m_appmap.find(applicationId);
            return (i!=static_cast<XMLConfigImpl*>(m_impl)->m_appmap.end()) ? i->second : NULL;
        }
        Iterator<ICredentials*> getCredentialsProviders() const {return static_cast<XMLConfigImpl*>(m_impl)->m_creds;}

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;

    private:
        friend class XMLConfigImpl;
        mutable ListenerService* m_listener;
        mutable ISessionCache* m_sessionCache;
        mutable IReplayCache* m_replayCache;
    };
}

IConfig* STConfig::ShibTargetConfigFactory(const DOMElement* e)
{
    return new XMLConfig(e);
}

XMLApplication::XMLApplication(
    const IConfig* ini,
    const Iterator<ICredentials*>& creds,
    const DOMElement* e,
    const XMLApplication* base
    ) : m_ini(ini), m_base(base), m_metadata(NULL), m_trust(NULL), m_profile(NULL), m_binding(NULL), m_bindingHook(NULL),
        m_credDefault(NULL), m_sessionInitDefault(NULL), m_acsDefault(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLApplication");
#endif
    Category& log=Category::getInstance("shibtarget.XMLApplication");

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

        m_hash=getId();
        m_hash+=getString("providerId").second;
        m_hash=SAMLArtifact::toHex(SAMLArtifactType0001::generateSourceId(m_hash.c_str()));

        SPConfig& conf=SPConfig::getConfig();
        XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
        opensaml::SAMLConfig& samlConf=opensaml::SAMLConfig::getConfig();
        SAMLConfig& shibConf=SAMLConfig::getConfig();

        // Process handlers.
        bool hardACS=false, hardSessionInit=false;
        DOMElement* handler=saml::XML::getFirstChildElement(propcheck->getElement());
        while (handler) {
            // A handler is split across a property set and the plugin itself, which is based on the Binding property.
            // We build both objects first and then insert them into various structures for lookup.
            IHandler* hobj=NULL;
            DOMPropertySet* hprops=new DOMPropertySet();
            try {
                hprops->load(handler,log,this); // filter irrelevant for now, no embedded elements expected
                const char* bindprop=hprops->getString("Binding").second;
                if (!bindprop)
                    throw ConfigurationException("Handler element has no Binding attribute, skipping it...");
                IPlugIn* hplug=shibConf.getPlugMgr().newPlugin(bindprop,handler);
                hobj=dynamic_cast<IHandler*>(hplug);
                if (!hobj) {
                    delete hplug;
                    throw UnsupportedProfileException(
                        "Plugin for binding ($1) does not implement IHandler interface.",saml::params(1,bindprop)
                        );
                }
            }
            catch (SAMLException& ex) {
                // If we get here, the handler's not built, so dispose of the property set.
                log.error("caught exception processing a handler element: %s",ex.what());
                delete hprops;
                hprops=NULL;
            }
            
            const char* location=hprops ? hprops->getString("Location").second : NULL;
            if (!location) {
                delete hprops;
                hprops=NULL;
                handler=saml::XML::getNextSiblingElement(handler);
                continue;
            }
            
            // Save off the objects after giving the property set to the handler for its use.
            hobj->setProperties(hprops);
            m_handlers.push_back(hobj);
            m_handlerProps.push_back(hprops);

            // Insert into location map.
            if (*location == '/')
                m_handlerMap[location]=hobj;
            else
                m_handlerMap[string("/") + location]=hobj;

            // If it's an ACS or SI, handle index/id mappings and defaulting.
            if (saml::XML::isElementNamed(handler,shibtarget::XML::SAML2META_NS,SHIBT_L(AssertionConsumerService))) {
                // Map it.
#ifdef HAVE_GOOD_STL
                const XMLCh* binding=hprops->getXMLString("Binding").second;
#else
                const char* binding=hprops->getString("Binding").second;
#endif
                if (m_acsBindingMap.count(binding)==0)
                    m_acsBindingMap[binding]=vector<const IHandler*>(1,hobj);
                else
                    m_acsBindingMap[binding].push_back(hobj);
                m_acsIndexMap[hprops->getUnsignedInt("index").second]=hobj;
                
                if (!hardACS) {
                    pair<bool,bool> defprop=hprops->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardACS=true;
                            m_acsDefault=hobj;
                        }
                    }
                    else if (!m_acsDefault)
                        m_acsDefault=hobj;
                }
            }
            else if (saml::XML::isElementNamed(handler,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SessionInitiator))) {
                pair<bool,const char*> si_id=hprops->getString("id");
                if (si_id.first && si_id.second)
                    m_sessionInitMap[si_id.second]=hobj;
                if (!hardSessionInit) {
                    pair<bool,bool> defprop=hprops->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardSessionInit=true;
                            m_sessionInitDefault=hobj;
                        }
                    }
                    else if (!m_sessionInitDefault)
                        m_sessionInitDefault=hobj;
                }
            }
            handler=saml::XML::getNextSiblingElement(handler);
        }

        // If no handlers defined at the root, assume a legacy configuration.
        if (!m_base && m_handlers.empty()) {
            // A legacy config installs a SAML POST handler at the root handler location.
            // We use the Sessions element itself as the PropertySet.

            xmltooling::auto_ptr_char b1(shibspconstants::SHIB1_SESSIONINIT_PROFILE_URI);
            IPlugIn* hplug=shibConf.getPlugMgr().newPlugin(b1.get(),propcheck->getElement());
            IHandler* h1=dynamic_cast<IHandler*>(hplug);
            if (!h1) {
                delete hplug;
                throw UnsupportedProfileException(
                    "Plugin for binding ($1) does not implement IHandler interface.",saml::params(1,b1.get())
                    );
            }
            h1->setProperties(propcheck);
            m_handlers.push_back(h1);
            m_sessionInitDefault=h1;

            xmltooling::auto_ptr_char b2(SAMLBrowserProfile::BROWSER_POST);
            hplug=shibConf.getPlugMgr().newPlugin(b2.get(),propcheck->getElement());
            IHandler* h2=dynamic_cast<IHandler*>(hplug);
            if (!h2) {
                delete hplug;
                throw UnsupportedProfileException(
                    "Plugin for binding ($1) does not implement IHandler interface.",saml::params(1,b2.get())
                    );
            }
            h2->setProperties(propcheck);
            m_handlers.push_back(h2);
            m_handlerMap[""] = h2;
            m_acsDefault=h2;
        }
        
        // Process general configuration elements.
        unsigned int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeDesignator));
        for (i=0; nlist && i<nlist->getLength(); i++)
            if (nlist->item(i)->getParentNode()->isSameNode(e))
                m_designators.push_back(new SAMLAttributeDesignator(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(Audience));
        for (i=0; nlist && i<nlist->getLength(); i++)
            if (nlist->item(i)->getParentNode()->isSameNode(e))
                m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());

        // Always include our own providerId as an audience.
        m_audiences.push_back(getXMLString("providerId").second);

        if (conf.isEnabled(SPConfig::AAP)) {
            nlist=e->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(AAPProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                if (nlist->item(i)->getParentNode()->isSameNode(e)) {
                    xmltooling::auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                    log.info("building AAP provider of type %s...",type.get());
                    try {
                        IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                        IAAP* aap=dynamic_cast<IAAP*>(plugin);
                        if (aap)
                            m_aaps.push_back(aap);
                        else {
                            delete plugin;
                            log.crit("plugin was not an AAP provider");
                        }
                    }
                    catch (SAMLException& ex) {
                        log.crit("error building AAP provider: %s",ex.what());
                    }
                }
            }
        }

        if (conf.isEnabled(SPConfig::Metadata)) {
            vector<MetadataProvider*> os2providers;
            nlist=e->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(MetadataProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                if (nlist->item(i)->getParentNode()->isSameNode(e)) {
                    xmltooling::auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                    log.info("building metadata provider of type %s...",type.get());
                    try {
                        // Old plugins...TODO: remove
                        IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                        IMetadata* md=dynamic_cast<IMetadata*>(plugin);
                        if (md)
                            m_metadatas.push_back(md);
                        else {
                            delete plugin;
                            log.crit("plugin was not a metadata provider");
                        }
                        
                        // New plugins...
                        if (!strcmp(type.get(),"edu.internet2.middleware.shibboleth.common.provider.XMLMetadata") ||
                            !strcmp(type.get(),"edu.internet2.middleware.shibboleth.metadata.provider.XMLMetadata")) {
                            os2providers.push_back(
                                samlConf.MetadataProviderManager.newPlugin(
                                    FILESYSTEM_METADATA_PROVIDER,static_cast<DOMElement*>(nlist->item(i))
                                )
                            );
                        }
                        else {
                            os2providers.push_back(
                                samlConf.MetadataProviderManager.newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)))
                            );
                        }
                    }
                    catch (XMLToolingException& ex) {
                        log.crit("error building metadata provider: %s",ex.what());
                        for_each(os2providers.begin(), os2providers.end(), xmltooling::cleanup<MetadataProvider>());
                    }
                    catch (SAMLException& ex) {
                        log.crit("error building metadata provider: %s",ex.what());
                    }
                }
            }
            
            if (os2providers.size()==1)
                m_metadata=os2providers.front();
            else {
                try {
                    m_metadata = samlConf.MetadataProviderManager.newPlugin(CHAINING_METADATA_PROVIDER,NULL);
                    ChainingMetadataProvider* chainMeta = dynamic_cast<ChainingMetadataProvider*>(m_metadata);
                    while (!os2providers.empty()) {
                        chainMeta->addMetadataProvider(os2providers.back());
                        os2providers.pop_back();
                    }
                }
                catch (XMLToolingException& ex) {
                    log.crit("error building metadata provider: %s",ex.what());
                    for_each(os2providers.begin(), os2providers.end(), xmltooling::cleanup<MetadataProvider>());
                }
            }
        }

        if (conf.isEnabled(SPConfig::Trust)) {
            ChainingTrustEngine* chainTrust = NULL;
            nlist=e->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(TrustProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                if (nlist->item(i)->getParentNode()->isSameNode(e)) {
                    xmltooling::auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                    log.info("building trust provider of type %s...",type.get());
                    try {
                        // Old plugins...TODO: remove
                        IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                        ITrust* trust=dynamic_cast<ITrust*>(plugin);
                        if (trust)
                            m_trusts.push_back(trust);
                        else {
                            delete plugin;
                            log.crit("plugin was not a trust provider");
                        }

                        // New plugins...
                        if (!m_trust) {
                            // For compatibility with old engine types, we're assuming a Shib engine is likely,
                            // which requires chaining, so we'll build that regardless.
                            m_trust = xmlConf.TrustEngineManager.newPlugin(CHAINING_TRUSTENGINE,NULL);
                            chainTrust = dynamic_cast<ChainingTrustEngine*>(m_trust);
                        }
                        if (!strcmp(type.get(),"edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust")) {
                            chainTrust->addTrustEngine(
                                xmlConf.TrustEngineManager.newPlugin(
                                    EXPLICIT_KEY_TRUSTENGINE,static_cast<DOMElement*>(nlist->item(i))
                                )
                            );
                            chainTrust->addTrustEngine(
                                xmlConf.TrustEngineManager.newPlugin(
                                    SHIBBOLETH_PKIX_TRUSTENGINE,static_cast<DOMElement*>(nlist->item(i))
                                )
                            );
                        }
                        else if (!strcmp(type.get(),"edu.internet2.middleware.shibboleth.common.provider.BasicTrust")) {
                            chainTrust->addTrustEngine(
                                xmlConf.TrustEngineManager.newPlugin(
                                    EXPLICIT_KEY_TRUSTENGINE,static_cast<DOMElement*>(nlist->item(i))
                                )
                            );
                        }
                        else {
                            chainTrust->addTrustEngine(
                                xmlConf.TrustEngineManager.newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)))
                            );
                        }
                    }
                    catch (XMLToolingException& ex) {
                        log.crit("error building trust provider: %s",ex.what());
                    }
                    catch (SAMLException& ex) {
                        log.crit("error building trust provider: %s",ex.what());
                    }
                }
            }
        }
        
        // Finally, load credential mappings.
        const DOMElement* cu=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(CredentialUse));
        if (cu) {
            m_credDefault=new DOMPropertySet();
            m_credDefault->load(cu,log,this);
            cu=saml::XML::getFirstChildElement(cu,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(RelyingParty));
            while (cu) {
                DOMPropertySet* rp=new DOMPropertySet();
                rp->load(cu,log,this);
                m_credMap[cu->getAttributeNS(NULL,SHIBT_L(Name))]=rp;
                cu=saml::XML::getNextSiblingElement(cu,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(RelyingParty));
            }
        }
        
        if (conf.isEnabled(SPConfig::OutOfProcess)) {
            // Really finally, build local browser profile and binding objects.
            m_profile=new ShibBrowserProfile(
                this,
                getMetadataProviders(),
                getTrustProviders()
                );
            m_bindingHook=new ShibHTTPHook(
                getTrustProviders(),
                creds
                );
            m_binding=SAMLBinding::getInstance(SAMLBinding::SOAP);
            SAMLSOAPHTTPBinding* bptr=dynamic_cast<SAMLSOAPHTTPBinding*>(m_binding);
            if (!bptr) {
                log.fatal("binding implementation was not SOAP over HTTP");
                throw UnsupportedExtensionException("binding implementation was not SOAP over HTTP");
            }
            bptr->addHook(m_bindingHook,m_bindingHook); // the hook is its own global context
        }
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while processing applicaton element: " << e.what() << CategoryStream::ENDLINE;
        cleanup();
        throw;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("Unexpected error while processing application element");
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
    for_each(m_handlers.begin(),m_handlers.end(),xmltooling::cleanup<IHandler>());
    
    delete m_trust;
    delete m_metadata;
    
    delete m_credDefault;
#ifdef HAVE_GOOD_STL
    for_each(m_credMap.begin(),m_credMap.end(),xmltooling::cleanup_pair<xmltooling::xstring,PropertySet>());
#else
    for_each(m_credMap.begin(),m_credMap.end(),xmltooling::cleanup_pair<const XMLCh*,PropertySet>());
#endif
    for_each(m_designators.begin(),m_designators.end(),xmltooling::cleanup<SAMLAttributeDesignator>());
    for_each(m_aaps.begin(),m_aaps.end(),xmltooling::cleanup<IAAP>());
    for_each(m_metadatas.begin(),m_metadatas.end(),xmltooling::cleanup<IMetadata>());
    for_each(m_trusts.begin(),m_trusts.end(),xmltooling::cleanup<ITrust>());
}

short XMLApplication::acceptNode(const DOMNode* node) const
{
    if (saml::XML::isElementNamed(static_cast<const DOMElement*>(node),saml::XML::SAML_NS,L(AttributeDesignator)))
        return FILTER_REJECT;
    else if (saml::XML::isElementNamed(static_cast<const DOMElement*>(node),saml::XML::SAML_NS,L(Audience)))
        return FILTER_REJECT;
    const XMLCh* name=node->getLocalName();
    if (!XMLString::compareString(name,SHIBT_L(Application)) ||
        !XMLString::compareString(name,SHIBT_L(AssertionConsumerService)) ||
        !XMLString::compareString(name,SHIBT_L(SingleLogoutService)) ||
        !XMLString::compareString(name,SHIBT_L(DiagnosticService)) ||
        !XMLString::compareString(name,SHIBT_L(SessionInitiator)) ||
        !XMLString::compareString(name,SHIBT_L(AAPProvider)) ||
        !XMLString::compareString(name,SHIBT_L(CredentialUse)) ||
        !XMLString::compareString(name,SHIBT_L(RelyingParty)) ||
        !XMLString::compareString(name,SHIBT_L(FederationProvider)) ||
        !XMLString::compareString(name,SHIBT_L(MetadataProvider)) ||
        !XMLString::compareString(name,SHIBT_L(TrustProvider)))
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

Iterator<SAMLAttributeDesignator*> XMLApplication::getAttributeDesignators() const
{
    if (!m_designators.empty() || !m_base)
        return m_designators;
    return m_base->getAttributeDesignators();
}

Iterator<IAAP*> XMLApplication::getAAPProviders() const
{
    return (m_aaps.empty() && m_base) ? m_base->getAAPProviders() : m_aaps;
}

Iterator<IMetadata*> XMLApplication::getMetadataProviders() const
{
    return (m_metadatas.empty() && m_base) ? m_base->getMetadataProviders() : m_metadatas;
}

Iterator<ITrust*> XMLApplication::getTrustProviders() const
{
    return (m_trusts.empty() && m_base) ? m_base->getTrustProviders() : m_trusts;
}

Iterator<const XMLCh*> XMLApplication::getAudiences() const
{
    return (m_audiences.empty() && m_base) ? m_base->getAudiences() : m_audiences;
}

const PropertySet* XMLApplication::getCredentialUse(const IEntityDescriptor* provider) const
{
    if (!m_credDefault && m_base)
        return m_base->getCredentialUse(provider);
        
#ifdef HAVE_GOOD_STL
    map<xmltooling::xstring,PropertySet*>::const_iterator i=m_credMap.find(provider->getId());
    if (i!=m_credMap.end())
        return i->second;
    const IEntitiesDescriptor* group=provider->getEntitiesDescriptor();
    while (group) {
        if (group->getName()) {
            i=m_credMap.find(group->getName());
            if (i!=m_credMap.end())
                return i->second;
        }
        group=group->getEntitiesDescriptor();
    }
#else
    map<const XMLCh*,PropertySet*>::const_iterator i=m_credMap.begin();
    for (; i!=m_credMap.end(); i++) {
        if (!XMLString::compareString(i->first,provider->getId()))
            return i->second;
        const IEntitiesDescriptor* group=provider->getEntitiesDescriptor();
        while (group) {
            if (!XMLString::compareString(i->first,group->getName()))
                return i->second;
            group=group->getEntitiesDescriptor();
        }
    }
#endif
    return m_credDefault;
}

const MetadataProvider* XMLApplication::getMetadataProvider() const
{
    return (!m_metadata && m_base) ? m_base->getMetadataProvider() : m_metadata;
}

const TrustEngine* XMLApplication::getTrustEngine() const
{
    return (!m_trust && m_base) ? m_base->getTrustEngine() : m_trust;
}

void XMLApplication::validateToken(SAMLAssertion* token, time_t ts, const IRoleDescriptor* role, const Iterator<ITrust*>& trusts) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("validateToken");
#endif
    Category& log=Category::getInstance("shibtarget.XMLApplication");

    // First we verify the time conditions, using the specified timestamp, if non-zero.
    SAMLConfig& config=SAMLConfig::getConfig();
    if (ts>0) {
        const SAMLDateTime* notBefore=token->getNotBefore();
        if (notBefore && ts+config.clock_skew_secs < notBefore->getEpoch())
            throw ExpiredAssertionException("Assertion is not yet valid.");
        const SAMLDateTime* notOnOrAfter=token->getNotOnOrAfter();
        if (notOnOrAfter && notOnOrAfter->getEpoch() <= ts-config.clock_skew_secs)
            throw ExpiredAssertionException("Assertion is no longer valid.");
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
            throw UnsupportedExtensionException("Assertion contains an unrecognized condition.");
        }
        else if (!ac->eval(getAudiences())) {
            ostringstream os;
            os << *ac;
            log.error("unacceptable AudienceRestrictionCondition in assertion (%s)",os.str().c_str());
            throw UnsupportedProfileException("Assertion contains an unacceptable AudienceRestrictionCondition.");
        }
    }

    if (!role) {
        log.warn("no metadata provided, so no signature validation was performed");
        return;
    }

    const PropertySet* credUse=getCredentialUse(role->getEntityDescriptor());
    pair<bool,bool> signedAssertions=credUse ? credUse->getBool("signedAssertions") : make_pair(false,false);
    Trust t(trusts);

    if (token->isSigned() && !t.validate(*token,role))
        throw TrustException("Assertion signature did not validate.");
    else if (signedAssertions.first && signedAssertions.second)
        throw TrustException("Assertion was unsigned, violating policy based on the issuer.");
}

const IHandler* XMLApplication::getDefaultSessionInitiator() const
{
    if (m_sessionInitDefault) return m_sessionInitDefault;
    return m_base ? m_base->getDefaultSessionInitiator() : NULL;
}

const IHandler* XMLApplication::getSessionInitiatorById(const char* id) const
{
    map<string,const IHandler*>::const_iterator i=m_sessionInitMap.find(id);
    if (i!=m_sessionInitMap.end()) return i->second;
    return m_base ? m_base->getSessionInitiatorById(id) : NULL;
}

const IHandler* XMLApplication::getDefaultAssertionConsumerService() const
{
    if (m_acsDefault) return m_acsDefault;
    return m_base ? m_base->getDefaultAssertionConsumerService() : NULL;
}

const IHandler* XMLApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
{
    map<unsigned int,const IHandler*>::const_iterator i=m_acsIndexMap.find(index);
    if (i!=m_acsIndexMap.end()) return i->second;
    return m_base ? m_base->getAssertionConsumerServiceByIndex(index) : NULL;
}

Iterator<const IHandler*> XMLApplication::getAssertionConsumerServicesByBinding(const XMLCh* binding) const
{
#ifdef HAVE_GOOD_STL
    ACSBindingMap::const_iterator i=m_acsBindingMap.find(binding);
#else
    xmltooling::auto_ptr_char temp(binding);
    ACSBindingMap::const_iterator i=m_acsBindingMap.find(temp.get());
#endif
    if (i!=m_acsBindingMap.end())
        return i->second;
    return m_base ? m_base->getAssertionConsumerServicesByBinding(binding) : EMPTY(const IHandler*);
}

const IHandler* XMLApplication::getHandler(const char* path) const
{
    string wrap(path);
    map<string,const IHandler*>::const_iterator i=m_handlerMap.find(wrap.substr(0,wrap.find('?')));
    if (i!=m_handlerMap.end())
        return i->second;
    return m_base ? m_base->getHandler(path) : NULL;
}

ReloadableXMLFileImpl* XMLConfig::newImplementation(const char* pathname, bool first) const
{
    return new XMLConfigImpl(pathname,first,this);
}

ReloadableXMLFileImpl* XMLConfig::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLConfigImpl(e,first,this);
}

short XMLConfigImpl::acceptNode(const DOMNode* node) const
{
    if (XMLString::compareString(node->getNamespaceURI(),shibtarget::XML::SHIBTARGET_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (!XMLString::compareString(name,SHIBT_L(Applications)) ||
        !XMLString::compareString(name,SHIBT_L(AttributeFactory)) ||
        !XMLString::compareString(name,SHIBT_L(CredentialsProvider)) ||
        !XMLString::compareString(name,SHIBT_L(Extensions)) ||
        !XMLString::compareString(name,SHIBT_L(Implementation)) ||
        !XMLString::compareString(name,SHIBT_L(Listener)) ||
        !XMLString::compareString(name,SHIBT_L(MemorySessionCache)) ||
        !XMLString::compareString(name,SHIBT_L(MySQLReplayCache)) ||
        !XMLString::compareString(name,SHIBT_L(MySQLSessionCache)) ||
        !XMLString::compareString(name,SHIBT_L(RequestMap)) ||
        !XMLString::compareString(name,SHIBT_L(RequestMapProvider)) ||
        !XMLString::compareString(name,SHIBT_L(ReplayCache)) ||
        !XMLString::compareString(name,SHIBT_L(SessionCache)) ||
        !XMLString::compareString(name,SHIBT_L(TCPListener)) ||
        !XMLString::compareString(name,SHIBT_L(UnixListener)))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void XMLConfigImpl::init(bool first)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("init");
#endif
    Category& log=Category::getInstance("shibtarget.Config");

    try {
        if (!saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(ShibbolethTargetConfig)) &&
            !saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SPConfig))) {
            log.error("Construction requires a valid configuration file: (conf:SPConfig as root element)");
            throw ConfigurationException("Construction requires a valid configuration file: (conf:SPConfig as root element)");
        }

        SAMLConfig& shibConf=SAMLConfig::getConfig();
        SPConfig& conf=SPConfig::getConfig();
        const DOMElement* SHAR=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SHAR));
        if (!SHAR)
            SHAR=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Global));
        if (!SHAR)
            SHAR=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(OutOfProcess));
        const DOMElement* SHIRE=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SHIRE));
        if (!SHIRE)
            SHIRE=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Local));
        if (!SHIRE)
            SHIRE=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(InProcess));

        // Initialize log4cpp manually in order to redirect log messages as soon as possible.
        if (conf.isEnabled(SPConfig::Logging)) {
            const XMLCh* logger=NULL;
            if (conf.isEnabled(SPConfig::OutOfProcess))
                logger=SHAR->getAttributeNS(NULL,SHIBT_L(logger));
            else if (conf.isEnabled(SPConfig::InProcess))
                logger=SHIRE->getAttributeNS(NULL,SHIBT_L(logger));
            if (!logger || !*logger)
                logger=ReloadableXMLFileImpl::m_root->getAttributeNS(NULL,SHIBT_L(logger));
            if (logger && *logger) {
                xmltooling::auto_ptr_char logpath(logger);
                log.debug("loading new logging configuration from (%s), check log destination for status of configuration",logpath.get());
                try {
                    PropertyConfigurator::configure(logpath.get());
                }
                catch (ConfigureFailure& e) {
                    log.error("Error reading logging configuration: %s",e.what());
                }
            }
        }
        
        // First load any property sets.
        map<string,string> root_remap;
        root_remap["SHAR"]="OutOfProcess";
        root_remap["SHIRE"]="InProcess";
        root_remap["Global"]="OutOfProcess";
        root_remap["Local"]="InProcess";
        load(ReloadableXMLFileImpl::m_root,log,this,&root_remap);

        // Much of the processing can only occur on the first instantiation.
        if (first) {
            // Now load any extensions to insure any needed plugins are registered.
            DOMElement* exts=
                saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Extensions));
            if (exts) {
                exts=saml::XML::getFirstChildElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                while (exts) {
                    xmltooling::auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
                    try {
                        SAMLConfig::getConfig().saml_register_extension(path.get(),exts);
                        log.debug("loaded global extension library %s",path.get());
                    }
                    catch (SAMLException& e) {
                        const XMLCh* fatal=exts->getAttributeNS(NULL,SHIBT_L(fatal));
                        if (fatal && (*fatal==chLatin_t || *fatal==chDigit_1)) {
                            log.fatal("unable to load mandatory global extension library %s: %s", path.get(), e.what());
                            throw;
                        }
                        else
                            log.crit("unable to load optional global extension library %s: %s", path.get(), e.what());
                    }
                    exts=saml::XML::getNextSiblingElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                }
            }
            
            if (conf.isEnabled(SPConfig::OutOfProcess)) {
                exts=saml::XML::getFirstChildElement(SHAR,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Extensions));
                if (exts) {
                    exts=saml::XML::getFirstChildElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                    while (exts) {
                        xmltooling::auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
                        try {
                            SAMLConfig::getConfig().saml_register_extension(path.get(),exts);
                            log.debug("loaded Global extension library %s",path.get());
                        }
                        catch (SAMLException& e) {
                            const XMLCh* fatal=exts->getAttributeNS(NULL,SHIBT_L(fatal));
                            if (fatal && (*fatal==chLatin_t || *fatal==chDigit_1)) {
                                log.fatal("unable to load mandatory Global extension library %s: %s", path.get(), e.what());
                                throw;
                            }
                            else
                                log.crit("unable to load optional Global extension library %s: %s", path.get(), e.what());
                        }
                        exts=saml::XML::getNextSiblingElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                    }
                }
            }

            if (conf.isEnabled(SPConfig::InProcess)) {
                exts=saml::XML::getFirstChildElement(SHIRE,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Extensions));
                if (exts) {
                    exts=saml::XML::getFirstChildElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                    while (exts) {
                        xmltooling::auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
                        try {
                            SAMLConfig::getConfig().saml_register_extension(path.get(),exts);
                            log.debug("loaded Local extension library %s",path.get());
                        }
                        catch (SAMLException& e) {
                            const XMLCh* fatal=exts->getAttributeNS(NULL,SHIBT_L(fatal));
                            if (fatal && (*fatal==chLatin_t || *fatal==chDigit_1)) {
                                log.fatal("unable to load mandatory Local extension library %s: %s", path.get(), e.what());
                                throw;
                            }
                            else
                                log.crit("unable to load optional Local extension library %s: %s", path.get(), e.what());
                        }
                        exts=saml::XML::getNextSiblingElement(exts,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Library));
                    }
                }
            }
            
            // Instantiate the ListenerService and SessionCache objects.
            if (conf.isEnabled(SPConfig::Listener)) {
                exts=saml::XML::getFirstChildElement(SHAR,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(UnixListener));
                if (exts) {
                    log.info("building Listener of type %s...",UNIX_LISTENER_SERVICE);
                    m_outer->m_listener=conf.ListenerServiceManager.newPlugin(UNIX_LISTENER_SERVICE,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(SHAR,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(TCPListener));
                    if (exts) {
                        log.info("building Listener of type %s...",TCP_LISTENER_SERVICE);
                        m_outer->m_listener=conf.ListenerServiceManager.newPlugin(TCP_LISTENER_SERVICE,exts);
                    }
                    else {
                        exts=saml::XML::getFirstChildElement(SHAR,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Listener));
                        if (exts) {
                            xmltooling::auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
                            log.info("building Listener of type %s...",type.get());
                            m_outer->m_listener=conf.ListenerServiceManager.newPlugin(type.get(),exts);
                        }
                        else {
                            log.fatal("can't build Listener object, missing conf:Listener element?");
                            throw ConfigurationException("can't build Listener object, missing conf:Listener element?");
                        }
                    }
                }
            }

            if (conf.isEnabled(SPConfig::Caching)) {
                IPlugIn* plugin=NULL;
                const DOMElement* container=conf.isEnabled(SPConfig::OutOfProcess) ? SHAR : SHIRE;
                exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(MemorySessionCache));
                if (exts) {
                    log.info("building Session Cache of type %s...",shibtarget::XML::MemorySessionCacheType);
                    plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::MemorySessionCacheType,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(ODBCSessionCache));
                    if (exts) {
                        log.info("building Session Cache of type %s...",shibtarget::XML::ODBCSessionCacheType);
                        plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::ODBCSessionCacheType,exts);
                    }
                    else {
                        exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(MySQLSessionCache));
                        if (exts) {
                            log.info("building Session Cache of type %s...",shibtarget::XML::MySQLSessionCacheType);
                            plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::MySQLSessionCacheType,exts);
                        }
                        else {
                            exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(SessionCache));
                            if (exts) {
                                xmltooling::auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
                                log.info("building Session Cache of type %s...",type.get());
                                plugin=shibConf.getPlugMgr().newPlugin(type.get(),exts);
                            }
                            else {
                                log.info("session cache not specified, building Session Cache of type %s...",shibtarget::XML::MemorySessionCacheType);
                                plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::MemorySessionCacheType,exts);
                            }
                        }
                    }
                }
                if (plugin) {
                    ISessionCache* cache=dynamic_cast<ISessionCache*>(plugin);
                    if (cache)
                        m_outer->m_sessionCache=cache;
                    else {
                        delete plugin;
                        log.fatal("plugin was not a Session Cache object");
                        throw UnsupportedExtensionException("plugin was not a Session Cache object");
                    }
                }
                
                // Replay cache.
                container=conf.isEnabled(SPConfig::OutOfProcess) ? SHAR : SHIRE;
                exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(ODBCReplayCache));
                if (exts) {
                    log.info("building Replay Cache of type %s...",shibtarget::XML::ODBCReplayCacheType);
                    m_outer->m_replayCache=IReplayCache::getInstance(shibtarget::XML::ODBCReplayCacheType,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(MySQLReplayCache));
                    if (exts) {
                        log.info("building Replay Cache of type %s...",shibtarget::XML::MySQLReplayCacheType);
                        m_outer->m_replayCache=IReplayCache::getInstance(shibtarget::XML::MySQLReplayCacheType,exts);
                    }
                    else {
                        exts=saml::XML::getFirstChildElement(container,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(ReplayCache));
                        if (exts) {
                            xmltooling::auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
                            log.info("building Replay Cache of type %s...",type.get());
                            m_outer->m_replayCache=IReplayCache::getInstance(type.get(),exts);
                        }
                        else {
                            // OpenSAML default provider.
                            log.info("building default Replay Cache...");
                            m_outer->m_replayCache=IReplayCache::getInstance();
                        }
                    }
                }
            }
        }
        
        // Back to the fully dynamic stuff...next up is the Request Mapper.
        if (conf.isEnabled(SPConfig::RequestMapper)) {
            const DOMElement* child=saml::XML::getFirstChildElement(SHIRE,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(RequestMapProvider));
            if (child) {
                xmltooling::auto_ptr_char type(child->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building Request Mapper of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),child);
                if (plugin) {
                    IRequestMapper* reqmap=dynamic_cast<IRequestMapper*>(plugin);
                    if (reqmap)
                        m_requestMapper=reqmap;
                    else {
                        delete plugin;
                        log.fatal("plugin was not a Request Mapper object");
                        throw UnsupportedExtensionException("plugin was not a Request Mapper object");
                    }
                }
            }
            else {
                log.fatal("can't build Request Mapper object, missing conf:RequestMapProvider element?");
                throw ConfigurationException("can't build Request Mapper object, missing conf:RequestMapProvider element?");
            }
        }
        
        // Now we load any credentials providers.
        DOMNodeList* nlist;
        if (conf.isEnabled(SPConfig::Credentials)) {
            nlist=ReloadableXMLFileImpl::m_root->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(CredentialsProvider));
            for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
                xmltooling::auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building credentials provider of type %s...",type.get());
                try {
                    IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                    if (plugin) {
                        ICredentials* creds=dynamic_cast<ICredentials*>(plugin);
                        if (creds)
                            m_creds.push_back(creds);
                        else {
                            delete plugin;
                            log.crit("plugin was not a credentials provider");
                        }
                    }
                }
                catch (SAMLException& ex) {
                    log.crit("error building credentials provider: %s",ex.what());
                }
            }
        }

        // Now we load any attribute factories
        nlist=ReloadableXMLFileImpl::m_root->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(AttributeFactory));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
            xmltooling::auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
            log.info("building Attribute factory of type %s...",type.get());
            try {
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                if (plugin) {
                    IAttributeFactory* fact=dynamic_cast<IAttributeFactory*>(plugin);
                    if (fact) {
                        m_attrFactories.push_back(fact);
                        ShibConfig::getConfig().regAttributeMapping(
                            static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,L(AttributeName)),
                            fact
                            );
                    }
                    else {
                        delete plugin;
                        log.crit("plugin was not an Attribute factory");
                    }
                }
            }
            catch (SAMLException& ex) {
                log.crit("error building Attribute factory: %s",ex.what());
            }
        }

        // Load the default application. This actually has a fixed ID of "default". ;-)
        const DOMElement* app=saml::XML::getFirstChildElement(
            ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Applications)
            );
        if (!app) {
            log.fatal("can't build default Application object, missing conf:Applications element?");
            throw ConfigurationException("can't build default Application object, missing conf:Applications element?");
        }
        XMLApplication* defapp=new XMLApplication(m_outer, m_creds, app);
        m_appmap[defapp->getId()]=defapp;
        
        // Load any overrides.
        nlist=app->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Application));
        for (unsigned int j=0; nlist && j<nlist->getLength(); j++) {
            auto_ptr<XMLApplication> iapp(new XMLApplication(m_outer,m_creds,static_cast<DOMElement*>(nlist->item(j)),defapp));
            if (m_appmap.find(iapp->getId())!=m_appmap.end())
                log.crit("found conf:Application element with duplicate Id attribute, ignoring it");
            else
                m_appmap[iapp->getId()]=iapp.release();
        }
    }
    catch (xmltooling::XMLToolingException& e) {
        log.errorStream() << "Error while loading SP configuration: " << e.what() << CategoryStream::ENDLINE;
        throw ConfigurationException(e.what());
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while loading SP configuration: " << e.what() << CategoryStream::ENDLINE;
        throw ConfigurationException(e.what());
    }
#ifndef _DEBUG
    catch (...) {
        log.error("Unexpected error while loading SP configuration");
        throw;
    }
#endif
}

XMLConfigImpl::~XMLConfigImpl()
{
    delete m_requestMapper;
    for_each(m_appmap.begin(),m_appmap.end(),xmltooling::cleanup_pair<string,IApplication>());
    for_each(m_creds.begin(),m_creds.end(),xmltooling::cleanup<ICredentials>());
    ShibConfig::getConfig().clearAttributeMappings();
    for_each(m_attrFactories.begin(),m_attrFactories.end(),xmltooling::cleanup<IAttributeFactory>());
}
