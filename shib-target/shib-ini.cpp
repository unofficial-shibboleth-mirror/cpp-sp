/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-ini.h -- config file handling, now XML-based
 *
 * $Id$
 */

#include "internal.h"

#include <shib/shib-threads.h>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>

#include <sys/types.h>
#include <sys/stat.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

namespace shibtarget {

    // Application configuration wrapper
    class XMLApplication : public virtual IApplication, public XMLPropertySet, public DOMNodeFilter
    {
    public:
        XMLApplication(const IConfig*, const Iterator<ICredentials*>& creds, const DOMElement* e, const XMLApplication* base=NULL);
        ~XMLApplication() { cleanup(); }
    
        // IPropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;

        // IApplication
        const char* getId() const {return getString("id").second;}
        const char* getHash() const {return m_hash.c_str();}
        Iterator<SAMLAttributeDesignator*> getAttributeDesignators() const;
        Iterator<IAAP*> getAAPProviders() const;
        Iterator<IMetadata*> getMetadataProviders() const;
        Iterator<ITrust*> getTrustProviders() const;
        Iterator<IRevocation*> getRevocationProviders() const;
        Iterator<const XMLCh*> getAudiences() const;
        const IPropertySet* getCredentialUse(const IEntityDescriptor* provider) const;
        const SAMLBrowserProfile* getBrowserProfile() const {return m_profile;}
        const SAMLBinding* getBinding(const XMLCh* binding) const
            {return XMLString::compareString(SAMLBinding::SOAP,binding) ? NULL : m_binding;}
        SAMLBrowserProfile::ArtifactMapper* getArtifactMapper() const {return new STArtifactMapper(this);}
        const IPropertySet* getDefaultSessionInitiator() const;
        const IPropertySet* getSessionInitiatorById(const char* id) const;
        const IPropertySet* getDefaultAssertionConsumerService() const;
        const IPropertySet* getAssertionConsumerServiceByIndex(unsigned short index) const;
        const IPropertySet* getHandler(const char* path) const;
        
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
        vector<IRevocation*> m_revocations;
        vector<const XMLCh*> m_audiences;
        ShibBrowserProfile* m_profile;
        SAMLBinding* m_binding;
        ShibHTTPHook* m_bindingHook;
        map<string,XMLPropertySet*> m_handlerMap;
        map<unsigned int,const IPropertySet*> m_acsMap;
        const IPropertySet* m_acsDefault;
        map<string,const IPropertySet*> m_sessionInitMap;
        const IPropertySet* m_sessionInitDefault;
        XMLPropertySet* m_credDefault;
#ifdef HAVE_GOOD_STL
        map<xstring,XMLPropertySet*> m_credMap;
#else
        map<const XMLCh*,XMLPropertySet*> m_credMap;
#endif
    };

    // Top-level configuration implementation
    class XMLConfig;
    class XMLConfigImpl : public ReloadableXMLFileImpl, public XMLPropertySet, public DOMNodeFilter
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
        ~XMLConfig() {delete m_listener; delete m_sessionCache; delete m_replayCache;}

        // IPropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getBool(name,ns);}
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getString(name,ns);}
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getXMLString(name,ns);}
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getUnsignedInt(name,ns);}
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const {return static_cast<XMLConfigImpl*>(m_impl)->getInt(name,ns);}
        const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const {return static_cast<XMLConfigImpl*>(m_impl)->getPropertySet(name,ns);}
        const DOMElement* getElement() const {return static_cast<XMLConfigImpl*>(m_impl)->getElement();}

        // IConfig
        const IListener* getListener() const {return m_listener;}
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
        mutable IListener* m_listener;
        mutable ISessionCache* m_sessionCache;
        mutable IReplayCache* m_replayCache;
    };
}

IConfig* STConfig::ShibTargetConfigFactory(const DOMElement* e)
{
    auto_ptr<XMLConfig> ret(new XMLConfig(e));
    ret->getImplementation();
    return ret.release();
}

XMLPropertySet::~XMLPropertySet()
{
    for (map<string,pair<char*,const XMLCh*> >::iterator i=m_map.begin(); i!=m_map.end(); i++)
        XMLString::release(&(i->second.first));
    for (map<string,IPropertySet*>::iterator j=m_nested.begin(); j!=m_nested.end(); j++)
        delete j->second;
}

void XMLPropertySet::load(
    const DOMElement* e,
    Category& log,
    DOMNodeFilter* filter,
    const std::map<std::string,std::string>* remapper
    )
{
#ifdef _DEBUG
    saml::NDC ndc("load");
#endif
    m_root=e;

    // Process each attribute as a property.
    DOMNamedNodeMap* attrs=m_root->getAttributes();
    for (XMLSize_t i=0; i<attrs->getLength(); i++) {
        DOMNode* a=attrs->item(i);
        if (!XMLString::compareString(a->getNamespaceURI(),saml::XML::XMLNS_NS))
            continue;
        char* val=XMLString::transcode(a->getNodeValue());
        if (val && *val) {
            auto_ptr_char ns(a->getNamespaceURI());
            auto_ptr_char name(a->getLocalName());
            const char* realname=name.get();
            if (remapper) {
                map<string,string>::const_iterator remap=remapper->find(realname);
                if (remap!=remapper->end()) {
                    log.debug("remapping property (%s) to (%s)",realname,remap->second.c_str());
                    realname=remap->second.c_str();
                }
            }
            if (ns.get()) {
                m_map[string("{") + ns.get() + '}' + realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log.debug("added property {%s}%s (%s)",ns.get(),realname,val);
            }
            else {
                m_map[realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log.debug("added property %s (%s)",realname,val);
            }
        }
    }
    
    // Process non-excluded elements as nested sets.
    DOMTreeWalker* walker=
        static_cast<DOMDocumentTraversal*>(
            m_root->getOwnerDocument())->createTreeWalker(const_cast<DOMElement*>(m_root),DOMNodeFilter::SHOW_ELEMENT,filter,false
            );
    e=static_cast<DOMElement*>(walker->firstChild());
    while (e) {
        auto_ptr_char ns(e->getNamespaceURI());
        auto_ptr_char name(e->getLocalName());
        const char* realname=name.get();
        if (remapper) {
            map<string,string>::const_iterator remap=remapper->find(realname);
            if (remap!=remapper->end()) {
                log.debug("remapping property set (%s) to (%s)",realname,remap->second.c_str());
                realname=remap->second.c_str();
            }
        }
        string key;
        if (ns.get())
            key=string("{") + ns.get() + '}' + realname;
        else
            key=realname;
        if (m_nested.find(key)!=m_nested.end())
            log.warn("load() skipping duplicate property set: %s",key.c_str());
        else {
            XMLPropertySet* set=new XMLPropertySet();
            set->load(e,log,filter,remapper);
            m_nested[key]=set;
            log.debug("added nested property set: %s",key.c_str());
        }
        e=static_cast<DOMElement*>(walker->nextSibling());
    }
    walker->release();
}

pair<bool,bool> XMLPropertySet::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret=pair<bool,bool>(false,false);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=(!strcmp(i->second.first,"true") || !strcmp(i->second.first,"1"));
    }
    return ret;
}

pair<bool,const char*> XMLPropertySet::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret=pair<bool,const char*>(false,NULL);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=i->second.first;
    }
    return ret;
}

pair<bool,const XMLCh*> XMLPropertySet::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret=pair<bool,const XMLCh*>(false,NULL);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=i->second.second;
    }
    return ret;
}

pair<bool,unsigned int> XMLPropertySet::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret=pair<bool,unsigned int>(false,0);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=strtol(i->second.first,NULL,10);
    }
    return ret;
}

pair<bool,int> XMLPropertySet::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret=pair<bool,int>(false,0);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=atoi(i->second.first);
    }
    return ret;
}

const IPropertySet* XMLPropertySet::getPropertySet(const char* name, const char* ns) const
{
    map<string,IPropertySet*>::const_iterator i;

    if (ns)
        i=m_nested.find(string("{") + ns + '}' + name);
    else
        i=m_nested.find(name);

    return (i!=m_nested.end()) ? i->second : NULL;
}

XMLApplication::XMLApplication(
    const IConfig* ini,
    const Iterator<ICredentials*>& creds,
    const DOMElement* e,
    const XMLApplication* base
    ) : m_ini(ini), m_base(base), m_profile(NULL), m_binding(NULL), m_bindingHook(NULL),
        m_credDefault(NULL), m_sessionInitDefault(NULL), m_acsDefault(NULL)
{
#ifdef _DEBUG
    saml::NDC ndc("XMLApplication");
#endif
    Category& log=Category::getInstance("shibtarget.XMLApplication");

    try {
        // First load any property sets.
        map<string,string> root_remap;
        root_remap["shire"]="session";
        root_remap["shireURL"]="handlerURL";
        root_remap["shireSSL"]="handlerSSL";
        load(e,log,this,&root_remap);
        const IPropertySet* propcheck=getPropertySet("Errors");
        if (propcheck && !propcheck->getString("session").first)
            throw ConfigurationException("<Errors> element requires 'session' (or deprecated 'shire') attribute");
        propcheck=getPropertySet("Sessions");
        if (propcheck && !propcheck->getString("handlerURL").first)
            throw ConfigurationException("<Sessions> element requires 'handlerURL' (or deprecated 'shireURL') attribute");

        m_hash=getId();
        m_hash+=getString("providerId").second;
        m_hash=SAMLArtifact::toHex(SAMLArtifactType0001::generateSourceId(m_hash.c_str()));

        ShibTargetConfig& conf=ShibTargetConfig::getConfig();
        SAMLConfig& shibConf=SAMLConfig::getConfig();

        if (conf.isEnabled(ShibTargetConfig::RequestMapper)) {
            // Process handlers.
            bool hardACS=false, hardSessionInit=false;
            DOMElement* handler=saml::XML::getFirstChildElement(propcheck->getElement());
            while (handler) {
                XMLPropertySet* hprops=new XMLPropertySet();
                hprops->load(handler,log,this); // filter irrelevant for now, no embedded elements expected
                m_handlerMap[hprops->getString("Location").second]=hprops;
                
                // If it's an ACS or SI, handle lookup mappings and defaulting.
                if (saml::XML::isElementNamed(handler,shibtarget::XML::SAML2META_NS,SHIBT_L(AssertionConsumerService))) {
                    m_acsMap[hprops->getUnsignedInt("index").second]=hprops;
                    if (!hardACS) {
                        pair<bool,bool> defprop=hprops->getBool("isDefault");
                        if (defprop.first) {
                            if (defprop.second) {
                                hardACS=true;
                                m_acsDefault=hprops;
                            }
                        }
                        else if (!m_acsDefault)
                            m_acsDefault=hprops;
                    }
                }
                else if (saml::XML::isElementNamed(handler,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(SessionInitiator))) {
                    pair<bool,const char*> si_id=hprops->getString("id");
                    if (si_id.first && si_id.second)
                        m_sessionInitMap[si_id.second]=hprops;
                    if (!hardSessionInit) {
                        pair<bool,bool> defprop=hprops->getBool("isDefault");
                        if (defprop.first) {
                            if (defprop.second) {
                                hardSessionInit=true;
                                m_sessionInitDefault=hprops;
                            }
                        }
                        else if (!m_sessionInitDefault)
                            m_sessionInitDefault=hprops;
                    }
                }
                handler=saml::XML::getNextSiblingElement(handler);
            }
        }
        
        // Process general configuration elements.
        int i;
        DOMNodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeDesignator));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_designators.push_back(new SAMLAttributeDesignator(static_cast<DOMElement*>(nlist->item(i))));

        nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(Audience));
        for (i=0; nlist && i<nlist->getLength(); i++)
            m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());

        // Always include our own providerId as an audience.
        m_audiences.push_back(getXMLString("providerId").second);

        if (conf.isEnabled(ShibTargetConfig::AAP)) {
            nlist=e->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(AAPProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building AAP provider of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                IAAP* aap=dynamic_cast<IAAP*>(plugin);
                if (aap)
                    m_aaps.push_back(aap);
                else {
                    delete plugin;
                    log.fatal("plugin was not an AAP provider");
                    throw UnsupportedExtensionException("plugin was not an AAP provider");
                }
            }
        }

        if (conf.isEnabled(ShibTargetConfig::Metadata)) {
            nlist=e->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(FederationProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building federation/metadata provider of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                IMetadata* md=dynamic_cast<IMetadata*>(plugin);
                if (md)
                    m_metadatas.push_back(md);
                else {
                    delete plugin;
                    log.fatal("plugin was not a federation/metadata provider");
                    throw UnsupportedExtensionException("plugin was not a federation/metadata provider");
                }
            }
        }

        if (conf.isEnabled(ShibTargetConfig::Trust)) {
            nlist=e->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(TrustProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building trust provider of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                ITrust* trust=dynamic_cast<ITrust*>(plugin);
                if (trust)
                    m_trusts.push_back(trust);
                else {
                    delete plugin;
                    log.fatal("plugin was not a trust provider");
                    throw UnsupportedExtensionException("plugin was not a trust provider");
                }
            }
            nlist=e->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(RevocationProvider));
            for (i=0; nlist && i<nlist->getLength(); i++) {
                auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building revocation provider of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                IRevocation* rev=dynamic_cast<IRevocation*>(plugin);
                if (rev)
                    m_revocations.push_back(rev);
                else {
                    delete plugin;
                    log.fatal("plugin was not a revocation provider");
                    throw UnsupportedExtensionException("plugin was not a revocation provider");
                }
            }
        }
        
        // Finally, load credential mappings.
        const DOMElement* cu=saml::XML::getFirstChildElement(e,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(CredentialUse));
        if (cu) {
            m_credDefault=new XMLPropertySet();
            m_credDefault->load(cu,log,this);
            cu=saml::XML::getFirstChildElement(cu,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(RelyingParty));
            while (cu) {
                XMLPropertySet* rp=new XMLPropertySet();
                rp->load(cu,log,this);
                m_credMap[cu->getAttributeNS(NULL,SHIBT_L(Name))]=rp;
                cu=saml::XML::getNextSiblingElement(cu,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(RelyingParty));
            }
        }
        
        if (conf.isEnabled(ShibTargetConfig::Caching)) {
            // Really finally, build local browser profile and binding objects.
            m_profile=new ShibBrowserProfile(
                getMetadataProviders(),
                getRevocationProviders(),
                getTrustProviders()
                );
            m_bindingHook=new ShibHTTPHook(
                getRevocationProviders(),
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
    map<string,XMLPropertySet*>::iterator h=m_handlerMap.begin();
    while (h!=m_handlerMap.end()) {
        delete h->second;
        h++;
    }
    delete m_credDefault;
#ifdef HAVE_GOOD_STL
    map<xstring,XMLPropertySet*>::iterator c=m_credMap.begin();
#else
    map<const XMLCh*,XMLPropertySet*>::iterator c=m_credMap.begin();
#endif
    while (c!=m_credMap.end()) {
        delete c->second;
        c++;
    }
    Iterator<SAMLAttributeDesignator*> i(m_designators);
    while (i.hasNext())
        delete i.next();
    Iterator<IAAP*> j(m_aaps);
    while (j.hasNext())
        delete j.next();
    Iterator<IMetadata*> k(m_metadatas);
    while (k.hasNext())
        delete k.next();
    Iterator<ITrust*> l(m_trusts);
    while (l.hasNext())
        delete l.next();
    Iterator<IRevocation*> m(m_revocations);
    while (m.hasNext())
        delete m.next();
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
        !XMLString::compareString(name,SHIBT_L(SessionInitiator)) ||
        !XMLString::compareString(name,SHIBT_L(AAPProvider)) ||
        !XMLString::compareString(name,SHIBT_L(CredentialUse)) ||
        !XMLString::compareString(name,SHIBT_L(RelyingParty)) ||
        !XMLString::compareString(name,SHIBT_L(FederationProvider)) ||
        !XMLString::compareString(name,SHIBT_L(RevocationProvider)) ||
        !XMLString::compareString(name,SHIBT_L(TrustProvider)))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

pair<bool,bool> XMLApplication::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret=XMLPropertySet::getBool(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getBool(name,ns) : ret;
}

pair<bool,const char*> XMLApplication::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret=XMLPropertySet::getString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getString(name,ns) : ret;
}

pair<bool,const XMLCh*> XMLApplication::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret=XMLPropertySet::getXMLString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getXMLString(name,ns) : ret;
}

pair<bool,unsigned int> XMLApplication::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret=XMLPropertySet::getUnsignedInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getUnsignedInt(name,ns) : ret;
}

pair<bool,int> XMLApplication::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret=XMLPropertySet::getInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getInt(name,ns) : ret;
}

const IPropertySet* XMLApplication::getPropertySet(const char* name, const char* ns) const
{
    const IPropertySet* ret=XMLPropertySet::getPropertySet(name,ns);
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

Iterator<IRevocation*> XMLApplication::getRevocationProviders() const
{
    return (m_revocations.empty() && m_base) ? m_base->getRevocationProviders() : m_revocations;
}

Iterator<const XMLCh*> XMLApplication::getAudiences() const
{
    return (m_audiences.empty() && m_base) ? m_base->getAudiences() : m_audiences;
}

const IPropertySet* XMLApplication::getCredentialUse(const IEntityDescriptor* provider) const
{
    if (!m_credDefault && m_base)
        return m_base->getCredentialUse(provider);
        
#ifdef HAVE_GOOD_STL
    map<xstring,XMLPropertySet*>::const_iterator i=m_credMap.find(provider->getId());
    if (i!=m_credMap.end())
        return i->second;
    const IEntitiesDescriptor* group=provider->getEntitiesDescriptor();
    while (group) {
        i=m_credMap.find(group->getName());
        if (i!=m_credMap.end())
            return i->second;
        group=group->getEntitiesDescriptor();
    }
#else
    map<const XMLCh*,XMLPropertySet*>::const_iterator i=m_credMap.begin();
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

const IPropertySet* XMLApplication::getDefaultSessionInitiator() const
{
    if (m_sessionInitDefault) return m_sessionInitDefault;
    return m_base ? m_base->getDefaultSessionInitiator() : NULL;
}

const IPropertySet* XMLApplication::getSessionInitiatorById(const char* id) const
{
    map<string,const IPropertySet*>::const_iterator i=m_sessionInitMap.find(id);
    if (i!=m_sessionInitMap.end()) return i->second;
    return m_base ? m_base->getSessionInitiatorById(id) : NULL;
}

const IPropertySet* XMLApplication::getDefaultAssertionConsumerService() const
{
    if (m_acsDefault) return m_acsDefault;
    return m_base ? m_base->getDefaultAssertionConsumerService() : NULL;
}

const IPropertySet* XMLApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
{
    map<unsigned int,const IPropertySet*>::const_iterator i=m_acsMap.find(index);
    if (i!=m_acsMap.end()) return i->second;
    return m_base ? m_base->getAssertionConsumerServiceByIndex(index) : NULL;
}

const IPropertySet* XMLApplication::getHandler(const char* path) const
{
    string wrap(path);
    map<string,XMLPropertySet*>::const_iterator i=m_handlerMap.find(wrap.substr(0,wrap.find('?')));
    return (i!=m_handlerMap.end()) ? i->second : NULL;
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
    if (XMLString::compareString(node->getNamespaceURI(),ShibTargetConfig::SHIBTARGET_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (!XMLString::compareString(name,SHIBT_L(Applications)) ||
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
    saml::NDC ndc("init");
#endif
    Category& log=Category::getInstance("shibtarget.XMLConfig");

    try {
        if (!saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(ShibbolethTargetConfig)) &&
            !saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(SPConfig))) {
            log.error("Construction requires a valid configuration file: (conf:SPConfig as root element)");
            throw ConfigurationException("Construction requires a valid configuration file: (conf:SPConfig as root element)");
        }

        SAMLConfig& shibConf=SAMLConfig::getConfig();
        ShibTargetConfig& conf=ShibTargetConfig::getConfig();
        const DOMElement* SHAR=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(SHAR));
        if (!SHAR)
            SHAR=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Global));
        const DOMElement* SHIRE=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(SHIRE));
        if (!SHIRE)
            SHIRE=saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Local));

        // Initialize log4cpp manually in order to redirect log messages as soon as possible.
        if (conf.isEnabled(ShibTargetConfig::Logging)) {
            const XMLCh* logger=NULL;
            if (conf.isEnabled(ShibTargetConfig::GlobalExtensions))
                logger=SHAR->getAttributeNS(NULL,SHIBT_L(logger));
            else if (conf.isEnabled(ShibTargetConfig::LocalExtensions))
                logger=SHIRE->getAttributeNS(NULL,SHIBT_L(logger));
            if (!logger || !*logger)
                logger=ReloadableXMLFileImpl::m_root->getAttributeNS(NULL,SHIBT_L(logger));
            if (logger && *logger) {
                auto_ptr_char logpath(logger);
                cerr << "loading new logging configuration from " << logpath.get() << "\n";
                try {
                    PropertyConfigurator::configure(logpath.get());
                    cerr << "New logging configuration loaded, check log destination for process status..." << "\n";
                }
                catch (ConfigureFailure& e) {
                    cerr << "Error reading logging configuration: " << e.what() << "\n";
                }
            }
        }
        
        // First load any property sets.
        map<string,string> root_remap;
        root_remap["SHAR"]="Global";
        root_remap["SHIRE"]="Local";
        load(ReloadableXMLFileImpl::m_root,log,this,&root_remap);

        // Much of the processing can only occur on the first instantiation.
        if (first) {
            // Now load any extensions to insure any needed plugins are registered.
            DOMElement* exts=
                saml::XML::getFirstChildElement(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Extensions));
            if (exts) {
                exts=saml::XML::getFirstChildElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                while (exts) {
                    auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
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
                    exts=saml::XML::getNextSiblingElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                }
            }
            
            if (conf.isEnabled(ShibTargetConfig::GlobalExtensions)) {
                exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Extensions));
                if (exts) {
                    exts=saml::XML::getFirstChildElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                    while (exts) {
                        auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
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
                        exts=saml::XML::getNextSiblingElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                    }
                }
            }

            if (conf.isEnabled(ShibTargetConfig::LocalExtensions)) {
                exts=saml::XML::getFirstChildElement(SHIRE,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Extensions));
                if (exts) {
                    exts=saml::XML::getFirstChildElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                    while (exts) {
                        auto_ptr_char path(exts->getAttributeNS(NULL,SHIBT_L(path)));
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
                        exts=saml::XML::getNextSiblingElement(exts,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Library));
                    }
                }
            }
            
            // Instantiate the Listener and SessionCache objects.
            if (conf.isEnabled(ShibTargetConfig::Listener)) {
                IPlugIn* plugin=NULL;
                exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(UnixListener));
                if (exts) {
                    log.info("building Listener of type %s...",shibtarget::XML::UnixListenerType);
                    plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::UnixListenerType,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(TCPListener));
                    if (exts) {
                        log.info("building Listener of type %s...",shibtarget::XML::TCPListenerType);
                        plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::TCPListenerType,exts);
                    }
                    else {
                        exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Listener));
                        if (exts) {
                            auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
                            log.info("building Listener of type %s...",type.get());
                            plugin=shibConf.getPlugMgr().newPlugin(type.get(),exts);
                        }
                        else {
                            log.fatal("can't build Listener object, missing conf:Listener element?");
                            throw ConfigurationException("can't build Listener object, missing conf:Listener element?");
                        }
                    }
                }
                if (plugin) {
                    IListener* listen=dynamic_cast<IListener*>(plugin);
                    if (listen)
                        m_outer->m_listener=listen;
                    else {
                        delete plugin;
                        log.fatal("plugin was not a Listener object");
                        throw UnsupportedExtensionException("plugin was not a Listener object");
                    }
                }
            }

            if (conf.isEnabled(ShibTargetConfig::Caching)) {
                IPlugIn* plugin=NULL;
                exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(MemorySessionCache));
                if (exts) {
                    log.info("building Session Cache of type %s...",shibtarget::XML::MemorySessionCacheType);
                    plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::MemorySessionCacheType,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(MySQLSessionCache));
                    if (exts) {
                        log.info("building Session Cache of type %s...",shibtarget::XML::MySQLSessionCacheType);
                        plugin=shibConf.getPlugMgr().newPlugin(shibtarget::XML::MySQLSessionCacheType,exts);
                    }
                    else {
                        exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(SessionCache));
                        if (exts) {
                            auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
                            log.info("building Session Cache of type %s...",type.get());
                            plugin=shibConf.getPlugMgr().newPlugin(type.get(),exts);
                        }
                        else {
                            log.fatal("can't build Session Cache object, missing conf:SessionCache element?");
                            throw ConfigurationException("can't build Session Cache object, missing conf:SessionCache element?");
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
                exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(MySQLReplayCache));
                if (exts) {
                    log.info("building Replay Cache of type %s...",shibtarget::XML::MySQLReplayCacheType);
                    m_outer->m_replayCache=IReplayCache::getInstance(shibtarget::XML::MySQLSessionCacheType,exts);
                }
                else {
                    exts=saml::XML::getFirstChildElement(SHAR,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(ReplayCache));
                    if (exts) {
                        auto_ptr_char type(exts->getAttributeNS(NULL,SHIBT_L(type)));
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
        
        // Back to the fully dynamic stuff...next up is the Request Mapper.
        if (conf.isEnabled(ShibTargetConfig::RequestMapper)) {
            const DOMElement* child=saml::XML::getFirstChildElement(SHIRE,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(RequestMapProvider));
            if (child) {
                auto_ptr_char type(child->getAttributeNS(NULL,SHIBT_L(type)));
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
        if (conf.isEnabled(ShibTargetConfig::Credentials)) {
            nlist=ReloadableXMLFileImpl::m_root->getElementsByTagNameNS(
                ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(CredentialsProvider)
                );
            for (int i=0; nlist && i<nlist->getLength(); i++) {
                auto_ptr_char type(static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building Credentials provider of type %s...",type.get());
                IPlugIn* plugin=shibConf.getPlugMgr().newPlugin(type.get(),static_cast<DOMElement*>(nlist->item(i)));
                if (plugin) {
                    ICredentials* creds=dynamic_cast<ICredentials*>(plugin);
                    if (creds)
                        m_creds.push_back(creds);
                    else {
                        delete plugin;
                        log.fatal("plugin was not a Credentials provider");
                        throw UnsupportedExtensionException("plugin was not a Credentials provider");
                    }
                }
            }
        }

        // Load the default application. This actually has a fixed ID of "default". ;-)
        const DOMElement* app=saml::XML::getFirstChildElement(
            ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Applications)
            );
        if (!app) {
            log.fatal("can't build default Application object, missing conf:Applications element?");
            throw ConfigurationException("can't build default Application object, missing conf:Applications element?");
        }
        XMLApplication* defapp=new XMLApplication(m_outer, m_creds, app);
        m_appmap[defapp->getId()]=defapp;
        
        // Load any overrides.
        nlist=app->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Application));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            XMLApplication* iapp=new XMLApplication(m_outer,m_creds,static_cast<DOMElement*>(nlist->item(i)),defapp);
            if (m_appmap.find(iapp->getId())!=m_appmap.end()) {
                log.fatal("found conf:Application element with duplicate Id attribute");
                throw ConfigurationException("found conf:Application element with duplicate Id attribute");
            }
            m_appmap[iapp->getId()]=iapp;
        }
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while loading SP configuration: " << e.what() << CategoryStream::ENDLINE;
        throw;
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
    for (map<string,IApplication*>::iterator i=m_appmap.begin(); i!=m_appmap.end(); i++)
        delete i->second;
    for (vector<ICredentials*>::iterator j=m_creds.begin(); j!=m_creds.end(); j++)
        delete (*j);
}
