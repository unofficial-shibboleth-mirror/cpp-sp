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

/* XMLRequestMapper.cpp - an XML-based map of URLs to application names and settings

   Scott Cantor
   1/6/04

   $History:$
*/

#include "internal.h"

#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace shibtarget {

    class Override : public XMLPropertySet, public DOMNodeFilter
    {
    public:
        Override() : m_base(NULL), m_acl(NULL) {}
        Override(const DOMElement* e, Category& log, const Override* base=NULL);
        ~Override();
        IAccessControl* m_acl;

        // IPropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;

        const Override* locate(const char* path) const;
        
    protected:
        void loadACL(const DOMElement* e, Category& log);
        
        map<string,Override*> m_map;
    
    private:
        const Override* m_base;
    };

    class XMLRequestMapperImpl : public ReloadableXMLFileImpl, public Override
    {
    public:
        XMLRequestMapperImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLRequestMapperImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
        ~XMLRequestMapperImpl() {}
    
        const Override* findOverride(const char* vhost, const char* path) const;
        Category* log;

    private:    
        map<string,Override*> m_extras;
    };

    // An implementation of the URL->application mapping API using an XML file
    class XMLRequestMapper : public IRequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLRequestMapper() {}

        virtual Settings getSettings(ShibTarget* st) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };
}

IPlugIn* XMLRequestMapFactory(const DOMElement* e)
{
    auto_ptr<XMLRequestMapper> m(new XMLRequestMapper(e));
    m->getImplementation();
    return m.release();
}

short Override::acceptNode(const DOMNode* node) const
{
    if (XMLString::compareString(node->getNamespaceURI(),shibtarget::XML::SHIBTARGET_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::compareString(name,SHIBT_L(AccessControlProvider)) ||
        XMLString::compareString(name,SHIBT_L(Host)) ||
        XMLString::compareString(name,SHIBT_L(Path)))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void Override::loadACL(const DOMElement* e, Category& log)
{
    IPlugIn* plugin=NULL;
    const DOMElement* acl=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(htaccess));
    if (acl) {
        log.info("building Apache htaccess provider...");
        plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::htAccessControlType,acl);
    }
    else {
        acl=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(AccessControl));
        if (acl) {
            log.info("building XML-based Access Control provider...");
            plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::XMLAccessControlType,acl);
        }
        else {
            acl=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(AccessControlProvider));
            if (acl) {
                auto_ptr_char type(acl->getAttributeNS(NULL,SHIBT_L(type)));
                log.info("building Access Control provider of type %s...",type.get());
                plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(type.get(),acl);
            }
        }
    }
    if (plugin) {
        IAccessControl* acl=dynamic_cast<IAccessControl*>(plugin);
        if (acl)
            m_acl=acl;
        else {
            delete plugin;
            log.fatal("plugin was not an Access Control provider");
            throw UnsupportedExtensionException("plugin was not an Access Control provider");
        }
    }
}

Override::Override(const DOMElement* e, Category& log, const Override* base) : m_base(base), m_acl(NULL)
{
    try {
        // Load the property set.
        load(e,log,this);
        
        // Load any AccessControl provider.
        loadACL(e,log);
    
        // Handle nested Paths.
        DOMNodeList* nlist=e->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Path));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
            DOMElement* path=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* n=path->getAttributeNS(NULL,SHIBT_L(name));
            if (!n || !*n) {
                log.warn("skipping Path element (%d) with empty name attribute",i);
                continue;
            }
            else if (*n==chForwardSlash && !n[1]) {
                log.warn("skipping Path element (%d) with a lone slash in the name attribute",i);
                continue;
            }
            Override* o=new Override(path,log,this);
            pair<bool,const char*> name=o->getString("name");
            char* dup=strdup(name.second);
            for (char* pch=dup; *pch; pch++)
                *pch=tolower(*pch);
            if (m_map.count(dup)) {
                log.warn("Skipping duplicate Path element (%s)",dup);
                free(dup);
                delete o;
                continue;
            }
            m_map[dup]=o;
            free(dup);
        }
    }
    catch (...) {
        this->~Override();
        throw;
    }
}

Override::~Override()
{
    delete m_acl;
    for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
        delete i->second;
}

pair<bool,bool> Override::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret=XMLPropertySet::getBool(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getBool(name,ns) : ret;
}

pair<bool,const char*> Override::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret=XMLPropertySet::getString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getString(name,ns) : ret;
}

pair<bool,const XMLCh*> Override::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret=XMLPropertySet::getXMLString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getXMLString(name,ns) : ret;
}

pair<bool,unsigned int> Override::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret=XMLPropertySet::getUnsignedInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getUnsignedInt(name,ns) : ret;
}

pair<bool,int> Override::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret=XMLPropertySet::getInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getInt(name,ns) : ret;
}

const IPropertySet* Override::getPropertySet(const char* name, const char* ns) const
{
    const IPropertySet* ret=XMLPropertySet::getPropertySet(name,ns);
    if (ret || !m_base)
        return ret;
    return m_base->getPropertySet(name,ns);
}

const Override* Override::locate(const char* path) const
{
    char* dup=strdup(path);
    char* sep=strchr(dup,'?');
    if (sep)
        *sep=0;
    for (char* pch=dup; *pch; pch++)
        *pch=tolower(*pch);
        
    const Override* o=this;
    
#ifdef HAVE_STRTOK_R
    char* pos=NULL;
    const char* token=strtok_r(dup,"/",&pos);
#else
    const char* token=strtok(dup,"/");
#endif
    while (token)
    {
        map<string,Override*>::const_iterator i=o->m_map.find(token);
        if (i==o->m_map.end())
            break;
        o=i->second;
#ifdef HAVE_STRTOK_R
        token=strtok_r(NULL,"/",&pos);
#else
        token=strtok(NULL,"/");
#endif
    }

    free(dup);
    return o;
}

void XMLRequestMapperImpl::init()
{
#ifdef _DEBUG
    NDC ndc("init");
#endif
    log=&Category::getInstance("shibtarget.RequestMapper");

    try {
        if (!saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,shibtarget::XML::SHIBTARGET_NS,SHIBT_L(RequestMap))) {
            log->error("Construction requires a valid request mapping file: (conf:RequestMap as root element)");
            throw MalformedException("Construction requires a valid request mapping file: (conf:RequestMap as root element)");
        }

        // Load the property set.
        load(ReloadableXMLFileImpl::m_root,*log,this);
        
        // Load any AccessControl provider.
        loadACL(ReloadableXMLFileImpl::m_root,*log);
    
        // Loop over the Host elements.
        DOMNodeList* nlist = ReloadableXMLFileImpl::m_root->getElementsByTagNameNS(shibtarget::XML::SHIBTARGET_NS,SHIBT_L(Host));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
            DOMElement* host=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* n=host->getAttributeNS(NULL,SHIBT_L(name));
            if (!n || !*n) {
                log->warn("Skipping Host element (%d) with empty name attribute",i);
                continue;
            }
            
            Override* o=new Override(host,*log,this);
            pair<bool,const char*> name=o->getString("name");
            pair<bool,const char*> scheme=o->getString("scheme");
            pair<bool,const char*> port=o->getString("port");
            
            char* dup=strdup(name.second);
            for (char* pch=dup; *pch; pch++)
                *pch=tolower(*pch);
            auto_ptr<char> dupwrap(dup);

            if (!scheme.first && port.first) {
                // No scheme, but a port, so assume http.
                scheme = pair<bool,const char*>(true,"http");
            }
            else if (scheme.first && !port.first) {
                // Scheme, no port, so default it.
                // XXX Use getservbyname instead?
                port.first = true;
                if (!strcmp(scheme.second,"http"))
                    port.second = "80";
                else if (!strcmp(scheme.second,"https"))
                    port.second = "443";
                else if (!strcmp(scheme.second,"ftp"))
                    port.second = "21";
                else if (!strcmp(scheme.second,"ldap"))
                    port.second = "389";
                else if (!strcmp(scheme.second,"ldaps"))
                    port.second = "636";
            }

            if (scheme.first) {
                string url(scheme.second);
                url=url + "://" + dup;
                
                // Is this the default port?
                if ((!strcmp(scheme.second,"http") && !strcmp(port.second,"80")) ||
                    (!strcmp(scheme.second,"https") && !strcmp(port.second,"443")) ||
                    (!strcmp(scheme.second,"ftp") && !strcmp(port.second,"21")) ||
                    (!strcmp(scheme.second,"ldap") && !strcmp(port.second,"389")) ||
                    (!strcmp(scheme.second,"ldaps") && !strcmp(port.second,"636"))) {
                    // First store a port-less version.
                    if (m_map.count(url) || m_extras.count(url)) {
                        log->warn("Skipping duplicate Host element (%s)",url.c_str());
                        delete o;
                        continue;
                    }
                    m_map[url]=o;
                    log->debug("Added <Host> mapping for %s",url.c_str());
                    
                    // Now append the port. We use the extras vector, to avoid double freeing the object later.
                    url=url + ':' + port.second;
                    m_extras[url]=o;
                    log->debug("Added <Host> mapping for %s",url.c_str());
                }
                else {
                    url=url + ':' + port.second;
                    if (m_map.count(url) || m_extras.count(url)) {
                        log->warn("Skipping duplicate Host element (%s)",url.c_str());
                        delete o;
                        continue;
                    }
                    m_map[url]=o;
                    log->debug("Added <Host> mapping for %s",url.c_str());
                }
            }
            else {
                // No scheme or port, so we enter dual hosts on http:80 and https:443
                string url("http://");
                url = url + dup;
                if (m_map.count(url) || m_extras.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                log->debug("Added <Host> mapping for %s",url.c_str());
                
                url = url + ":80";
                if (m_map.count(url) || m_extras.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_extras[url]=o;
                log->debug("Added <Host> mapping for %s",url.c_str());
                
                url = "https://";
                url = url + dup;
                if (m_map.count(url) || m_extras.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_extras[url]=o;
                log->debug("Added <Host> mapping for %s",url.c_str());
                
                url = url + ":443";
                if (m_map.count(url) || m_extras.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_extras[url]=o;
                log->debug("Added <Host> mapping for %s",url.c_str());
            }
        }
    }
    catch (SAMLException& e) {
        log->errorStream() << "Error while parsing request mapping configuration: " << e.what() << CategoryStream::ENDLINE;
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log->error("Unexpected error while parsing request mapping configuration");
        throw;
    }
#endif
}

const Override* XMLRequestMapperImpl::findOverride(const char* vhost, const char* path) const
{
    const Override* o=NULL;
    map<string,Override*>::const_iterator i=m_map.find(vhost);
    if (i!=m_map.end())
        o=i->second;
    else {
        i=m_extras.find(vhost);
        if (i!=m_extras.end())
            o=i->second;
    }
    
    return o ? o->locate(path) : this;
}

ReloadableXMLFileImpl* XMLRequestMapper::newImplementation(const char* pathname, bool first) const
{
    return new XMLRequestMapperImpl(pathname);
}

ReloadableXMLFileImpl* XMLRequestMapper::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLRequestMapperImpl(e);
}

IRequestMapper::Settings XMLRequestMapper::getSettings(ShibTarget* st) const
{
    ostringstream vhost;
    vhost << st->getProtocol() << "://" << st->getHostname() << ':' << st->getPort();

    XMLRequestMapperImpl* impl=static_cast<XMLRequestMapperImpl*>(getImplementation());
    const Override* o=impl->findOverride(vhost.str().c_str(), st->getRequestURI());

    if (impl->log->isDebugEnabled()) {
#ifdef _DEBUG
        saml::NDC ndc("getSettings");
#endif
        pair<bool,const char*> ret=o->getString("applicationId");
        impl->log->debug("mapped %s%s to %s", vhost.str().c_str(), st->getRequestURI() ? st->getRequestURI() : "", ret.second);
    }

    return Settings(o,o->m_acl);
}
