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

        virtual Settings getSettingsFromURL(const char* url) const;
        virtual Settings getSettingsFromParsedURL(
            const char* scheme, const char* hostname, unsigned int port, const char* path=NULL
            ) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };
}

IPlugIn* XMLRequestMapFactory(const DOMElement* e)
{
    return new XMLRequestMapper(e);
}

short Override::acceptNode(const DOMNode* node) const
{
    if (XMLString::compareString(node->getNamespaceURI(),ShibTargetConfig::SHIBTARGET_NS))
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
    const DOMElement* acl=saml::XML::getFirstChildElement(e,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(htaccess));
    if (acl) {
        log.info("building htaccess provider...");
        plugin=ShibConfig::getConfig().m_plugMgr.newPlugin(shibtarget::XML::htaccessType,acl);
    }
    else {
        acl=saml::XML::getFirstChildElement(e,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(AccessControlProvider));
        if (acl) {
            auto_ptr_char type(acl->getAttributeNS(NULL,SHIBT_L(type)));
            log.info("building Access Control provider of type %s...",type.get());
            plugin=ShibConfig::getConfig().m_plugMgr.newPlugin(type.get(),acl);
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
        DOMNodeList* nlist=e->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Path));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            DOMElement* path=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* n=path->getAttributeNS(NULL,SHIBT_L(name));
            if (!n || !*n) {
                log.warn("skipping Path element (%d) with empty name attribute",i);
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
    char* sep=strchr(path,'?');
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
    NDC ndc("init");
    log=&Category::getInstance("shibtarget.XMLRequestMapper");

    try {
        if (!saml::XML::isElementNamed(ReloadableXMLFileImpl::m_root,ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(RequestMap))) {
            log->error("Construction requires a valid request mapping file: (conf:RequestMap as root element)");
            throw MalformedException("Construction requires a valid request mapping file: (conf:RequestMap as root element)");
        }

        // Load the property set.
        load(ReloadableXMLFileImpl::m_root,*log,this);
        
        // Load any AccessControl provider.
        loadACL(ReloadableXMLFileImpl::m_root,*log);
    
        // Loop over the Host elements.
        DOMNodeList* nlist = ReloadableXMLFileImpl::m_root->getElementsByTagNameNS(ShibTargetConfig::SHIBTARGET_NS,SHIBT_L(Host));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
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

            string url(scheme.first ? scheme.second : "http");
            url=url + "://" + dup;
            free(dup);
            if (!port.first) {
                // First store a port-less version.
                if (m_map.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                
                // Now append the default port.
                // XXX Use getservbyname instead?
                if (!scheme.first || !strcmp(scheme.second,"http"))
                    url=url + ":80";
                else if (!strcmp(scheme.second,"https"))
                    url=url + ":443";
                else if (!strcmp(scheme.second,"ftp"))
                    url=url + ":21";
                else if (!strcmp(scheme.second,"ldap"))
                    url=url + ":389";
                else if (!strcmp(scheme.second,"ldaps"))
                    url=url + ":636";
                
                m_extras[url]=o;
            }
            else {
                url=url + ':' + port.second;
                if (m_map.count(url)) {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
            }
            log->debug("Added <Host> mapping for %s",url.c_str());
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

const char* split_url(const char* url, string& vhost)
{
    const char* path=NULL;
    char* slash=strchr(url,'/');
    if (slash)
    {
        slash=strchr(slash,'/');
        if (slash)
        {
            path=strchr(slash,'/');
            if (path)
                vhost.append(url,path-url);
            else
                vhost=url;
        }
    }
    return path;
}

ReloadableXMLFileImpl* XMLRequestMapper::newImplementation(const char* pathname, bool first) const
{
    return new XMLRequestMapperImpl(pathname);
}

ReloadableXMLFileImpl* XMLRequestMapper::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLRequestMapperImpl(e);
}

IRequestMapper::Settings XMLRequestMapper::getSettingsFromURL(const char* url) const
{
    string vhost;
    const char* path=split_url(url,vhost);

    XMLRequestMapperImpl* impl=static_cast<XMLRequestMapperImpl*>(getImplementation());
    const Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled()) {
        saml::NDC ndc("getApplicationFromURL");
        pair<bool,const char*> ret=o->getString("applicationId");
        impl->log->debug("mapped %s to %s", url, ret.second);
    }

    return Settings(o,o->m_acl);
}

IRequestMapper::Settings XMLRequestMapper::getSettingsFromParsedURL(
    const char* scheme, const char* hostname, unsigned int port, const char* path
    ) const
{
    char buf[21];
    string vhost(scheme);
    vhost=vhost + "://" + hostname + ':';
#ifdef WIN32
    _snprintf(buf,20,"%u",port);
#else
    snprintf(buf,20,"%u",port);
#endif
    vhost+=buf;

    XMLRequestMapperImpl* impl=static_cast<XMLRequestMapperImpl*>(getImplementation());
    const Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled())
    {
        saml::NDC ndc("getApplicationFromParsedURL");
        pair<bool,const char*> ret=o->getString("applicationId");
        impl->log->debug("mapped %s%s to %s", vhost.c_str(), path ? path : "", ret.second);
    }

    return Settings(o,o->m_acl);
}
