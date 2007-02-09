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

/** XMLRequestMapper.cpp
 * 
 * XML-based RequestMapper implementation
 */

#include "internal.h"
#include "AccessControl.h"
#include "RequestMapper.h"
#include "SPRequest.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace shibsp {

    // Blocks access when an ACL plugin fails to load. 
    class AccessControlDummy : public AccessControl
    {
    public:
        Lockable* lock() {
            return this;
        }
        
        void unlock() {}
    
        bool authorized(const SPRequest& request, const Session* session) const {
            return false;
        }
    };

    class Override : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        Override() : m_base(NULL), m_acl(NULL) {}
        Override(const DOMElement* e, Category& log, const Override* base=NULL);
        ~Override();

        // PropertySet
        pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;
        
        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const;

        const Override* locate(const char* path) const;
        AccessControl* getAC() const { return (m_acl ? m_acl : (m_base ? m_base->getAC() : NULL)); }
        
    protected:
        void loadACL(const DOMElement* e, Category& log);
        
        map<string,Override*> m_map;
    
    private:
        const Override* m_base;
        AccessControl* m_acl;
    };

    class XMLRequestMapperImpl : public Override
    {
    public:
        XMLRequestMapperImpl(const DOMElement* e, Category& log);

        ~XMLRequestMapperImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }
    
        const Override* findOverride(const char* vhost, const char* path) const;

    private:    
        map<string,Override*> m_extras;
        DOMDocument* m_document;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLRequestMapper : public RequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(const DOMElement* e)
                : ReloadableXMLFile(e), m_impl(NULL), m_log(Category::getInstance(SHIBSP_LOGCAT".RequestMapper")) {
            load();
        }

        ~XMLRequestMapper() {
            delete m_impl;
        }

        Settings getSettings(const SPRequest& request) const;

    protected:
        pair<bool,DOMElement*> load();

    private:
        XMLRequestMapperImpl* m_impl;
        Category& m_log;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    RequestMapper* SHIBSP_DLLLOCAL XMLRequestMapperFactory(const DOMElement* const & e)
    {
        return new XMLRequestMapper(e);
    }

    static const XMLCh _AccessControl[] =            UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh AccessControlProvider[] =    UNICODE_LITERAL_21(A,c,c,e,s,s,C,o,n,t,r,o,l,P,r,o,v,i,d,e,r);
    static const XMLCh htaccess[] =                 UNICODE_LITERAL_8(h,t,a,c,c,e,s,s);
    static const XMLCh Host[] =                     UNICODE_LITERAL_4(H,o,s,t);
    static const XMLCh Path[] =                     UNICODE_LITERAL_4(P,a,t,h);
    static const XMLCh name[] =                     UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh type[] =                     UNICODE_LITERAL_4(t,y,p,e);
}

void SHIBSP_API shibsp::registerRequestMappers()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.RequestMapperManager.registerFactory(XML_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory("edu.internet2.middleware.shibboleth.sp.provider.XMLRequestMapProvider", XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory("edu.internet2.middleware.shibboleth.target.provider.XMLRequestMap", XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory("edu.internet2.middleware.shibboleth.sp.provider.NativeRequestMapProvider", XMLRequestMapperFactory);
}

short Override::acceptNode(const DOMNode* node) const
{
    if (!XMLString::equals(node->getNamespaceURI(),shibspconstants::SHIB1SPCONFIG_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,Host) ||
        XMLString::equals(name,Path) ||
        XMLString::equals(name,_AccessControl) ||
        XMLString::equals(name,htaccess) ||
        XMLString::equals(name,AccessControlProvider))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void Override::loadACL(const DOMElement* e, Category& log)
{
    try {
        const DOMElement* acl=XMLHelper::getFirstChildElement(e,htaccess);
        if (acl) {
            log.info("building Apache htaccess AccessControl provider...");
            m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(HT_ACCESS_CONTROL,acl);
        }
        else {
            acl=XMLHelper::getFirstChildElement(e,_AccessControl);
            if (acl) {
                log.info("building XML-based AccessControl provider...");
                m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL,acl);
            }
            else {
                acl=XMLHelper::getFirstChildElement(e,AccessControlProvider);
                if (acl) {
                    xmltooling::auto_ptr_char type(acl->getAttributeNS(NULL,type));
                    log.info("building AccessControl provider of type %s...",type.get());
                    m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(type.get(),acl);
                }
            }
        }
    }
    catch (exception& ex) {
        log.crit("exception building AccessControl provider: %s", ex.what());
        m_acl = new AccessControlDummy();
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
        DOMElement* path = XMLHelper::getFirstChildElement(e,Path);
        for (int i=1; path; ++i, path=XMLHelper::getNextSiblingElement(path,Path)) {
            const XMLCh* n=path->getAttributeNS(NULL,name);
            
            // Skip any leading slashes.
            while (n && *n==chForwardSlash)
                n++;
            
            // Check for empty name.
            if (!n || !*n) {
                log.warn("skipping Path element (%d) with empty name attribute", i);
                continue;
            }

            // Check for an embedded slash.
            int slash=XMLString::indexOf(n,chForwardSlash);
            if (slash>0) {
                // Copy the first path segment.
                XMLCh* namebuf=new XMLCh[slash + 1];
                for (int pos=0; pos < slash; pos++)
                    namebuf[pos]=n[pos];
                namebuf[slash]=chNull;
                
                // Move past the slash in the original pathname.
                n=n+slash+1;
                
                // Skip any leading slashes again.
                while (*n==chForwardSlash)
                    n++;
                
                if (*n) {
                    // Create a placeholder Path element for the first path segment and replant under it.
                    DOMElement* newpath=path->getOwnerDocument()->createElementNS(shibspconstants::SHIB1SPCONFIG_NS,Path);
                    newpath->setAttributeNS(NULL,name,namebuf);
                    path->setAttributeNS(NULL,name,n);
                    path->getParentNode()->replaceChild(newpath,path);
                    newpath->appendChild(path);
                    
                    // Repoint our locals at the new parent.
                    path=newpath;
                    n=path->getAttributeNS(NULL,name);
                }
                else {
                    // All we had was a pathname with trailing slash(es), so just reset it without them.
                    path->setAttributeNS(NULL,name,namebuf);
                    n=path->getAttributeNS(NULL,name);
                }
                delete[] namebuf;
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
    catch (exception&) {
        delete m_acl;
        for_each(m_map.begin(),m_map.end(),xmltooling::cleanup_pair<string,Override>());
        throw;
    }
}

Override::~Override()
{
    delete m_acl;
    for_each(m_map.begin(),m_map.end(),xmltooling::cleanup_pair<string,Override>());
}

pair<bool,bool> Override::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret=DOMPropertySet::getBool(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getBool(name,ns) : ret;
}

pair<bool,const char*> Override::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret=DOMPropertySet::getString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getString(name,ns) : ret;
}

pair<bool,const XMLCh*> Override::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret=DOMPropertySet::getXMLString(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getXMLString(name,ns) : ret;
}

pair<bool,unsigned int> Override::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret=DOMPropertySet::getUnsignedInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getUnsignedInt(name,ns) : ret;
}

pair<bool,int> Override::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret=DOMPropertySet::getInt(name,ns);
    if (ret.first)
        return ret;
    return m_base ? m_base->getInt(name,ns) : ret;
}

const PropertySet* Override::getPropertySet(const char* name, const char* ns) const
{
    const PropertySet* ret=DOMPropertySet::getPropertySet(name,ns);
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

XMLRequestMapperImpl::XMLRequestMapperImpl(const DOMElement* e, Category& log) : m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLRequestMapperImpl");
#endif

    // Load the property set.
    load(e,log,this);
    
    // Load any AccessControl provider.
    loadACL(e,log);

    // Loop over the Host elements.
    const DOMElement* host = XMLHelper::getFirstChildElement(e,Host);
    for (int i=1; host; ++i, host=XMLHelper::getNextSiblingElement(host,Host)) {
        const XMLCh* n=host->getAttributeNS(NULL,name);
        if (!n || !*n) {
            log.warn("Skipping Host element (%d) with empty name attribute",i);
            continue;
        }
        
        Override* o=new Override(host,log,this);
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
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
                
                // Now append the port. We use the extras vector, to avoid double freeing the object later.
                url=url + ':' + port.second;
                m_extras[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
            else {
                url=url + ':' + port.second;
                if (m_map.count(url) || m_extras.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
        }
        else {
            // No scheme or port, so we enter dual hosts on http:80 and https:443
            string url("http://");
            url = url + dup;
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                delete o;
                continue;
            }
            m_map[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = url + ":80";
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = "https://";
            url = url + dup;
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = url + ":443";
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
        }
    }
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

pair<bool,DOMElement*> XMLRequestMapper::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLRequestMapperImpl* impl = new XMLRequestMapperImpl(raw.second,m_log);
    
    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}

RequestMapper::Settings XMLRequestMapper::getSettings(const SPRequest& request) const
{
    ostringstream vhost;
    vhost << request.getScheme() << "://" << request.getHostname() << ':' << request.getPort();

    const Override* o=m_impl->findOverride(vhost.str().c_str(), request.getRequestURI());

    if (m_log.isDebugEnabled()) {
#ifdef _DEBUG
        xmltooling::NDC ndc("getSettings");
#endif
        pair<bool,const char*> ret=o->getString("applicationId");
        m_log.debug("mapped %s%s to %s", vhost.str().c_str(), request.getRequestURI() ? request.getRequestURI() : "", ret.second);
    }

    return Settings(o,o->getAC());
}
