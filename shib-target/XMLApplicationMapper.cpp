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

/* XMLApplicationMapper.cpp - an XML-based config file for mapping URLs to application names

   Scott Cantor
   1/6/04

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>

namespace shibtarget {

    class XMLApplicationMapperImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLApplicationMapperImpl(const char* pathname);
        ~XMLApplicationMapperImpl();
    
        struct Override
        {
            Override(const XMLCh* AppID) : m_XMLChAppID(AppID), m_AppID(AppID) {}
            ~Override();
            const Override* locate(const char* path) const;
            auto_ptr_char m_AppID;
            const XMLCh* m_XMLChAppID;
            map<string,Override*> m_map;
        };
    
        const XMLCh* m_XMLChAppID;
        string m_AppID;
        map<string,Override*> m_map;
        map<string,Override*> m_extras;
    
    private:
        Override* buildOverride(const XMLCh* appID, DOMElement* root, Category& log);
    };
}

ReloadableXMLFileImpl* XMLApplicationMapper::newImplementation(const char* pathname) const
{
    return new XMLApplicationMapperImpl(pathname);
}

XMLApplicationMapperImpl::Override::~Override()
{
    for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
        delete i->second;
}

XMLApplicationMapperImpl::Override* XMLApplicationMapperImpl::buildOverride(const XMLCh* appID, DOMElement* root, Category& log)
{
    Override* o=new Override(appID);
    DOMNodeList* nlist = root->getElementsByTagNameNS(shibtarget::XML::APPMAP_NS,shibtarget::XML::Literals::Path);
    for (int i=0; nlist && i<nlist->getLength(); i++)
    {
        DOMElement* path=static_cast<DOMElement*>(nlist->item(i));
        const XMLCh* name=path->getAttributeNS(NULL,shibboleth::XML::Literals::Name);
        if (!name || !*name)
        {
            log.warn("Skipping Path element (%d) with empty Name attribute",i);
            continue;
        }
        
        auto_ptr_char n(name);
        o->m_map[n.get()]=buildOverride(path->getAttributeNS(NULL,shibtarget::XML::Literals::ApplicationID),path,log);
    }
    return o;
}

XMLApplicationMapperImpl::XMLApplicationMapperImpl(const char* pathname) : ReloadableXMLFileImpl(pathname)
{
    NDC ndc("XMLApplicationMapperImpl");
    Category& log=Category::getInstance("shibtarget.XMLApplicationMapperImpl");

    try
    {
        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(shibtarget::XML::APPMAP_NS,e->getNamespaceURI()) ||
            XMLString::compareString(shibtarget::XML::Literals::ApplicationMap,e->getLocalName()))
        {
            log.error("Construction requires a valid app mapping file: (appmap:ApplicationMap as root element)");
            throw MetadataException("Construction requires a valid app mapping file: (appmap:ApplicationMap as root element)");
        }
        
        m_XMLChAppID=e->getAttributeNS(NULL,shibtarget::XML::Literals::ApplicationID);
        if (!m_XMLChAppID || !*m_XMLChAppID)
        {
            log.error("Default ApplicationID must be defined");
            throw MetadataException("Default ApplicationID must be defined");
        }
        auto_ptr_char defappid(m_XMLChAppID);
        m_AppID=defappid.get();

        // Loop over the Host elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(shibtarget::XML::APPMAP_NS,shibtarget::XML::Literals::Host);
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            DOMElement* host=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* scheme=host->getAttributeNS(NULL,shibtarget::XML::Literals::Scheme);
            const XMLCh* name=host->getAttributeNS(NULL,shibboleth::XML::Literals::Name);
            const XMLCh* port=host->getAttributeNS(NULL,shibtarget::XML::Literals::Port);

            if (!name || !*name)
            {
                log.warn("Skipping Host element (%d) with empty Name attribute",i);
                continue;
            }

            Override* o=buildOverride(host->getAttributeNS(NULL,shibtarget::XML::Literals::ApplicationID),host,log);

            auto_ptr_char s(scheme);
            auto_ptr_char n(name);
            auto_ptr_char p(port);
            string url(s.get() ? s.get() : "http");
            url=url + "://" + n.get();
            if (p.get()==NULL)
            {
                // First store a port-less version.
                if (m_map.count(url))
                {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_map[url]=o;
                
                // Now append the default port.
                // XXX Use getservbyname instead?
                if (s.get()==NULL || !strcmp(s.get(),"http"))
                    url=url + ":80";
                else if (!strcmp(s.get(),"https"))
                    url=url + ":443";
                else if (!strcmp(s.get(),"ftp"))
                    url=url + ":21";
                else if (!strcmp(s.get(),"ldap"))
                    url=url + ":389";
                else if (!strcmp(s.get(),"ldaps"))
                    url=url + ":636";
                
                m_extras[url]=o;
            }
            else
            {
                url=url + ':' + p.get();
                if (m_map.count(url))
                {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_map[url]=o;
            }
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "Error while parsing app mapping configuration: " << e.what() << CategoryStream::ENDLINE;
        for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing app mapping configuration");
        for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
}

XMLApplicationMapperImpl::~XMLApplicationMapperImpl()
{
    for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
        delete i->second;
}

const XMLApplicationMapperImpl::Override* XMLApplicationMapperImpl::Override::locate(const char* path) const
{
    char* dup=strdup(path);
    const Override* o=this;
    const Override* specifier=((m_XMLChAppID && *m_XMLChAppID) ? this : NULL);
    
#ifdef WIN32
    const char* token=strtok(dup,"/");
#else
    char* pos=NULL;
    const char* token=strtok_r(dup,"/",&pos);
#endif
    while (token)
    {
        map<string,Override*>::const_iterator i=o->m_map.find(token);
        if (i==o->m_map.end())
            break;
        o=i->second;
        if (o->m_XMLChAppID && *(o->m_XMLChAppID))
            specifier=o;
#ifdef WIN32
        token=strtok(NULL,"/");
#else
        token=strtok_r(NULL,"/",&pos);
#endif
    }

    free(dup);
    return specifier;
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

const char* XMLApplicationMapper::getApplicationFromURL(const char* url) const
{
    string vhost;
    const char* path=split_url(url,vhost);
    XMLApplicationMapperImpl* impl=dynamic_cast<XMLApplicationMapperImpl*>(getImplementation());
    
    map<string,XMLApplicationMapperImpl::Override*>::const_iterator i=impl->m_map.find(vhost);
    if (i==impl->m_map.end())
        i=impl->m_extras.find(vhost);
    if (i!=impl->m_map.end())
    {
        const XMLApplicationMapperImpl::Override* o=i->second->locate(path);
        if (o)
            return o->m_AppID.get();
    }
    
    return impl->m_AppID.c_str();
}

const XMLCh* XMLApplicationMapper::getXMLChApplicationFromURL(const char* url) const
{
    string vhost;
    const char* path=split_url(url,vhost);
    XMLApplicationMapperImpl* impl=dynamic_cast<XMLApplicationMapperImpl*>(getImplementation());
    
    map<string,XMLApplicationMapperImpl::Override*>::const_iterator i=impl->m_map.find(vhost);
    if (i==impl->m_map.end())
        i=impl->m_extras.find(vhost);
    if (i!=impl->m_map.end())
    {
        const XMLApplicationMapperImpl::Override* o=i->second->locate(path);
        if (o)
            return o->m_XMLChAppID;
    }
    
    return impl->m_XMLChAppID;
}

const char* XMLApplicationMapper::getApplicationFromParsedURL(
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

    XMLApplicationMapperImpl* impl=dynamic_cast<XMLApplicationMapperImpl*>(getImplementation());
    map<string,XMLApplicationMapperImpl::Override*>::const_iterator i=impl->m_map.find(vhost);
    if (i==impl->m_map.end())
        i=impl->m_extras.find(vhost);
    if (i!=impl->m_map.end())
    {
        const XMLApplicationMapperImpl::Override* o=i->second->locate(path);
        if (o)
            return o->m_AppID.get();
    }
    
    return impl->m_AppID.c_str();
}

const XMLCh* XMLApplicationMapper::getXMLChApplicationFromParsedURL(
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

    XMLApplicationMapperImpl* impl=dynamic_cast<XMLApplicationMapperImpl*>(getImplementation());
    map<string,XMLApplicationMapperImpl::Override*>::const_iterator i=impl->m_map.find(vhost);
    if (i==impl->m_map.end())
        i=impl->m_extras.find(vhost);
    if (i!=impl->m_map.end())
    {
        const XMLApplicationMapperImpl::Override* o=i->second->locate(path);
        if (o)
            return o->m_XMLChAppID;
    }
    
    return impl->m_XMLChAppID;
}
