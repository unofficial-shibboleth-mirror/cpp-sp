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

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace shibtarget {

    class XMLApplicationMapperImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLApplicationMapperImpl(const char* pathname);
        ~XMLApplicationMapperImpl();
    
        struct Override
        {
            Override(const XMLCh* AppID) : m_XMLChAppID((AppID && *AppID) ? AppID : NULL),
                m_AppID((AppID && *AppID) ? AppID : NULL) {}
            ~Override();
            const Override* locate(const char* path) const;
            auto_ptr_char m_AppID;
            const XMLCh* m_XMLChAppID;
            map<string,Override*> m_map;
        };
        
        const Override* findOverride(const char* vhost, const char* path) const;
    
        map<string,Override*> m_map;
        map<string,Override*> m_extras;
        
        Category* log;
    
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

XMLApplicationMapperImpl::XMLApplicationMapperImpl(const char* pathname) : ReloadableXMLFileImpl(pathname)
{
    NDC ndc("XMLApplicationMapperImpl");
    log=&Category::getInstance("shibtarget.XMLApplicationMapper");

    try
    {
        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(shibtarget::XML::APPMAP_NS,e->getNamespaceURI()) ||
            XMLString::compareString(shibtarget::XML::Literals::ApplicationMap,e->getLocalName()))
        {
            log->error("Construction requires a valid app mapping file: (appmap:ApplicationMap as root element)");
            throw MetadataException("Construction requires a valid app mapping file: (appmap:ApplicationMap as root element)");
        }
        
        // Loop over the Host elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(shibtarget::XML::APPMAP_NS,shibtarget::XML::Literals::Host);
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            DOMElement* host=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* scheme=host->getAttributeNS(NULL,shibtarget::XML::Literals::Scheme);
            const XMLCh* port=host->getAttributeNS(NULL,shibtarget::XML::Literals::Port);
            auto_ptr_XMLCh name(host->getAttributeNS(NULL,shibboleth::XML::Literals::Name));

            if (!name.get() || !*(name.get()))
            {
                log->warn("Skipping Host element (%d) with empty Name attribute",i);
                continue;
            }
            XMLString::lowerCase(const_cast<XMLCh*>(name.get()));

            Override* o=buildOverride(host->getAttributeNS(NULL,shibtarget::XML::Literals::ApplicationID),host,*log);

            auto_ptr_char s(scheme);
            auto_ptr_char n(name.get());
            auto_ptr_char p(port);
            string url((s.get() && *(s.get())) ? s.get() : "http");
            url=url + "://" + n.get();
            if (p.get()==NULL || *(p.get())=='\0')
            {
                // First store a port-less version.
                if (m_map.count(url))
                {
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
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
                    log->warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
            }
            log->debug("Added <Host> mapping for %s",url.c_str());
        }
    }
    catch (SAMLException& e)
    {
        log->errorStream() << "Error while parsing app mapping configuration: " << e.what() << CategoryStream::ENDLINE;
        for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log->error("Unexpected error while parsing app mapping configuration");
        for (map<string,Override*>::iterator i=m_map.begin(); i!=m_map.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
#endif
}

XMLApplicationMapperImpl::~XMLApplicationMapperImpl()
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
        auto_ptr_XMLCh name(path->getAttributeNS(NULL,shibboleth::XML::Literals::Name));
        if (!name.get() || !*(name.get()))
        {
            log.warn("Skipping Path element (%d) with empty Name attribute",i);
            continue;
        }
        XMLString::lowerCase(const_cast<XMLCh*>(name.get()));
        
        auto_ptr_char n(name.get());
        o->m_map[n.get()]=buildOverride(path->getAttributeNS(NULL,shibtarget::XML::Literals::ApplicationID),path,log);
    }
    return o;
}

const XMLApplicationMapperImpl::Override* XMLApplicationMapperImpl::findOverride(const char* vhost, const char* path) const
{
    const Override* o=NULL;
    map<string,Override*>::const_iterator i=m_map.find(vhost);
    if (i!=m_map.end())
        o=i->second;
    else
    {
        i=m_extras.find(vhost);
        if (i!=m_extras.end())
            o=i->second;
    }
    
    if (o)
    {
        const Override* o2=o->locate(path);
        if (o2)
            return o2;
    }
    return o;
}

const XMLApplicationMapperImpl::Override* XMLApplicationMapperImpl::Override::locate(const char* path) const
{
    char* dup=strdup(path);
    char* sep=strchr(path,'?');
    if (sep)
        *sep=0;
    for (char* pch=dup; *pch; pch++)
        *pch=tolower(*pch);
        
    
    const Override* o=this;
    const Override* specifier=((m_XMLChAppID && *m_XMLChAppID) ? this : NULL);
    
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
        if (o->m_XMLChAppID && *(o->m_XMLChAppID))
            specifier=o;
#ifdef HAVE_STRTOK_R
        token=strtok_r(NULL,"/",&pos);
#else
        token=strtok(NULL,"/");
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
    const XMLApplicationMapperImpl::Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled())
    {
        saml::NDC ndc("getApplicationFromURL");
        impl->log->debug("mapped %s to %s", url, o ? o->m_AppID.get() : "default application ID");
    }

    return o ? o->m_AppID.get() : "";
}

const XMLCh* XMLApplicationMapper::getXMLChApplicationFromURL(const char* url) const
{
    string vhost;
    const char* path=split_url(url,vhost);

    XMLApplicationMapperImpl* impl=dynamic_cast<XMLApplicationMapperImpl*>(getImplementation());
    const XMLApplicationMapperImpl::Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled())
    {
        saml::NDC ndc("getXMLChApplicationFromURL");
        impl->log->debug("mapped %s to %s", url, o ? o->m_AppID.get() : "default application ID");
    }

    return o ? o->m_XMLChAppID : &chNull;
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
    const XMLApplicationMapperImpl::Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled())
    {
        saml::NDC ndc("getApplicationFromParsedURL");
        impl->log->debug("mapped %s%s to %s", vhost.c_str(), path ? path : "", o ? o->m_AppID.get() : "default application ID");
    }

    return o ? o->m_AppID.get() : "";
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
    const XMLApplicationMapperImpl::Override* o=impl->findOverride(vhost.c_str(), path);

    if (impl->log->isDebugEnabled())
    {
        saml::NDC ndc("getXMLChApplicationFromParsedURL");
        impl->log->debug("mapped %s%s to %s", vhost.c_str(), path ? path : "", o ? o->m_AppID.get() : "default application ID");
    }

    return o ? o->m_XMLChAppID : &chNull;
}
