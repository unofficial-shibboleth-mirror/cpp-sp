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

/* XMLCredentials.cpp - a credentials implementation that uses an XML file

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace shibboleth {
    
    class XMLCredentialsImpl
    {
    public:
        XMLCredentialsImpl(const char* pathname);
        ~XMLCredentialsImpl();
        
        typedef map<string,ICredResolver*> resolvermap_t;
        resolvermap_t m_resolverMap;

        struct KeyUse
        {
            KeyUse(resolvermap_t& resolverMap, const XMLCh* keyref, const XMLCh* certref=NULL);
            
            ICredResolver* m_key;
            ICredResolver* m_cert;
            vector<pair<const XMLCh*,bool> > m_relying;
        };
        
        vector<KeyUse*> m_keyuses;
        typedef multimap<pair<const XMLCh*,bool>,KeyUse*> BindingMap;
        BindingMap m_bindings;
        
        DOMDocument* m_doc;
    };

    class XMLCredentials : public ICredentials
    {
    public:
        XMLCredentials(const char* pathname);
        ~XMLCredentials() { delete m_lock; delete m_impl; }
        bool attach(const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx) const;

    private:
        void lock();
        void unlock() { m_lock->unlock(); }
        std::string m_source;
        time_t m_filestamp;
        RWLock* m_lock;
        XMLCredentialsImpl* m_impl;
    };

}

extern "C" ICredentials* XMLCredentialsFactory(const char* source)
{
    return new XMLCredentials(source);
}

XMLCredentialsImpl::KeyUse::KeyUse(resolvermap_t& resolverMap, const XMLCh* keyref, const XMLCh* certref) : m_key(NULL), m_cert(NULL)
{
    auto_ptr<char> temp(XMLString::transcode(keyref));
    resolvermap_t::iterator i=resolverMap.find(temp.get());
    if (i==resolverMap.end())
        throw MetadataException(string("XMLCredentialsImpl::KeyUse::KeyUse() unable to find valid key reference (") + temp.get() + ")");
    m_key=i->second;
    
    if (certref && *certref)
    {
        auto_ptr<char> temp2(XMLString::transcode(certref));
        i=resolverMap.find(temp2.get());
        if (i==resolverMap.end())
            throw MetadataException(string("XMLCredentialsImpl::KeyUse::KeyUse() unable to find valid certificate reference (") + temp2.get() + ")");
        m_cert=i->second;
    }
}

XMLCredentialsImpl::XMLCredentialsImpl(const char* pathname) : m_doc(NULL)
{
    NDC ndc("XMLCredentialsImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentialsImpl");

    saml::XML::Parser p;
    try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,pathname);
        Wrapper4InputSource dsrc(&src,false);
        m_doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed creds file (" << pathname << ")" << CategoryStream::ENDLINE;

        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(XML::SHIB_NS,e->getNamespaceURI()) ||
            XMLString::compareString(SHIB_L(Credentials),e->getLocalName()))
        {
            log.error("Construction requires a valid creds file: (shib:Credentials as root element)");
            throw MetadataException("Construction requires a valid creds file: (shib:Credentials as root element)");
        }

        // Process everything up to the first shib:KeyUse as a resolver.
        DOMElement* child=saml::XML::getFirstChildElement(e);
        while (!saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(KeyUse)))
        {
            CredResolverFactory* factory=NULL;
            auto_ptr<char> id(XMLString::transcode(child->getAttributeNS(NULL,SHIB_L(Id))));
            
            if (saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(FileCredResolver)))
                factory=ShibConfig::getConfig().getCredResolverFactory("edu.internet2.middleware.shibboleth.creds.provider.FileCredResolver");
            else if (saml::XML::isElementNamed(child,saml::XML::XMLSIG_NS,L(KeyInfo)))
                factory=ShibConfig::getConfig().getCredResolverFactory("edu.internet2.middleware.shibboleth.creds.provider.KeyInfoResolver");
            else if (saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(CustomCredResolver)))
            {
                auto_ptr<char> c(XMLString::transcode(child->getAttributeNS(NULL,SHIB_L(Class))));
                factory=ShibConfig::getConfig().getCredResolverFactory(c.get());
            }
            
            if (factory)
            {
                try
                {
                    ICredResolver* cr=(*factory)(child);
                    m_resolverMap[id.get()]=cr;
                }
                catch (SAMLException& e)
                {
                    log.error("failed to instantiate credential resolver (%s): %s", id.get(), e.what());
                }
            }
            
            child=saml::XML::getNextSiblingElement(child);
        }

        // Now loop over the KeyUse elements.
        while (child && saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(KeyUse)))
        {
            KeyUse* ku = new KeyUse(
                m_resolverMap,
                child->getAttributeNS(NULL,SHIB_L(KeyRef)),
                child->getAttributeNS(NULL,SHIB_L(CertificateRef))
                );
            m_keyuses.push_back(ku);

            // Pull in the relying parties.
            DOMNodeList* parties=child->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(RelyingParty));
            int m=0;
            while (parties && m<parties->getLength())
            {
                const XMLCh* name=parties->item(m)->getFirstChild()->getNodeValue();
                if (name && *name)
                {
                    static const XMLCh one[]={ chDigit_1, chNull };
                    static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                    const XMLCh* regexp=
                        static_cast<DOMElement*>(parties->item(m))->getAttributeNS(NULL,SHIB_L(regexp));
                    bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
                    ku->m_relying.push_back(pair<const XMLCh*,bool>(name,flag));
                }
                m++;
            }
            // If no RelyingParties, this is a catch-all binding.
            if (m==0)
                ku->m_relying.push_back(pair<const XMLCh*,bool>(NULL,false));
            
            // Now map the subjects to the credentials.
            DOMNodeList* subs=child->getElementsByTagNameNS(XML::SHIB_NS,L(Subject));
            int l=0;
            while (subs && l<subs->getLength())
            {
                const XMLCh* name=subs->item(l)->getFirstChild()->getNodeValue();
                if (name && *name)
                {
                    static const XMLCh one[]={ chDigit_1, chNull };
                    static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                    const XMLCh* regexp=
                        static_cast<DOMElement*>(subs->item(l))->getAttributeNS(NULL,SHIB_L(regexp));
                    bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
                    m_bindings.insert(BindingMap::value_type(pair<const XMLCh*,bool>(name,flag),ku));
                }
                l++;
            }
            // If no Subjects, this is a catch-all binding.
            if (l==0)
                m_bindings.insert(BindingMap::value_type(pair<const XMLCh*,bool>(NULL,false),ku));

            child=saml::XML::getNextSiblingElement(child);
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing creds configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
            delete (*i);
        for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
            delete j->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing creds configuration");
        for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
            delete (*i);
        for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
            delete j->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
}

XMLCredentialsImpl::~XMLCredentialsImpl()
{
    for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
        delete (*i);
    for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
        delete j->second;
    if (m_doc)
        m_doc->release();
}

XMLCredentials::XMLCredentials(const char* pathname) : m_filestamp(0), m_source(pathname), m_impl(NULL)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(pathname, &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(pathname, &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;
    m_impl=new XMLCredentialsImpl(pathname);
    m_lock=RWLock::create();
}

void XMLCredentials::lock()
{
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
        {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
            {
                try
                {
                    XMLCredentialsImpl* new_mapper=new XMLCredentialsImpl(m_source.c_str());
                    delete m_impl;
                    m_impl=new_mapper;
                    m_filestamp=stat_buf.st_mtime;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLCredentials").error("failed to reload credentials metadata, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLCredentials").error("caught an unknown exception, sticking with what we have");
                }
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
}


bool XMLCredentials::attach(const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx) const
{
    NDC ndc("attach");

    // Use the matching bindings.
    for (XMLCredentialsImpl::BindingMap::const_iterator i=m_impl->m_bindings.begin(); i!=m_impl->m_bindings.end(); i++)
    {
        bool match=false;
        
        if (i->first.first==NULL)   // catch-all entry
        {
            match=true;
        }
        else if (i->first.second)   // regexp
        {
            try
            {
                RegularExpression re(i->first.first);
                if (re.matches(subject))
                    match=true;
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentials");
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << CategoryStream::ENDLINE;
            }
        }
        else if (!XMLString::compareString(subject,i->first.first))
        {
            match=true;
        }
        
        if (match)
        {
            // See if the relying party applies...
            match=false;
            for (vector<pair<const XMLCh*,bool> >::const_iterator j=i->second->m_relying.begin(); j!=i->second->m_relying.end(); j++)
            {
                if (j->first==NULL)     // catch-all entry
                {
                    match=true;
                }
                else if (j->second)     // regexp
                {
                    try
                    {
                        RegularExpression re(j->first);
                        if (re.matches(relyingParty->getName()))
                            match=true;
                        else
                        {
                            Iterator<const XMLCh*> groups=relyingParty->getGroups();
                            while (!match && groups.hasNext())
                                if (re.matches(groups.next()))
                                    match=true;
                        }
                    }
                    catch (XMLException& ex)
                    {
                        auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                        Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentials");
                        log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                            << CategoryStream::ENDLINE;
                    }
                }
                else if (!XMLString::compareString(relyingParty->getName(),j->first))
                {
                    match=true;
                }
                else
                {
                    Iterator<const XMLCh*> groups=relyingParty->getGroups();
                    while (!match && groups.hasNext())
                        if (!XMLString::compareString(groups.next(),j->first))
                            match=true;
                }
            }
        }
        
        if (match)
        {
            try
            {
                i->second->m_key->resolveKey(ctx);
                if (i->second->m_cert)
                    i->second->m_cert->resolveCert(ctx);

                if (!SSL_CTX_check_private_key(ctx))
                {
                    log_openssl();
                    throw MetadataException("XMLCredentials::attach() found mismatch between the private key and certificate used");
                }

                return true;
            }
            catch (SAMLException& e)
            {
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentials");
                log.error("caught a SAML exception while attaching credentials: %s", e.what());
            }
            catch (...)
            {
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentials");
                log.error("caught an unknown exception while attaching credentials");
            }
        }
    }

    return false;
}
