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
    
    class XMLCredentialsImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLCredentialsImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLCredentialsImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
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
    };

    class XMLCredentials : public ICredentials, public ReloadableXMLFile
    {
    public:
        XMLCredentials(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLCredentials() {}
        
        bool attach(const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e) const;
    };

}

extern "C" ICredentials* XMLCredentialsFactory(const DOMElement* e)
{
    XMLCredentials* creds=new XMLCredentials(e);
    try
    {
        creds->getImplementation();
    }
    catch (...)
    {
        delete creds;
        throw;
    }
    return creds;    
}

ReloadableXMLFileImpl* XMLCredentials::newImplementation(const char* pathname) const
{
    return new XMLCredentialsImpl(pathname);
}

ReloadableXMLFileImpl* XMLCredentials::newImplementation(const DOMElement* e) const
{
    return new XMLCredentialsImpl(e);
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

void XMLCredentialsImpl::init()
{
    NDC ndc("XMLCredentialsImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLCredentialsImpl");

    try
    {
        if (XMLString::compareString(XML::SHIB_NS,m_root->getNamespaceURI()) ||
            XMLString::compareString(SHIB_L(Credentials),m_root->getLocalName()))
        {
            log.error("Construction requires a valid creds file: (shib:Credentials as root element)");
            throw MetadataException("Construction requires a valid creds file: (shib:Credentials as root element)");
        }

        // Process everything up to the first shib:KeyUse as a resolver.
        DOMElement* child=saml::XML::getFirstChildElement(m_root);
        while (!saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(KeyUse)))
        {
            string cr_type;
            auto_ptr<char> id(XMLString::transcode(child->getAttributeNS(NULL,SHIB_L(Id))));
            
            if (saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(FileCredResolver)))
                cr_type="edu.internet2.middleware.shibboleth.creds.provider.FileCredResolver";
            else if (saml::XML::isElementNamed(child,saml::XML::XMLSIG_NS,L(KeyInfo)))
                cr_type="edu.internet2.middleware.shibboleth.creds.provider.KeyInfoResolver";
            else if (saml::XML::isElementNamed(child,XML::SHIB_NS,SHIB_L(CustomCredResolver)))
            {
                auto_ptr_char c(child->getAttributeNS(NULL,SHIB_L(Class)));
                cr_type=c.get();
            }
            
            if (!cr_type.empty())
            {
                try
                {
                    ICredResolver* cr=ShibConfig::getConfig().newCredResolver(cr_type.c_str(),child);
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
        log.errorStream() << "Error while parsing creds configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
            delete (*i);
        for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
            delete j->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
#ifndef _DEBUG
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
#endif
}

XMLCredentialsImpl::~XMLCredentialsImpl()
{
    for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
        delete (*i);
    for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
        delete j->second;
}

bool XMLCredentials::attach(const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx) const
{
    NDC ndc("attach");

    // Use the matching bindings.
    XMLCredentialsImpl* impl=dynamic_cast<XMLCredentialsImpl*>(getImplementation());
    for (XMLCredentialsImpl::BindingMap::const_iterator i=impl->m_bindings.begin(); i!=impl->m_bindings.end(); i++)
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
