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

/* XMLRevocation.cpp - a revocation implementation that uses an XML file

   Scott Cantor
   2/16/04

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/err.h>

#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {

    class XMLRevocationImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLRevocationImpl(const char* pathname) : ReloadableXMLFileImpl(pathname), m_wildcard(NULL) { init(); }
        XMLRevocationImpl(const DOMElement* e) : ReloadableXMLFileImpl(e), m_wildcard(NULL) { init(); }
        void init();
        ~XMLRevocationImpl();
        
        struct KeyAuthority
        {
            KeyAuthority() {}
            ~KeyAuthority();

#ifndef HAVE_GOOD_STL
            vector<const XMLCh*> m_subjects;
#endif
            vector<void*> m_crls;
        };
        
        vector<KeyAuthority*> m_keyauths;
        KeyAuthority* m_wildcard;
#ifdef HAVE_GOOD_STL
        typedef map<xstring,KeyAuthority*> AuthMap;
        AuthMap m_map;
#endif
    };

    class XMLRevocation : public IRevocation, public ReloadableXMLFile
    {
    public:
        XMLRevocation(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLRevocation() {}

        Iterator<void*> getRevocationLists(const IProvider* provider, const IProviderRole* role=NULL) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };

}

IPlugIn* XMLRevocationFactory(const DOMElement* e)
{
    XMLRevocation* r=new XMLRevocation(e);
    try {
        r->getImplementation();
    }
    catch (...) {
        delete r;
        throw;
    }
    return r;
}


ReloadableXMLFileImpl* XMLRevocation::newImplementation(const char* pathname, bool first) const
{
    return new XMLRevocationImpl(pathname);
}

ReloadableXMLFileImpl* XMLRevocation::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLRevocationImpl(e);
}

XMLRevocationImpl::KeyAuthority::~KeyAuthority()
{
    for (vector<void*>::iterator i=m_crls.begin(); i!=m_crls.end(); i++)
        X509_CRL_free(reinterpret_cast<X509_CRL*>(*i));
}

void XMLRevocationImpl::init()
{
    NDC ndc("XMLRevocationImpl");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLRevocationImpl");

    try {
        if (!saml::XML::isElementNamed(m_root,::XML::TRUST_NS,SHIB_L(Trust))) {
            log.error("Construction requires a valid trust file: (trust:Trust as root element)");
            throw TrustException("Construction requires a valid trust file: (trust:Trust as root element)");
        }

        // Loop over the KeyAuthority elements.
        DOMNodeList* nlist=m_root->getElementsByTagNameNS(::XML::TRUST_NS,SHIB_L(KeyAuthority));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            auto_ptr<KeyAuthority> ka(new KeyAuthority());
                        
            // Very rudimentary, grab up all the in-band X509CRL elements, and flatten into one list.
            DOMNodeList* crllist=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(
                saml::XML::XMLSIG_NS,SHIB_L(X509CRL)
                );
            for (int j=0; crllist && j<crllist->getLength(); j++) {
                auto_ptr_char blob(crllist->item(j)->getFirstChild()->getNodeValue());
                X509_CRL* x=B64_to_CRL(blob.get());
                if (x)
                    ka->m_crls.push_back(x);
                else
                    log.warn("unable to create CRL from inline X509CRL data");
            }
            
            // Now look for externally referenced objects.
            crllist=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(
                saml::XML::XMLSIG_NS,SHIB_L(RetrievalMethod)
                );
            for (int k=0; crllist && k<crllist->getLength(); k++) {
                DOMElement* crl=static_cast<DOMElement*>(crllist->item(k));
                if (!XMLString::compareString(crl->getAttributeNS(NULL,SHIB_L(Type)),::XML::XMLSIG_RETMETHOD_RAWX509CRL)) {
                    // DER format
                    auto_ptr_char fname(crl->getAttributeNS(NULL,SHIB_L(URI)));
                    FILE* f=fopen(fname.get(),"r");
                    if (f) {
                        X509_CRL* x=NULL;
                        d2i_X509_CRL_fp(f,&x);
                        if (x) {
                            ka->m_crls.push_back(x);
                            continue;
                        }
                        else
                            log_openssl();
                    }
                    log.warn("unable to create CRL from externally referenced X509CRL file");
                }
                else if (!XMLString::compareString(crl->getAttributeNS(NULL,SHIB_L(Type)),::XML::SHIB_RETMETHOD_PEMX509CRL)) {
                    // PEM format
                    int count=0;
                    auto_ptr_char fname(crl->getAttributeNS(NULL,SHIB_L(URI)));
                    FILE* f=fopen(fname.get(),"r");
                    if (f) {
                        X509_CRL* x=NULL;
                        while (x=PEM_read_X509_CRL(f,NULL,NULL,NULL)) {
                            ka->m_crls.push_back(x);
                            count++;
                        }
                    }
                    if (!count)
                        log.warn("unable to create CRL from externally referenced X509CRL file");
                }
            }

            if (ka->m_crls.empty())
                continue;
            m_keyauths.push_back(ka.get());
            
            // Now map the ds:KeyName values to the list of certs.
            bool wildcard=true;
            DOMElement* sub=saml::XML::getFirstChildElement(static_cast<DOMElement*>(nlist->item(i)),saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            while (sub) {
                const XMLCh* name=sub->getFirstChild()->getNodeValue();
                if (name && *name) {
                    wildcard=false;
#ifdef HAVE_GOOD_STL
                    m_map[name]=ka.get();
#else
                    ka->m_subjects.push_back(name);
#endif
                }
                sub=saml::XML::getNextSiblingElement(sub,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            }
            
            // If no Subjects, this is a catch-all binding.
            if (wildcard) {
                if (!m_wildcard)
                    m_wildcard=ka.get();
                else
                    log.warn("found multiple wildcard KeyAuthority elements, ignoring all but the first");
            }
            ka.release();
        }
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while parsing revocation configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        throw;
    }
    catch (...) {
        log.error("Unexpected error while parsing revocation configuration");
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        throw;
    }
}

XMLRevocationImpl::~XMLRevocationImpl()
{
    for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
        delete (*i);
}

Iterator<void*> XMLRevocation::getRevocationLists(const IProvider* provider, const IProviderRole* role) const
{
    saml::NDC ndc("getRevocationLists");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLRevocation");
    XMLRevocationImpl* impl=dynamic_cast<XMLRevocationImpl*>(getImplementation());

    // Build a list of the names to match. We include any named KeyDescriptors, and the provider ID and its groups.
    vector<const XMLCh*> names;
    if (role) {
        Iterator<const IKeyDescriptor*> kdlist=role->getKeyDescriptors();
        while (kdlist.hasNext()) {
            const IKeyDescriptor* kd=kdlist.next();
            if (kd->getUse()!=IKeyDescriptor::signing)
                continue;
            DSIGKeyInfoList* kilist=kd->getKeyInfo();
            for (size_t s=0; kilist && s<kilist->getSize(); s++) {
                const XMLCh* n=kilist->item(s)->getKeyName();
                if (n)
                    names.push_back(n);
            }
        }
    }
    names.push_back(provider->getId());
    Iterator<const XMLCh*> groups=provider->getGroups();
    while (groups.hasNext())
        names.push_back(groups.next());

    // Now check each name.
    for (vector<const XMLCh*>::const_iterator name=names.begin(); name!=names.end(); name++) {
#ifdef HAVE_GOOD_STL
        XMLRevocationImpl::AuthMap::const_iterator c=impl->m_map.find(*name);
        if (c!=impl->m_map.end()) {
            if (log.isInfoEnabled()) {
                auto_ptr_char temp(*name);
                log.info("revocation list match on %s",temp.get());
            }
            return c->second->m_crls;
        }
#else
        // Without a decent STL, we trade-off the transcoding by doing a linear search.
        for (vector<XMLRevocationImpl::KeyAuthority*>::const_iterator keyauths=impl->m_keyauths.begin(); keyauths!=impl->m_keyauths.end(); keyauths++) {
            for (vector<const XMLCh*>::const_iterator subs=(*keyauths)->m_subjects.begin(); subs!=(*keyauths)->m_subjects.end(); subs++) {
                if (!XMLString::compareString(*name,*subs)) {
                    if (log.isInfoEnabled()) {
                        auto_ptr_char temp(*name);
                        log.info("revocation list match on %s",temp.get());
                    }
                    return (*keyauths)->m_crls;
                }
            }
        }
#endif
    }
    
    if (impl->m_wildcard) {
        log.info("no matching revocation list, using wildcard list");
        return impl->m_wildcard->m_crls;
    }

    log.info("no matching revocation list");
    return EMPTY(void*);
}
