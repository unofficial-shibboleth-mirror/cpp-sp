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

/* XMLTrust.h - a trust implementation that uses an XML file

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

int verify_callback(int ok, X509_STORE_CTX* store)
{
    if (!ok)
        Category::getInstance("OpenSSL").error(X509_verify_cert_error_string(store->error));
    return ok;
}

class shibboleth::XMLTrustImpl
{
public:
    XMLTrustImpl(const char* pathname);
    ~XMLTrustImpl();
    
    struct KeyAuthority
    {
        KeyAuthority() : m_store(NULL), m_depth(0), m_type(authority) {}
        ~KeyAuthority();
        X509_STORE* getX509Store(bool cached=true);

        vector<XSECCryptoX509*> m_certs;
        vector<X509*> m_nativecerts;
        X509_STORE* m_store;
        unsigned short m_depth;
        enum {authority, entity} m_type;
    };
    
    vector<KeyAuthority*> m_keyauths;
    typedef map<pair<const XMLCh*,bool>,KeyAuthority*> BindingMap;
    BindingMap m_bindings;
    
    DOMDocument* m_doc;
};

X509_STORE* XMLTrustImpl::KeyAuthority::getX509Store(bool cached)
{
    // We cache them once they're built...
    if (m_store && cached)
        return m_store;
    
    NDC ndc("getX509Store");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLTrust");

    // Do we need to convert to native cert format?
    if (m_nativecerts.empty())
    {
        for (vector<XSECCryptoX509*>::const_iterator i=m_certs.begin(); i!=m_certs.end(); i++)
        {
            X509* x509=B64_to_X509((*i)->getDEREncodingSB().rawCharBuffer());
            if (!x509)
            {
                log.warn("failed to parse X509 buffer: %s", (*i)->getDEREncodingSB().rawCharBuffer());
                continue;
            }
            m_nativecerts.push_back(x509);
        }
    }
    
    // Load the cert vector into a store.
    X509_STORE* store=NULL;
    if (!(store=X509_STORE_new()))
    {
        log_openssl();
        return NULL;
    }
    
    X509_STORE_set_verify_cb_func(store,verify_callback);

    for (vector<X509*>::iterator j=m_nativecerts.begin(); j!=m_nativecerts.end(); j++)
    {
        if (!X509_STORE_add_cert(store,X509_dup(*j)))
        {
            log_openssl();
            log.warn("failed to add cert: %s", (*j)->name);
            continue;
        }
    }

    if (cached)
        m_store=store;
    return store;
}

XMLTrustImpl::KeyAuthority::~KeyAuthority()
{
    if (m_store)
        X509_STORE_free(m_store);
    for (vector<X509*>::iterator i=m_nativecerts.begin(); i!=m_nativecerts.end(); i++)
        X509_free(*i);
    for (vector<XSECCryptoX509*>::iterator j=m_certs.begin(); j!=m_certs.end(); j++)
        delete (*j);
}

XMLTrustImpl::XMLTrustImpl(const char* pathname) : m_doc(NULL)
{
    NDC ndc("XMLTrustImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLTrustImpl");

    saml::XML::Parser p;
    try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,pathname);
        Wrapper4InputSource dsrc(&src,false);
        m_doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed trust file (" << pathname << ")" << CategoryStream::ENDLINE;

        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(XML::SHIB_NS,e->getNamespaceURI()) ||
            XMLString::compareString(SHIB_L(Trust),e->getLocalName()))
        {
            log.error("Construction requires a valid trust file: (shib:Trust as root element)");
            throw MetadataException("Construction requires a valid trust file: (shib:Trust as root element)");
        }

        // Loop over the KeyAuthority elements.
        DOMNodeList* nlist=e->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(KeyAuthority));
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            KeyAuthority* ka=new KeyAuthority();
            m_keyauths.push_back(ka);
            
            const XMLCh* depth=static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(VerifyDepth));
            if (depth && *depth)
                ka->m_depth=XMLString::parseInt(depth);
            
            const XMLCh* type=static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(NULL,SHIB_L(Type));
            if (type && *type==chLatin_e)
                ka->m_type=KeyAuthority::entity;

            // Very rudimentary, grab up all the X509Certificate elements, and flatten into one list.
            DOMNodeList* certlist=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(
                saml::XML::XMLSIG_NS,L(X509Certificate)
                );
            for (int j=0; certlist && j<certlist->getLength(); j++)
            {
                auto_ptr<char> blob(XMLString::transcode(certlist->item(j)->getFirstChild()->getNodeValue()));
                XSECCryptoX509* cert=new OpenSSLCryptoX509();
                cert->loadX509Base64Bin(blob.get(),strlen(blob.get()));
                ka->m_certs.push_back(cert);
            }
            
            // Now map the subjects to the list of certs.
            DOMNodeList* subs=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(XML::SHIB_NS,L(Subject));
            int k=0;
            while (subs && k<subs->getLength())
            {
                const XMLCh* name=subs->item(k)->getFirstChild()->getNodeValue();
                if (name && *name)
                {
                    static const XMLCh one[]={ chDigit_1, chNull };
                    static const XMLCh tru[]={ chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull };
                    const XMLCh* regexp=
                        static_cast<DOMElement*>(subs->item(k))->getAttributeNS(NULL,SHIB_L(regexp));
                    bool flag=(!XMLString::compareString(regexp,one) || !XMLString::compareString(regexp,tru));
                    m_bindings[pair<const XMLCh*,bool>(name,flag)]=ka;
                }
                k++;
            }
            // If no Subjects, this is a catch-all binding.
            if (k==0)
                m_bindings[pair<const XMLCh*,bool>(NULL,false)]=ka;
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing trust configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing trust configuration");
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        if (m_doc)
            m_doc->release();
        throw;
    }
}

XMLTrustImpl::~XMLTrustImpl()
{
    for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
        delete (*i);
    if (m_doc)
        m_doc->release();
}

XMLTrust::XMLTrust(const char* pathname) : m_filestamp(0), m_source(pathname), m_impl(NULL)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(pathname, &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(pathname, &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;
    m_impl=new XMLTrustImpl(pathname);
    m_lock=RWLock::create();
}

XMLTrust::~XMLTrust()
{
    delete m_lock;
    delete m_impl;
}

void XMLTrust::lock()
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
                    XMLTrustImpl* new_mapper=new XMLTrustImpl(m_source.c_str());
                    delete m_impl;
                    m_impl=new_mapper;
                    m_filestamp=stat_buf.st_mtime;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLTrust").error("failed to reload trust metadata, sticking with what we have: %s", e.what());
                }
/*                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLTrust").error("caught an unknown exception, sticking with what we have");
                } */
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
}

void XMLTrust::unlock()
{
    m_lock->unlock();
}

Iterator<XSECCryptoX509*> XMLTrust::getCertificates(const XMLCh* subject) const
{
    // Find the first matching entity binding.
    for (XMLTrustImpl::BindingMap::const_iterator i=m_impl->m_bindings.begin(); i!=m_impl->m_bindings.end(); i++)
    {
        if (i->second->m_type!=XMLTrustImpl::KeyAuthority::entity)
            continue;
            
        if (i->first.first==NULL)   // catch-all entry
        {
            return i->second->m_certs;
        }
        else if (i->first.second)   // regexp
        {
            try
            {
                RegularExpression re(i->first.first);
                if (re.matches(subject))
                    return i->second->m_certs;
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                NDC ndc("getCertificates");
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLTrust");
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << CategoryStream::ENDLINE;
            }
        }
        else if (!XMLString::compareString(subject,i->first.first))     // exact match
        {
            return i->second->m_certs;
        }
    }
    return EMPTY(XSECCryptoX509*);
}

bool XMLTrust::attach(const ISite* site, SSL_CTX* ctx) const
{
    NDC ndc("attach");

    // Use the matching bindings.
    for (XMLTrustImpl::BindingMap::const_iterator i=m_impl->m_bindings.begin(); i!=m_impl->m_bindings.end(); i++)
    {
        if (i->second->m_type!=XMLTrustImpl::KeyAuthority::authority)
            continue;

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
                if (re.matches(site->getName()))
                    match=true;
                else
                {
                    Iterator<const XMLCh*> groups=site->getGroups();
                    while (!match && groups.hasNext())
                        if (re.matches(groups.next()))
                            match=true;
                }
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLTrust");
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << CategoryStream::ENDLINE;
            }
        }
        else if (!XMLString::compareString(site->getName(),i->first.first))     // exact match
        {
            match=true;
        }
        else
        {
            Iterator<const XMLCh*> groups=site->getGroups();
            while (!match && groups.hasNext())
                if (!XMLString::compareString(i->first.first,groups.next()))
                    match=true;
        }

        // If we have a match, use the associated keyauth and load it into the context's store.
        if (match)
        {
            X509_STORE* store=i->second->getX509Store(false);
            if (store)
            {
                SSL_CTX_set_cert_store(ctx,store);
                SSL_CTX_set_verify_depth(ctx,i->second->m_depth);
            }
            return true;
        }
    }

    return false;
}

bool XMLTrust::validate(const ISite* site, Iterator<XSECCryptoX509*> certs) const
{
    vector<const XMLCh*> temp;
    while (certs.hasNext())
        temp.push_back(certs.next()->getDEREncodingSB().sbStrToXMLCh());
    return validate(site,temp);
}

bool XMLTrust::validate(const ISite* site, Iterator<const XMLCh*> certs) const
{
    NDC ndc("validate");

    STACK_OF(X509)* chain=sk_X509_new_null();
    while (certs.hasNext())
    {
        auto_ptr<char> temp(XMLString::transcode(certs.next()));
        X509* x=B64_to_X509(temp.get());
        if (!x)
        {
            sk_X509_pop_free(chain,X509_free);
            return false;
        }
        sk_X509_push(chain,x);
    }

    // Use the matching bindings.
    for (XMLTrustImpl::BindingMap::const_iterator i=m_impl->m_bindings.begin(); i!=m_impl->m_bindings.end(); i++)
    {
        if (i->second->m_type!=XMLTrustImpl::KeyAuthority::authority)
            continue;

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
                if (re.matches(site->getName()))
                    match=true;
                else
                {
                    Iterator<const XMLCh*> groups=site->getGroups();
                    while (!match && groups.hasNext())
                        if (re.matches(groups.next()))
                            match=true;
                }
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                Category& log=Category::getInstance(SHIB_LOGCAT".XMLTrust");
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << CategoryStream::ENDLINE;
            }
        }
        else if (!XMLString::compareString(site->getName(),i->first.first))     // exact match
        {
            match=true;
        }
        else
        {
            Iterator<const XMLCh*> groups=site->getGroups();
            while (!match && groups.hasNext())
                if (!XMLString::compareString(i->first.first,groups.next()))
                    match=true;
        }

        // If we have a match, use the associated keyauth and do a verify against the store.
        if (match)
        {
            X509_STORE* store=i->second->getX509Store();
            if (store)
            {
                X509_STORE_CTX* ctx=X509_STORE_CTX_new();
                if (!ctx)
                {
                    log_openssl();
                    return false;
                }

#if (OPENSSL_VERSION_NUMBER > 0x009070000L)
                if (X509_STORE_CTX_init(ctx,store,sk_X509_value(chain,0),chain)!=1)
                {
                    log_openssl();
                    sk_X509_pop_free(chain,X509_free);
                    return false;
                }
#else
                X509_STORE_CTX_init(ctx,store,sk_X509_value(chain,0),chain);
#endif
                if (i->second->m_depth)
                    X509_STORE_CTX_set_depth(ctx,i->second->m_depth);
                if (X509_verify_cert(ctx)==1)
                {
                    sk_X509_pop_free(chain,X509_free);
                    X509_STORE_CTX_free(ctx);
                    return true;
                }
                X509_STORE_CTX_free(ctx);
            }
        }
    }

    return false;
}
