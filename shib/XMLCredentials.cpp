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

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

class shibboleth::XMLCredentialsImpl
{
public:
    XMLCredentialsImpl(const char* pathname);
    ~XMLCredentialsImpl();
    
    struct KeyUse
    {
        KeyUse() {}
        ~KeyUse();

        bool attach(SSL_CTX* ctx);
        
        enum format_t { X509DATA, DER, PEM };
        
        format_t m_certtype, m_keytype;
        vector<X509*> m_certs;
        string m_certfile, m_keyfile;
        vector<pair<const XMLCh*,bool> > m_relying;
    };
    
    vector<KeyUse*> m_keyuses;
    typedef multimap<pair<const XMLCh*,bool>,KeyUse*> BindingMap;
    BindingMap m_bindings;
    
    DOMDocument* m_doc;
};

XMLCredentialsImpl::KeyUse::~KeyUse()
{
    for (vector<X509*>::iterator i=m_certs.begin(); i!=m_certs.end(); i++)
        X509_free(*i);
}

bool XMLCredentialsImpl::KeyUse::attach(SSL_CTX* ctx)
{
    switch (m_certtype)
    {
        case PEM:
            if (SSL_CTX_use_certificate_chain_file(ctx, m_certfile.c_str()) != 1)
            {
                log_openssl();
                throw TrustException("XMLCredentials::KeyUse::attach() unable to set PEM certificate chain");
            }
            break;
            
        case DER:
            if (SSL_CTX_use_certificate_file(ctx, m_certfile.c_str(), SSL_FILETYPE_ASN1) != 1)
            {
                log_openssl();
                throw TrustException("XMLCredentials::KeyUse::attach() unable to set DER certificate");
            }
            break;
            
        case X509DATA:
            for (vector<X509*>::reverse_iterator i=m_certs.rbegin(); i!=m_certs.rend(); i++)
            {
                if (i==m_certs.rbegin())
                {
                    if (SSL_CTX_use_certificate(ctx, *i) != 1)
                    {
                        log_openssl();
                        throw TrustException("XMLCredentials::KeyUse::attach() unable to set certificate from X509Data");
                    }
                }
                else
                {
                    // When we add extra certs, they don't get ref counted, so we need to duplicate them.
                    X509* dup = X509_dup(*i);
                    if (SSL_CTX_add_extra_chain_cert(ctx, dup) != 0)
                    {
                        X509_free(dup);
                        log_openssl();
                        throw TrustException("XMLCredentials::KeyUse::attach() unable to add CA certificate from X509Data");
                    }
                }
            }
    }
    
    switch (m_keytype)
    {
        case PEM:
            if (SSL_CTX_use_PrivateKey_file(ctx, m_keyfile.c_str(), SSL_FILETYPE_PEM) != 1)
            {
                log_openssl();
                throw TrustException("XMLCredentials::KeyUse::attach() unable to set PEM private key");
            }
            break;
            
        case DER:
            if (SSL_CTX_use_PrivateKey_file(ctx, m_keyfile.c_str(), SSL_FILETYPE_ASN1) != 1)
            {
                log_openssl();
                throw TrustException("XMLCredentials::KeyUse::attach() unable to set PEM private key");
            }
    }
    
    if (!SSL_CTX_check_private_key(ctx))
    {
        log_openssl();
        throw TrustException("XMLCredentials::KeyUse::attach found mismatch between the private key and certificate");
    }
    
    return true;
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

        // Loop over the KeyUse elements.
        DOMNodeList* nlist=e->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(KeyUse));
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            auto_ptr<KeyUse> ku(new KeyUse());

            bool key=false,cert=false;
            
            // Grab all the RetrievalMethods for external material.
            DOMNodeList* extlist=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(
                saml::XML::XMLSIG_NS,SHIB_L(RetrievalMethod)
                );
            for (int j=0; (!key || !cert) && extlist && j<extlist->getLength(); j++)
            {
                DOMElement* method=static_cast<DOMElement*>(extlist->item(j));
                const XMLCh* rmtype=method->getAttributeNS(NULL,SHIB_L(Type));
                auto_ptr<char> uri(XMLString::transcode(method->getAttributeNS(NULL,SHIB_L(URI))));
                
                // Is the URI locally accessible as a relative URL?
#ifdef WIN32
                struct _stat stat_buf;
                if (_stat(uri.get(), &stat_buf) != 0)
#else
                struct stat stat_buf;
                if (stat(uri.get(), &stat_buf) != 0)
#endif
                {
                    log.warn("Credential referenced by ds:RetrievalMethod can't be opened");
                    continue;
                }
                
                if (!XMLString::compareString(rmtype,shibboleth::Constants::XMLSIG_RETMETHOD_RAWX509))
                {
                    if (cert)
                        log.warn("Found another certificate credential (DER), replacing the original with it");
                    ku->m_certfile=uri.get();
                    ku->m_certtype=KeyUse::DER;
                    cert=true;
                }
                else if (!XMLString::compareString(rmtype,shibboleth::Constants::SHIB_RETMETHOD_PEMX509))
                {
                    if (cert)
                        log.warn("Found another certificate credential (PEM), replacing the original with it");
                    ku->m_certfile=uri.get();
                    ku->m_certtype=KeyUse::PEM;
                    cert=true;
                }
                else if (!XMLString::compareString(rmtype,shibboleth::Constants::SHIB_RETMETHOD_PEMRSA))
                {
                    if (key)
                        log.warn("Found another private key credential (PEM/RSA), replacing the original with it");
                    ku->m_keyfile=uri.get();
                    ku->m_keytype=KeyUse::PEM;
                    key=true;
                }
                else if (!XMLString::compareString(rmtype,shibboleth::Constants::SHIB_RETMETHOD_DERRSA))
                {
                    if (key)
                        log.warn("Found another private key credential (DER/RSA), replacing the original with it");
                    ku->m_keyfile=uri.get();
                    ku->m_keytype=KeyUse::DER;
                    key=true;
                }
            }
            
            if (!cert)
            {
                // Is there an X509Data?
                DOMNodeList* x509data=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(
                    saml::XML::XMLSIG_NS,L(X509Data)
                    );
                if (x509data && x509data->getLength())
                {
                    if (x509data->getLength()>1)
                        log.warn("Found multiple certificate chains, using the first");
            
                    // Grab up any X509Certificate elements, and flatten into one list.
                    DOMNodeList* certlist=static_cast<DOMElement*>(x509data->item(0))->getElementsByTagNameNS(
                        saml::XML::XMLSIG_NS,L(X509Certificate)
                        );
                    for (int k=0; certlist && k<certlist->getLength(); k++)
                    {
                        auto_ptr<char> blob(XMLString::transcode(certlist->item(k)->getFirstChild()->getNodeValue()));
                        X509* x=B64_to_X509(blob.get());
                        if (x)
                            ku->m_certs.push_back(x);
                        else
                            log.warn("Unable to parse ds:X509Certificate element, can't include in chain");
                    }
                    
                    if (ku->m_certs.size()>0)
                    {
                        ku->m_certtype=KeyUse::X509DATA;
                        cert=true;
                    }
                    else
                        log.warn("Found no inline certificates in the ds:X509Data element, ignoring it");
                }
            }
            
            if (!cert)
            {
                log.error("Found no acceptable certificate in shib:KeyUse element, ignoring it");
                continue;
            }
            
            if (!key)
            {
                log.error("Found no acceptable private/secret key in shib:KeyUse element, ignoring it");
                continue;
            }
            
            // Pull in the relying parties.
            DOMNodeList* parties=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(RelyingParty));
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
            DOMNodeList* subs=static_cast<DOMElement*>(nlist->item(i))->getElementsByTagNameNS(XML::SHIB_NS,L(Subject));
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
                    m_bindings.insert(BindingMap::value_type(pair<const XMLCh*,bool>(name,flag),ku.get()));
                }
                l++;
            }
            // If no Subjects, this is a catch-all binding.
            if (l==0)
                m_bindings.insert(BindingMap::value_type(pair<const XMLCh*,bool>(NULL,false),ku.get()));

            m_keyuses.push_back(ku.release());
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing creds configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
            delete (*i);
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing creds configuration");
        for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
            delete (*i);
        if (m_doc)
            m_doc->release();
        throw;
    }
}

XMLCredentialsImpl::~XMLCredentialsImpl()
{
    for (vector<KeyUse*>::iterator i=m_keyuses.begin(); i!=m_keyuses.end(); i++)
        delete (*i);
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

XMLCredentials::~XMLCredentials()
{
    delete m_lock;
    delete m_impl;
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

void XMLCredentials::unlock()
{
    m_lock->unlock();
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
            // We have the credentials to use...
            return i->second->attach(ctx);
        }
    }

    return false;
}
