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

/* CredResolvers.cpp - default implementations of the ICredResolver interface

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <log4cpp/Category.hh>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace log4cpp;
using namespace std;

// OpenSSL password callback...
int passwd_callback(char* buf, int len, int verify, void* passwd)
{
    if(!verify)
    {
        if(passwd && len > strlen(reinterpret_cast<char*>(passwd)))
        {
            strcpy(buf,reinterpret_cast<char*>(passwd));
            return strlen(buf);
        }
    }  
    return 0;
}

// File-based resolver

class FileResolver : public ICredResolver
{
public:
    FileResolver(const DOMElement* e);
    ~FileResolver() {}
    virtual void resolveKey(SSL_CTX* ctx) const;
    virtual void resolveCert(SSL_CTX* ctx) const;
    virtual void dump(FILE* f) const;
    
protected:
    enum format_t { DER=SSL_FILETYPE_ASN1, PEM=SSL_FILETYPE_PEM };
    format_t m_format;
    string m_path;
    string m_password;
};

// ds:KeyInfo resolver, currently limited to X.509 certs

class KeyInfoResolver : public ICredResolver
{
public:
    KeyInfoResolver(const DOMElement* e);
    ~KeyInfoResolver();
    virtual void resolveKey(SSL_CTX* ctx) const;
    virtual void resolveCert(SSL_CTX* ctx) const;
    virtual void dump(FILE* f) const;
    
private:
    vector<X509*> m_certs;
};


FileResolver::FileResolver(const DOMElement* e)
{
    static const XMLCh cPEM[] = { chLatin_P, chLatin_E, chLatin_M, chNull };
    
    const XMLCh* format=e->getAttributeNS(NULL,L(Format));
    if (!format || !*format || !XMLString::compareString(format,cPEM))
        m_format=PEM;
    else
        m_format=DER;
        
    const XMLCh* s=saml::XML::getFirstChildElement(e,XML::SHIB_NS,SHIB_L(Path))->getFirstChild()->getNodeValue();
    auto_ptr<char> path(XMLString::transcode(s));
    
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(path.get(), &stat_buf) != 0)
#else
    struct stat stat_buf;
    if (stat(path.get(), &stat_buf) != 0)
#endif
    {
        saml::NDC ndc("FileResolver");
        Category::getInstance(SHIB_LOGCAT".CredResolvers").error("credential file '%s' can't be opened", path.get());
        throw MetadataException("FileResolver() can't access credential file");
    }
    m_path=path.get();

    DOMElement* p=saml::XML::getFirstChildElement(e,XML::SHIB_NS,SHIB_L(Password));
    if (p)
    {
        s=p->getFirstChild()->getNodeValue();
        auto_ptr<char> pass(XMLString::transcode(s));
        m_password=pass.get();
    }
}

void FileResolver::resolveKey(SSL_CTX* ctx) const
{
    SSL_CTX_set_default_passwd_cb_userdata(ctx, const_cast<char*>(m_password.c_str()));
    SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);

    int ret;
    switch (m_format)
    {
        case PEM:
            ret=SSL_CTX_use_PrivateKey_file(ctx, m_path.c_str(), m_format);
            break;
            
        default:
            ret=SSL_CTX_use_RSAPrivateKey_file(ctx, m_path.c_str(), m_format);
    }
    
    if (ret!=1)
    {
        log_openssl();
        throw MetadataException("FileResolver::resolveKey() unable to set private key from file");
    }
}

void FileResolver::resolveCert(SSL_CTX* ctx) const
{
    SSL_CTX_set_default_passwd_cb_userdata(ctx, const_cast<char*>(m_password.c_str()));
    SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);

    int ret;
    switch (m_format)
    {
        case PEM:
            ret=SSL_CTX_use_certificate_chain_file(ctx, m_path.c_str());
            break;
            
        default:
            ret=SSL_CTX_use_certificate_file(ctx, m_path.c_str(), m_format);
    }
    
    if (ret!=1)
    {
        log_openssl();
        throw MetadataException("FileResolver::resolveCert() unable to set certificate from file");
    }
}

void FileResolver::dump(FILE* f) const
{
    RSA* rsa=NULL;
    X509* x=NULL;
    BIO* in=BIO_new(BIO_s_file_internal());
    if (in && BIO_read_filename(in,m_path.c_str())>0)
    {
        if (m_format==DER)
        {
            rsa=d2i_RSAPrivateKey_bio(in,NULL);
            if (!rsa)
                x=d2i_X509_bio(in,NULL);
        }
        else
        {
            rsa=PEM_read_bio_RSAPrivateKey(in,NULL,passwd_callback,const_cast<char*>(m_password.c_str()));
            if (!rsa)
                x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(m_password.c_str()));
        }
        if (rsa)
        {
            RSA_print_fp(f,rsa,0);
            RSA_free(rsa);
            BIO_free(in);
            return;
        }
        else if (x)
        {
            X509_print_ex_fp(f,x,XN_FLAG_SEP_MULTILINE,0);
            X509_free(x);
            if (m_format==PEM)
            {
                while (x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(m_password.c_str())))
                {
                    fprintf(f,"\n-------\n");
                    X509_print_ex_fp(f,x,XN_FLAG_SEP_MULTILINE,0);
                    X509_free(x);
                }
            }
            BIO_free(in);
            return;
        }
        if (in)
            BIO_free(in);
    }
    fprintf(f,"ERROR while loading credential for printing\n");
}

KeyInfoResolver::KeyInfoResolver(const DOMElement* e)
{
    saml::NDC ndc("KeyInfoResolver");
    Category& log=Category::getInstance(SHIB_LOGCAT".CredResolvers");
 
    // Is there an X509Data?
    DOMNodeList* x509data=e->getElementsByTagNameNS(saml::XML::XMLSIG_NS,L(X509Data));
    if (x509data && x509data->getLength())
    {
        if (x509data->getLength()>1)
            log.warn("Found multiple certificate chains, using the first");

        // Grab up any X509Certificate elements.
        DOMNodeList* certlist=static_cast<DOMElement*>(x509data->item(0))->getElementsByTagNameNS(
            saml::XML::XMLSIG_NS,L(X509Certificate)
            );
        for (int i=0; certlist && i<certlist->getLength(); i++)
        {
            auto_ptr<char> blob(XMLString::transcode(certlist->item(i)->getFirstChild()->getNodeValue()));
            X509* x=B64_to_X509(blob.get());
            if (x)
                m_certs.push_back(x);
            else
                log.warn("Unable to parse ds:X509Certificate element, can't include in chain");
        }
    }
    
    if (m_certs.size()==0)
    {
        log.error("found no inline certificates in a ds:X509Data element");
        throw MetadataException("KeyInfoResolver() can't find inline certificates to use");
    }
}

KeyInfoResolver::~KeyInfoResolver()
{
    for (vector<X509*>::iterator i=m_certs.begin(); i!=m_certs.end(); i++)
        X509_free(*i);
}

void KeyInfoResolver::resolveKey(SSL_CTX* ctx) const
{
    throw MetadataException("KeyInfoResolver::resolveKey() cannot set private key based on ds:KeyInfo");
}

void KeyInfoResolver::resolveCert(SSL_CTX* ctx) const
{
    for (vector<X509*>::const_reverse_iterator i=m_certs.rbegin(); i!=m_certs.rend(); i++)
    {
        if (i==m_certs.rbegin())
        {
            if (SSL_CTX_use_certificate(ctx, *i) != 1)
            {
                log_openssl();
                throw MetadataException("KeyInfoResolver::resolveCert() unable to set entity certificate from ds:KeyInfo");
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
                throw MetadataException("KeyInfoResolver::resolveCert() unable to add CA certificate from ds:KeyInfo");
            }
        }
    }
}

void KeyInfoResolver::dump(FILE* f) const
{
    for (vector<X509*>::const_reverse_iterator i=m_certs.rbegin(); i!=m_certs.rend(); i++)
    {
        if (i!=m_certs.rbegin())
            fprintf(f,"\n-------\n");
        X509_print_ex_fp(f,*i,XN_FLAG_SEP_MULTILINE,0);
    }
}

extern "C" ICredResolver* FileCredResolverFactory(const DOMElement* e)
{
    return new FileResolver(e);
}

extern "C" ICredResolver* KeyInfoResolverFactory(const DOMElement* e)
{
    return new KeyInfoResolver(e);
}

