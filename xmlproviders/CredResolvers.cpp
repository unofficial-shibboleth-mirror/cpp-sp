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

/* CredResolvers.cpp - implementations of the ICredResolver interface

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/pkcs12.h>
#include <log4cpp/Category.hh>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>

using namespace saml;
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
    ~FileResolver();
    virtual void attach(void* ctx) const;
    virtual XSECCryptoKey* getKey() const;
    virtual saml::Iterator<XSECCryptoX509*> getCertificates() const { return m_xseccerts; }
    virtual void dump(FILE* f) const;
    
protected:
    enum format_t { DER=SSL_FILETYPE_ASN1, PEM=SSL_FILETYPE_PEM, _PKCS12 };
    format_t m_keyformat;
    string m_keypath,m_keypass;
    vector<X509*> m_certs;
    vector<XSECCryptoX509*> m_xseccerts;
};

IPlugIn* FileCredResolverFactory(const DOMElement* e)
{
    return new FileResolver(e);
}

FileResolver::FileResolver(const DOMElement* e)
{
    saml::NDC ndc("FileResolver");
    static const XMLCh cPEM[] = { chLatin_P, chLatin_E, chLatin_M, chNull };
    static const XMLCh cDER[] = { chLatin_D, chLatin_E, chLatin_R, chNull };
    
    // Move to Key
    e=saml::XML::getFirstChildElement(e);
    const XMLCh* format=e->getAttributeNS(NULL,SHIB_L(format));
    if (!format || !*format || !XMLString::compareString(format,cPEM))
        m_keyformat=PEM;
    else if (!XMLString::compareString(format,cDER))
        m_keyformat=DER;
    else
        m_keyformat=_PKCS12;
        
    const XMLCh* password=e->getAttributeNS(NULL,SHIB_L(password));
    if (password) {
        auto_ptr_char kp(password);
        m_keypass=kp.get();
    }
    
    const XMLCh* s=saml::XML::getFirstChildElement(e,::XML::CREDS_NS,SHIB_L(Path))->getFirstChild()->getNodeValue();
    auto_ptr_char kpath(s);
    
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(kpath.get(), &stat_buf) != 0)
#else
    struct stat stat_buf;
    if (stat(kpath.get(), &stat_buf) != 0)
#endif
    {
        Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("key file '%s' can't be opened", kpath.get());
        throw CredentialException("FileResolver() can't access key file");
    }
    m_keypath=kpath.get();
    
    // Check for Certificate
    e=saml::XML::getNextSiblingElement(e);
    password=e->getAttributeNS(NULL,SHIB_L(password));
    auto_ptr_char certpass(password);
    s=saml::XML::getFirstChildElement(e,::XML::CREDS_NS,SHIB_L(Path))->getFirstChild()->getNodeValue();
    auto_ptr_char certpath(s);

    try {
        X509* x=NULL;
        BIO* in=BIO_new(BIO_s_file_internal());
        if (in && BIO_read_filename(in,certpath.get())>0) {
            format=e->getAttributeNS(NULL,SHIB_L(format));
            if (!format || !*format || !XMLString::compareString(format,cPEM)) {
                while (x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(certpass.get()))) {
                    m_certs.push_back(x);
                }
            }
            else if (!XMLString::compareString(format,cDER)) {
                x=d2i_X509_bio(in,NULL);
                if (x)
                    m_certs.push_back(x);
                else {
                    log_openssl();
                    BIO_free(in);
                    throw CredentialException("FileResolver() unable to load DER certificate from file");
                }
            }
            else {
                PKCS12* p12=d2i_PKCS12_bio(in,NULL);
                if (p12) {
                    PKCS12_parse(p12, certpass.get(), NULL, &x, NULL);
                    PKCS12_free(p12);
                }
                if (x) {
                    m_certs.push_back(x);
                    x=NULL;
                }
                else {
                    log_openssl();
                    BIO_free(in);
                    throw CredentialException("FileResolver() unable to load PKCS12 certificate from file");
                }
            }
        }
        if (in) {
            BIO_free(in);
            in=NULL;
        }

        // Load any extra CA files.
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::CREDS_NS,SHIB_L(CAPath));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            s=static_cast<DOMElement*>(nlist->item(i))->getFirstChild()->getNodeValue();
            auto_ptr_char capath(s);
            x=NULL;
            in=BIO_new(BIO_s_file_internal());
            if (in && BIO_read_filename(in,capath.get())>0) {
                if (!format || !*format || !XMLString::compareString(format,cPEM)) {
                    while (x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(certpass.get()))) {
                        m_certs.push_back(x);
                    }
                }
                else if (!XMLString::compareString(format,cDER)) {
                    x=d2i_X509_bio(in,NULL);
                    if (x)
                        m_certs.push_back(x);
                    else {
                        log_openssl();
                        BIO_free(in);
                        throw CredentialException("FileResolver() unable to load DER CA certificate from file");
                    }
                }
                else {
                    PKCS12* p12 = d2i_PKCS12_bio(in, NULL);
                    if (p12) {
                        PKCS12_parse(p12, certpass.get(), NULL, &x, NULL);
                        PKCS12_free(p12);
                    }
                    if (x) {
                        m_certs.push_back(x);
                        x=NULL;
                    }
                    else {
                        log_openssl();
                        BIO_free(in);
                        throw CredentialException("FileResolver() unable to load PKCS12 CA certificate from file");
                    }
                }
                BIO_free(in);
            }
            else {
                if (in)
                    BIO_free(in);
                log_openssl();
                Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("CA file '%s' can't be opened", capath.get());
                throw CredentialException("FileResolver() can't open CA file");
            }
        }
    }
    catch (...) {
        for (vector<X509*>::iterator j=m_certs.begin(); j!=m_certs.end(); j++)
            X509_free(*j);
        throw;
    }

    // Reflect certs over to XSEC form.
    for (vector<X509*>::iterator j=m_certs.begin(); j!=m_certs.end(); j++)
        m_xseccerts.push_back(new OpenSSLCryptoX509(*j));
}

FileResolver::~FileResolver()
{
    for (vector<X509*>::iterator i=m_certs.begin(); i!=m_certs.end(); i++)
        X509_free(*i);
    for (vector<XSECCryptoX509*>::iterator j=m_xseccerts.begin(); j!=m_xseccerts.end(); j++)
        delete (*j);
}

void FileResolver::attach(void* ctx) const
{
    saml::NDC ndc("FileResolver");
    
    SSL_CTX* ssl_ctx=reinterpret_cast<SSL_CTX*>(ctx);

    // Attach key.
    SSL_CTX_set_default_passwd_cb(ssl_ctx, passwd_callback);
    SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, const_cast<char*>(m_keypass.c_str()));

    int ret=0;
    switch (m_keyformat)
    {
        case PEM:
            ret=SSL_CTX_use_PrivateKey_file(ssl_ctx, m_keypath.c_str(), m_keyformat);
            break;
            
        case DER:
            ret=SSL_CTX_use_RSAPrivateKey_file(ssl_ctx, m_keypath.c_str(), m_keyformat);
            break;
            
        default: {
            BIO* in=BIO_new(BIO_s_file_internal());
            if (in && BIO_read_filename(in,m_keypath.c_str())>0) {
                EVP_PKEY* pkey=NULL;
                PKCS12* p12 = d2i_PKCS12_bio(in, NULL);
                if (p12) {
                    PKCS12_parse(p12, const_cast<char*>(m_keypass.c_str()), &pkey, NULL, NULL);
                    PKCS12_free(p12);
                    if (pkey) {
                        ret=SSL_CTX_use_PrivateKey(ssl_ctx, pkey);
                        EVP_PKEY_free(pkey);
                    }
                }
            }
            if (in)
                BIO_free(in);
        }
    }
    
    if (ret!=1) {
        log_openssl();
        throw CredentialException("FileResolver::attach() unable to set private key");
    }

    // Attach certs.
    for (vector<X509*>::const_iterator i=m_certs.begin(); i!=m_certs.end(); i++) {
        if (i==m_certs.begin()) {
            if (SSL_CTX_use_certificate(ssl_ctx, *i) != 1) {
                log_openssl();
                throw CredentialException("FileResolver::attach() unable to set EE certificate in context");
            }
        }
        else {
            // When we add certs, they don't get ref counted, so we need to duplicate them.
            X509* dup = X509_dup(*i);
            if (SSL_CTX_add_extra_chain_cert(ssl_ctx, dup) != 1) {
                X509_free(dup);
                log_openssl();
                throw CredentialException("FileResolver::attach() unable to add CA certificate to context");
            }
        }
    }
}

XSECCryptoKey* FileResolver::getKey() const
{
    // Get a EVP_PKEY.
    EVP_PKEY* pkey=NULL;
    BIO* in=BIO_new(BIO_s_file_internal());
    if (in && BIO_read_filename(in,m_keypath.c_str())>0) {
        switch (m_keyformat)
        {
            case PEM:
                pkey=PEM_read_bio_PrivateKey(in, NULL, passwd_callback, const_cast<char*>(m_keypass.c_str()));
                break;
            
            case DER:
                pkey=d2i_PrivateKey_bio(in, NULL);
                break;
                
            default: {
                PKCS12* p12 = d2i_PKCS12_bio(in, NULL);
                if (p12) {
                    PKCS12_parse(p12, const_cast<char*>(m_keypass.c_str()), &pkey, NULL, NULL);
                    PKCS12_free(p12);
                }
            }
        }
    }
    if (in)
        BIO_free(in);
    
    // Now map it to an XSEC wrapper.
    if (pkey) {
        XSECCryptoKey* ret=NULL;
        switch (pkey->type)
        {
            case EVP_PKEY_RSA:
                ret=new OpenSSLCryptoKeyRSA(pkey);
                break;
                
            case EVP_PKEY_DSA:
                ret=new OpenSSLCryptoKeyDSA(pkey);
                break;
            
            default:
                saml::NDC ndc("FileResolver");
                Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("unsupported private key type");
        }
        EVP_PKEY_free(pkey);
        if (ret)
            return ret;
    }

    saml::NDC ndc("FileResolver");
    log_openssl();
    Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("FileResolver::getKey() unable to load private key from file");
    return NULL;
}

void FileResolver::dump(FILE* f) const
{
    // Dump private key.
    RSA* rsa=NULL;
    BIO* in=BIO_new(BIO_s_file_internal());
    if (in && BIO_read_filename(in,m_keypath.c_str())>0) {
        if (m_keyformat==DER)
            rsa=d2i_RSAPrivateKey_bio(in,NULL);
        else if (m_keyformat==PEM)
            rsa=PEM_read_bio_RSAPrivateKey(in,NULL,passwd_callback,const_cast<char*>(m_keypass.c_str()));
        else {
            EVP_PKEY* pkey=NULL;
            PKCS12* p12 = d2i_PKCS12_bio(in, NULL);
            if (p12) {
                PKCS12_parse(p12, const_cast<char*>(m_keypass.c_str()), &pkey, NULL, NULL);
                PKCS12_free(p12);
                if (pkey) {
                    fprintf(f,"----- PRIVATE KEY -----\n");
                    if (pkey->type==EVP_PK_RSA)
                        RSA_print_fp(f,pkey->pkey.rsa,0);
                    else if (pkey->type==EVP_PK_DSA)
                        DSA_print_fp(f,pkey->pkey.dsa,0);
                    EVP_PKEY_free(pkey);
                }
            }
        }
        if (rsa) {
            fprintf(f,"----- PRIVATE KEY -----\n");
            RSA_print_fp(f,rsa,0);
            RSA_free(rsa);
        }
    }
    if (in) {
        BIO_free(in);
        in=NULL;
    }
    
    // Dump certificates.
    for (vector<X509*>::const_iterator i=m_certs.begin(); i!=m_certs.end(); i++) {
        fprintf(f,"----- CERTIFICATE(S) -----\n");
#if (OPENSSL_VERSION_NUMBER > 0x009070000L)
        X509_print_ex_fp(f,*i,XN_FLAG_SEP_MULTILINE,0);
#else
        X509_print_fp(f,*i);
#endif
    }
}
