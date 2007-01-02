/*
 *  Copyright 2001-2005 Internet2
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

/* CredResolvers.cpp - implementations of the ICredResolver interface

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <algorithm>
#include <openssl/pkcs12.h>
#include <log4cpp/Category.hh>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xmltooling/util/NDC.h>

using namespace shibboleth;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

// OpenSSL password callback...
static int passwd_callback(char* buf, int len, int verify, void* passwd)
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
    
private:
    enum format_t { PEM=SSL_FILETYPE_PEM, DER=SSL_FILETYPE_ASN1, _PKCS12, UNKNOWN };

    format_t getEncodingFormat(BIO* in) const;
    string formatToString(format_t format) const;
    format_t xmlFormatToFormat(const XMLCh* format_xml) const;

    format_t m_keyformat;
    string m_keypath,m_keypass;
    vector<X509*> m_certs;
    vector<XSECCryptoX509*> m_xseccerts;
};

saml::IPlugIn* FileCredResolverFactory(const DOMElement* e)
{
    return new FileResolver(e);
}

FileResolver::FileResolver(const DOMElement* e)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("FileResolver");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers");

    format_t format;
    BIO* in = NULL;
    
    // Move to Key
    const DOMElement* root=e;
    e=saml::XML::getFirstChildElement(root,::XML::CREDS_NS,SHIB_L(Key));
    if (e) {

        // Get raw format attrib value, but defer processing til later since may need to 
        // determine format dynamically, and we need the Path for that.
        const XMLCh* format_xml=e->getAttributeNS(NULL,SHIB_L(format));
            
        const XMLCh* password=e->getAttributeNS(NULL,SHIB_L(password));
        if (password) {
            auto_ptr_char kp(password);
            m_keypass=kp.get();
        }
        
        e=saml::XML::getFirstChildElement(e,::XML::CREDS_NS,SHIB_L(Path));
        if (e && e->hasChildNodes()) {
            const XMLCh* s=e->getFirstChild()->getNodeValue();
            auto_ptr_char kpath(s);
#ifdef WIN32
            struct _stat stat_buf;
            if (_stat(kpath.get(), &stat_buf) != 0)
#else
            struct stat stat_buf;
            if (stat(kpath.get(), &stat_buf) != 0)
#endif
            {
                log.error("key file (%s) can't be opened", kpath.get());
                throw IOException("FileResolver can't access key file ($1)",params(1,kpath.get()));
            }
            m_keypath=kpath.get();
        }
        else {
            log.error("Path element missing inside Key element");
            throw IOException("FileResolver can't access key file, no Path element specified.");
        }

        // Determine the key encoding format dynamically, if not explicitly specified
        try {
            if (format_xml && *format_xml) {
                format = xmlFormatToFormat(format_xml);
                if (format != UNKNOWN) {
                    m_keyformat = format;
                }
                else {
                    auto_ptr_char unknown(format_xml);
                    log.error("Configuration specifies unknown key encoding format (%s)", unknown.get());
                    throw IOException("FileResolver configuration contains unknown key encoding format ($1)",params(1,unknown.get()));
                }
            }
            else {
                in=BIO_new(BIO_s_file_internal());
                if (in && BIO_read_filename(in,m_keypath.c_str())>0) {
                    m_keyformat = getEncodingFormat(in);
                    log.debug("Key encoding format for (%s) dynamically resolved as (%s)", m_keypath.c_str(), formatToString(m_keyformat).c_str());
                }
                else {
                    log.error("Key file (%s) can't be read to determine encoding format", m_keypath.c_str());
                    throw IOException("FileResolver can't read key file ($1) to determine encoding format",params(1,m_keypath.c_str()));
                }
                if (in)
                    BIO_free(in);
                in = NULL;    
            }
        }
        catch (...) {
            log.error("Error determining key encoding format");
            throw;
        }

    }
        
    // Check for Certificate
    e=saml::XML::getFirstChildElement(root,::XML::CREDS_NS,SHIB_L(Certificate));
    if (!e)
        return;
    auto_ptr_char certpass(e->getAttributeNS(NULL,SHIB_L(password)));
    
    DOMElement* ep=saml::XML::getFirstChildElement(e,::XML::CREDS_NS,SHIB_L(Path));
    if (!ep || !ep->hasChildNodes()) {
        log.error("Path element missing inside Certificate element");
        throw IOException("FileResolver can't access certificate file, missing Path element.");
    }
    
    auto_ptr_char certpath(ep->getFirstChild()->getNodeValue());
    const XMLCh* format_xml=e->getAttributeNS(NULL,SHIB_L(format));
    if (format_xml && *format_xml) {
        format = xmlFormatToFormat(format_xml);
        if (format == UNKNOWN) {
            auto_ptr_char unknown(format_xml);
            log.error("Configuration specifies unknown certificate encoding format (%s)", unknown.get());
            throw IOException("FileResolver configuration contains unknown certificate encoding format ($1)",params(1,unknown.get()));
        }
    }
    
    try {
        X509* x=NULL;
        PKCS12* p12=NULL;
        in=BIO_new(BIO_s_file_internal());
        if (in && BIO_read_filename(in,certpath.get())>0) {
            if (!format_xml || !*format_xml) {
                // Determine the cert encoding format dynamically, if not explicitly specified
                format = getEncodingFormat(in);
                log.debug("Cert encoding format for (%s) dynamically resolved as (%s)", certpath.get(), formatToString(format).c_str());
            }

            switch(format) {
                case PEM:
                    while (x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(certpass.get()))) {
                           m_certs.push_back(x);
                    }
                    break;
                                
                case DER:
                    x=d2i_X509_bio(in,NULL);
                    if (x)
                        m_certs.push_back(x);
                    else {
                        log_openssl();
                        BIO_free(in);
                        throw IOException("FileResolver unable to load DER certificate from file ($1)",params(1,certpath.get()));
                    }
                    break;

                case _PKCS12:
                    p12=d2i_PKCS12_bio(in,NULL);
                    if (p12) {
                        PKCS12_parse(p12, certpass.get(), NULL, &x, NULL);
                        PKCS12_free(p12);
                    }
                    if (x) {
                        m_certs.push_back(x);
                        x=NULL;
                    } else {
                        log_openssl();
                        BIO_free(in);
                        throw IOException("FileResolver unable to load PKCS12 certificate from file ($1)",params(1,certpath.get()));
                    }
                    break;
            } // end switch

        } else {
            log_openssl();
            if (in) {
                BIO_free(in);
                in=NULL;
            }
            throw IOException("FileResolver unable to load certificate(s) from file ($1)",params(1,certpath.get()));
        }
        if (in) {
            BIO_free(in);
            in=NULL;
        }

        if (m_certs.empty()) {
            throw IOException("FileResolver unable to load any certificate(s)");
        }

        // Load any extra CA files.
        DOMNodeList* nlist=e->getElementsByTagNameNS(::XML::CREDS_NS,SHIB_L(CAPath));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
            if (!nlist->item(i)->hasChildNodes())
                continue;
            auto_ptr_char capath(static_cast<DOMElement*>(nlist->item(i))->getFirstChild()->getNodeValue());
            x=NULL;
            p12=NULL;
            in=BIO_new(BIO_s_file_internal());
            if (in && BIO_read_filename(in,capath.get())>0) {
                if (!format_xml || !*format_xml) {
                    // Determine the cert encoding format dynamically, if not explicitly specified
                    format = getEncodingFormat(in);
                    log.debug("Cert encoding format for (%s) dynamically resolved as (%s)", certpath.get(), formatToString(format).c_str());
                }

                switch (format)
                {
                    case PEM:
                        while (x=PEM_read_bio_X509(in,NULL,passwd_callback,const_cast<char*>(certpass.get()))) {
                            m_certs.push_back(x);
                        }
                        break;

                    case DER:
                        x=d2i_X509_bio(in,NULL);
                        if (x)
                            m_certs.push_back(x);
                        else {
                            log_openssl();
                            BIO_free(in);
                            throw IOException("FileResolver unable to load DER CA certificate from file ($1)",params(1,capath.get()));
                        }
                        break;

                    case _PKCS12:
                        p12 = d2i_PKCS12_bio(in, NULL);
                        if (p12) {
                            PKCS12_parse(p12, certpass.get(), NULL, &x, NULL);
                            PKCS12_free(p12);
                        }
                        if (x) {
                            m_certs.push_back(x);
                            x=NULL;
                        } else {
                            log_openssl();
                            BIO_free(in);
                            throw IOException("FileResolver unable to load PKCS12 CA certificate from file ($1)",params(1,capath.get()));
                        }
                        break;
                } //end switch

                BIO_free(in);

            } else {
                if (in)
                    BIO_free(in);
                log_openssl();
                log.error("CA file (%s) can't be opened", capath.get());
                throw IOException("FileResolver can't open CA file ($1)",params(1,capath.get()));
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
    for_each(m_certs.begin(),m_certs.end(),X509_free);
    for_each(m_xseccerts.begin(),m_xseccerts.end(),xmltooling::cleanup<XSECCryptoX509>());
}

void FileResolver::attach(void* ctx) const
{
#ifdef _DEBUG
    saml::NDC ndc("attach");
#endif
    
    SSL_CTX* ssl_ctx=reinterpret_cast<SSL_CTX*>(ctx);

    // Attach key.
    SSL_CTX_set_default_passwd_cb(ssl_ctx, passwd_callback);
    SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, const_cast<char*>(m_keypass.c_str()));

    int ret=0;
    switch (m_keyformat) {
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
        throw IOException("Unable to attach private key to SSL context");
    }

    // Attach certs.
    for (vector<X509*>::const_iterator i=m_certs.begin(); i!=m_certs.end(); i++) {
        if (i==m_certs.begin()) {
            if (SSL_CTX_use_certificate(ssl_ctx, *i) != 1) {
                log_openssl();
                throw IOException("Unable to attach SP client certificate to SSL context");
            }
        }
        else {
            // When we add certs, they don't get ref counted, so we need to duplicate them.
            X509* dup = X509_dup(*i);
            if (SSL_CTX_add_extra_chain_cert(ssl_ctx, dup) != 1) {
                X509_free(dup);
                log_openssl();
                throw IOException("Unable to attach CA certificate to SSL context");
            }
        }
    }
}

XSECCryptoKey* FileResolver::getKey() const
{
#ifdef _DEBUG
    saml::NDC ndc("getKey");
#endif

    // Get a EVP_PKEY.
    EVP_PKEY* pkey=NULL;
    BIO* in=BIO_new(BIO_s_file_internal());
    if (in && BIO_read_filename(in,m_keypath.c_str())>0) {
        switch (m_keyformat) {
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
        switch (pkey->type) {
            case EVP_PKEY_RSA:
                ret=new OpenSSLCryptoKeyRSA(pkey);
                break;
                
            case EVP_PKEY_DSA:
                ret=new OpenSSLCryptoKeyDSA(pkey);
                break;
            
            default:
                Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("unsupported private key type");
        }
        EVP_PKEY_free(pkey);
        if (ret)
            return ret;
    }

    log_openssl();
    Category::getInstance(XMLPROVIDERS_LOGCAT".CredResolvers").error("FileResolver unable to load private key from file");
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

// Used to determine the encoding format of credentials files
// dynamically. Supports: PEM, DER, PKCS12.
FileResolver::format_t FileResolver::getEncodingFormat(BIO* in) const
{
    PKCS12* p12 = NULL;
    format_t format;

    const int READSIZE = 1;
    char buf[READSIZE];
    char b1;
    int mark;

    try {
        if ( (mark = BIO_tell(in)) < 0 ) 
            throw IOException("getEncodingFormat: BIO_tell() can't get the file position");
        if ( BIO_read(in, buf, READSIZE) <= 0 ) 
            throw IOException("getEncodingFormat: BIO_read() can't read from the stream");
        if ( BIO_seek(in, mark) < 0 ) 
            throw IOException("getEncodingFormat: BIO_seek() can't reset the file position");
    }
    catch (...) {
        log_openssl();
        throw;
    }

    b1 = buf[0];

    // This is a slight variation of the Java code by Chad La Joie.
    //
    // Check the first byte of the file.  If it's some kind of
    // DER-encoded structure (including PKCS12), it will begin with ASCII 048.
    // Otherwise, assume it's PEM.
    if (b1 !=  48) {
        format = PEM;
    } else {
        // Here we know it's DER-encoded, now try to parse it as a PKCS12
        // ASN.1 structure.  If it fails, must be another kind of DER-encoded
        // key/cert structure.  A little inefficient...but it works.
        if ( (p12=d2i_PKCS12_bio(in,NULL)) == NULL ) {
            format = DER;
        } else {
            format = _PKCS12;
        }
        if (p12)
            PKCS12_free(p12);    
        if ( BIO_seek(in, mark) < 0 ) {
            log_openssl();
            throw IOException("getEncodingFormat: BIO_seek() can't reset the file position");
        }
    }

    return format;
}

// Convert key/cert format_t types to a human-meaningful string for debug output
string FileResolver::formatToString(format_t format) const
{
    switch(format) {
        case PEM:
            return "PEM";
        case DER:
            return "DER";
        case _PKCS12:
            return "PKCS12";
        default:
            return "UNKNOWN";
    }
}

// Convert key/cert raw XML format attribute (XMLCh[]) to format_t type
FileResolver::format_t FileResolver::xmlFormatToFormat(const XMLCh* format_xml) const
{
    static const XMLCh cPEM[] = { chLatin_P, chLatin_E, chLatin_M, chNull };
    static const XMLCh cDER[] = { chLatin_D, chLatin_E, chLatin_R, chNull };
    static const XMLCh cPKCS12[] = { chLatin_P, chLatin_K, chLatin_C, chLatin_S, chDigit_1, chDigit_2, chNull };
    format_t format;

    if (!XMLString::compareString(format_xml,cPEM))
        format=PEM;
    else if (!XMLString::compareString(format_xml,cDER))
        format=DER;
    else if (!XMLString::compareString(format_xml,cPKCS12))
        format=_PKCS12;
    else
        format=UNKNOWN;

    return format;
}
