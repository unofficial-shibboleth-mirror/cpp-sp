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

/* ShibbolethTrust.cpp - a trust implementation that relies solely on standard SAML metadata

   Scott Cantor
   4/10/05

   $History:$
*/

#include "internal.h"

#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <xsec/dsig/DSIGKeyInfoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {
    void log_openssl()
    {
        const char* file;
        const char* data;
        int flags,line;
    
        unsigned long code=ERR_get_error_line_data(&file,&line,&data,&flags);
        while (code) {
            Category& log=Category::getInstance("OpenSSL");
            log.errorStream() << "error code: " << code << " in " << file << ", line " << line << CategoryStream::ENDLINE;
            if (data && (flags & ERR_TXT_STRING))
                log.errorStream() << "error data: " << data << CategoryStream::ENDLINE;
            code=ERR_get_error_line_data(&file,&line,&data,&flags);
        }
    }
    
    X509* B64_to_X509(const char* buf)
    {
        BIO* bmem = BIO_new_mem_buf((void*)buf,-1);
        BIO* b64 = BIO_new(BIO_f_base64());
        b64 = BIO_push(b64, bmem);
        X509* x=NULL;
        d2i_X509_bio(b64,&x);
        if (!x)
            log_openssl();
        BIO_free_all(b64);
        return x;
    }
    
    X509_CRL* B64_to_CRL(const char* buf)
    {
        BIO* bmem = BIO_new_mem_buf((void*)buf,-1);
        BIO* b64 = BIO_new(BIO_f_base64());
        b64 = BIO_push(b64, bmem);
        X509_CRL* x=NULL;
        d2i_X509_CRL_bio(b64,&x);
        if (!x)
            log_openssl();
        BIO_free_all(b64);
        return x;
    }

    class ShibbolethTrust : public BasicTrust
    {
    public:
        ShibbolethTrust(const DOMElement* e);
        ~ShibbolethTrust();

        bool validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName=true);
        bool validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator=NULL);
        
    private:
        bool validate(X509* EE, STACK_OF(X509)* untrusted, const IKeyAuthority* rule);

        vector<IMetadata*> m_metas;
    };
}

IPlugIn* ShibbolethTrustFactory(const DOMElement* e)
{
    return new ShibbolethTrust(e);
}

ShibbolethTrust::ShibbolethTrust(const DOMElement* e) : BasicTrust(e)
{
    static const XMLCh MetadataProvider[] =
    { chLatin_M, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a,
      chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
    };
    static const XMLCh _type[] = { chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };

#ifdef _DEBUG
    saml::NDC ndc("ShibbolethTrust");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Shibboleth");

    // Check for embedded trust metadata.
    e=saml::XML::getFirstChildElement(e);
    while (e) {
        if (!XMLString::compareString(e->getLocalName(),MetadataProvider) && e->hasAttributeNS(NULL,_type)) {
            auto_ptr_char type(e->getAttributeNS(NULL,_type));
            log.info("trust provider building embedded metadata provider of type %s...",type.get());
            try {
                IPlugIn* plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(type.get(),e);
                IMetadata* md=dynamic_cast<IMetadata*>(plugin);
                if (md)
                    m_metas.push_back(md);
                else {
                    delete plugin;
                    log.error("plugin was not a metadata provider");
                }
            }
            catch (SAMLException& ex) {
                log.error("caught SAML exception building embedded metadata provider: %s", ex.what());
            }
#ifndef _DEBUG
            catch (...) {
                log.error("caught unknown exception building embedded metadata provider");
            }
#endif
        }
        e=saml::XML::getNextSiblingElement(e);
    }
}

ShibbolethTrust::~ShibbolethTrust()
{
    for (vector<IMetadata*>::iterator i=m_metas.begin(); i!=m_metas.end(); i++)
        delete *i;
}

static int error_callback(int ok, X509_STORE_CTX* ctx)
{
    if (!ok)
        Category::getInstance("OpenSSL").error("path validation failure: %s", X509_verify_cert_error_string(ctx->error));
    return ok;
}

bool ShibbolethTrust::validate(X509* EE, STACK_OF(X509)* untrusted, const IKeyAuthority* rule)
{
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Shibboleth");

    // First we build a stack of CA certs. These objects are all referenced in place.
    log.debug("building CA list from KeyAuthority extension");

    // We need this for CRL support.
    X509_STORE* store=X509_STORE_new();
    if (!store) {
        log_openssl();
        return false;
    }
    X509_STORE_set_flags(store,X509_V_FLAG_CRL_CHECK_ALL);

    STACK_OF(X509)* CAstack = sk_X509_new_null();
    
    // This contains the state of the validate operation.
    X509_STORE_CTX ctx;
        
    Iterator<DSIGKeyInfoList*> iKIL=rule->getKeyInfos();
    while (iKIL.hasNext()) {
        DSIGKeyInfoList* KIL=iKIL.next();
        
        // Try and locate a certificate.
        Iterator<KeyInfoResolver*> resolvers(m_resolvers);
        while (resolvers.hasNext()) {
            XSECCryptoX509* cert=resolvers.next()->resolveCert(KIL);
            if (cert && cert->getProviderName()==DSIGConstants::s_unicodeStrPROVOpenSSL) {
                sk_X509_push(CAstack,static_cast<OpenSSLCryptoX509*>(cert)->getOpenSSLX509());
                break;
            }
        }
        
        // Try and locate one or more CRLs.
        for (size_t s=0; s<KIL->getSize(); s++) {
            DSIGKeyInfo* KI=KIL->item(s);
            if (KI->getKeyInfoType()==DSIGKeyInfo::KEYINFO_X509) {
                const XMLCh* raw=static_cast<DSIGKeyInfoX509*>(KI)->getX509CRL();
                if (raw) {
                    auto_ptr_char blob(raw);
                    X509_CRL* crl=B64_to_CRL(blob.get());
                    if (crl)
                        X509_STORE_add_crl(store,crl);  // owned by store
                    else
                        log.error("unable to create CRL from X509CRL data");
                }
            }
        }
    }
 
    // AFAICT, EE and untrusted are passed in but not owned by the ctx.
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
    if (X509_STORE_CTX_init(&ctx,store,EE,untrusted)!=1) {
        log_openssl();
        log.error("unable to initialize X509_STORE_CTX");
        sk_X509_free(CAstack);
        X509_STORE_free(store);
        return false;
    }
#else
    X509_STORE_CTX_init(&ctx,store,EE,untrusted);
#endif

    // Seems to be most efficient to just pass in the CA stack.
    X509_STORE_CTX_trusted_stack(&ctx,CAstack);
    X509_STORE_CTX_set_depth(&ctx,100);    // we check the depth down below
    X509_STORE_CTX_set_verify_cb(&ctx,error_callback);
    
    int ret=X509_verify_cert(&ctx);
    if (ret==1) {
        // Now see if the depth was acceptable by counting the number of intermediates.
        int depth=sk_X509_num(ctx.chain)-2;
        if (rule->getVerifyDepth() < depth) {
            log.error(
                "certificate chain was too long (%d intermediates, only %d allowed)",
                (depth==-1) ? 0 : depth,
                rule->getVerifyDepth()
                );
            ret=0;
        }
    }
    
    // Clean up...
    X509_STORE_CTX_cleanup(&ctx);
    X509_STORE_free(store);
    sk_X509_free(CAstack);

    if (ret==1) {
        log.info("successfully validated certificate chain");
        return true;
    }
    
    return false;
}

bool ShibbolethTrust::validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName)
{
    if (BasicTrust::validate(certEE,certChain,role))
        return true;
        
#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Shibboleth");

    if (!certEE)
        return false;

    // The extended trust implementation supports metadata extensions to validate
    // signing certificates found inside the signature.

    if (checkName) {
        // Before we do the cryptogprahy, check that the EE certificate "name" matches
        // one of the acceptable key "names" for the signer.
        vector<string> keynames;
        
        // Build a list of acceptable names. Transcode the possible key "names" to UTF-8.
        // For some simple cases, this should handle UTF-8 encoded DNs in certificates.
        Iterator<const IKeyDescriptor*> kd_i=role->getKeyDescriptors();
        while (kd_i.hasNext()) {
            const IKeyDescriptor* kd=kd_i.next();
            if (kd->getUse()!=IKeyDescriptor::signing)
                continue;
            DSIGKeyInfoList* KIL=kd->getKeyInfo();
            if (!KIL)
                continue;
            for (size_t s=0; s<KIL->getSize(); s++) {
                const XMLCh* n=KIL->item(s)->getKeyName();
                if (n) {
                    auto_ptr<char> kn(toUTF8(n));
                    keynames.push_back(kn.get());
                }
            }
        }
        auto_ptr<char> kn(toUTF8(role->getEntityDescriptor()->getId()));
        keynames.push_back(kn.get());
        
        char buf[256];
        X509* x=(X509*)certEE;
        X509_NAME* subject=X509_get_subject_name(x);
        if (subject) {
            // One way is a direct match to the subject DN.
            // Seems that the way to do the compare is to write the X509_NAME into a BIO.
            BIO* b = BIO_new(BIO_s_mem());
            BIO* b2 = BIO_new(BIO_s_mem());
            BIO_set_mem_eof_return(b, 0);
            BIO_set_mem_eof_return(b2, 0);
            // The flags give us LDAP order instead of X.500, with a comma separator.
            int len=X509_NAME_print_ex(b,subject,0,XN_FLAG_RFC2253);
            string subjectstr,subjectstr2;
            BIO_flush(b);
            while ((len = BIO_read(b, buf, 255)) > 0) {
                buf[len] = '\0';
                subjectstr+=buf;
            }
            log.infoStream() << "certificate subject: " << subjectstr << CategoryStream::ENDLINE;
            // The flags give us LDAP order instead of X.500, with a comma plus space separator.
            len=X509_NAME_print_ex(b2,subject,0,XN_FLAG_RFC2253 + XN_FLAG_SEP_CPLUS_SPC - XN_FLAG_SEP_COMMA_PLUS);
            BIO_flush(b2);
            while ((len = BIO_read(b2, buf, 255)) > 0) {
                buf[len] = '\0';
                subjectstr2+=buf;
            }
            
            // Check each keyname.
            for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
#ifdef HAVE_STRCASECMP
                if (!strcasecmp(n->c_str(),subjectstr.c_str()) || !strcasecmp(n->c_str(),subjectstr2.c_str())) {
#else
                if (!stricmp(n->c_str(),subjectstr.c_str()) || !stricmp(n->c_str(),subjectstr2.c_str())) {
#endif
                    log.info("matched full subject DN to a key name (%s)", n->c_str());
                    checkName=false;
                    break;
                }
            }
            BIO_free(b);
            BIO_free(b2);

            if (checkName) {
                log.debug("unable to match DN, trying TLS subjectAltName match");
                STACK_OF(GENERAL_NAME)* altnames=(STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
                if (altnames) {
                    int numalts = sk_GENERAL_NAME_num(altnames);
                    for (int an=0; !checkName && an<numalts; an++) {
                        const GENERAL_NAME* check = sk_GENERAL_NAME_value(altnames, an);
                        if (check->type==GEN_DNS || check->type==GEN_URI) {
                            const char* altptr = (char*)ASN1_STRING_data(check->d.ia5);
                            const int altlen = ASN1_STRING_length(check->d.ia5);
                            
                            for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
#ifdef HAVE_STRCASECMP
                                if (!strncasecmp(altptr,n->c_str(),altlen)) {
#else
                                if (!strnicmp(altptr,n->c_str(),altlen)) {
#endif
                                    log.info("matched DNS/URI subjectAltName to a key name (%s)", n->c_str());
                                    checkName=false;
                                    break;
                                }
                            }
                        }
                    }
                    GENERAL_NAMES_free(altnames);
                }
                
                if (checkName) {
                    log.debug("unable to match subjectAltName, trying TLS CN match");
                    memset(buf,0,sizeof(buf));
                    if (X509_NAME_get_text_by_NID(subject,NID_commonName,buf,255)>0) {
                        for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
#ifdef HAVE_STRCASECMP
                            if (!strcasecmp(buf,n->c_str())) {
#else
                            if (!stricmp(buf,n->c_str())) {
#endif
                                log.info("matched subject CN to a key name (%s)", n->c_str());
                                checkName=false;
                                break;
                            }
                        }
                    }
                    else
                        log.warn("no common name in certificate subject");
                }
            }
        }
        else
            log.error("certificate has no subject?!");
    }

    if (checkName) {
        log.error("cannot match certificate subject against acceptable key names based on KeyDescriptors");
        return false;
    }
    
    log.debug("performing certificate path validation...");

    STACK_OF(X509)* untrusted=sk_X509_new_null();
    certChain.reset();
    while (certChain.hasNext())
        sk_X509_push(untrusted,(X509*)certChain.next());

    // Check for entity-level KeyAuthorities.
    const IExtendedEntityDescriptor* entity=dynamic_cast<const IExtendedEntityDescriptor*>(role->getEntityDescriptor());
    if (entity) {
        Iterator<const IKeyAuthority*> kauths=entity->getKeyAuthorities();
        while (kauths.hasNext())
            if (validate((X509*)certEE,untrusted,kauths.next())) {
                sk_X509_free(untrusted);
                return true;
            }
    }

    // Now repeat using any embedded metadata.
    Iterator<IMetadata*> metas(m_metas);
    while (metas.hasNext()) {
        IMetadata* m=metas.next();
        Locker locker(m);
        const IEntityDescriptor* ed=m->lookup(role->getEntityDescriptor()->getId());
        if (!ed)
            continue;

        // Check for entity-level KeyAuthorities.
        entity=dynamic_cast<const IExtendedEntityDescriptor*>(ed);
        if (entity) {
            Iterator<const IKeyAuthority*> kauths=entity->getKeyAuthorities();
            while (kauths.hasNext())
                if (validate((X509*)certEE,untrusted,kauths.next())) {
                    sk_X509_free(untrusted);
                    return true;
                }
        }
    }
    
    const IEntitiesDescriptor* group=role->getEntityDescriptor()->getEntitiesDescriptor();
    while (group) {
        const IExtendedEntitiesDescriptor* egroup=dynamic_cast<const IExtendedEntitiesDescriptor*>(group);
        if (egroup) {
            Iterator<const IKeyAuthority*> kauths=egroup->getKeyAuthorities();
            while (kauths.hasNext())
                if (validate((X509*)certEE,untrusted,kauths.next())) {
                    sk_X509_free(untrusted);
                    return true;
                }
        }
        
        // Now repeat using any embedded metadata.
        Iterator<IMetadata*> metas(m_metas);
        while (metas.hasNext()) {
            IMetadata* m=metas.next();
            Locker locker(m);
            const IEntitiesDescriptor* g=m->lookupGroup(group->getName());
            if (!g)
                continue;
    
            // Check for group-level KeyAuthorities.
            egroup=dynamic_cast<const IExtendedEntitiesDescriptor*>(g);
            if (egroup) {
                Iterator<const IKeyAuthority*> kauths=egroup->getKeyAuthorities();
                while (kauths.hasNext())
                    if (validate((X509*)certEE,untrusted,kauths.next())) {
                        sk_X509_free(untrusted);
                        return true;
                    }
            }
        }
        
        group=group->getEntitiesDescriptor();
    }
    
    log.debug("failed to validate certificate chain using KeyAuthority extensions");
    return false;
}

bool ShibbolethTrust::validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator)
{
    if (BasicTrust::validate(token,role))
        return true;

#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".Trust.Shibboleth");

    // The extended trust implementation supports metadata extensions to validate
    // signing certificates found inside the signature.
 
    // Get the certificate chain out of the object in portable form.
    vector<XSECCryptoX509*> certs;
    for (unsigned int i=0; i<token.getX509CertificateCount(); i++) {
        auto_ptr_char cert(token.getX509Certificate(i));
        auto_ptr<XSECCryptoX509> x(XSECPlatformUtils::g_cryptoProvider->X509());
        try {
            x->loadX509Base64Bin(cert.get(),strlen(cert.get()));
            certs.push_back(x.release());
        }
        catch (...) {
            log.error("unable to load certificate from signature, skipping it");
        }
    }

    log.debug("validating signature using certificate from within the signature");

    // Native representations.
    X509* certEE=NULL;
    vector<void*> chain;
    
    // Find and save off a pointer to the certificate that unlocks the object.
    // Most of the time, this will be the first one anyway.
    Iterator<XSECCryptoX509*> iter(certs);
    while (iter.hasNext()) {
        try {
            XSECCryptoX509* c=iter.next();
            chain.push_back(static_cast<OpenSSLCryptoX509*>(c)->getOpenSSLX509());
            if (!certEE) {
                token.verify(*c);
                log.info("signature verified with key inside signature, attempting certificate validation...");
                certEE=static_cast<OpenSSLCryptoX509*>(c)->getOpenSSLX509();
            }
        }
        catch (...) {
            // trap failures
        }
    }
    
    bool ret=false;
    if (certEE)
        ret=(certValidator) ? certValidator->validate(certEE,chain,role) : this->validate(certEE,chain,role);
    else
        log.debug("failed to verify signature with embedded certificates");
    
    for (vector<XSECCryptoX509*>::iterator j=certs.begin(); j!=certs.end(); j++)
        delete *j;

    return ret;
}
