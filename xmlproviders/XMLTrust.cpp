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

/* XMLTrust.cpp - a trust implementation that uses an XML file

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {

    int logging_callback(int ok, X509_STORE_CTX* store)
    {
        if (!ok)
            Category::getInstance("OpenSSL").error(X509_verify_cert_error_string(store->error));
        return ok;
    }
    
    int verify_callback(X509_STORE_CTX* ctx, void* arg)
    {
        Category::getInstance("OpenSSL").debug("invoking default X509 verify callback");
        return X509_verify_cert(ctx);
    }

    class XMLTrustImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLTrustImpl(const char* pathname) : ReloadableXMLFileImpl(pathname), m_wildcard(NULL) { init(); }
        XMLTrustImpl(const DOMElement* e) : ReloadableXMLFileImpl(e), m_wildcard(NULL) { init(); }
        void init();
        ~XMLTrustImpl();
        
        struct KeyAuthority
        {
            KeyAuthority() : m_depth(1) {}
            ~KeyAuthority();
            X509_STORE* getX509Store();
            
#ifndef HAVE_GOOD_STL
            vector<const XMLCh*> m_subjects;
#endif
            vector<X509*> m_certs;
            unsigned short m_depth;
        };
        
        vector<DSIGKeyInfoList*> m_keybinds;
        vector<KeyAuthority*> m_keyauths;
        KeyAuthority* m_wildcard;
#ifdef HAVE_GOOD_STL
        typedef map<xstring,KeyAuthority*> AuthMap;
        typedef map<xstring,DSIGKeyInfoList*> BindMap;
        AuthMap m_authMap;
        BindMap m_bindMap;
#endif
    };

    class XMLTrust : public ITrust, public ReloadableXMLFile
    {
    public:
        XMLTrust(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLTrust() {}

    bool validate(
        const saml::Iterator<IRevocation*>& revocations,
        const IProviderRole* role, const saml::SAMLSignedObject& token,
        const saml::Iterator<IMetadata*>& metadatas=EMPTY(IMetadata*)
        );
    bool attach(const Iterator<IRevocation*>& revocations, const IProviderRole* role, void* ctx);

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };

}

IPlugIn* XMLTrustFactory(const DOMElement* e)
{
    XMLTrust* t=new XMLTrust(e);
    try {
        t->getImplementation();
    }
    catch (...) {
        delete t;
        throw;
    }
    return t;    
}


ReloadableXMLFileImpl* XMLTrust::newImplementation(const char* pathname, bool first) const
{
    return new XMLTrustImpl(pathname);
}

ReloadableXMLFileImpl* XMLTrust::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLTrustImpl(e);
}

X509_STORE* XMLTrustImpl::KeyAuthority::getX509Store()
{
    NDC ndc("getX509Store");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLTrust");

    // Load the cert vector into a store.
    X509_STORE* store=X509_STORE_new();
    if (!store) {
        log_openssl();
        return NULL;
    }
    
    for (vector<X509*>::iterator j=m_certs.begin(); j!=m_certs.end(); j++) {
        if (!X509_STORE_add_cert(store,X509_dup(*j))) {
            log_openssl();
            log.warn("failed to add cert: %s", (*j)->name);
            continue;
        }
    }

    return store;
}

XMLTrustImpl::KeyAuthority::~KeyAuthority()
{
    for (vector<X509*>::iterator i=m_certs.begin(); i!=m_certs.end(); i++)
        X509_free(*i);
}

class KeyInfoNodeFilter : public DOMNodeFilter
{
public:
    short acceptNode(const DOMNode* node) const
    {
        // Our filter just skips any trees not rooted by ds:KeyInfo.
        if (node->getNodeType()==DOMNode::ELEMENT_NODE) {
            if (saml::XML::isElementNamed(static_cast<const DOMElement*>(node),saml::XML::XMLSIG_NS,L(KeyInfo)))
                return FILTER_ACCEPT;
        }
        return FILTER_REJECT;
    }
};

void XMLTrustImpl::init()
{
    NDC ndc("XMLTrustImpl");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLTrustImpl");

    try {
        if (!saml::XML::isElementNamed(m_root,::XML::TRUST_NS,SHIB_L(Trust))) {
            log.error("Construction requires a valid trust file: (trust:Trust as root element)");
            throw TrustException("Construction requires a valid trust file: (trust:Trust as root element)");
        }

        // Loop over the KeyAuthority elements.
        DOMNodeList* nlist=m_root->getElementsByTagNameNS(::XML::TRUST_NS,SHIB_L(KeyAuthority));
        for (int i=0; nlist && i<nlist->getLength(); i++) {
            KeyAuthority* ka=new KeyAuthority();
            m_keyauths.push_back(ka);
            
            DOMElement* e=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* depth=e->getAttributeNS(NULL,SHIB_L(VerifyDepth));
            if (depth && *depth)
                ka->m_depth=XMLString::parseInt(depth);
            
            // Very rudimentary, grab up all the in-band X509Certificate elements, and flatten into one list.
            DOMNodeList* certlist=e->getElementsByTagNameNS(saml::XML::XMLSIG_NS,L(X509Certificate));
            for (int j=0; certlist && j<certlist->getLength(); j++) {
                auto_ptr_char blob(certlist->item(j)->getFirstChild()->getNodeValue());
                X509* x=B64_to_X509(blob.get());
                if (x)
                    ka->m_certs.push_back(x);
                else
                    log.warn("unable to create certificate from inline X509Certificate data");
            }

            // Now look for externally referenced objects.
            certlist=e->getElementsByTagNameNS(saml::XML::XMLSIG_NS,SHIB_L(RetrievalMethod));
            for (int k=0; certlist && k<certlist->getLength(); k++) {
                DOMElement* cert=static_cast<DOMElement*>(certlist->item(k));
                if (!XMLString::compareString(cert->getAttributeNS(NULL,SHIB_L(Type)),::XML::XMLSIG_RETMETHOD_RAWX509)) {
                    // DER format
                    auto_ptr_char fname(cert->getAttributeNS(NULL,SHIB_L(URI)));
                    FILE* f=fopen(fname.get(),"r");
                    if (f) {
                        X509* x=NULL;
                        d2i_X509_fp(f,&x);
                        if (x) {
                            ka->m_certs.push_back(x);
                            continue;
                        }
                        else
                            log_openssl();
                    }
                    log.warn("unable to create certificate from externally referenced file");
                }
                else if (!XMLString::compareString(cert->getAttributeNS(NULL,SHIB_L(Type)),::XML::SHIB_RETMETHOD_PEMX509)) {
                    // PEM format
                    int count=0;
                    auto_ptr_char fname(cert->getAttributeNS(NULL,SHIB_L(URI)));
                    FILE* f=fopen(fname.get(),"r");
                    if (f) {
                        X509* x=NULL;
                        while (x=PEM_read_X509(f,NULL,NULL,NULL)) {
                            ka->m_certs.push_back(x);
                            count++;
                        }
                    }
                    if (!count)
                        log.warn("unable to create certificate from externally referenced file");
                }
            }
            
            // Now map the ds:KeyName values to the list of certs.
            bool wildcard=true;
            DOMElement* sub=saml::XML::getFirstChildElement(e,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            while (sub) {
                const XMLCh* name=sub->getFirstChild()->getNodeValue();
                if (name && *name) {
                    wildcard=false;
#ifdef HAVE_GOOD_STL
                    m_authMap[name]=ka;
#else
                    ka->m_subjects.push_back(name);
#endif
                }
                sub=saml::XML::getNextSiblingElement(sub,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            }
            
            // If no Subjects, this is a catch-all binding.
            if (wildcard) {
                if (!m_wildcard) {
                    log.warn("found a wildcard KeyAuthority element, make sure this is what you intend");
                    m_wildcard=ka;
                }
                else
                    log.warn("found multiple wildcard KeyAuthority elements, ignoring all but the first");
            }
        }

        // Now traverse the outer ds:KeyInfo elements. Supposedly this cast just works...
        int count=0;
        KeyInfoNodeFilter filter;
        XSECKeyInfoResolverDefault resolver;
        DOMTreeWalker* walker=
            static_cast<DOMDocumentTraversal*>(m_doc)->createTreeWalker(const_cast<DOMElement*>(m_root),DOMNodeFilter::SHOW_ELEMENT,&filter,false);
        DOMElement* kidom=static_cast<DOMElement*>(walker->firstChild());
        while (kidom) {
            count++;
            DSIGKeyInfoList* KIL = new DSIGKeyInfoList(NULL);
            // We let XMLSec hack through anything it can. This should evolve over time, or we can
            // plug in our own KeyResolver later...
            DOMElement* child=saml::XML::getFirstChildElement(kidom);
            int count2=1;
            while (child) {
                if (!KIL->addXMLKeyInfo(child))
                    log.warn("skipped unsupported ds:KeyInfo child element (%d)",count2);
                child=saml::XML::getNextSiblingElement(child);
                count2++;
            }
            
            // Dry run...can we resolve to a key?
            XSECCryptoKey* key=resolver.resolveKey(KIL);
            if (key) {
                // So far so good, now look for the name binding(s).
                delete key;
                bool named=false;
                for (size_t index=0; index<KIL->getSize(); index++) {
                    DSIGKeyInfo* info=KIL->item(index);
                    const XMLCh* name=info->getKeyName();
                    if (name && *name) {
                        if (!named)
                            m_keybinds.push_back(KIL);
                        named=true;
#ifdef HAVE_GOOD_STL
                        m_bindMap[name]=KIL;
#endif
                    }
                }
                if (!named) {
                    log.warn("skipping ds:KeyInfo binding (%d) that does not contain a usable key name",count);
                    delete KIL;
                }
            }
            else {
                log.warn("skipping ds:KeyInfo binding (%d) that does not resolve to a key",count);
                delete KIL;
            }
            kidom=static_cast<DOMElement*>(walker->nextSibling());
        }
        walker->release();    // This just cleans up aggressively, but there's no leak if we don't.
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while parsing trust configuration: " << e.what() << CategoryStream::ENDLINE;
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        for (vector<DSIGKeyInfoList*>::iterator j=m_keybinds.begin(); j!=m_keybinds.end(); j++)
            delete (*j);
        throw;
    }
    catch (...) {
        log.error("Unexpected error while parsing trust configuration");
        for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
            delete (*i);
        for (vector<DSIGKeyInfoList*>::iterator j=m_keybinds.begin(); j!=m_keybinds.end(); j++)
            delete (*j);
        throw;
    }
}

XMLTrustImpl::~XMLTrustImpl()
{
    for (vector<KeyAuthority*>::iterator i=m_keyauths.begin(); i!=m_keyauths.end(); i++)
        delete (*i);
    for (vector<DSIGKeyInfoList*>::iterator j=m_keybinds.begin(); j!=m_keybinds.end(); j++)
        delete (*j);
}

bool XMLTrust::attach(const Iterator<IRevocation*>& revocations, const IProviderRole* role, void* ctx)
{
    lock();
    try {
        saml::NDC ndc("attach");
        Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLTrust");
        XMLTrustImpl* impl=dynamic_cast<XMLTrustImpl*>(getImplementation());
    
        // Build a list of the names to match. We include any named KeyDescriptors, and the provider ID and its groups.
        vector<const XMLCh*> names;
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
        names.push_back(role->getProvider()->getId());
        Iterator<const XMLCh*> groups=role->getProvider()->getGroups();
        while (groups.hasNext())
            names.push_back(groups.next());
    
        // Now check each name.
        XMLTrustImpl::KeyAuthority* kauth=NULL;
        for (vector<const XMLCh*>::const_iterator name=names.begin(); !kauth && name!=names.end(); name++) {
    #ifdef HAVE_GOOD_STL
            XMLTrustImpl::AuthMap::const_iterator c=impl->m_authMap.find(*name);
            if (c!=impl->m_authMap.end()) {
                kauth=c->second;
                if (log.isDebugEnabled()) {
                    auto_ptr_char temp(*name);
                    log.debug("KeyAuthority match on %s",temp.get());
                }
            }
    #else
            // Without a decent STL, we trade-off the transcoding by doing a linear search.
            for (vector<XMLTrustImpl::KeyAuthority*>::const_iterator keyauths=impl->m_keyauths.begin(); !kauth && keyauths!=impl->m_keyauths.end(); keyauths++) {
                for (vector<const XMLCh*>::const_iterator subs=(*keyauths)->m_subjects.begin(); !kauth && subs!=(*keyauths)->m_subjects.end(); subs++) {
                    if (!XMLString::compareString(*name,*subs)) {
                        kauth=*keyauths;
                        if (log.isDebugEnabled()) {
                            auto_ptr_char temp(*name);
                            log.debug("KeyAuthority match on %s",temp.get());
                        }
                    }
                }
            }
    #endif
        }
    
        if (!kauth) {
            if (impl->m_wildcard) {
               log.warn("applying wildcard KeyAuthority, use with caution!");
                kauth=impl->m_wildcard;
            }
            else {
                unlock();
                log.error("no KeyAuthority found to validate SSL connection, leaving it alone");
                return false;
            }
        }
    
        // If we have a match, use the associated keyauth unless we already did...
        X509_STORE* store=kauth->getX509Store();
        if (store) {
      
            // Add any relevant CRLs.
            log.debug("obtaining CRLs for this provider/role");
            Revocation rev(revocations);
            Iterator<void*> crls=rev.getRevocationLists(role->getProvider(),role);
            while (crls.hasNext()) {
                if (!X509_STORE_add_crl(store,X509_CRL_dup(reinterpret_cast<X509_CRL*>(crls.next())))) {
                    log_openssl();
                    log.warn("failed to add CRL");
                }
            }
        
            // Apply store to this context.
            SSL_CTX_set_verify(reinterpret_cast<SSL_CTX*>(ctx),SSL_VERIFY_PEER,logging_callback);
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
            SSL_CTX_set_cert_verify_callback(reinterpret_cast<SSL_CTX*>(ctx),verify_callback,NULL);
#else
            SSL_CTX_set_cert_verify_callback(reinterpret_cast<SSL_CTX*>(ctx),reinterpret_cast<int (*)()>(verify_callback),NULL);
#endif
            SSL_CTX_set_cert_store(reinterpret_cast<SSL_CTX*>(ctx),store);
            SSL_CTX_set_verify_depth(reinterpret_cast<SSL_CTX*>(ctx),kauth->m_depth);
        }
    }
    catch (...) {
        unlock();
        throw;
    }
    unlock();
    return true;
}

bool XMLTrust::validate(
    const saml::Iterator<IRevocation*>& revocations,
    const IProviderRole* role, const saml::SAMLSignedObject& token,
    const saml::Iterator<IMetadata*>& metadatas
    )
{
    lock();
    try {
        NDC ndc("validate");
        Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLTrust");
        XMLTrustImpl* impl=dynamic_cast<XMLTrustImpl*>(getImplementation());
    
        // This is where we're going to hide all the juicy SAML trust bits. If we botch it
        // we can just plug in a new version, hopefully.
    
        Metadata metadata(metadatas);   // With luck we won't need this.
    
        // Did the caller tell us about the signer?
        const IProvider* provider=(role ? role->getProvider() : NULL);
        if (!provider) {
            log.debug("no role descriptor passed in, trying to map token to provider");
            
            // The first step is to identify the provider responsible for signing the token.
            // We can't narrow it down to role, because we don't know why the token is being validated.
            
            // If it's an assertion, this isn't terribly hard, but we need to hack in support for both
            // Issuer and NameQualifier as a provider ID. Issuer will be the main one going forward.
            // 1.0/1.1 origins will be sending a hostname as Issuer, but this won't hit the metadata lookup
            // and we'll fall back to NameQualifier. Non-Shib SAML origins generally would be based on Issuer.
            
            // Responses allow us to try and locate a provider by checking the assertion(s) inside.
            // Technically somebody could enclose somebody else's assertions, but if the use case is
            // that advanced, we're probably into SAML 2.0 and we'll have Issuer up top.
            
            // Requests...umm, pretty much out of luck. We'll apply our own hack if there's an
            // attribute query, and use Resource.
            
            if (typeid(token)==typeid(SAMLResponse)) {
                Iterator<SAMLAssertion*> assertions=dynamic_cast<const SAMLResponse&>(token).getAssertions();
                while (!provider && assertions.hasNext()) {
                    SAMLAssertion* assertion=assertions.next();
                    provider=metadata.lookup(assertion->getIssuer());
                    if (!provider) {
                        Iterator<SAMLStatement*> statements=assertion->getStatements();
                        while (!provider && statements.hasNext()) {
                            SAMLSubjectStatement* statement=dynamic_cast<SAMLSubjectStatement*>(statements.next());
                            if (statement && statement->getSubject()->getNameQualifier())
                                provider=metadata.lookup(statement->getSubject()->getNameQualifier());
                        }
                    }
                }
            }
            else if (typeid(token)==typeid(SAMLAssertion)) {
                provider=metadata.lookup(dynamic_cast<const SAMLAssertion&>(token).getIssuer());
                if (!provider) {
                    Iterator<SAMLStatement*> statements=dynamic_cast<const SAMLAssertion&>(token).getStatements();
                    while (!provider && statements.hasNext()) {
                        SAMLSubjectStatement* statement=dynamic_cast<SAMLSubjectStatement*>(statements.next());
                        if (statement && statement->getSubject()->getNameQualifier())
                            provider=metadata.lookup(statement->getSubject()->getNameQualifier());
                    }
                }
            }
            else if (typeid(token)==typeid(SAMLRequest)) {
                const SAMLQuery* q=dynamic_cast<const SAMLRequest&>(token).getQuery();
                if (q && dynamic_cast<const SAMLAttributeQuery*>(q))
                    provider=metadata.lookup(dynamic_cast<const SAMLAttributeQuery*>(q)->getResource());
            }
            
            // If we still don't have a provider, there's no likely basis for trust,
            // but a wildcard KeyAuthority might apply.
            if (log.isInfoEnabled() && provider) {
                auto_ptr_char temp(provider->getId());
                log.info("mapped signed token to provider: %s", temp.get());
            }
            else if (!provider)
                log.warn("unable to map signed token to provider, only wildcarded trust will apply");
        }
        
        vector<const XMLCh*> names;
        XSECKeyInfoResolverDefault keyResolver;
        
        // First, try to resolve a KeyDescriptor from the role into an actual key.
        // That's the simplest case. Failing that, remember any key names we run across.
        
        if (role) {
            log.debug("checking for key descriptors that resolve directly");
            Iterator<const IKeyDescriptor*> kd_i=role->getKeyDescriptors();
            while (kd_i.hasNext()) {
                const IKeyDescriptor* kd=kd_i.next();
                if (kd->getUse()!=IKeyDescriptor::signing)
                    continue;
                DSIGKeyInfoList* KIL=kd->getKeyInfo();
                if (!KIL)
                    continue;
                XSECCryptoKey* key=keyResolver.resolveKey(KIL);
                if (key) {
                    log.debug("found an inline key, trying it...");
                    try {
                        token.verify(key);
                        unlock();
                        log.info("token verified with inline key, nothing more to verify");
                        return true;
                    }
                    catch (SAMLException& e) {
                        log.debug("inline key failed: %s", e.what());
                    }
                }
                else {
                    for (size_t s=0; s<KIL->getSize(); s++) {
                        const XMLCh* n=KIL->item(s)->getKeyName();
                        if (n)
                            names.push_back(n);
                    }
                }
            }
        }
        
        // Push the provider ID on the key name list. We don't push provider groups in, since
        // matching groups to a key makes no sense.
        if (provider)
            names.push_back(provider->getId());
        
        // No keys inline in metadata. Now we try and find a key inline in trust.
        log.debug("checking for keys in trust file");
        DSIGKeyInfoList* KIL=NULL;
        for (vector<const XMLCh*>::const_iterator name=names.begin(); !KIL && name!=names.end(); name++) {
    #ifdef HAVE_GOOD_STL
            XMLTrustImpl::BindMap::const_iterator c=impl->m_bindMap.find(*name);
            if (c!=impl->m_bindMap.end()) {
                KIL=c->second;
                if (log.isDebugEnabled()) {
                    auto_ptr_char temp(*name);
                    log.debug("KeyInfo match on %s",temp.get());
                }
            }
    #else
            // Without a decent STL, we trade-off the transcoding by doing a linear search.
            for (vector<DSIGKeyInfoList*>::const_iterator keybinds=impl->m_keybinds.begin(); !KIL && keybinds!=impl->m_keybinds.end(); keybinds++) {
                for (size_t s=0; !KIL && s<(*keybinds)->getSize(); s++) {
                    if (!XMLString::compareString(*name,(*keybinds)->item(s)->getKeyName())) {
                        KIL=*keybinds;
                        if (log.isDebugEnabled()) {
                            auto_ptr_char temp(*name);
                            log.debug("KeyInfo match on %s",temp.get());
                        }
                    }
                }
            }
    #endif
        }
        
        if (KIL) {
            // Any inline KeyInfo should ostensible resolve to a key we can try.
            XSECCryptoKey* key=keyResolver.resolveKey(KIL);
            if (key) {
                log.debug("resolved key, trying it...");
                try {
                    token.verify(key);
                    unlock();
                    log.info("token verified with KeyInfo, nothing more to verify");
                    return true;
                }
                catch (SAMLException& e) {
                    log.debug("inline key failed: %s", e.what());
                }
            }
            else
                log.warn("KeyInfo in trust provider did not resolve to a key");
        }
        
        // Direct key verification hasn't worked. Now we have to switch over to KeyAuthority-based
        // validation. The actual verification key has to be inside the token.
        log.debug("verifying signature using key inside token...");
        try {
            token.verify();
            log.info("verified with key inside token, entering validation stage");
        }
        catch (SAMLException& e) {
            unlock();
            log.debug("verification using key inside token failed: %s", e.what());
            return false;
        }
        
        // Before we do the cryptogprahy, check that the EE certificate "name" matches
        // one of the acceptable key "names" for the signer. Without this, we have a gaping
        // hole in the validation.
        log.debug("matching token's certificate subject against valid key names...");
        vector<const XMLCh*> certs;
        for (unsigned int i=0; i<token.getX509CertificateCount(); i++)
            certs.push_back(token.getX509Certificate(i));
    
        // Decode the EE cert.
        auto_ptr_char EE(certs[0]);
        X509* x=B64_to_X509(EE.get());
        if (!x) {
            unlock();
            log.error("unable to decode X.509 signing certificate");
            return false;
        }
        
        // Transcode the possible key "names" to UTF-8. For some simple cases, this should
        // handle UTF-8 encoded DNs in certificates.
        vector<string> keynames;
        Iterator<const XMLCh*> iname(names);
        while (iname.hasNext()) {
            auto_ptr<char> kn(toUTF8(iname.next()));
            keynames.push_back(kn.get());
        }
        
        bool match=false;
        char buf[256];
        X509_NAME* subject=X509_get_subject_name(x);
        if (subject) {
            // The best way is a direct match to the subject DN. We should encourage this.
            // Seems that the way to do the compare is to write the X509_NAME into a BIO.
            // Believe this will give us RFC 2253 / LDAP syntax...
            BIO* b = BIO_new(BIO_s_mem());
            if (b) {
                BIO_set_mem_eof_return(b, 0);
                // The DN_REV flag gives us LDAP order instead of X.500
                int len=X509_NAME_print_ex(b,subject,0,XN_FLAG_SEP_COMMA_PLUS|XN_FLAG_DN_REV);
                if (len) {
                    BIO_flush(b);
                    string subjectstr;
                    while ((len = BIO_read(b, buf, 255)) > 0) {
                        buf[len] = '\0';
                        subjectstr+=buf;
                    }
                    log.infoStream() << "certificate subject: " << subjectstr << CategoryStream::ENDLINE;
                    // Check each keyname.
                    for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
    #ifdef HAVE_STRCASECMP
                        if (!strcasecmp(n->c_str(),subjectstr.c_str())) {
    #else
                        if (!stricmp(n->c_str(),subjectstr.c_str())) {
    #endif
                            log.info("matched full subject DN to a key name");
                            match=true;
                            break;
                        }
                    }
                }
                else
                    log.error("certificate has no subject?!");
                BIO_free(b);
            }
            else
                log.error("unable to obtain memory BIO from OpenSSL");
            
            if (!match) {
                log.debug("unable to match DN, trying TLS-style hostname match");
                memset(buf,0,sizeof(buf));
                if (X509_NAME_get_text_by_NID(subject,NID_commonName,buf,255)>0) {
                    for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
    #ifdef HAVE_STRCASECMP
                        if (!strcasecmp(buf,n->c_str())) {
    #else
                        if (!stricmp(buf,n->c_str())) {
    #endif
                            log.info("matched subject CN to a key name");
                            match=true;
                            break;
                        }
                    }
                }
                else
                    log.warn("no common name in certificate subject");
                
                if (!match) {
                    log.debug("unable to match CN, trying DNS subjectAltName");
                    int extcount=X509_get_ext_count(x);
                    for (int c=0; c<extcount; c++) {
                        X509_EXTENSION* ext=X509_get_ext(x,c);
                        const char* extstr=OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
                        if (!strcmp(extstr,"subjectAltName")) {
                            X509V3_EXT_METHOD* meth=X509V3_EXT_get(ext);
                            if (!meth || !meth->d2i || !meth->i2v || !ext->value->data) // had to add all these to prevent crashing
                                break;
                            unsigned char* data=ext->value->data;
                            STACK_OF(CONF_VALUE)* val=meth->i2v(meth,meth->d2i(NULL,&data,ext->value->length),NULL);
                            for (int j=0; j<sk_CONF_VALUE_num(val); j++) {
                                CONF_VALUE* nval=sk_CONF_VALUE_value(val,j);
                                if (!strcmp(nval->name,"DNS")) {
                                    for (vector<string>::const_iterator n=keynames.begin(); n!=keynames.end(); n++) {
    #ifdef HAVE_STRCASECMP
                                        if (!strcasecmp(nval->value,n->c_str())) {
    #else
                                        if (!stricmp(nval->value,n->c_str())) {
    #endif
                                            log.info("matched DNS subjectAltName to a key name");
                                            match=true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
            log.error("certificate has no subject?!");
    
        X509_free(x);
    
        if (!match) {
            unlock();
            log.error("cannot match certificate subject against provider's key names");
            return false;
        }
    
        // We're ready for the final stage.
        log.debug("final step, certificate path validation...");
    
        // Push any provider groups on the name match list.
        if (provider) {
            Iterator<const XMLCh*> groups=provider->getGroups();
            while (groups.hasNext())
                names.push_back(groups.next());
        }
    
        // Now we hunt the list for a KeyAuthority that matches one of the names.
        XMLTrustImpl::KeyAuthority* kauth=NULL;
        for (vector<const XMLCh*>::const_iterator name2=names.begin(); !kauth && name2!=names.end(); name2++) {
#ifdef HAVE_GOOD_STL
            XMLTrustImpl::AuthMap::const_iterator c=impl->m_authMap.find(*name2);
            if (c!=impl->m_authMap.end()) {
                kauth=c->second;
                if (log.isDebugEnabled()) {
                    auto_ptr_char temp(*name2);
                    log.debug("KeyAuthority match on %s",temp.get());
                }
            }
#else
            // Without a decent STL, we trade-off the transcoding by doing a linear search.
            for (vector<XMLTrustImpl::KeyAuthority*>::const_iterator keyauths=impl->m_keyauths.begin(); !kauth && keyauths!=impl->m_keyauths.end(); keyauths++) {
                for (vector<const XMLCh*>::const_iterator subs=(*keyauths)->m_subjects.begin(); !kauth && subs!=(*keyauths)->m_subjects.end(); subs++) {
                    if (!XMLString::compareString(*name2,*subs)) {
                        kauth=*keyauths;
                        if (log.isDebugEnabled()) {
                            auto_ptr_char temp(*name2);
                            log.debug("KeyAuthority match on %s",temp.get());
                        }
                    }
                }
            }
#endif
        }
    
        if (!kauth) {
            if (impl->m_wildcard) {
               log.warn("applying wildcard KeyAuthority, use with caution!");
                kauth=impl->m_wildcard;
            }
            else {
                unlock();
                log.error("no KeyAuthority found to validate the token, leaving untrusted");
                return false;
            }
        }
    
        log.debug("building untrusted certificate chain from signature");
        STACK_OF(X509)* chain=sk_X509_new_null();
        Iterator<const XMLCh*> icerts(certs);
        while (icerts.hasNext()) {
            auto_ptr_char xbuf(icerts.next());
            X509* x=B64_to_X509(xbuf.get());
            if (!x) {
                unlock();
                log.error("unable to parse certificate in signature");
                sk_X509_pop_free(chain,X509_free);
                return false;
            }
            sk_X509_push(chain,x);
        }
    
        X509_STORE* store=kauth->getX509Store();
        if (!store) {
            unlock();
            log.error("unable to load X509_STORE from KeyAuthority object");
            sk_X509_pop_free(chain,X509_free);
            return false;
        }
        
        X509_STORE_CTX* ctx=X509_STORE_CTX_new();
        if (!ctx) {
            log_openssl();
            unlock();
            log.error("unable to create X509_STORE_CTX");
            X509_STORE_free(store);
            sk_X509_pop_free(chain,X509_free);
            return false;
        }
    
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
        if (X509_STORE_CTX_init(ctx,store,sk_X509_value(chain,0),chain)!=1) {
            log_openssl();
            unlock();
            log.error("unable to initialize X509_STORE_CTX");
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            sk_X509_pop_free(chain,X509_free);
            return false;
        }
#else
        X509_STORE_CTX_init(ctx,store,sk_X509_value(chain,0),chain);
#endif
        if (kauth->m_depth)
            X509_STORE_CTX_set_depth(ctx,kauth->m_depth);
    
        // Add any relevant CRLs.
        log.debug("obtaining CRLs for this provider/role");
        Revocation rev(revocations);
        Iterator<void*> crls=rev.getRevocationLists(provider,role);
        while (crls.hasNext()) {
            if (!X509_STORE_add_crl(store,X509_CRL_dup(reinterpret_cast<X509_CRL*>(crls.next())))) {
                log_openssl();
                log.warn("failed to add CRL");
            }
        }
    
        int result=X509_verify_cert(ctx);
        sk_X509_pop_free(chain,X509_free);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        unlock();
        
        if (result==1) {
            log.info("successfully validated certificate chain, token signature trusted");
            return true;
        }
        
        log.error("failed to validate certificate chain, token signature untrusted");
        return false;
    }
    catch (...) {
        unlock();
        throw;
    }       
}
