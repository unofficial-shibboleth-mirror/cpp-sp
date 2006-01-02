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

/* XMLTrust.cpp - a trust implementation that uses an XML file

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>

using namespace xmlproviders;
using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {
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
            vector<X509_CRL*> m_crls;
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
        XMLTrust(const DOMElement* e);
        ~XMLTrust();

    bool validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName=true);
    bool validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator=NULL);

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;

        vector<KeyInfoResolver*> m_resolvers;
        ITrust* m_delegate;
    };
}

IPlugIn* XMLTrustFactory(const DOMElement* e)
{
    auto_ptr<XMLTrust> t(new XMLTrust(e));
    t->getImplementation();
    return t.release();
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
#ifdef _DEBUG
    NDC ndc("getX509Store");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Trust");

    // Load the cert vector into a store.
    X509_STORE* store=X509_STORE_new();
    if (!store) {
        log_openssl();
        return NULL;
    }
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
    X509_STORE_set_flags(store,X509_V_FLAG_CRL_CHECK_ALL);
#endif

    for (vector<X509*>::iterator j=m_certs.begin(); j!=m_certs.end(); j++) {
        if (!X509_STORE_add_cert(store,*j)) {
            log_openssl();
            log.warn("failed to add cert: %s", (*j)->name);
            continue;
        }
    }

    for (vector<X509_CRL*>::iterator k=m_crls.begin(); k!=m_crls.end(); k++) {
        if (!X509_STORE_add_crl(store,*k)) {
            log_openssl();
            log.warn("failed to add CRL");
            continue;
        }
    }

    return store;
}

XMLTrustImpl::KeyAuthority::~KeyAuthority()
{
    for_each(m_certs.begin(),m_certs.end(),X509_free);
    for_each(m_crls.begin(),m_crls.end(),X509_CRL_free);
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
#ifdef _DEBUG
    saml::NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Trust");

    try {
        if (!saml::XML::isElementNamed(m_root,::XML::TRUST_NS,SHIB_L(Trust))) {
            log.error("Construction requires a valid trust file: (trust:Trust as root element)");
            throw TrustException("Construction requires a valid trust file: (trust:Trust as root element)");
        }

        // Loop over the KeyAuthority elements.
        DOMNodeList* nlist=m_root->getElementsByTagNameNS(::XML::TRUST_NS,SHIB_L(KeyAuthority));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++) {
            auto_ptr<KeyAuthority> ka(new KeyAuthority());
            
            const DOMElement* e=static_cast<DOMElement*>(nlist->item(i));
            const XMLCh* depth=e->getAttributeNS(NULL,SHIB_L(VerifyDepth));
            if (depth && *depth)
                ka->m_depth=XMLString::parseInt(depth);
            
            const DOMElement* k_child=saml::XML::getLastChildElement(e,saml::XML::XMLSIG_NS,L(KeyInfo));
            if (!k_child) {
                log.error("ignoring KeyAuthority element with no ds:KeyInfo");
                continue;
            }
            const DOMElement* badkeyname=saml::XML::getFirstChildElement(k_child,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            if (badkeyname) {
                log.error("ignoring KeyAuthority element with embedded ds:KeyName, these must appear only outside of ds:KeyInfo");
                continue;
            }
            
            // Very rudimentary, grab up all the in-band X509Certificate elements, and flatten into one list.
            DOMNodeList* certlist=k_child->getElementsByTagNameNS(saml::XML::XMLSIG_NS,L(X509Certificate));
            for (unsigned int j=0; certlist && j<certlist->getLength(); j++) {
                auto_ptr_char blob(certlist->item(j)->getFirstChild()->getNodeValue());
                X509* x=B64_to_X509(blob.get());
                if (x)
                    ka->m_certs.push_back(x);
                else
                    log.error("unable to create certificate from inline X509Certificate data");
            }

            // Now look for externally referenced objects.
            certlist=k_child->getElementsByTagNameNS(saml::XML::XMLSIG_NS,SHIB_L(RetrievalMethod));
            for (unsigned int k=0; certlist && k<certlist->getLength(); k++) {
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
                    log.error("unable to create certificate from externally referenced file");
                }
            }

            // Very rudimentary, grab up all the in-band X509CRL elements, and flatten into one list.
            certlist=k_child->getElementsByTagNameNS(saml::XML::XMLSIG_NS,SHIB_L(X509CRL));
            for (unsigned int r=0; certlist && r<certlist->getLength(); r++) {
                auto_ptr_char blob(certlist->item(r)->getFirstChild()->getNodeValue());
                X509_CRL* x=B64_to_CRL(blob.get());
                if (x)
                    ka->m_crls.push_back(x);
                else
                    log.warn("unable to create CRL from inline X509CRL data");
            }

            KeyAuthority* ka2=ka.release();
            m_keyauths.push_back(ka2);
            
            // Now map the ds:KeyName values to the list of certs.
            bool wildcard=true;
            DOMElement* sub=saml::XML::getFirstChildElement(e,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            while (sub) {
                const XMLCh* name=sub->getFirstChild()->getNodeValue();
                if (name && *name) {
                    wildcard=false;
#ifdef HAVE_GOOD_STL
                    m_authMap[name]=ka2;
#else
                    ka2->m_subjects.push_back(name);
#endif
                }
                sub=saml::XML::getNextSiblingElement(sub,saml::XML::XMLSIG_NS,SHIB_L(KeyName));
            }
            
            // If no Subjects, this is a catch-all binding.
            if (wildcard) {
                if (!m_wildcard) {
                    log.warn("found a wildcard KeyAuthority element, make sure this is what you intend");
                    m_wildcard=ka2;
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
            try {
                if (!KIL->loadListFromXML(kidom))
                    log.error("skipping ds:KeyInfo element (%d) containing unsupported children",count);
            }
            catch (XSECCryptoException& xe) {
                log.error("unable to process ds:KeyInfo element (%d): %s",count,xe.getMsg());
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
        this->~XMLTrustImpl();
        throw;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("Unexpected error while parsing trust configuration");
        this->~XMLTrustImpl();
        throw;
    }
#endif
}

XMLTrustImpl::~XMLTrustImpl()
{
    for_each(m_keyauths.begin(),m_keyauths.end(),cleanup<KeyAuthority>);
    for_each(m_keybinds.begin(),m_keybinds.end(),cleanup<DSIGKeyInfoList>);
}

XMLTrust::XMLTrust(const DOMElement* e) : ReloadableXMLFile(e), m_delegate(NULL)
{
    static const XMLCh resolver[] =
    { chLatin_K, chLatin_e, chLatin_y, chLatin_I, chLatin_n, chLatin_f, chLatin_o,
      chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull
    };

    static const XMLCh _type[] =
    { chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };

    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Trust");

    // Find any KeyResolver plugins.
    DOMElement* child=saml::XML::getFirstChildElement(e);
    while (child) {
        if (!XMLString::compareString(resolver,child->getLocalName()) && child->hasAttributeNS(NULL,_type)) {
            try {
                auto_ptr_char temp(child->getAttributeNS(NULL,_type));
                m_resolvers.push_back(KeyInfoResolver::getInstance(temp.get(),child));
            }
            catch (SAMLException& ex) {
                log.error("caught SAML exception building KeyInfoResolver plugin: %s",ex.what());
            }
#ifndef _DEBUG
            catch (...) {
                log.error("caught unknown exception building KeyInfoResolver plugin");
            }
#endif
        }
        child=saml::XML::getNextSiblingElement(child);
    }
    m_resolvers.push_back(KeyInfoResolver::getInstance(e));

    try {
        IPlugIn* plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(
            "edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust",e
            );
        m_delegate=dynamic_cast<ITrust*>(plugin);
        if (!m_delegate) {
            delete plugin;
            log.error("plugin was not a trust provider");
            throw UnsupportedExtensionException("Legacy trust provider requires Shibboleth trust provider in order to function.");
        }
    }
    catch (SAMLException& ex) {
        log.error("caught SAML exception building embedded trust provider: %s", ex.what());
        throw;
    }
}

XMLTrust::~XMLTrust()
{
    delete m_delegate;
    for_each(m_resolvers.begin(),m_resolvers.end(),cleanup<KeyInfoResolver>);
}

static int error_callback(int ok, X509_STORE_CTX* ctx)
{
    if (!ok)
        Category::getInstance("OpenSSL").error("path validation failure: %s", X509_verify_cert_error_string(ctx->error));
    return ok;
}

bool XMLTrust::validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName)
{
    // The delegated trust plugin handles path validation with metadata extensions.
    // We only take over if the legacy format has to kick in.
    if (m_delegate->validate(certEE,certChain,role,checkName))
        return true;

#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Trust");

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
                if (!_stricmp(n->c_str(),subjectstr.c_str()) || !_stricmp(n->c_str(),subjectstr2.c_str())) {
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
                                if (!_strnicmp(altptr,n->c_str(),altlen)) {
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
                            if (!_stricmp(buf,n->c_str())) {
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

    lock();
    try {
        XMLTrustImpl* impl=dynamic_cast<XMLTrustImpl*>(getImplementation());
    
        // Build a list of the names to match. We include any named KeyDescriptors, and the provider ID and its groups.
        vector<const XMLCh*> names;
        Iterator<const IKeyDescriptor*> kdlist=role->getKeyDescriptors();
        while (kdlist.hasNext()) {
            const IKeyDescriptor* kd=kdlist.next();
            if (kd->getUse()==IKeyDescriptor::encryption)
                continue;
            DSIGKeyInfoList* kilist=kd->getKeyInfo();
            for (size_t s=0; kilist && s<kilist->getSize(); s++) {
                const XMLCh* n=kilist->item(s)->getKeyName();
                if (n)
                    names.push_back(n);
            }
        }
        names.push_back(role->getEntityDescriptor()->getId());
        const IEntitiesDescriptor* group=role->getEntityDescriptor()->getEntitiesDescriptor();
        while (group) {
            if (group->getName())
                names.push_back(group->getName());
            group=group->getEntitiesDescriptor();
        }
    
        // Now check each name.
        XMLTrustImpl::KeyAuthority* kauth=NULL;
        for (vector<const XMLCh*>::const_iterator name=names.begin(); !kauth && name!=names.end(); name++) {
#ifdef HAVE_GOOD_STL
            XMLTrustImpl::AuthMap::const_iterator c=impl->m_authMap.find(*name);
            if (c!=impl->m_authMap.end()) {
                kauth=c->second;
                if (log.isInfoEnabled()) {
                    auto_ptr_char temp(*name);
                    log.info("KeyAuthority match on %s",temp.get());
                }
            }
#else
            // Without a decent STL, we trade-off the transcoding by doing a linear search.
            for (vector<XMLTrustImpl::KeyAuthority*>::const_iterator keyauths=impl->m_keyauths.begin(); !kauth && keyauths!=impl->m_keyauths.end(); keyauths++) {
                for (vector<const XMLCh*>::const_iterator subs=(*keyauths)->m_subjects.begin(); !kauth && subs!=(*keyauths)->m_subjects.end(); subs++) {
                    if (!XMLString::compareString(*name,*subs)) {
                        kauth=*keyauths;
                        if (log.isInfoEnabled()) {
                            auto_ptr_char temp(*name);
                            log.info("KeyAuthority match on %s",temp.get());
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
                log.warn("no KeyAuthority found to validate SSL connection, leaving it alone");
                return false;
            }
        }
    
        log.debug("performing certificate path validation...");

        // If we have a match, use the associated keyauth.
        X509_STORE* store=kauth->getX509Store();
        if (store) {
            STACK_OF(X509)* untrusted=sk_X509_new_null();
            certChain.reset();
            while (certChain.hasNext())
                sk_X509_push(untrusted,(X509*)certChain.next());

            // This contains the state of the validate operation.
            X509_STORE_CTX ctx;

            // AFAICT, EE and untrusted are passed in but not owned by the ctx.
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
            if (X509_STORE_CTX_init(&ctx,store,(X509*)certEE,untrusted)!=1) {
                log_openssl();
                log.error("unable to initialize X509_STORE_CTX");
                X509_STORE_free(store);
                sk_X509_free(untrusted);
                unlock();
                return false;
            }
#else
            X509_STORE_CTX_init(&ctx,store,(X509*)certEE,untrusted);
#endif
            X509_STORE_CTX_set_depth(&ctx,100);    // handle depth below
            X509_STORE_CTX_set_verify_cb(&ctx,error_callback);
            
            int ret=X509_verify_cert(&ctx);
            if (ret==1) {
                // Now see if the depth was acceptable by counting the number of intermediates.
                int depth=sk_X509_num(ctx.chain)-2;
                if (kauth->m_depth < depth) {
                    log.error(
                        "certificate chain was too long (%d intermediates, only %d allowed)",
                        (depth==-1) ? 0 : depth,
                        kauth->m_depth
                        );
                    ret=0;
                }
            }
            
            // Clean up...
            X509_STORE_CTX_cleanup(&ctx);
            X509_STORE_free(store);

            if (ret==1) {
                log.info("successfully validated certificate chain");
                unlock();
                return true;
            }
        }
    }
    catch (...) {
        unlock();
        throw;
    }
    unlock();
    return false;
}

bool XMLTrust::validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator)
{
    // The delegated trust plugin handles metadata keys and use of metadata extensions.
    // If it fails to find an inline key in metadata, then it will branch off to the
    // extended version and verify the token using the certificates inside it. At that
    // point, control will pass to the other virtual function above and we can handle
    // legacy KeyAuthority rules that way.
    if (m_delegate->validate(token,role,certValidator ? certValidator : this))
        return true;

#ifdef _DEBUG
    saml::NDC ndc("validate");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Trust");

    lock();
    try {
        XMLTrustImpl* impl=dynamic_cast<XMLTrustImpl*>(getImplementation());

        // If we actually make it this far, the only case we're handling directly
        // is an inline key in the old trust file format. Build a list of key names
        // which will be used to find matching rules.
        vector<const XMLCh*> names;
        
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
                if (n)
                    names.push_back(n);
            }
        }
        names.push_back(role->getEntityDescriptor()->getId());

        log.debug("checking for keys in trust file");
        DSIGKeyInfoList* KIL=NULL;
        for (vector<const XMLCh*>::const_iterator name=names.begin(); !KIL && name!=names.end(); name++) {
#ifdef HAVE_GOOD_STL
            XMLTrustImpl::BindMap::const_iterator c=impl->m_bindMap.find(*name);
            if (c!=impl->m_bindMap.end()) {
                KIL=c->second;
                if (log.isInfoEnabled()) {
                    auto_ptr_char temp(*name);
                    log.info("KeyInfo match on %s",temp.get());
                }
            }
#else
            // Without a decent STL, we trade-off the transcoding by doing a linear search.
            for (vector<DSIGKeyInfoList*>::const_iterator keybinds=impl->m_keybinds.begin(); !KIL && keybinds!=impl->m_keybinds.end(); keybinds++) {
                for (size_t s=0; !KIL && s<(*keybinds)->getSize(); s++) {
                    if (!XMLString::compareString(*name,(*keybinds)->item(s)->getKeyName())) {
                        KIL=*keybinds;
                        if (log.isInfoEnabled()) {
                            auto_ptr_char temp(*name);
                            log.info("KeyInfo match on %s",temp.get());
                        }
                    }
                }
            }
#endif
        }
        
        if (KIL) {
            // Any inline KeyInfo should ostensibly resolve to a key we can try.
            Iterator<KeyInfoResolver*> resolvers(m_resolvers);
            while (resolvers.hasNext()) {
                XSECCryptoKey* key=((XSECKeyInfoResolver*)*resolvers.next())->resolveKey(KIL);
                if (key) {
                    log.debug("resolved key, trying it...");
                    try {
                        token.verify(key);
                        unlock();
                        log.info("token verified with KeyInfo, nothing more to verify");
                        return true;
                    }
                    catch (SAMLException& e) {
                        unlock();
                        log.warn("verification with inline key failed: %s", e.what());
                        return false;
                    }
                }
            }
            log.warn("KeyInfo in trust provider did not resolve to a key");
        }
    }
    catch (...) {
        unlock();
        throw;
    }       

    unlock();
    return false;
}
