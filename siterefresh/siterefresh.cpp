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

/* siterefresh.cpp - command-line tool to refresh and verify metadata

   Scott Cantor
   5/12/03

   $Id$
*/

#include "../shib-target/shib-target.h"

#include <fstream>
#include <log4cpp/Category.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>
#include <xsec/enc/XSECKeyInfoResolverDefault.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/dsig/DSIGTransformC14n.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGTransformList.hpp>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace log4cpp;

void verifySignature(DOMDocument* doc, DOMElement* sigNode, const char* cert=NULL)
{
    Category& log=Category::getInstance("siterefresh");

    // Load the signature.
    XSECProvider prov;
    DSIGSignature* sig=NULL;
    try {
        sig=prov.newSignatureFromDOM(doc,sigNode);
        sig->load();

        bool valid=false;

        // Verify the signature coverage.
        DSIGReferenceList* refs=sig->getReferenceList();
        if (sig->getSignatureMethod()==SIGNATURE_RSA && refs && refs->getSize()==1) {
            DSIGReference* ref=refs->item(0);
            if (ref) {
                const XMLCh* URI=ref->getURI();
                if (URI==NULL || *URI==0) {
                    DSIGTransformList* tlist=ref->getTransforms();
                    for (int i=0; tlist && i<tlist->getSize(); i++) {
                        if (tlist->item(i)->getTransformType()==TRANSFORM_ENVELOPED_SIGNATURE)
                            valid=true;
                        else if (tlist->item(i)->getTransformType()!=TRANSFORM_EXC_C14N &&
                                 tlist->item(i)->getTransformType()!=TRANSFORM_C14N) {
                            valid=false;
                            break;
                        }
                    }
                }
            }
        }
    
        if (!valid) {
            log.error("detected an invalid signature profile");
            throw InvalidCryptoException("detected an invalid signature profile");
        }

        if (cert) {
            // Load the certificate, stripping the first and last lines.
            string certbuf,line;
            auto_ptr<OpenSSLCryptoX509> x509(new OpenSSLCryptoX509());
            ifstream infile(cert);
            while (!getline(infile,line).fail())
                if (line.find("CERTIFICATE")==string::npos)
                    certbuf+=line + '\n';
            x509->loadX509Base64Bin(certbuf.data(),certbuf.length());
            sig->setSigningKey(x509->clonePublicKey());
        }
        else {
            XSECKeyInfoResolverDefault resolver;
            sig->setKeyInfoResolver(resolver.clone());
        }
        
        if (!sig->verify()) {
            log.error("detected an invalid signature value");
            throw InvalidCryptoException("detected an invalid signature value");
        }

        prov.releaseSignature(sig);
    }
    catch(...) {
        if (sig)
            prov.releaseSignature(sig);
        throw;
    }
}

int main(int argc,char* argv[])
{
    int ret=0;
    SAMLConfig& conf=SAMLConfig::getConfig();
    bool verify=true;
    char* url_param=NULL;
    char* cert_param=NULL;
    char* out_param=NULL;
    char* path=getenv("SHIBSCHEMAS");
    char* ns_param=NULL;
    char* name_param=NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"--schema") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"--url") && i+1<argc)
            url_param=argv[++i];
        else if (!strcmp(argv[i],"--noverify"))
            verify=false;
        else if (!strcmp(argv[i],"--cert") && i+1<argc)
            cert_param=argv[++i];
        else if (!strcmp(argv[i],"--out") && i+1<argc)
            out_param=argv[++i];
        else if (!strcmp(argv[i],"--rootns") && i+1<argc)
            ns_param=argv[++i];
        else if (!strcmp(argv[i],"--rootname") && i+1<argc)
            name_param=argv[++i];
    }

    if (!url_param || !out_param || (verify && !cert_param)) {
        cout << "usage: " << argv[0] << endl <<
            "\t--url <URL of metadata>" << endl <<
            "\t--out <pathname to copy data to>" << endl <<
            "\t--noverify OR --cert <PEM Certificate>" << endl <<
            "\t[--schema <schema path>]" << endl <<
            "\t[--rootns <root element XML namespace>]" << endl <<
            "\t[--rootname <root element name>]" << endl;
        return -100;
    }

    Category& log=Category::getInstance("siterefresh");
    Category::setRootPriority(Priority::WARN);
    conf.schema_dir=path ? path : SHIB_SCHEMAS;
    if (!conf.init())
        return -10;

    static const XMLCh Trust[] = { chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chNull };
    static const XMLCh SiteGroup[] =
    { chLatin_S, chLatin_i, chLatin_t, chLatin_e, chLatin_G, chLatin_r, chLatin_o, chLatin_u, chLatin_p, chNull };

    static const XMLCh TRUST_NS[] = // urn:mace:shibboleth:trust:1.0
    { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
      chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
      chLatin_t, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chColon, chDigit_1, chPeriod, chDigit_0, chNull
    };

    static const XMLCh TRUST_SCHEMA_ID[] = // shibboleth-trust-1.0.xsd
    { chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chDash,
      chLatin_t, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chDash, chDigit_1, chPeriod, chDigit_0, chPeriod,
      chLatin_x, chLatin_s, chLatin_d, chNull
    };

    static const XMLCh SHIB_SCHEMA_ID[] = // shibboleth.xsd
    { chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chPeriod,
      chLatin_x, chLatin_s, chLatin_d, chNull
    };

    saml::XML::registerSchema(shibboleth::Constants::SHIB_NS,SHIB_SCHEMA_ID);
    saml::XML::registerSchema(TRUST_NS,TRUST_SCHEMA_ID);

    try {
        // Parse the specified document.
        saml::XML::Parser p;
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,url_param);
        Wrapper4InputSource dsrc(&src,false);
        DOMDocument* doc=p.parse(dsrc);

        // Check root element.
        if (ns_param && name_param) {
            auto_ptr_XMLCh ns(ns_param);
            auto_ptr_XMLCh name(name_param);
            if (!saml::XML::isElementNamed(doc->getDocumentElement(),ns.get(),name.get()))
                throw MalformedException(string("Root element does not match specified QName of {") + ns_param + "}:" + name_param);
        }
        else if (!saml::XML::isElementNamed(doc->getDocumentElement(),shibboleth::Constants::SHIB_NS,SiteGroup) &&
                    !saml::XML::isElementNamed(doc->getDocumentElement(),TRUST_NS,Trust))
            throw MalformedException("Root element does not match SiteGroup or Trust");

        // If we're verifying, grab the embedded signature.
        DOMElement* n=saml::XML::getLastChildElement(doc->getDocumentElement(),saml::XML::XMLSIG_NS,L(Signature));
        if (verify) {
            if (n)
                verifySignature(doc,n,cert_param);
            else {
                doc->release();
			    log.error("unable to locate a signature to verify in document");
			    throw InvalidCryptoException("Verification implies that the document must be signed");
            }
        }
        else if (n) {
            log.warn("verification of signer disabled, make sure you trust the source of this file!");
            verifySignature(doc,n);
        }
        else {
            log.warn("verification disabled, and file is unsigned!");
        }

        // Output the data to the specified file.
        ofstream outfile(out_param);
        outfile << *(doc->getDocumentElement());

        doc->release();
    }
    catch (InvalidCryptoException&) {
        ret=-1;
    }
    catch(SAMLException& e) {
        log.errorStream() << "caught a SAML exception: " << e.what() << CategoryStream::ENDLINE;
        ret=-2;
    }
    catch(XMLException& e) {
        auto_ptr_char temp(e.getMessage());
        log.errorStream() << "caught an XML exception: " << temp.get() << CategoryStream::ENDLINE;
        ret=-3;
    }
    catch(XSECException& e) {
        auto_ptr_char temp(e.getMsg());
        log.errorStream() << "caught an XMLSec exception: " << temp.get() << CategoryStream::ENDLINE;
        ret=-4;
    }
    catch(XSECCryptoException& e) {
        log.errorStream() << "caught an XMLSecCrypto exception: " << e.getMsg() << CategoryStream::ENDLINE;
        ret=-5;
    }
    catch(...) {
        log.errorStream() << "caught an unknown exception" << CategoryStream::ENDLINE;
        ret=-6;
    }

    conf.term();
    return ret;
}
