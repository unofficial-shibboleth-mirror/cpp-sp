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

/* siterefresh.cpp - command-line tool to refresh and verify site metadata

   Scott Cantor
   5/12/03

   $History:$
*/

#include "../shib/shib.h"

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

#ifndef DEFAULT_SCHEMA_DIR
#define DEFAULT_SCHEMA_DIR "/opt/shibboleth/etc/shibboleth/"
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace log4cpp;

void verifySignature(DOMDocument* doc, DOMElement* sigNode, const char* cert)
{
    Category& log=Category::getInstance("siterefresh");

    // Load the certificate, stripping the first and last lines.
    string certbuf,line;
    auto_ptr<OpenSSLCryptoX509> x509(new OpenSSLCryptoX509());
    ifstream infile(cert);
    while (!getline(infile,line).fail())
        if (line.find("CERTIFICATE")==string::npos)
            certbuf+=line + '\n';
    x509->loadX509Base64Bin(certbuf.data(),certbuf.length());

    // Load the signature.
    XSECProvider prov;
    DSIGSignature* sig=NULL;
    try
    {
        sig=prov.newSignatureFromDOM(doc,sigNode);
        sig->load();

        bool valid=false;

        // Verify the signature coverage.
        DSIGReferenceList* refs=sig->getReferenceList();
        if (sig->getSignatureMethod()==SIGNATURE_RSA && refs && refs->getSize()==1)
        {
            DSIGReference* ref=refs->item(0);
            if (ref)
            {
                const XMLCh* URI=ref->getURI();
                if (URI==NULL || *URI==0)
                {
                    DSIGTransformList* tlist=ref->getTransforms();
                    for (int i=0; tlist && i<tlist->getSize(); i++)
                    {
                        if (tlist->item(i)->getTransformType()==TRANSFORM_ENVELOPED_SIGNATURE)
                            valid=true;
                        else if (tlist->item(i)->getTransformType()!=TRANSFORM_EXC_C14N &&
                                 tlist->item(i)->getTransformType()!=TRANSFORM_C14N)
                        {
                            valid=false;
                            break;
                        }
                    }
                }
            }
        }
    
        if (!valid)
        {
            log.error("detected an invalid signature profile");
            throw InvalidCryptoException("detected an invalid signature profile");
        }

        sig->setSigningKey(x509->clonePublicKey());
        if (!sig->verify())
        {
            log.error("detected an invalid signature value");
            throw InvalidCryptoException("detected an invalid signature value");
        }

        prov.releaseSignature(sig);
    }
    catch(...)
    {
        if (sig)
            prov.releaseSignature(sig);
        throw;
    }
}

int main(int argc,char* argv[])
{
    int ret=0;
    SAMLConfig& conf=SAMLConfig::getConfig();
    char* url_param=NULL;
    char* cert_param=NULL;
    char* out_param=NULL;
    char* path=DEFAULT_SCHEMA_DIR;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"--schema") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"--url") && i+1<argc)
            url_param=argv[++i];
        else if (!strcmp(argv[i],"--cert") && i+1<argc)
            cert_param=argv[++i];
        else if (!strcmp(argv[i],"--out") && i+1<argc)
            out_param=argv[++i];
    }

    if (!url_param || !out_param) {
        cout << "usage: " << argv[0] << " --url <URL of metadata> --out <pathname to copy data into> [--cert <PEM Certificate> --schema <schema path>]" << endl;
        exit(0);
    }

    Category& log=Category::getInstance("siterefresh");
    Category::setRootPriority(Priority::ERROR);
    conf.schema_dir=path;
    if (!conf.init())
        return -10;

    static const XMLCh CREDS_NS[] = // urn:mace:shibboleth:credentials:1.0
    { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
      chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
      chLatin_c, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s, chColon,
      chDigit_1, chPeriod, chDigit_0, chNull
    };

    static const XMLCh CREDS_SCHEMA_ID[] = // credentials.xsd
    { chLatin_c, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s,
      chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
    };

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

    static const XMLCh SHIB_NS[] = // urn:mace:shibboleth:1.0
    { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
      chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
      chDigit_1, chPeriod, chDigit_0, chNull
    };

    static const XMLCh SHIB_SCHEMA_ID[] = // shibboleth.xsd
    { chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, 
      chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
    };

    saml::XML::registerSchema(SHIB_NS,SHIB_SCHEMA_ID);
    saml::XML::registerSchema(TRUST_NS,TRUST_SCHEMA_ID);

    try {
        // Parse the specified document.
        saml::XML::Parser p;
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,url_param);
        Wrapper4InputSource dsrc(&src,false);
        DOMDocument* doc=p.parse(dsrc);

        // If we're verifying, grab the embedded signature.
        if (cert_param) {
            DOMElement* n=saml::XML::getLastChildElement(doc->getDocumentElement(),saml::XML::XMLSIG_NS,L(Signature));
            if (n)
                verifySignature(doc,n,cert_param);
            else {
                doc->release();
			    log.error("unable to locate a signature to verify in document");
			    throw InvalidCryptoException("Verification implies that the document must be signed");
            }
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
        log.errorStream() << "caught a SAML exception: " << e << CategoryStream::ENDLINE;
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
    }
    catch(XSECCryptoException& e) {
        log.errorStream() << "caught an XMLSecCrypto exception: " << e.getMsg() << CategoryStream::ENDLINE;
    }
    catch(...) {
        log.errorStream() << "caught an unknown exception" << CategoryStream::ENDLINE;
        ret=-4;
    }

    conf.term();
    return ret;
}
