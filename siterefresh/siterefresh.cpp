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

/* siterefresh.cpp - command-line tool to refresh and verify metadata

   Scott Cantor
   5/12/03

   $Id$
*/

#include <shib-target/shib-target.h>

#include <fstream>
#include <log4cpp/Category.hh>
#include <log4cpp/OstreamAppender.hh>
#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/framework/StdInInputSource.hpp>
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

void verifySignature(DOMDocument* doc, DOMNode* sigNode, const char* cert=NULL)
{
    Category& log=Category::getInstance("siterefresh");
    static const XMLCh ID[]={chLatin_I, chLatin_D, chNull};

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
                if (!URI || !*URI || (*URI==chPound &&
                        !XMLString::compareString(&URI[1],static_cast<DOMElement*>(sigNode->getParentNode())->getAttributeNS(NULL,ID)))) {
                    DSIGTransformList* tlist=ref->getTransforms();
                    for (unsigned int i=0; tlist && i<tlist->getSize(); i++) {
                        if (tlist->item(i)->getTransformType()==TRANSFORM_ENVELOPED_SIGNATURE)
                            valid=true;
                        else if (tlist->item(i)->getTransformType()!=TRANSFORM_EXC_C14N) {
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
            // Load the certificate, stripping the header and trailer.
            string certbuf,line;
            auto_ptr<OpenSSLCryptoX509> x509(new OpenSSLCryptoX509());
            bool sawheader=false;
            ifstream infile(cert);
            while (!getline(infile,line).fail()) {
                if (line.find("CERTIFICATE-----")==string::npos) {
                    if (sawheader)
                        certbuf+=line + '\n';
                }
                else
                    sawheader=true;
            }
            x509->loadX509Base64Bin(certbuf.data(),certbuf.length());
            sig->setSigningKey(x509->clonePublicKey());
        }
        else {
            log.warn("verifying with key inside signature, this is a sanity check but provides no security");
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

    if (verify && !cert_param) {
        cout << "usage: " << argv[0] << endl <<
            "\t--url <URL of metadata>" << endl <<
            "\t--noverify OR --cert <PEM Certificate>" << endl <<
            "\t[--out <pathname to copy data to>]" << endl <<
            "\t[--schema <schema path>]" << endl <<
            "\t[--rootns <root element XML namespace>]" << endl <<
            "\t[--rootname <root element name>]" << endl;
        return -100;
    }

    static const XMLCh Trust[] = { chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chNull };
    static const XMLCh SiteGroup[] =
    { chLatin_S, chLatin_i, chLatin_t, chLatin_e, chLatin_G, chLatin_r, chLatin_o, chLatin_u, chLatin_p, chNull };
    static const XMLCh EntitiesDescriptor[] =
    { chLatin_E, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_i, chLatin_e, chLatin_s,
      chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull };
    static const XMLCh EntityDescriptor[] =
    { chLatin_E, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_y,
      chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull };

    Category::setRootPriority(Priority::WARN);
    Category::getRoot().addAppender(new OstreamAppender("default",&cerr));
    Category& log=Category::getInstance("siterefresh");
    conf.schema_dir=path ? path : SHIB_SCHEMAS;
    if (!conf.init())
        return -10;

    saml::XML::registerSchema(Constants::SHIB_NS,SHIB_SCHEMA_ID);
    saml::XML::registerSchema(TRUST_NS,TRUST_SCHEMA_ID);
    saml::XML::registerSchema(shibtarget::XML::SAML2META_NS,shibtarget::XML::SAML2META_SCHEMA_ID);
    saml::XML::registerSchema(shibtarget::XML::SAML2ASSERT_NS,shibtarget::XML::SAML2ASSERT_SCHEMA_ID);
    saml::XML::registerSchema(shibtarget::XML::XMLENC_NS,shibtarget::XML::XMLENC_SCHEMA_ID);

    try {
        // Parse the specified document.
        saml::XML::Parser p;
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        DOMDocument* doc=NULL;
        if (url_param && *url_param) {
            URLInputSource src(base,url_param);
            Wrapper4InputSource dsrc(&src,false);
            doc=p.parse(dsrc);
        }
        else {
            StdInInputSource src;
            Wrapper4InputSource dsrc(&src,false);
            doc=p.parse(dsrc);
        }
    
        // Check root element.
        if (ns_param && name_param) {
            auto_ptr_XMLCh ns(ns_param);
            auto_ptr_XMLCh name(name_param);
            if (!saml::XML::isElementNamed(doc->getDocumentElement(),ns.get(),name.get()))
                throw MalformedException(string("Root element does not match specified QName of {") + ns_param + "}:" + name_param);
        }
        else if (!saml::XML::isElementNamed(doc->getDocumentElement(),Constants::SHIB_NS,SiteGroup) &&
                 !saml::XML::isElementNamed(doc->getDocumentElement(),shibtarget::XML::SAML2META_NS,EntitiesDescriptor) &&
                 !saml::XML::isElementNamed(doc->getDocumentElement(),shibtarget::XML::SAML2META_NS,EntityDescriptor) &&
                 !saml::XML::isElementNamed(doc->getDocumentElement(),TRUST_NS,Trust))
            throw MalformedException("Root element does not signify a known metadata or trust format");

        // Verify the "root" signature.
        DOMElement* rootSig=saml::XML::getFirstChildElement(doc->getDocumentElement(),saml::XML::XMLSIG_NS,L(Signature));
        if (verify) {
            if (rootSig) {
                verifySignature(doc,rootSig,cert_param);
            }
            else {
                doc->release();
                log.error("unable to locate root signature to verify in document");
                throw InvalidCryptoException("Verification implies that the document must be signed");
            }
        }
        else if (rootSig) {
            log.warn("verification of signer disabled, make sure you trust the source of this file!");
            verifySignature(doc,rootSig,cert_param);
        }
        else {
            log.warn("verification disabled, and file is unsigned!");
        }

        // Verify all signatures.
        DOMNodeList* siglist=doc->getElementsByTagNameNS(saml::XML::XMLSIG_NS,L(Signature));
        for (unsigned int i=0; siglist && i<siglist->getLength(); i++)
            verifySignature(doc,siglist->item(i),cert_param);

        if (out_param) {
            // Output the data to the specified file.
            ofstream outfile(out_param);
            outfile << *(doc->getDocumentElement());
        }
        else
            cout << *(doc->getDocumentElement());
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
