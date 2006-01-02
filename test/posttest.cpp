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

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include "../shib/shib.h"
#include <sstream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;
using namespace saml;
using namespace shibboleth;

int main(int argc,char* argv[])
{
    SAMLConfig& conf1=SAMLConfig::getConfig();
    ShibConfig& conf2=ShibConfig::getConfig();
    char* path="";
    char* key="";

    for (int i=1; i<argc; i++)
    {
        if (!strcmp(argv[i],"-d") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"-k") && i+1<argc)
            key=argv[++i];
    }

    conf1.schema_dir=path;
    if (!conf1.init())
        cerr << "unable to initialize SAML runtime" << endl;

    if (!conf2.init())
        cerr << "unable to initialize Shibboleth runtime" << endl;

    try
    {

        DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(NULL);
        DOMDocument* dummydoc=impl->createDocument();
        DOMElement* dummy = dummydoc->createElementNS(NULL,L(Request));
        static const XMLCh url[] = { chLatin_u, chLatin_r, chLatin_l, chNull };
        auto_ptr_XMLCh src("/opt/shibboleth/etc/shibboleth/sites.xml");
        dummy->setAttributeNS(NULL,url,src.get());

        IMetadata* metadatas[1];
        metadatas[0]=dynamic_cast<IMetadata*>(conf1.getPlugMgr().newPlugin("edu.internet2.middleware.shibboleth.provider.XMLMetadata",dummy));
        dummydoc->release();
        ArrayIterator<IMetadata*> sites(metadatas,1);
        
        Metadata m(sites);

        auto_ptr<XMLCh> recip(XMLString::transcode("https://shib2.internet2.edu/shib/SHIRE"));
        ShibBrowserProfile p (sites,EMPTY(ITrust*));

        char ch;
        string buf;
        cin >> ch;
        while (!cin.fail())
        {
            buf+=ch;
            cin >> ch;
        }

        SAMLBrowserProfile::BrowserProfileResponse bpr=p.receive(buf.c_str(),recip.get(),NULL);
        cout << "Consumed Response: " << endl << *bpr.response << endl;
        bpr.clear();
    }
    catch(SAMLException& e)
    {
        cerr << "caught a SAML exception: " << e << endl;
    }
    catch(XMLException& e)
    {
        cerr << "caught an XML exception: "; xmlout(cerr,e.getMessage()); cerr << endl;
    }
    catch(...)
    {
        cerr << "caught an unknown exception" << endl;
    }

    conf2.term();
    conf1.term();
    return 0;
}
