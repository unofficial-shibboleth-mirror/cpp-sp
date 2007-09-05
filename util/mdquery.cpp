/*
 *  Copyright 2001-2007 Internet2
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

/**
 * mdquery.cpp
 * 
 * SAML Metadata Query tool layered on SP configuration
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/Application.h>
#include <shibsp/exceptions.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/util/SPConstants.h>
#include <saml/saml2/metadata/Metadata.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

int main(int argc,char* argv[])
{
    /*
    char* n_param=NULL;
    char* q_param=NULL;
    char* f_param=NULL;
    char* a_param=NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-n") && i+1<argc)
            n_param=argv[++i];
        else if (!strcmp(argv[i],"-q") && i+1<argc)
            q_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            f_param=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            a_param=argv[++i];
    }

    if (!n_param || !q_param) {
        cerr << "usage: samlquery -n <name> -q <IdP> [-f <format URI> -a <application id>]" << endl;
        exit(0);
    }
    if (!a_param)
        a_param="default";
    */

    char* path=getenv("SHIBSP_SCHEMAS");
    if (!path)
        path=SHIBSP_SCHEMAS;
    char* config=getenv("SHIBSP_CONFIG");
    if (!config)
        config=SHIBSP_CONFIG;

    XMLToolingConfig::getConfig().log_config(getenv("SHIBSP_LOGGING") ? getenv("SHIBSP_LOGGING") : SHIBSP_LOGGING);

    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(SPConfig::Metadata | SPConfig::OutOfProcess);
    if (!conf.init(path))
        return -10;

    try {
        static const XMLCh _path[] = UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        xercesc::DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
        xercesc::DOMElement* dummy = dummydoc->createElementNS(NULL,_path);
        auto_ptr_XMLCh src(config);
        dummy->setAttributeNS(NULL,_path,src.get());
        dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);
        conf.setServiceProvider(conf.ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
        conf.getServiceProvider()->init();
    }
    catch (exception&) {
        conf.term();
        return -20;
    }

    ServiceProvider* sp=conf.getServiceProvider();
    sp->lock();

    sp->unlock();
    conf.term();
    return 0;
}
