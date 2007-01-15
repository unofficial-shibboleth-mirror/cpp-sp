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

#include <fstream>
#include <shib-target/shib-target.h>

#include <shibsp/exceptions.h>
#include <shibsp/SPConfig.h>

using namespace shibsp;
using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace std;

int main(int argc,char* argv[])
{
    char* a_param=NULL;
    char* r_param=NULL;
    char* f_param=NULL;
    char* path=NULL;
    char* config=NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-c") && i+1<argc)
            config=argv[++i];
        else if (!strcmp(argv[i],"-d") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"-r") && i+1<argc)
            r_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            f_param=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            a_param=argv[++i];
    }

    if (!r_param || !f_param) {
        cerr << "usage: posttest -f <file> -r <recipient URL> [-a <application_id> -d <schema path> -c <config>]" << endl;
        exit(0);
    }
    
    if (!path)
        path=getenv("SHIBSCHEMAS");
    if (!path)
        path=SHIB_SCHEMAS;
    if (!config)
        config=getenv("SHIBCONFIG");
    if (!config)
        config=SHIB_CONFIG;
    if (!a_param)
        a_param="default";

    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    SPConfig::getConfig().setFeatures(
        SPConfig::Listener |
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::OutOfProcess
        );
    if (!conf.init(path) || !conf.load(config))
        return -10;

    try {
        string buf;
        ifstream is(f_param);
        char ch;
        is >> ch;
        while (!is.fail()) {
            buf+=ch;
            is >> ch;
        }

        auto_ptr_XMLCh recip(r_param);

        ServiceProvider* sp=SPConfig::getConfig().getServiceProvider();
        xmltooling::Locker locker(sp);

        const IApplication* app=dynamic_cast<const IApplication*>(sp->getApplication(a_param));
        if (!app) {
            throw ConfigurationException("Unable to locate application for new session, deleted?");
        }

        SAMLBrowserProfile::BrowserProfileResponse bpr=
            app->getBrowserProfile()->receive(buf.c_str(), recip.get(), NULL, 1);

        cout << "Success!" << endl;
        bpr.clear();
    }
    catch(exception& e) {
        cerr << "caught an exception: " << e.what() << endl;
    }

    conf.shutdown();
    return 0;
}
