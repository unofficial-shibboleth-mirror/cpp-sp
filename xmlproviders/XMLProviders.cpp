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

/* XMLProviders.cpp - bootstraps the extension library

   Scott Cantor
   2/14/04

   $History:$
*/

#ifdef WIN32
# define XML_EXPORTS __declspec(dllexport)
#else
# define XML_EXPORTS
#endif

#include "internal.h"
#include <shib-target/shib-target.h>
#include <log4cpp/Category.hh>
#include <openssl/err.h>

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;
using namespace std;

// Metadata Factories

PlugManager::Factory TargetedIDFactory;
PlugManager::Factory XMLCredentialsFactory;
PlugManager::Factory XMLAAPFactory;
PlugManager::Factory XMLAccessControlFactory;

extern "C" int XML_EXPORTS saml_extension_init(void*)
{
    // Register extension schemas.
    saml::XML::registerSchema(::XML::SHIB_NS,::XML::SHIB_SCHEMA_ID);

    // Register metadata factories (some are legacy aliases)
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.common.provider.TargetedIDFactory",&TargetedIDFactory);
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.common.Credentials",&XMLCredentialsFactory);
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.aap.provider.XMLAAP",&XMLAAPFactory);
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.target.provider.XMLAAP",&XMLAAPFactory);
    conf.getPlugMgr().regFactory(shibtarget::XML::XMLAccessControlType,&XMLAccessControlFactory);

    return 0;
}

extern "C" void XML_EXPORTS saml_extension_term()
{
    // Unregister metadata factories
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.common.provider.TargetedIDFactory");
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.common.Credentials");
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.aap.provider.XMLAAP");
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.target.provider.XMLAAP");
    conf.getPlugMgr().unregFactory(shibtarget::XML::XMLAccessControlType);
}
