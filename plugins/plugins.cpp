/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * plugins.cpp
 *
 * Extension plugins for Shibboleth SP.
 */

#include "internal.h"
#include <shibsp/SPConfig.h>
#include <shibsp/util/SPConstants.h>
#include <xmltooling/impl/AnyElement.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#ifdef WIN32
# define PLUGINS_EXPORTS __declspec(dllexport)
#else
# define PLUGINS_EXPORTS
#endif

namespace shibsp {
    PluginManager<AccessControl,string,const DOMElement*>::Factory TimeAccessControlFactory;
#ifndef SHIBSP_LITE
# ifdef HAVE_GSSAPI_NAMINGEXTS
    PluginManager<AttributeExtractor,string,const DOMElement*>::Factory GSSAPIExtractorFactory;
# endif
    PluginManager<AttributeResolver,string,const DOMElement*>::Factory TemplateAttributeResolverFactory;
    PluginManager<AttributeResolver,string,const DOMElement*>::Factory TransformAttributeResolverFactory;
    PluginManager<AttributeResolver,string,const DOMElement*>::Factory UpperCaseAttributeResolverFactory;
    PluginManager<AttributeResolver,string,const DOMElement*>::Factory LowerCaseAttributeResolverFactory;
#endif
};

extern "C" int PLUGINS_EXPORTS xmltooling_extension_init(void*)
{
    SPConfig& conf = SPConfig::getConfig();
    conf.AccessControlManager.registerFactory("Time", TimeAccessControlFactory);
#ifndef SHIBSP_LITE
# ifdef HAVE_GSSAPI_NAMINGEXTS
    conf.AttributeExtractorManager.registerFactory("GSSAPI", GSSAPIExtractorFactory);
    static const XMLCh _GSSAPIName[] = UNICODE_LITERAL_10(G,S,S,A,P,I,N,a,m,e);
    static const XMLCh _GSSAPIContext[] = UNICODE_LITERAL_13(G,S,S,A,P,I,C,o,n,t,e,x,t);
    XMLObjectBuilder::registerBuilder(xmltooling::QName(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPIName), new AnyElementBuilder());
    XMLObjectBuilder::registerBuilder(xmltooling::QName(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPIContext), new AnyElementBuilder());
# endif
    conf.AttributeResolverManager.registerFactory("Template", TemplateAttributeResolverFactory);
    conf.AttributeResolverManager.registerFactory("Transform", TransformAttributeResolverFactory);
    conf.AttributeResolverManager.registerFactory("UpperCase", UpperCaseAttributeResolverFactory);
    conf.AttributeResolverManager.registerFactory("LowerCase", LowerCaseAttributeResolverFactory);
#endif
    return 0;   // signal success
}

extern "C" void PLUGINS_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
