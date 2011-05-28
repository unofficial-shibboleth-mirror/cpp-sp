/*
 *  Copyright 2011 Internet2
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
using namespace std;

#ifdef WIN32
# define PLUGINS_EXPORTS __declspec(dllexport)
#else
# define PLUGINS_EXPORTS
#endif

namespace shibsp {
#ifdef HAVE_GSSAPI_NAMINGEXTS
    PluginManager<AttributeExtractor,string,const DOMElement*>::Factory GSSAPIExtractorFactory;
#endif
};

extern "C" int PLUGINS_EXPORTS xmltooling_extension_init(void*)
{
#ifdef HAVE_GSSAPI_NAMINGEXTS
    SPConfig::getConfig().AttributeExtractorManager.registerFactory("GSSAPI", GSSAPIExtractorFactory);
    static const XMLCh _GSSAPIName[] = UNICODE_LITERAL_10(G,S,S,A,P,I,N,a,m,e);
    static const XMLCh _GSSAPIContext[] = UNICODE_LITERAL_13(G,S,S,A,P,I,C,o,n,t,e,x,t);
    XMLObjectBuilder::registerBuilder(xmltooling::QName(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPIName), new AnyElementBuilder());
    XMLObjectBuilder::registerBuilder(xmltooling::QName(shibspconstants::SHIB2ATTRIBUTEMAP_NS, _GSSAPIContext), new AnyElementBuilder());
#endif
    return 0;   // signal success
}

extern "C" void PLUGINS_EXPORTS xmltooling_extension_term()
{
    // Factories normally get unregistered during library shutdown, so no work usually required here.
}
