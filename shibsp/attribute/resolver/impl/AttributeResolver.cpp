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
 * AttributeResolver.cpp
 * 
 * The service that resolves the attributes for a particular subject.
 */

#include "internal.h"
#include "attribute/resolver/AttributeResolver.h"

#include <xercesc/dom/DOM.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<AttributeResolver,const DOMElement*>::Factory SimpleAttributeResolverFactory;
};

void SHIBSP_API shibsp::registerAttributeResolvers()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.AttributeResolverManager.registerFactory(SIMPLE_ATTRIBUTE_RESOLVER, SimpleAttributeResolverFactory);
}
