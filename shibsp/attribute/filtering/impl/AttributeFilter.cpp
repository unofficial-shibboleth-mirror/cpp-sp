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
 * AttributeFilter.cpp
 * 
 * Engine for filtering attribute values.
 */

#include "internal.h"
#include "attribute/filtering/AttributeFilter.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<AttributeFilter,string,const DOMElement*>::Factory XMLAttributeFilterFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeFilter,string,const DOMElement*>::Factory DummyAttributeFilterFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeFilter,string,const DOMElement*>::Factory ChainingAttributeFilterFactory;
};

void SHIBSP_API shibsp::registerAttributeFilters()
{
    SPConfig& conf = SPConfig::getConfig();
    conf.AttributeFilterManager.registerFactory(XML_ATTRIBUTE_FILTER, XMLAttributeFilterFactory);
    conf.AttributeFilterManager.registerFactory(DUMMY_ATTRIBUTE_FILTER, DummyAttributeFilterFactory);
    conf.AttributeFilterManager.registerFactory(CHAINING_ATTRIBUTE_FILTER, ChainingAttributeFilterFactory);
}

AttributeFilter::AttributeFilter()
{
}

AttributeFilter::~AttributeFilter()
{
}
