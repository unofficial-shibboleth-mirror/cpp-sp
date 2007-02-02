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
 * shibsp/attribute/Attribute.cpp
 * 
 * A resolved attribute.
 */


#include "internal.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/ScopedAttribute.h"
#include "attribute/NameIDAttribute.h"

using namespace shibsp;
using namespace std;

namespace shibsp {

    Attribute* SimpleAttributeFactory(DDF& in) {
        return new SimpleAttribute(in);
    }
    
    Attribute* ScopedAttributeFactory(DDF& in) {
        return new ScopedAttribute(in);
    }
    
    Attribute* NameIDAttributeFactory(DDF& in) {
        return new NameIDAttribute(in);
    }
    
};

void shibsp::registerAttributeFactories()
{
    Attribute::registerFactory("", SimpleAttributeFactory);
    Attribute::registerFactory("simple", SimpleAttributeFactory);
    Attribute::registerFactory("scoped", ScopedAttributeFactory);
    Attribute::registerFactory("nameid", NameIDAttributeFactory);
}

std::map<std::string,Attribute::AttributeFactory*> Attribute::m_factoryMap;

Attribute* Attribute::unmarshall(DDF& in)
{
    map<string,AttributeFactory*>::const_iterator i = m_factoryMap.find(in.name() ? in.name() : "");
    if (i == m_factoryMap.end())
        throw AttributeException("No registered factory for Attribute of type ($1).", xmltooling::params(1,in.name()));
    return (i->second)(in);
}
