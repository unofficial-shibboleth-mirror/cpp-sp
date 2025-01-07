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
 * shibsp/attribute/Attribute.cpp
 *
 * A resolved attribute.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/SimpleAttribute.h"
#include "util/SPConstants.h"

using namespace shibsp;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* SimpleAttributeFactory(DDF& in);
    SHIBSP_DLLLOCAL Attribute* ScopedAttributeFactory(DDF& in);
    SHIBSP_DLLLOCAL Attribute* BinaryAttributeFactory(DDF& in);
};

void shibsp::registerAttributeFactories()
{
    Attribute::registerFactory("", SimpleAttributeFactory);
    Attribute::registerFactory("Simple", SimpleAttributeFactory);
    Attribute::registerFactory("Binary", BinaryAttributeFactory);
    Attribute::registerFactory("Scoped", ScopedAttributeFactory);
}

map<string,Attribute::AttributeFactory*> Attribute::m_factoryMap;

void Attribute::registerFactory(const char* type, AttributeFactory* factory)
{
    m_factoryMap[type] = factory;
}

void Attribute::deregisterFactory(const char* type)
{
    m_factoryMap.erase(type);
}

void Attribute::deregisterFactories()
{
    m_factoryMap.clear();
}

Attribute::Attribute(const vector<string>& ids) : m_id(ids), m_caseSensitive(true), m_internal(false)
{
}

Attribute::Attribute(DDF& in) : m_caseSensitive(in["case_insensitive"].isnull()), m_internal(!in["internal"].isnull())
{
    const char* id = in.first().name();
    if (id && *id)
        m_id.push_back(id);
    else
        throw AttributeException("No id found in marshalled attribute content.");
    DDF aliases = in["aliases"];
    if (aliases.islist()) {
        DDF alias = aliases.first();
        while (alias.isstring()) {
            m_id.push_back(alias.string());
            alias = aliases.next();
        }
    }
}

Attribute::~Attribute()
{
}

const char* Attribute::getId() const
{
    return m_id.front().c_str();
}

const vector<string>& Attribute::getAliases() const
{
    return m_id;
}

vector<string>& Attribute::getAliases()
{
    return m_id;
}

void Attribute::setCaseSensitive(bool caseSensitive)
{
    m_caseSensitive = caseSensitive;
}

void Attribute::setInternal(bool internal)
{
    m_internal = internal;
}

bool Attribute::isCaseSensitive() const
{
    return m_caseSensitive;
}

bool Attribute::isInternal() const
{
    return m_internal;
}

size_t Attribute::valueCount() const
{
    return m_serialized.size();
}

const vector<string>& Attribute::getSerializedValues() const
{
    return m_serialized;
}

const char* Attribute::getString(size_t index) const
{
    return m_serialized[index].c_str();
}

const char* Attribute::getScope(size_t index) const
{
    return nullptr;
}

void Attribute::removeValue(size_t index)
{
    if (index < m_serialized.size())
        m_serialized.erase(m_serialized.begin() + index);
}

DDF Attribute::marshall() const
{
    DDF ddf(nullptr);
    ddf.structure().addmember(m_id.front().c_str()).list();
    if (!m_caseSensitive)
        ddf.addmember("case_insensitive");
    if (m_internal)
        ddf.addmember("internal");
    if (m_id.size() > 1) {
        DDF alias;
        DDF aliases = ddf.addmember("aliases").list();
        for (std::vector<std::string>::const_iterator a = m_id.begin() + 1; a != m_id.end(); ++a) {
            alias = DDF(nullptr).string(a->c_str());
            aliases.add(alias);
        }
    }
    return ddf;
}

Attribute* Attribute::unmarshall(DDF& in)
{
    map<string,AttributeFactory*>::const_iterator i = m_factoryMap.find(in.name() ? in.name() : "");
    if (i == m_factoryMap.end())
        throw AttributeException(string("No registered factory for Attribute of type ") + in.name());
    return (i->second)(in);
}
