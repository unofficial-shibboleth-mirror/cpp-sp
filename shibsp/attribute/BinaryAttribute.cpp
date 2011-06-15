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
 * BinaryAttribute.cpp
 *
 * An Attribute whose values are binary data.
 */

#include "internal.h"
#include "attribute/BinaryAttribute.h"

#include <xercesc/util/Base64.hpp>

using namespace shibsp;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* BinaryAttributeFactory(DDF& in) {
        return new BinaryAttribute(in);
    }
};

BinaryAttribute::BinaryAttribute(const vector<string>& ids) : Attribute(ids)
{
}

BinaryAttribute::BinaryAttribute(DDF& in) : Attribute(in)
{
    xsecsize_t x;
    DDF val = in.first().first();
    while (val.string()) {
        m_serialized.push_back(val.string());
        XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(val.string()), &x);
        if (decoded) {
            m_values.push_back(string(reinterpret_cast<char*>(decoded), x));
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
            XMLString::release(&decoded);
#else
            XMLString::release((char**)&decoded);
#endif
        }
        val = in.first().next();
    }
}

BinaryAttribute::~BinaryAttribute()
{
}

vector<string>& BinaryAttribute::getValues()
{
    return m_values;
}

const vector<string>& BinaryAttribute::getValues() const
{
    return m_values;
}

size_t BinaryAttribute::valueCount() const
{
    return m_values.size();
}

void BinaryAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* BinaryAttribute::getString(size_t index) const
{
    return m_values[index].c_str();
}

void BinaryAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    if (index < m_values.size())
        m_values.erase(m_values.begin() + index);
}

const vector<string>& BinaryAttribute::getSerializedValues() const
{
    xsecsize_t len;
    XMLByte *pos, *pos2;
    if (m_serialized.empty()) {
        for (vector<string>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
            XMLByte* enc = Base64::encode(reinterpret_cast<const XMLByte*>(i->data()), i->size(), &len);
            if (enc) {
                for (pos=enc, pos2=enc; *pos2; pos2++)
                    if (isgraph(*pos2))
                        *pos++=*pos2;
                *pos=0;
                m_serialized.push_back(reinterpret_cast<char*>(enc));
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
                XMLString::release(&enc);
#else
                XMLString::release((char**)&enc);
#endif
            }
        }
    }
    return Attribute::getSerializedValues();
}

DDF BinaryAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    ddf.name("Binary");
    DDF vlist = ddf.first();
    const vector<string>& encoded = getSerializedValues();
    for (vector<string>::const_iterator i = encoded.begin(); i != encoded.end(); ++i) {
        DDF val = DDF(nullptr).string(i->c_str());
        vlist.add(val);
    }
    return ddf;
}
