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
 * NameIDAttribute.cpp
 *
 * An Attribute whose values are derived from or mappable to a SAML NameID.
 */

#include "internal.h"
#include "ServiceProvider.h"
#include "attribute/NameIDAttribute.h"
#include "remoting/ListenerService.h"

#include <boost/algorithm/string/trim.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/security/SecurityHelper.h>

using namespace shibsp;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL Attribute* NameIDAttributeFactory(DDF& in) {
        return new NameIDAttribute(in);
    }
};

NameIDAttribute::NameIDAttribute(const vector<string>& ids, const char* formatter, const char* hashAlg)
    : Attribute(ids), m_formatter(formatter), m_hashAlg(hashAlg ? hashAlg : "")
{
}

NameIDAttribute::NameIDAttribute(DDF& in) : Attribute(in)
{
    DDF val = in["_formatter"];
    if (val.isstring() && val.string())
        m_formatter = val.string();
    else
        m_formatter = DEFAULT_NAMEID_FORMATTER;
    val = in["_hashalg"];
    if (val.isstring() && val.string())
        m_hashAlg = val.string();
    const char* pch;
    val = in.first().first();
    while (!val.isnull()) {
        m_values.push_back(Value());
        Value& v = m_values.back();
        // There are two serializations supported. The new one is in 2.5.1 and fixes SPPCPP-504.
        // The original is the first branch and was vulnerable to non-ASCII characters in the value.
        // Supporting both means at least minimal support for rolling upgrades if a shibd instance is
        // shared.
        if (val.name()) {
            v.m_Name = val.name();
        }
        else {
            pch = val["Name"].string();
            if (pch)
                v.m_Name = pch;
        }
        pch = val["Format"].string();
        if (pch)
            v.m_Format = pch;
        pch = val["NameQualifier"].string();
        if (pch)
            v.m_NameQualifier = pch;
        pch = val["SPNameQualifier"].string();
        if (pch)
            v.m_SPNameQualifier = pch;
        pch = val["SPProvidedID"].string();
        if (pch)
            v.m_SPProvidedID = pch;
        val = in.first().next();
    }
}

NameIDAttribute::~NameIDAttribute()
{
}

vector<NameIDAttribute::Value>& NameIDAttribute::getValues()
{
    return m_values;
}

const vector<NameIDAttribute::Value>& NameIDAttribute::getValues() const
{
    return m_values;
}

size_t NameIDAttribute::valueCount() const
{
    return m_values.size();
}

void NameIDAttribute::clearSerializedValues()
{
    m_serialized.clear();
}

const char* NameIDAttribute::getString(size_t index) const
{
    return m_values[index].m_Name.c_str();
}

const char* NameIDAttribute::getScope(size_t index) const
{
    return m_values[index].m_NameQualifier.c_str();
}

void NameIDAttribute::removeValue(size_t index)
{
    Attribute::removeValue(index);
    if (index < m_values.size())
        m_values.erase(m_values.begin() + index);
}

const vector<string>& NameIDAttribute::getSerializedValues() const
{
    if (m_serialized.empty()) {
        for (vector<Value>::const_iterator i = m_values.begin(); i != m_values.end(); ++i) {
            // This is kind of a hack, but it's a good way to reuse some code.
            XMLToolingException e(
                m_formatter,
                namedparams(
                    5,
                    "Name", i->m_Name.c_str(),
                    "Format", i->m_Format.c_str(),
                    "NameQualifier", i->m_NameQualifier.c_str(),
                    "SPNameQualifier", i->m_SPNameQualifier.c_str(),
                    "SPProvidedID", i->m_SPProvidedID.c_str()
                    )
                );
            if (m_hashAlg.empty()) {
                m_serialized.push_back(e.what());
                boost::trim(m_serialized.back());
            }
            else {
                string trimmed(e.what());
                boost::trim(trimmed);
#ifndef SHIBSP_LITE
                m_serialized.push_back(SecurityHelper::doHash(m_hashAlg.c_str(), trimmed.c_str(), strlen(e.what())));
#else
                try {
                    DDF out, in("hash");
                    DDFJanitor jin(in), jout(out);
                    in.addmember("alg").string(m_hashAlg.c_str());
                    in.addmember("data").unsafe_string(trimmed.c_str());
                    out = SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
                    if (out.isstring() && out.string())
                        m_serialized.push_back(out.string());
                }
                catch (exception& ex) {
                    Category::getInstance(SHIBSP_LOGCAT".Attribute.NameID").error("exception remoting hash operation: %s", ex.what());
                }
#endif
            }
        }
    }
    return Attribute::getSerializedValues();
}

DDF NameIDAttribute::marshall() const
{
    DDF ddf = Attribute::marshall();
    ddf.name("NameID");
    ddf.addmember("_formatter").string(m_formatter.c_str());
    if (!m_hashAlg.empty())
        ddf.addmember("_hashalg").string(m_hashAlg.c_str());
    DDF vlist = ddf.first();
    for (vector<Value>::const_iterator i=m_values.begin(); i!=m_values.end(); ++i) {
        DDF val = DDF(nullptr).structure();
        val.addmember("Name").string(i->m_Name.c_str());
        if (!i->m_Format.empty())
            val.addmember("Format").string(i->m_Format.c_str());
        if (!i->m_NameQualifier.empty())
            val.addmember("NameQualifier").string(i->m_NameQualifier.c_str());
        if (!i->m_SPNameQualifier.empty())
            val.addmember("SPNameQualifier").string(i->m_SPNameQualifier.c_str());
        if (!i->m_SPProvidedID.empty())
            val.addmember("SPProvidedID").string(i->m_SPProvidedID.c_str());
        vlist.add(val);
    }
    return ddf;
}
