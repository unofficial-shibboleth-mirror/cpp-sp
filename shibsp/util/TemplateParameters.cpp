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
 * TemplateParameters.cpp
 * 
 * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet. 
 */

#include "internal.h"
#include "SessionCache.h"
#include "attribute/Attribute.h"
#include "util/PropertySet.h"
#include "util/TemplateParameters.h"

#include <ctime>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

TemplateParameters::TemplateParameters(const exception* e, const PropertySet* props, const Session* session)
    : m_exception(e), m_toolingException(dynamic_cast<const XMLToolingException*>(e)), m_session(session)
{
    setPropertySet(props);
}

TemplateParameters::~TemplateParameters()
{
}

void TemplateParameters::setPropertySet(const PropertySet* props)
{
    m_props = props;

    // Create a timestamp.
    time_t now = time(nullptr);
#if defined(HAVE_CTIME_R_2)
    char timebuf[32];
    m_map["now"] = ctime_r(&now,timebuf);
#elif defined(HAVE_CTIME_R_3)
    char timebuf[32];
    m_map["now"] = ctime_r(&now,timebuf,sizeof(timebuf));
#else
    m_map["now"] = ctime(&now);
#endif
    string& s = m_map["now"];
    s.erase(s.begin() + s.size() - 1);
}

const XMLToolingException* TemplateParameters::getRichException() const
{
    return m_toolingException;
}

const char* TemplateParameters::getParameter(const char* name) const
{
    if (m_exception) {
        if (!strcmp(name, "errorType"))
            return m_toolingException ? m_toolingException->getClassName() : "std::exception";
        else if (!strcmp(name, "errorText"))
            return m_exception->what();
    }

    const char* pch = TemplateEngine::TemplateParameters::getParameter(name);
    if (pch)
        return pch;

    if (m_session) {
        if (!strcmp(name, "entityID"))
            return m_session->getEntityID();

        const multimap<string,const Attribute*>& attrs = m_session->getIndexedAttributes();
        pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> walker;
        for (walker = attrs.equal_range(name); walker.first != walker.second; ++walker.first) {
            if (walker.first->second->valueCount() > 0)
                return walker.first->second->getSerializedValues().front().c_str();
        }
    }

    if (m_props) {
        pair<bool,const char*> p = m_props->getString(name);
        if (p.first)
            return p.second;
    }

    return nullptr;
}

string TemplateParameters::toQueryString() const
{
    // Capture local stuff.
    string q;

    const URLEncoder* enc = XMLToolingConfig::getConfig().getURLEncoder();
    for (map<string,string>::const_iterator i = m_map.begin(); i != m_map.end(); ++i)
        q = q + '&' + i->first + '=' + enc->encode(i->second.c_str());

    // Add in the exception content.
    if (m_exception) {
        q = q + "&errorType=" + enc->encode(getParameter("errorType")) + "&errorText=" + enc->encode(getParameter("errorText"));
        if (m_toolingException)
            q = q + '&' + m_toolingException->toQueryString();
    }

    q.erase(0,1);
    return q;
}
