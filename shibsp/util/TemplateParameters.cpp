/*
 *  Copyright 2001-2006 Internet2
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
 * TemplateParameters.cpp
 * 
 * Supplies xmltooling TemplateEngine with additional parameters from a PropertySet. 
 */

#include "internal.h"
#include "util/TemplateParameters.h"

#include <ctime>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

void TemplateParameters::setPropertySet(const PropertySet* props)
{
    m_props = props;

    // Create a timestamp.
    time_t now = time(NULL);
#ifdef HAVE_CTIME_R
    char timebuf[32];
    m_map["now"] = ctime_r(&now,timebuf);
#else
    m_map["now"] = ctime(&now);
#endif
}

const char* TemplateParameters::getParameter(const char* name) const
{
    const char* pch = TemplateEngine::TemplateParameters::getParameter(name);
    if (pch || !m_props)
        return pch;
    pair<bool,const char*> p = m_props->getString(name);
    return p.first ? p.second : NULL;
}
