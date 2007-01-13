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
 * Application.cpp
 * 
 * Interface to a Shibboleth Application instance.
 */

#include "internal.h"
#include "Application.h"

using namespace shibsp;
using namespace std;

pair<string,const char*> Application::getCookieNameProps(const char* prefix) const
{
    static const char* defProps="; path=/";
    
    const PropertySet* props=getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> p=props->getString("cookieProps");
        if (!p.first)
            p.second=defProps;
        pair<bool,const char*> p2=props->getString("cookieName");
        if (p2.first)
            return make_pair(string(prefix) + p2.second,p.second);
        return make_pair(string(prefix) + getHash(),p.second);
    }
    
    // Shouldn't happen, but just in case..
    return pair<string,const char*>(prefix,defProps);
}
