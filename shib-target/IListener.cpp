/*
 *  Copyright 2001-2005 Internet2
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

/*
 * IListener.cpp - basic functionality for remoting
 *
 * $Id$
 */

#include "internal.h"

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibtarget;

IRemoted* IListener::regListener(const char* address, IRemoted* listener)
{
    IRemoted* ret=NULL;
    map<string,IRemoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end())
        ret=i->second;
    m_listenerMap[address]=listener;
    Category::getInstance(SHIBT_LOGCAT".Listener").info("registered remoted message endpoint (%s)",address);
    return ret;
}

bool IListener::unregListener(const char* address, IRemoted* current, IRemoted* restore)
{
    map<string,IRemoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end() && i->second==current) {
        if (restore)
            m_listenerMap[address]=restore;
        else
            m_listenerMap.erase(address);
        return true;
    }
    return false;
}

IRemoted* IListener::lookup(const char *address) const
{
    map<string,IRemoted*>::const_iterator i=m_listenerMap.find(address);
    return (i==m_listenerMap.end()) ? NULL : i->second;
}

DDF IListener::receive(const DDF &in)
{
    if (!in.name())
        throw ListenerException("Incoming message with no destination address rejected.");
    IRemoted* dest=lookup(in.name());
    if (!dest)
        throw ListenerException("No destination registered for incoming message addressed to ($1).",params(1,in.name()));
    return dest->receive(in);
}
