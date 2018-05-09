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
 * ListenerService.cpp
 *
 * Interprocess remoting engine.
 */

#include "internal.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "remoting/ListenerService.h"

#include <xercesc/dom/DOM.hpp>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/util/Threads.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager<ListenerService,string,const DOMElement*>::Factory TCPListenerServiceFactory;
#ifndef WIN32
    SHIBSP_DLLLOCAL PluginManager<ListenerService,string,const DOMElement*>::Factory UnixListenerServiceFactory;
#endif
};

void SHIBSP_API shibsp::registerListenerServices()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.ListenerServiceManager.registerFactory(TCP_LISTENER_SERVICE, TCPListenerServiceFactory);
#ifndef WIN32
    conf.ListenerServiceManager.registerFactory(UNIX_LISTENER_SERVICE, UnixListenerServiceFactory);
#endif
}

Remoted::Remoted()
{
}

Remoted::~Remoted()
{
}

ListenerService::ListenerService() : m_listenerLock(RWLock::create()), m_threadLocalKey(ThreadKey::create(nullptr))
{
}

ListenerService::~ListenerService()
{
}

void ListenerService::regListener(const char* address, Remoted* listener)
{
    m_listenerLock->wrlock();
    SharedLock locker(m_listenerLock, false);

    Remoted* ret=nullptr;
    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end())
        ret=i->second;
    m_listenerMap[address]=listener;
    Category::getInstance(SHIBSP_LOGCAT ".Listener").debug("registered remoted message endpoint (%s)",address);
}

bool ListenerService::unregListener(const char* address, Remoted* current)
{
    m_listenerLock->wrlock();
    SharedLock locker(m_listenerLock, false);

    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    if (i!=m_listenerMap.end() && i->second==current) {
        m_listenerMap.erase(address);
        Category::getInstance(SHIBSP_LOGCAT ".Listener").debug("unregistered remoted message endpoint (%s)",address);
        return true;
    }
    return false;
}

Remoted* ListenerService::lookup(const char *address) const
{
    SharedLock locker(m_listenerLock, true);
    map<string,Remoted*>::const_iterator i=m_listenerMap.find(address);
    return (i==m_listenerMap.end()) ? nullptr : i->second;
}

void ListenerService::receive(DDF &in, ostream& out)
{
    if (!in.name())
        throw ListenerException("Incoming message with no destination address rejected.");
    else if (!strcmp("ping", in.name())) {
        DDF outmsg = DDF(nullptr).integer(in.integer() + 1);
        DDFJanitor jan(outmsg);
        out << outmsg;
        return;
    }
    else if (!strcmp("hash", in.name())) {
#ifndef SHIBSP_LITE
        const char* hashAlg = in["alg"].string();
        const char* data = in["data"].string();
        if (!hashAlg || !*hashAlg || !data || !*data)
            throw ListenerException("Hash request missing algorithm or data parameters.");
        DDF outmsg(nullptr);
        DDFJanitor jan(outmsg);
        outmsg.string(SecurityHelper::doHash(hashAlg, data, strlen(data)).c_str());
        out << outmsg;
        return;
#else
        throw ListenerException("Hash algorithms unavailable in lite build of library.");
#endif
    }

    // Two stage lookup, on the listener itself, and the SP interface.
    ServiceProvider* sp = SPConfig::getConfig().getServiceProvider();
    Locker locker(sp);
    Remoted* dest = lookup(in.name());
    if (!dest) {
        dest = sp->lookupListener(in.name());
        if (!dest)
            throw ListenerException("No destination registered for incoming message addressed to ($1).", params(1,in.name()));
    }

    try {
        // Input is saved for surreptitious access by components without direct API access to the data.
        m_threadLocalKey->setData(&in);
        auto_ptr_XMLCh selfEntityID(in["_mapped.entityID"].string());
        if (selfEntityID.get()) {
            in.addmember("_mapped.entityID-16").pointer(const_cast<XMLCh*>(selfEntityID.get()));
        }

        dest->receive(in, out);
        m_threadLocalKey->setData(nullptr);
    }
    catch (...) {
        // Clear on error.
        m_threadLocalKey->setData(nullptr);
        throw;
    }
}

DDF* ListenerService::getInput() const
{
    return reinterpret_cast<DDF*>(m_threadLocalKey->getData());
}

bool ListenerService::init(bool force)
{
    return true;
}

void ListenerService::term()
{
}
