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
 * Application.cpp
 *
 * Interface to a Shibboleth Application instance.
 */

#include "internal.h"
#include "Application.h"
#include "SPRequest.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "remoting/ListenerService.h"

#include <algorithm>
#include <boost/bind.hpp>
#include <xmltooling/util/Threads.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

Application::Application(const ServiceProvider* sp) : m_sp(sp), m_lock(RWLock::create())
{
}

Application::~Application()
{
    delete m_lock;
}

const ServiceProvider& Application::getServiceProvider() const
{
    return *m_sp;
}

const char* Application::getId() const
{
    pair<bool,const char*> ret = getString("id");
    return ret.first ? ret.second : "default";
}

pair<string,const char*> Application::getCookieNameProps(const char* prefix, time_t* lifetime) const
{
    static const char* defProps="; path=/; HttpOnly";
    static const char* sslProps="; path=/; secure; HttpOnly";

    if (lifetime)
        *lifetime = 0;
    if (!prefix)
        prefix = "";
    const PropertySet* props = getPropertySet("Sessions");
    if (props) {
        if (lifetime) {
            pair<bool,unsigned int> lt = props->getUnsignedInt("cookieLifetime");
            if (lt.first)
                *lifetime = lt.second;
        }
        pair<bool,const char*> p = props->getString("cookieProps");
        if (!p.first || !strcmp(p.second, "http"))
            p.second = defProps;
        else if (!strcmp(p.second, "https"))
            p.second = sslProps;
        pair<bool,const char*> p2 = props->getString("cookieName");
        if (p2.first)
            return make_pair(string(prefix) + p2.second, p.second);
        return make_pair(string(prefix) + getHash(), p.second);
    }

    // Shouldn't happen, but just in case..
    return pair<string,const char*>(prefix, defProps);
}

void Application::clearHeader(SPRequest& request, const char* rawname, const char* cginame) const
{
    request.clearHeader(rawname, cginame);
}

void Application::setHeader(SPRequest& request, const char* name, const char* value) const
{
    request.setHeader(name, value);
}

string Application::getSecureHeader(const SPRequest& request, const char* name) const
{
    return request.getSecureHeader(name);
}

void Application::clearAttributeHeaders(SPRequest& request) const
{
    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        for_each(
            m_unsetHeaders.begin(), m_unsetHeaders.end(),
            boost::bind(
                &SPRequest::clearHeader,
                boost::ref(request),
                boost::bind(&string::c_str, boost::bind(&pair<string,string>::first, _1)),
                boost::bind(&string::c_str, boost::bind(&pair<string,string>::second, _1))
                )
            );
        return;
    }

    m_lock->rdlock();
    if (m_unsetHeaders.empty()) {
        // No headers yet, so we have to request them from the remote half.
        m_lock->unlock();
        m_lock->wrlock();
        if (m_unsetHeaders.empty()) {
            SharedLock wrlock(m_lock, false);
            string addr=string(getId()) + "::getHeaders::Application";
            DDF out,in = DDF(addr.c_str());
            DDFJanitor jin(in),jout(out);
            out = getServiceProvider().getListenerService()->send(in);
            if (out.islist()) {
                DDF header = out.first();
                while (header.name() && header.isstring()) {
                    m_unsetHeaders.push_back(pair<string,string>(header.name(),header.string()));
                    header = out.next();
                }
            }
        }
        else {
            m_lock->unlock();
        }
        m_lock->rdlock();
    }

    // Now holding read lock.
    SharedLock unsetLock(m_lock, false);
    for_each(
        m_unsetHeaders.begin(), m_unsetHeaders.end(),
        boost::bind(
            &SPRequest::clearHeader,
            boost::ref(request),
            boost::bind(&string::c_str, boost::bind(&pair<string,string>::first, _1)),
            boost::bind(&string::c_str, boost::bind(&pair<string,string>::second, _1))
            )
        );
}

const Handler* Application::getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding) const
{
    auto_ptr_XMLCh b(binding);
    const vector<const Handler*>& handlers = getAssertionConsumerServicesByBinding(b.get());
    return handlers.empty() ? nullptr : handlers.front();
}

void Application::limitRedirect(const GenericRequest& request, const char* url) const
{
}
