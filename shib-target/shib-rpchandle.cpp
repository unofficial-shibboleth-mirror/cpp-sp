/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-rpchandle.cpp -- the RPC Handle abstraction
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <shib/shib-threads.h>

#include <stdexcept>
#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

RPCHandle::RPCHandle() : m_clnt(NULL), m_sock((IListener::ShibSocket)NULL), log(&(log4cpp::Category::getInstance("shibtarget.RPCHandle")))
{
    log->debug("New RPCHandle created: %p", this);
}

RPCHandle::~RPCHandle()
{
    log->debug("Destroying RPC Handle: %p", this);
    disconnect();
}

void RPCHandle::disconnect()
{
    if (m_clnt) {
        clnt_destroy(m_clnt);
        m_clnt=NULL;
        IConfig* conf=ShibTargetConfig::getConfig().getINI();
        Locker locker(conf);
        conf->getListener()->close(m_sock);
        m_sock=(IListener::ShibSocket)0;
    }
}

CLIENT* RPCHandle::connect()
{
    saml::NDC ndc("connect");

    if (m_clnt) {
        log->debug ("returning existing connection: %p -> %p", this, m_clnt);
        return m_clnt;
    }

    log->debug("trying to connect to SHAR");

    IListener::ShibSocket sock;
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IListener* listener=conf->getListener();
    if (!listener->create(sock)) {
        log->error("cannot create socket");
        throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR, "Cannot create socket");
    }

    bool connected = false;
    int num_tries = 3;

    for (int i = num_tries-1; i >= 0; i--) {
        if (listener->connect(sock)) {
            connected = true;
            break;
        }
    
        log->warn ("cannot connect %p to SHAR... %s", this, (i > 0 ? "retrying" : ""));

        if (i)
#ifdef WIN32
            Sleep(2000*(num_tries-i));
#else
            sleep(2*(num_tries-i));
#endif
    }

    if (!connected) {
        log->crit("SHAR Unavailable..  Failing.");
        listener->close(sock);
        throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR, "Cannot connect to SHAR process, target site adminstrator should be notified");
    }

    CLIENT *clnt = listener->getClientHandle(sock, SHIBRPC_PROG, SHIBRPC_VERS_1);
    if (!clnt) {
        const char* rpcerror = clnt_spcreateerror("RPCHandle::connect");
        log->crit("RPC failed for %p: %s", this, rpcerror);
        listener->close(sock);
        throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR, rpcerror);
    }

    // Set the RPC timeout to a fairly high value...
    struct timeval tv;
    tv.tv_sec = 300;    /* change timeout to 5 minutes */
    tv.tv_usec = 0;     /* this should always be set  */
    clnt_control(clnt, CLSET_TIMEOUT, (char*)&tv);

    m_clnt = clnt;
    m_sock = sock;

    log->debug("success: %p -> %p", this, m_clnt);
    return m_clnt;
}

RPCHandlePool::~RPCHandlePool()
{
    while (!m_pool.empty()) {
        delete m_pool.top();
        m_pool.pop();
    }
}

RPCHandle* RPCHandlePool::get()
{
    m_lock->lock();
    if (m_pool.empty()) {
        m_lock->unlock();
        return new RPCHandle();
    }
    RPCHandle* ret=m_pool.top();
    m_pool.pop();
    m_lock->unlock();
    return ret;
}

void RPCHandlePool::put(RPCHandle* handle)
{
    m_lock->lock();
    m_pool.push(handle);
    m_lock->unlock();
}

RPC::RPC() : m_pool(dynamic_cast<STConfig&>(ShibTargetConfig::getConfig()).getRPCHandlePool())
{
    m_handle=m_pool.get();
}
