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
 * UnixListener.cpp
 * 
 * Unix Domain-based SocketListener implementation.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "remoting/impl/SocketListener.h"
#include "util/PathResolver.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/unicode.h>
#include <xmltooling/util/XMLHelper.h>

#ifdef HAVE_UNISTD_H
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
# include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>		/* for chmod() */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;


namespace shibsp {
    class UnixListener : virtual public SocketListener
    {
    public:
        UnixListener(const DOMElement* e);
        ~UnixListener() {if (m_bound) unlink(m_address.c_str());}

        bool create(ShibSocket& s) const;
        bool bind(ShibSocket& s, bool force=false) const;
        bool connect(ShibSocket& s) const;
        bool close(ShibSocket& s) const;
        bool accept(ShibSocket& listener, ShibSocket& s) const;

        int send(ShibSocket& s, const char* buf, int len) const {
            return ::send(s, buf, len, 0);
        }
        
        int recv(ShibSocket& s, char* buf, int buflen) const {
            return ::recv(s, buf, buflen, 0);
        }
        
    private:
        string m_address;
        mutable bool m_bound;
    };

    ListenerService* SHIBSP_DLLLOCAL UnixListenerServiceFactory(const DOMElement* const & e, bool)
    {
        return new UnixListener(e);
    }

    static const XMLCh address[] = UNICODE_LITERAL_7(a,d,d,r,e,s,s);
    static const XMLCh clientAddress[] = UNICODE_LITERAL_13(c,l,i,e,n,t,A,d,d,r,e,s,s);
};

UnixListener::UnixListener(const DOMElement* e) : SocketListener(e), m_bound(false)
{
    // In-process, check the clientAddress/clientPort settings first.
    if (SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        m_address = XMLHelper::getAttrString(e, nullptr, clientAddress);
    }

    // Back-off to address setting, environment, or default.
    if (m_address.empty()) {
        m_address = XMLHelper::getAttrString(e, getenv("SHIBSP_LISTENER_ADDRESS"), address);
        if (m_address.empty()) {
            m_address = "shibd.sock";
        }
    }

    log->info("using socket address: %s", m_address.c_str());

    AgentConfig::getConfig().getPathResolver().resolve(m_address, PathResolver::SHIBSP_RUN_FILE);
}

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 100
#endif

bool UnixListener::create(ShibSocket& s) const
{
    int type = SOCK_STREAM;
#ifdef HAVE_SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif
    s = socket(PF_UNIX, type, 0);
    if (s < 0)
        return log_error("socket");

#if !defined(HAVE_SOCK_CLOEXEC) && defined(HAVE_FD_CLOEXEC)
    int fdflags = fcntl(s, F_GETFD);
    if (fdflags != -1) {
        fdflags |= FD_CLOEXEC;
        fcntl(s, F_SETFD, fdflags);
    }
#endif

    return true;
}

bool UnixListener::bind(ShibSocket& s, bool force) const
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_address.c_str(), UNIX_PATH_MAX);

    if (force)
        unlink(m_address.c_str());

    if (::bind(s, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
        log_error("bind");
        close(s);
        return false;
    }

    // Make sure that only the creator can read -- we don't want just
    // anyone connecting, do we?
    if (chmod(m_address.c_str(),0777) < 0) {
        log_error("chmod");
        close(s);
        unlink(m_address.c_str());
        return false;
    }

    listen(s, 3);
    return m_bound=true;
}

bool UnixListener::connect(ShibSocket& s) const
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_address.c_str(), UNIX_PATH_MAX);

    if (::connect(s, (struct sockaddr *)&addr, sizeof (addr)) < 0)
        return log_error("connect");
    return true;
}

bool UnixListener::close(ShibSocket& s) const
{
    ::close(s);
    return true;
}

bool UnixListener::accept(ShibSocket& listener, ShibSocket& s) const
{
    s=::accept(listener,nullptr,nullptr);
    if (s < 0)
        return log_error("accept");
    return true;
}
