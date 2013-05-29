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
 * TCPListener.cpp
 *
 * TCP-based SocketListener implementation.
 */

#include "internal.h"
#include "exceptions.h"
#include "remoting/impl/SocketListener.h"
#include "util/IPRange.h"

#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/unicode.h>
#include <xmltooling/util/XMLHelper.h>

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#ifdef HAVE_UNISTD_H
# include <sys/socket.h>
# include <sys/un.h>
# include <netdb.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/in.h>
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
using namespace boost;
using namespace std;

namespace shibsp {
    class TCPListener : virtual public SocketListener
    {
    public:
        TCPListener(const DOMElement* e);
        ~TCPListener() {}

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
        bool setup_tcp_sockaddr();

        string m_address;
        unsigned short m_port;
        vector<IPRange> m_acl;
        size_t m_sockaddrlen;
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
        struct sockaddr_storage m_sockaddr;
#else
        struct sockaddr_in m_sockaddr;
#endif
    };

    ListenerService* SHIBSP_DLLLOCAL TCPListenerServiceFactory(const DOMElement* const & e)
    {
        return new TCPListener(e);
    }

    static const XMLCh address[] = UNICODE_LITERAL_7(a,d,d,r,e,s,s);
    static const XMLCh port[] = UNICODE_LITERAL_4(p,o,r,t);
    static const XMLCh acl[] = UNICODE_LITERAL_3(a,c,l);
};

TCPListener::TCPListener(const DOMElement* e)
    : SocketListener(e),
      m_address(XMLHelper::getAttrString(e, getenv("SHIBSP_LISTENER_ADDRESS"), address)),
      m_port(XMLHelper::getAttrInt(e, 0, port))
{
    if (m_address.empty())
        m_address = "127.0.0.1";

    if (m_port == 0) {
        const char* p = getenv("SHIBSP_LISTENER_PORT");
        if (p && *p)
            m_port = atoi(p);
        if (m_port == 0)
            m_port = 1600;
    }

    vector<string> rawacls;
    string aclbuf = XMLHelper::getAttrString(e, "127.0.0.1", acl);
    boost::split(rawacls, aclbuf, boost::is_space(), algorithm::token_compress_on);
    for (vector<string>::const_iterator i = rawacls.begin();  i < rawacls.end();  ++i) {
        try {
            m_acl.push_back(IPRange::parseCIDRBlock(i->c_str()));
        }
        catch (std::exception& ex) {
            log->error("invalid CIDR block (%s): %s", i->c_str(), ex.what());
        }
    }

    if (m_acl.empty()) {
        log->warn("invalid CIDR range(s) in acl property, allowing 127.0.0.1 as a fall back");
        m_acl.push_back(IPRange::parseCIDRBlock("127.0.0.1"));
    }

    if (!setup_tcp_sockaddr()) {
        throw ConfigurationException("Unable to use configured socket address property.");
    }
}

bool TCPListener::setup_tcp_sockaddr()
{
    struct addrinfo* ret = nullptr;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(m_address.c_str(), nullptr, &hints, &ret) != 0) {
        log->error("unable to parse server address (%s)", m_address.c_str());
        return false;
    }

    m_sockaddrlen = ret->ai_addrlen;
    if (ret->ai_family == AF_INET) {
        memcpy(&m_sockaddr, ret->ai_addr, m_sockaddrlen);
        freeaddrinfo(ret);
        ((struct sockaddr_in*)&m_sockaddr)->sin_port=htons(m_port);
        return true;
    }
#if defined(AF_INET6) && defined(HAVE_STRUCT_SOCKADDR_STORAGE)
    else if (ret->ai_family == AF_INET6) {
        memcpy(&m_sockaddr, ret->ai_addr, m_sockaddrlen);
        freeaddrinfo(ret);
        ((struct sockaddr_in6*)&m_sockaddr)->sin6_port=htons(m_port);
        return true;
    }
#endif

    log->error("unknown address type (%d)", ret->ai_family);
    freeaddrinfo(ret);
    return false;
}

bool TCPListener::create(ShibSocket& s) const
{
    int type = SOCK_STREAM;
#ifdef HAVE_SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif

#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    s = socket(m_sockaddr.ss_family, type, 0);
#else
    s = socket(m_sockaddr.sin_family, type, 0);
#endif
#ifdef WIN32
    if(s == INVALID_SOCKET)
#else
    if (s < 0)
#endif
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

bool TCPListener::bind(ShibSocket& s, bool force) const
{
    // XXX: Do we care about the return value from setsockopt?
    int opt = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

#ifdef WIN32
    if (SOCKET_ERROR==::bind(s, (const struct sockaddr*)&m_sockaddr, m_sockaddrlen) || SOCKET_ERROR==::listen(s, 3)) {
        log_error("bind");
        close(s);
        return false;
    }
#else
    // Newer BSDs, and Solaris, require the struct length be passed based on the socket address.
    // All but Solaris seem to have an ss_len field in the sockaddr_storage struct.
# ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
#  ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    if (::bind(s, (const struct sockaddr*)&m_sockaddr, m_sockaddr.ss_len) < 0) {
#  else
    if (::bind(s, (const struct sockaddr*)&m_sockaddr, m_sockaddr.sin_len) < 0) {
#  endif
# else
    if (::bind(s, (const struct sockaddr*)&m_sockaddr, m_sockaddrlen) < 0) {
# endif
        log_error("bind");
        close(s);
        return false;
    }
    ::listen(s, 3);
#endif
    return true;
}

bool TCPListener::connect(ShibSocket& s) const
{
#ifdef WIN32
    if(SOCKET_ERROR==::connect(s, (const struct sockaddr*)&m_sockaddr, m_sockaddrlen))
        return log_error("connect");
#else
    // Newer BSDs require the struct length be passed based on the socket address.
    // Others have no field for that and take the whole struct size like Windows does.
# ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
#  ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    if (::connect(s, (const struct sockaddr*)&m_sockaddr, m_sockaddr.ss_len) < 0)
#  else
    if (::connect(s, (const struct sockaddr*)&m_sockaddr, m_sockaddr.sin_len) < 0)
#  endif
# else
    if (::connect(s, (const struct sockaddr*)&m_sockaddr, m_sockaddrlen) < 0)
# endif
        return log_error("connect");
#endif
    return true;
}

bool TCPListener::close(ShibSocket& s) const
{
#ifdef WIN32
    closesocket(s);
#else
    ::close(s);
#endif
    return true;
}

bool TCPListener::accept(ShibSocket& listener, ShibSocket& s) const
{
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
    struct sockaddr_storage addr;
#else
    struct sockaddr_in addr;
#endif
    memset(&addr, 0, sizeof(addr));

#ifdef WIN32
    int size=sizeof(addr);
    s=::accept(listener, (struct sockaddr*)&addr, &size);
    if(s==INVALID_SOCKET)
#else
    socklen_t size=sizeof(addr);
    s=::accept(listener, (struct sockaddr*)&addr, &size);
    if (s < 0)
#endif
        return log_error("accept");

    static bool (IPRange::* contains)(const struct sockaddr*) const = &IPRange::contains;
    if (find_if(m_acl.begin(), m_acl.end(), boost::bind(contains, _1, (const struct sockaddr*)&addr)) == m_acl.end()) {
        close(s);
        s = -1;
        log->error("accept() rejected client with invalid address");
        return false;
    }
    return true;
}
