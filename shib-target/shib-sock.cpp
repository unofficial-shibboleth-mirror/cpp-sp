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
 * shib-sock.cpp -- Socket-based IListener implementations
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>, revised by Scott Cantor
 */

#include <saml/saml.h>  // need this to "prime" the xmlsec-constrained windows.h declaration
#include <shib-target/shibrpc.h>
#include "internal.h"

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
#include <errno.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

static const XMLCh address[] = { chLatin_a, chLatin_d, chLatin_d, chLatin_r, chLatin_e, chLatin_s, chLatin_s, chNull };
static const XMLCh port[] = { chLatin_p, chLatin_o, chLatin_r, chLatin_t, chNull };

class TCPListener : virtual public RPCListener
{
public:
    TCPListener(const DOMElement* e);
    ~TCPListener() {}

    bool create(ShibSocket& s) const;
    bool bind(ShibSocket& s, bool force=false) const;
    bool connect(ShibSocket& s) const;
    bool close(ShibSocket& s) const;
    bool accept(ShibSocket& listener, ShibSocket& s) const;
    void* getClientHandle(ShibSocket& s, u_long program, u_long version) const;
    
private:
    void setup_tcp_sockaddr(struct sockaddr_in* addr) const;
    bool log_error() const;

    string m_address;
    unsigned short m_port;
    vector<string> m_acl;
};

IPlugIn* TCPListenerFactory(const DOMElement* e)
{
    return new TCPListener(e);
}

TCPListener::TCPListener(const DOMElement* e) : RPCListener(e), m_address("127.0.0.1"), m_port(12345)
{
    // We're stateless, but we need to load the configuration.
    const XMLCh* tag=e->getAttributeNS(NULL,address);
    if (tag && *tag) {
        auto_ptr_char a(tag);
        m_address=a.get();
    }
    
    tag=e->getAttributeNS(NULL,port);
    if (tag && *tag) {
        m_port=XMLString::parseInt(tag);
        if (m_port==0)
            m_port=12345;
    }
    
    tag=e->getAttributeNS(NULL,SHIBT_L(acl));
    if (tag && *tag) {
        auto_ptr_char temp(tag);
        string sockacl=temp.get();
        if (sockacl.length()) {
            int j = 0;
            for (unsigned int i=0;  i < sockacl.length();  i++) {
                if (sockacl.at(i)==' ') {
                    m_acl.push_back(sockacl.substr(j, i-j));
                    j = i+1;
                }
            }
            m_acl.push_back(sockacl.substr(j, sockacl.length()-j));
        }
    }
    else
        m_acl.push_back("127.0.0.1");
}

void TCPListener::setup_tcp_sockaddr(struct sockaddr_in* addr) const
{
    // Split on host:port boundary. Default to port only.
    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_family=AF_INET;
    addr->sin_port=htons(m_port);
    addr->sin_addr.s_addr=inet_addr(m_address.c_str());
}

bool TCPListener::log_error() const
{
#ifdef WIN32
    int rc=WSAGetLastError();
#else
    int rc=errno;
#endif
#ifdef HAVE_STRERROR_R
    char buf[256];
    memset(buf,0,sizeof(buf));
    strerror_r(rc,buf,sizeof(buf));
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#else
    const char* buf=strerror(rc);
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#endif
    return false;
}

bool TCPListener::create(ShibSocket& s) const
{
    s=socket(AF_INET,SOCK_STREAM,0);
#ifdef WIN32
    if(s==INVALID_SOCKET)
#else
    if (s < 0)
#endif
        return log_error();
    return true;
}

bool TCPListener::bind(ShibSocket& s, bool force) const
{
    struct sockaddr_in addr;
    setup_tcp_sockaddr(&addr);

    // XXX: Do we care about the return value from setsockopt?
    int opt = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

#ifdef WIN32
    if (SOCKET_ERROR==::bind(s,(struct sockaddr *)&addr,sizeof(addr)) || SOCKET_ERROR==::listen(s,3)) {
        log_error();
        close(s);
        return false;
    }
#else
    if (::bind(s, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
        log_error();
        close(s);
        return false;
    }
    ::listen(s,3);
#endif
    return true;
}

bool TCPListener::connect(ShibSocket& s) const
{
    struct sockaddr_in addr;
    setup_tcp_sockaddr(&addr);
#ifdef WIN32
    if(SOCKET_ERROR==::connect(s,(struct sockaddr *)&addr,sizeof(addr)))
        return log_error();
#else
    if (::connect(s, (struct sockaddr*)&addr, sizeof (addr)) < 0)
        return log_error();
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
    struct sockaddr_in addr;

#ifdef WIN32
    int size=sizeof(addr);
    s=::accept(listener,(struct sockaddr*)&addr,&size);
    if(s==INVALID_SOCKET)
#else
    socklen_t size=sizeof(addr);
    s=::accept(listener,(struct sockaddr*)&addr,&size);
    if (s < 0)
#endif
        return log_error();
    char* client=inet_ntoa(addr.sin_addr);
    for (vector<string>::const_iterator i=m_acl.begin(); i!=m_acl.end(); i++) {
        if (*i==client)
            return true;
    }
    close(s);
    s=-1;
    log->error("accept() rejected client at %s\n",client);
    return false;
}

void* TCPListener::getClientHandle(ShibSocket& s, u_long program, u_long version) const
{
    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_port = 1;
    return clnttcp_create(&sin, program, version, &s, 0, 0);
}

#ifndef WIN32

class UnixListener : virtual public RPCListener
{
public:
    UnixListener(const DOMElement* e);
    ~UnixListener() {if (m_bound) unlink(m_address.c_str());}

    bool create(ShibSocket& s) const;
    bool bind(ShibSocket& s, bool force=false) const;
    bool connect(ShibSocket& s) const;
    bool close(ShibSocket& s) const;
    bool accept(ShibSocket& listener, ShibSocket& s) const;
    void* getClientHandle(ShibSocket& s, u_long program, u_long version) const;
    
private:
    bool log_error() const;

    string m_address;
    mutable bool m_bound;
};

IPlugIn* UnixListenerFactory(const DOMElement* e)
{
    return new UnixListener(e);
}

UnixListener::UnixListener(const DOMElement* e) : RPCListener(e), m_address("/var/run/shar-socket"), m_bound(false)
{
    // We're stateless, but we need to load the configuration.
    const XMLCh* tag=e->getAttributeNS(NULL,address);
    if (tag && *tag) {
        auto_ptr_char a(tag);
        m_address=a.get();
    }
}

bool UnixListener::log_error() const
{
    int rc=errno;
#ifdef HAVE_STRERROR_R
    char buf[256];
    memset(buf,0,sizeof(buf));
    strerror_r(rc,buf,sizeof(buf));
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#else
    const char* buf=strerror(rc);
    log->error("socket call resulted in error (%d): %s",rc,isprint(*buf) ? buf : "no message");
#endif
    return false;
}

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 100
#endif

bool UnixListener::create(ShibSocket& sock) const
{
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        return log_error();
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
        log_error();
        close(s);
        return false;
    }

    /* Make sure that only the creator can read -- we don't want just
     * anyone connecting, do we?
     */
    if (chmod(m_address.c_str(),0777) < 0) {
        log_error();
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
        return log_error();
    return true;
}

bool UnixListener::close(ShibSocket& s) const
{
    ::close(s);
    return true;
}

bool UnixListener::accept(ShibSocket& listener, ShibSocket& s) const
{
    s=::accept(listener,NULL,NULL);
    if (s < 0)
        return log_error();
    return true;
}

void* UnixListener::getClientHandle(ShibSocket& s, u_long program, u_long version) const
{
    struct sockaddr_in sin;
    memset (&sin, 0, sizeof (sin));
    sin.sin_port = 1;
    return clnttcp_create(&sin, program, version, &s, 0, 0);
}

#endif /* !WIN32 */
