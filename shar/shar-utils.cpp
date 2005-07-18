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
 * shar-utils.cpp -- utility functions for the SHAR
 *
 * Created By:	Derek Atkins  <derek@ihtfp.com>
 *
 * $Id$
 */

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
# include <sys/select.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include "shar-utils.h"

#include <shib/shib-threads.h>
#include <log4cpp/Category.hh>

// Deal with inadequate Sun RPC libraries

#if !HAVE_DECL_SVCFD_CREATE
  extern "C" SVCXPRT* svcfd_create(int, u_int, u_int);
#endif

#ifndef HAVE_WORKING_SVC_DESTROY
struct tcp_conn {  /* kept in xprt->xp_p1 */
    enum xprt_stat strm_stat;
    u_long x_id;
    XDR xdrs;
    char verf_body[MAX_AUTH_BYTES];
};
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

namespace {
  map<IListener::ShibSocket,Thread*> children;
  Mutex* 	child_lock = NULL;
  CondWait*	child_wait = NULL;
  bool		running;
};

void* shar_client_thread (void* arg)
{
  SharChild* child = (SharChild*)arg;

  // First, let's block all signals
  Thread::mask_all_signals();

  ShibTargetConfig::getConfig().getINI()->getSessionCache()->thread_init();
  ShibTargetConfig::getConfig().getINI()->getReplayCache()->thread_init();

  // the run the child until they exit.
  child->run();

  ShibTargetConfig::getConfig().getINI()->getSessionCache()->thread_end();
  ShibTargetConfig::getConfig().getINI()->getReplayCache()->thread_end();

  // now we can clean up and exit the thread.
  delete child;
  return NULL;
}

SharChild::SharChild(IListener::ShibSocket& s, const Iterator<ShibRPCProtocols>& protos) : sock(s), child(NULL)
{
  protos.reset();
  while (protos.hasNext())
    v_protos.push_back(protos.next());
  
  // Create the child thread
  child = Thread::create(shar_client_thread, (void*)this);
  child->detach();
}

SharChild::~SharChild()
{
  // Then lock the children map, remove this socket/thread, signal waiters, and return
  child_lock->lock();
  children.erase(sock);
  child_lock->unlock();
  child_wait->signal();
  
  delete child;
}

void SharChild::run()
{
    // Before starting up, make sure we fully "own" this socket.
    child_lock->lock();
    while (children.find(sock)!=children.end())
        child_wait->wait(child_lock);
    children[sock] = child;
    child_lock->unlock();
    
  if (!svc_create())
   return;

  fd_set readfds;
  struct timeval tv = { 0, 0 };

  while(running && FD_ISSET(sock, &svc_fdset)) {
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    tv.tv_sec = 1;

    switch (select(sock+1, &readfds, 0, 0, &tv)) {
#ifdef WIN32
    case SOCKET_ERROR:
#else
    case -1:
#endif
      if (errno == EINTR) continue;
      SHARUtils::log_error();
      Category::getInstance("SHAR.SharChild").error("select() on incoming request socket (%u) returned error",sock);
      return;

    case 0:
      break;

    default:
      svc_getreqset(&readfds);
    }
  }
}

bool SharChild::svc_create()
{
  /* Wrap an RPC Service around the new connection socket. */
  SVCXPRT* transp = svcfd_create(sock, 0, 0);
  if (!transp) {
    NDC ndc("svc_create");
    Category::getInstance("SHAR.SharChild").error("cannot create RPC listener");
    return false;
  }

  /* Register the SHIBRPC RPC Program */
  Iterator<ShibRPCProtocols> i(v_protos);
  while (i.hasNext()) {
    const ShibRPCProtocols& p=i.next();
    if (!svc_register (transp, p.prog, p.vers, p.dispatch, 0)) {
#ifdef HAVE_WORKING_SVC_DESTROY
      svc_destroy(transp);
#else
      /* we have to inline svc_destroy because we can't pass in the xprt variable */
      struct tcp_conn *cd = (struct tcp_conn *)transp->xp_p1;
      xprt_unregister(transp);
      close(transp->xp_sock);
      if (transp->xp_port != 0) {
        /* a rendezvouser socket */
        transp->xp_port = 0;
      } else {
        /* an actual connection socket */
        XDR_DESTROY(&(cd->xdrs));
      }
      mem_free((caddr_t)cd, sizeof(struct tcp_conn));
      mem_free((caddr_t)transp, sizeof(SVCXPRT));
#endif
      NDC ndc("svc_create");
      Category::getInstance("SHAR.SharChild").error("cannot register RPC program");
      return false;
    }
  }
  return true;
}

void SHARUtils::log_error()
{
#ifdef WIN32
    int rc=WSAGetLastError();
#else
    int rc=errno;
#endif
#ifdef HAVE_STRERROR_R
    char buf[256];
    strerror_r(rc,buf,sizeof(buf));
    buf[255]=0;
    Category::getInstance("SHAR.SHARUtils").error("system call resulted in error (%d): %s",rc,buf);
#else
    Category::getInstance("SHAR.SHARUtils").error("system call resulted in error (%d): %s",rc,strerror(rc));
#endif
}

void SHARUtils::init()
{
  child_lock = Mutex::create();
  child_wait = CondWait::create();
  running = true;
}

void SHARUtils::fini()
{
  running = false;

  // wait for all children to exit.
  child_lock->lock();
  while (children.size())
    child_wait->wait(child_lock);
  child_lock->unlock();

  // Ok, we're done.
  delete child_wait;
  child_wait = NULL;
  delete child_lock;
  child_lock = NULL;
}
