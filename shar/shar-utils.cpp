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

#ifdef USE_OUR_ONCRPC
# define svc_fdset onc_svc_fdset
#endif

extern "C" SVCXPRT* svcfd_create(int, u_int, u_int);

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

namespace {
  map<Thread*,int> children;
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

  // the run the child until they exit.
  child->run();

  ShibTargetConfig::getConfig().getINI()->getSessionCache()->thread_end();

  // now we can clean up and exit the thread.
  delete child;
  return NULL;
}

SharChild::SharChild(IListener::ShibSocket& s, const Iterator<ShibRPCProtocols>& protos) : sock(s)
{
  protos.reset();
  while (protos.hasNext())
    v_protos.push_back(protos.next());
  
  // Create the lock and then lock this child
  lock = Mutex::create();
  Lock tl(lock);

  // Create the child thread
  child = Thread::create(shar_client_thread, (void*)this);
  child->detach();

  // Lock the children map and add this child
  Lock cl(child_lock);
  children[child] = 1;
}

SharChild::~SharChild()
{
  // Lock this object
  Lock tl(lock);

  // Then lock the children map, remove this thread, signal waiters, and return
  child_lock->lock();
  children.erase(child);
  child_lock->unlock();
  child_wait->signal();
}

void SharChild::run()
{
  NDC ndc("run");
  if (SHARUtils::shar_create_svc(sock, v_protos) != 0)
    return;

  fd_set readfds;
  struct timeval tv = { 0, 0 };

  while(running && FD_ISSET(sock, &svc_fdset)) {
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    tv.tv_sec = 1;

    switch (select (sock+1, &readfds, 0, 0, &tv)) {

    case -1:
      if (errno == EINTR) continue;
      SHARUtils::log_error();
      return;

    case 0:
      break;

    default:
      svc_getreqset (&readfds);
    }
  }

  if (running) {
      ShibTargetConfig::getConfig().getINI()->getListener()->close(sock);
  }
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

int SHARUtils::shar_create_svc(IListener::ShibSocket& sock, const Iterator<ShibRPCProtocols>& protos)
{
  NDC ndc("shar_create_svc");

  /* Wrap an RPC Service around the new connection socket */
  SVCXPRT* svc = svcfd_create (sock, 0, 0);
  if (!svc) {
    Category::getInstance("SHAR.SHARUtils").error("cannot create RPC listener");
    return -1;
  }

  /* Register the SHIBRPC RPC Program */
  while (protos.hasNext()) {
    const ShibRPCProtocols& p=protos.next();
    if (!svc_register (svc, p.prog, p.vers, p.dispatch, 0)) {
      svc_destroy(svc);
      ShibTargetConfig::getConfig().getINI()->getListener()->close(sock);
      Category::getInstance("SHAR.SHARUtils").error("cannot register RPC program");
      return -2;
    }
  }
  return 0;
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

  // wait for all childred to exit.
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

