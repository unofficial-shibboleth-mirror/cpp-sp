/*
 * shar-utils.cpp -- utility functions for the SHAR
 *
 * Created By:	Derek Atkins  <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>

#include "config.h"

#include "shar-utils.h"
#include <shib/shib-threads.h>
#include <shib-target/ccache-utils.h>

using namespace std;
using namespace shibboleth;
using namespace shibtarget;

//
// PRIVATE interfaces
//

class SharChild {
public:
  SharChild(ShibSocket, const ShibRPCProtocols protos[], int numprotos);
  ~SharChild();

  void	run();

  ShibSocket	sock;
  const ShibRPCProtocols *protos;
  int		numprotos;

  Thread*	child;
  Mutex*	lock;
};

namespace {
  map<Thread*,int> children;
  Mutex* 	child_lock = NULL;
  CondWait*	child_wait = NULL;
  bool		running;
};

void*
shar_client_thread (void* arg)
{
  SharChild* child = (SharChild*)arg;

  // First, let's block all signals
  sigset_t sigmask;
  sigfillset(&sigmask);
  Thread::mask_signals(SIG_BLOCK, &sigmask, NULL);

  g_shibTargetCCache->thread_init();

  // the run the child until they exit.
  child->run();

  g_shibTargetCCache->thread_end();

  // now we can clean up and exit the thread.
  delete child;
  return NULL;
}

SharChild::SharChild(ShibSocket a_sock, const ShibRPCProtocols a_protos[], int a_numprotos)
  : sock(a_sock), protos(a_protos), numprotos(a_numprotos)
{
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
  if (shar_create_svc(sock, protos, numprotos) != 0)
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
      perror ("SharChild::run(): - select failed");
      return;

    case 0:
      break;

    default:
      svc_getreqset (&readfds);
    }
  }
}

//
// PUBLIC interfaces -- used by SHAR
//

extern "C" void
shar_new_connection(ShibSocket sock, const ShibRPCProtocols protos[], int numprotos)
{
  SharChild* child = new SharChild(sock, protos, numprotos);
}

extern "C" void
shar_utils_init()
{
  child_lock = Mutex::create();
  child_wait = CondWait::create();
  running = true;
}

extern "C" void
shar_utils_fini()
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

