/*
 * shib-threads.cpp -- an abstraction around Pthreads
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <shib-target/shib-threads.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_PTHREAD
#include <pthread.h>
#else
#error "You need to create the proper thread implementation"
#endif

#include <stdexcept>

using namespace std;
using namespace shibtarget;


// pthread implementation of the Shib Target Threads API

//
// "Private" Implementation
//

class ThreadImpl : public Thread {
public:
  ThreadImpl(void* (*start_routine)(void*), void* arg);
  ~ThreadImpl() {}

  int detach() { return pthread_detach(thread_id); }
  int join(void** thread_return) { return pthread_join(thread_id, thread_return); }

  pthread_t	thread_id;
};

class MutexImpl : public Mutex {
public:
  MutexImpl();
  ~MutexImpl() { pthread_mutex_destroy (&mutex); }

  int lock() { return pthread_mutex_lock (&mutex); }
  int unlock() { return pthread_mutex_unlock (&mutex); }

  pthread_mutex_t mutex;
};

class CondWaitImpl : public CondWait {
public:
  CondWaitImpl();
  ~CondWaitImpl() { pthread_cond_destroy (&cond); }

  int wait(Mutex* mutex) { return wait (dynamic_cast<MutexImpl*>(mutex)); }
  int wait(MutexImpl* mutex) { return pthread_cond_wait (&cond, &(mutex->mutex)); }
  int timedwait(Mutex* mutex, struct timespec *abstime)
  	{ return timedwait (dynamic_cast<MutexImpl*>(mutex), abstime); }
  int timedwait(MutexImpl* mutex, struct timespec *abstime) 
  	{ return pthread_cond_timedwait (&cond, &(mutex->mutex), abstime); }
  int signal() { return pthread_cond_signal (&cond); }
  int broadcast() { return pthread_cond_broadcast (&cond); }

  pthread_cond_t cond;
};

class RWLockImpl : public RWLock {
public:
  RWLockImpl();
  ~RWLockImpl() { pthread_rwlock_destroy (&lock); }

  int rdlock() { return pthread_rwlock_rdlock (&lock); }
  int wrlock() { return pthread_rwlock_wrlock (&lock); }
  int unlock() { return pthread_rwlock_unlock (&lock); }

  pthread_rwlock_t lock;
};



// Constructor Implementation follows...

ThreadImpl::ThreadImpl(void* (*start_routine)(void*), void* arg)
{
  if (pthread_create (&thread_id, NULL, start_routine, arg) != 0)
    throw runtime_error("pthread_create failed");
}

MutexImpl::MutexImpl()
{
  if (pthread_mutex_init (&mutex, NULL) != 0)
    throw runtime_error("pthread_mutex_init failed");
}

CondWaitImpl::CondWaitImpl()
{
  if (pthread_cond_init (&cond, NULL) != 0)
    throw runtime_error("pthread_cond_init failed");
}

RWLockImpl::RWLockImpl()
{
  if (pthread_rwlock_init (&lock, NULL) != 0)
    throw runtime_error("pthread_rwlock_init failed");
}


//
// public "static" creation functions
//

Thread* Thread::create(void* (*start_routine)(void*), void* arg)
{
  return new ThreadImpl(start_routine, arg);
}

void Thread::exit(void* return_val)
{
  pthread_exit (return_val);
}
    
Mutex * Mutex::create()
{
  return new MutexImpl();
}

CondWait * CondWait::create()
{
  return new CondWaitImpl();
}

RWLock * RWLock::create()
{
  return new RWLockImpl();
}
