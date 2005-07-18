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
 * shib-threads.cpp -- an abstraction around Pthreads
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id: shib-threads.cpp,v 1.5 2003/01/30 15:18:36 warlord Exp $
 */

#include "internal.h"
#include "shib-threads.h"

#include <log4cpp/Category.hh>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#ifndef HAVE_PTHREAD_RWLOCK_INIT
#include <synch.h>
#endif
#else
#error "You need to create the proper thread implementation"
#endif

#include <stdexcept>

using namespace std;
using namespace shibboleth;
using namespace log4cpp;

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
  int kill(int signo) { return pthread_kill(thread_id, signo); }

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
  int timedwait(Mutex* mutex, int delay_seconds)
  	{ return timedwait (dynamic_cast<MutexImpl*>(mutex), delay_seconds); }
  int timedwait(MutexImpl* mutex, int delay_seconds) {
    struct timespec ts;
    memset (&ts, 0, sizeof(ts));
    ts.tv_sec = time(NULL) + delay_seconds;
    return pthread_cond_timedwait (&cond, &(mutex->mutex), &ts);
  }
  int signal() { return pthread_cond_signal (&cond); }
  int broadcast() { return pthread_cond_broadcast (&cond); }

  pthread_cond_t cond;
};

class RWLockImpl : public RWLock {
public:
#ifdef HAVE_PTHREAD_RWLOCK_INIT
  RWLockImpl();
  ~RWLockImpl() { pthread_rwlock_destroy (&lock); }

  int rdlock() { return pthread_rwlock_rdlock (&lock); }
  int wrlock() { return pthread_rwlock_wrlock (&lock); }
  int unlock() { return pthread_rwlock_unlock (&lock); }

  pthread_rwlock_t lock;
#else
  RWLockImpl();
  ~RWLockImpl() { rwlock_destroy (&lock); }

  int rdlock() { return rw_rdlock (&lock); }
  int wrlock() { return rw_wrlock (&lock); }
  int unlock() { return rw_unlock (&lock); }

  rwlock_t lock;
#endif
};

class ThreadKeyImpl : public ThreadKey {
public:
  ThreadKeyImpl(void (*destroy_fcn)(void*));
  ~ThreadKeyImpl() { pthread_key_delete (key); }

  int setData(void* data) { return pthread_setspecific (key,data); }
  void* getData() { return pthread_getspecific (key); }

  pthread_key_t key;
};

//
// Constructor Implementation follows...
//

ThreadImpl::ThreadImpl(void* (*start_routine)(void*), void* arg)
{
    int rc=pthread_create(&thread_id, NULL, start_routine, arg);
    if (rc) {
#ifdef HAVE_STRERROR_R
        char buf[256];
        strerror_r(rc,buf,sizeof(buf));
        buf[255]=0;
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_create error (%d): %s",rc,buf);
#else
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_create error (%d): %s",rc,strerror(rc));
#endif
        throw rc;
    }
}

MutexImpl::MutexImpl()
{
    int rc=pthread_mutex_init(&mutex, NULL);
    if (rc) {
#ifdef HAVE_STRERROR_R
        char buf[256];
        strerror_r(rc,buf,sizeof(buf));
        buf[255]=0;
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_mutex_init error (%d): %s",rc,buf);
#else
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_mutex_init error (%d): %s",rc,strerror(rc));
#endif
        throw rc;
    }
}

CondWaitImpl::CondWaitImpl()
{
    int rc=pthread_cond_init(&cond, NULL);
    if (rc) {
#ifdef HAVE_STRERROR_R
        char buf[256];
        strerror_r(rc,buf,sizeof(buf));
        buf[255]=0;
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_cond_init error (%d): %s",rc,buf);
#else
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_cond_init error (%d): %s",rc,strerror(rc));
#endif
        throw rc;
    }
}

RWLockImpl::RWLockImpl()
{
#ifdef HAVE_PTHREAD_RWLOCK_INIT
    int rc=pthread_rwlock_init(&lock, NULL);
#else
    int rc=rwlock_init(&lock, USYNC_THREAD, NULL);
#endif
    if (rc) {
#ifdef HAVE_STRERROR_R
        char buf[256];
        strerror_r(rc,buf,sizeof(buf));
        buf[255]=0;
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_rwlock_init error (%d): %s",rc,buf);
#else
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_rwlock_init error (%d): %s",rc,strerror(rc));
#endif
        throw rc;
    }
}

ThreadKeyImpl::ThreadKeyImpl(void (*destroy_fcn)(void*))
{
    int rc=pthread_key_create(&key, destroy_fcn);
    if (rc) {
#ifdef HAVE_STRERROR_R
        char buf[256];
        strerror_r(rc,buf,sizeof(buf));
        buf[255]=0;
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_key_create error (%d): %s",rc,buf);
#else
        Category::getInstance(SHIB_LOGCAT".threads").error("pthread_key_create error (%d): %s",rc,strerror(rc));
#endif
        throw rc;
    }
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
    
void Thread::mask_all_signals(void)
{
  sigset_t sigmask;
  sigfillset(&sigmask);
  Thread::mask_signals(SIG_BLOCK, &sigmask, NULL);
}

int Thread::mask_signals(int how, const sigset_t *newmask, sigset_t *oldmask)
{
  return pthread_sigmask(how,newmask,oldmask);
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

ThreadKey* ThreadKey::create (void (*destroy_fcn)(void*))
{
  return new ThreadKeyImpl(destroy_fcn);
}
