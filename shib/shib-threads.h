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
 * shib-threads.h -- abstraction around Pthreads interface
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id: shib-threads.h,v 1.6 2003/01/30 15:18:36 warlord Exp $
 */

#ifndef SHIB_THREADS_H
#define SHIB_THREADS_H

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

#ifdef __cplusplus

#include <time.h>
#include <signal.h>

namespace shibboleth {

  //
  // core thread objects
  //

  class SHIB_EXPORTS Thread {
  public:
    static Thread* create(void* (*start_routine)(void*), void* arg);
    static void exit(void* return_val);
    static void mask_all_signals(void);
#ifndef WIN32
    static int mask_signals(int how, const sigset_t *newmask, sigset_t *oldmask);
#endif
    virtual int detach() = 0;
    virtual int join(void** thread_return) = 0;
    virtual int kill(int signo) = 0;
    virtual ~Thread(){};
  };

  class SHIB_EXPORTS Mutex {
  public:
    static Mutex* create();

    virtual int lock() = 0;
    virtual int unlock() = 0;
    virtual ~Mutex(){};
  };

  class SHIB_EXPORTS CondWait {
  public:
    static CondWait* create();

    virtual int wait(Mutex*) = 0;
    virtual int timedwait(Mutex*,int delay_seconds) = 0;
    virtual int signal() = 0;
    virtual int broadcast() = 0;
    virtual ~CondWait(){};
  };

  class SHIB_EXPORTS RWLock {
  public:
    static RWLock* create();

    virtual int rdlock() = 0;
    virtual int wrlock() = 0;
    virtual int unlock() = 0;
    virtual ~RWLock(){};
  };

  class SHIB_EXPORTS ThreadKey {
  public:
    static ThreadKey* create(void (*destroy_fcn)(void*));

    virtual int setData(void* data) = 0;
    virtual void* getData() = 0;
    virtual ~ThreadKey(){};
  };

  //
  // Helper classes.
  //

  class SHIB_EXPORTS Lock {
  public:
    Lock(Mutex* mtx) : mutex(mtx) { mutex->lock(); }
    ~Lock() { mutex->unlock(); }

  private:
    Lock(const Lock&);
    void operator=(const Lock&);
    Mutex* mutex;
  };

  class SHIB_EXPORTS ReadLock {
  public:
    ReadLock(RWLock* lock) : rwlock(lock) { rwlock->rdlock(); }
    ~ReadLock() { rwlock->unlock(); }

  private:
    ReadLock(const ReadLock&);
    void operator=(const ReadLock&);
    RWLock* rwlock;
  };

} // namespace

#endif /* __cplusplus */
#endif /* SHIB_THREADS_H */
