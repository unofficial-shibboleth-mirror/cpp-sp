/*
 * shib-threads.h -- abstraction around Pthreads interface
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id: shib-threads.h,v 1.6 2003/01/30 15:18:36 warlord Exp $
 */

#ifndef SHIB_THREADS_H
#define SHIB_THREADS_H

#ifdef __cplusplus

#include <time.h>
#include <signal.h>

namespace shibboleth {

  //
  // core thread objects
  //

  class Thread {
  public:
    static Thread* create(void* (*start_routine)(void*), void* arg);
    static void exit(void* return_val);
    static int mask_signals(int how, const sigset_t *newmask, sigset_t *oldmask);

    virtual int detach() = 0;
    virtual int join(void** thread_return) = 0;
    virtual int kill(int signo) = 0;
  };

  class Mutex {
  public:
    static Mutex* create();

    virtual int lock() = 0;
    virtual int unlock() = 0;
  };

  class CondWait {
  public:
    static CondWait* create();

    virtual int wait(Mutex*) = 0;
    virtual int timedwait(Mutex*, struct timespec *abstime) = 0;
    virtual int signal() = 0;
    virtual int broadcast() = 0;
  };

  class RWLock {
  public:
    static RWLock* create();

    virtual int rdlock() = 0;
    virtual int wrlock() = 0;
    virtual int unlock() = 0;
  };

  class ThreadKey {
  public:
    static ThreadKey* create (void (*destroy_fcn)(void*));

    virtual int setData(void* data) = 0;
    virtual void* getData() = 0;
  };

  //
  // Helper classes.
  //

  class Lock {
  public:
    Lock(Mutex* mtx) : mutex(mtx) { mutex->lock(); }
    ~Lock() { mutex->unlock(); }

  private:
    Lock(const Lock&);
    void operator=(const Lock&);
    Mutex* mutex;
  };

  class ReadLock {
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
