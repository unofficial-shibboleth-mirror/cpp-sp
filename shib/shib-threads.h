/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
