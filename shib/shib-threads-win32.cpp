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
 * shib-threads-win32.cpp -- an abstraction around win32 threads
 *
 * Created by:	aaron wohl <xshib@awohl.com>
 *
 * $Id$
 */

#ifdef STANDALONE_SHIBTHREADS_TESTING
#include <windows.h>
#else
#include "internal.h"
#endif

#include "shib-threads.h"

#ifndef WIN32
#error "This implementaiton is just for windows 32"
#endif

#include <stdexcept>

using namespace std;
using namespace shibboleth;

// base error code for a routine to return onf failure
#define THREAD_ERROR_TIMEOUT 	(1)
#define THREAD_ERROR_WAKE_OTHER (2)
#define THREAD_ERROR_
#define THREAD_ERROR 		(3)

static void note_last_error(int rc) {
    // set a breakpoint here to see windows error codes for failing
    // thread operations
}

// windows returns non zero for sucess pthreads returns zero
static int map_windows_error_status_to_pthreads(int rc) {
  if(rc!=0)  // sucess?
    return 0; // yes
  int last_error=GetLastError();
  note_last_error(last_error);
  return THREAD_ERROR;
}

// win32 implementation of the Shib Target Threads API

//
// "Private" Implementation
//

// two levels of classes are needed here
// in case InitializeCriticalSection
// throws an exception we can keep from
// calling the critical_section destructor
// on unitilized data, or it could be done with a flag
class critical_section_data {
public:
  CRITICAL_SECTION cs;
  critical_section_data(){
    InitializeCriticalSection(&cs);    
  }
};

class critical_section {
private:
  critical_section_data	cse;
public:
  critical_section(){}
  ~critical_section(){
    DeleteCriticalSection (&cse.cs);
  }
  void enter(void) {
    EnterCriticalSection(&cse.cs);
  }
  void leave(void) {
    LeaveCriticalSection(&cse.cs);
  }
};

// hold a critical section over the lifetime of this object
// used to make a stack variable that unlocks automaticly
// on return/throw
class with_crit_section {
private:
  critical_section& cs;
public:
  with_crit_section(critical_section& acs):cs(acs){
    cs.enter();
  }
  ~with_crit_section(){
    cs.leave();
  }
};

class ThreadImpl : public Thread {
private:
  HANDLE thread_id;
public:
  ThreadImpl(void* (*start_routine)(void*), void* arg):thread_id(0){
	 thread_id=CreateThread(
      0, // security attributes
      0, // use default stack size, maybe this should be setable
     (LPTHREAD_START_ROUTINE ) start_routine,
     arg,
     0, // flags, default is ignore stacksize and dont create suspeneded which
        // is what we want
     0);
  if(thread_id==0) {
      int rc=map_windows_error_status_to_pthreads(0);
	  throw("thread create failed");
  }
  }

  int detach() {
    if(thread_id==0)
      return THREAD_ERROR;
    int rc=map_windows_error_status_to_pthreads(CloseHandle(thread_id));
    thread_id=0;
    return rc;
  }
  ~ThreadImpl() {
    (void)detach();
  }

  int join(void** thread_return) {
  if(thread_id==0)
      return THREAD_ERROR;
  if(thread_return!=0)
    *thread_return=0;
  int rc=WaitForSingleObject(thread_id,INFINITE);
  switch(rc) {
  case WAIT_OBJECT_0:
      if (thread_return)
	    map_windows_error_status_to_pthreads(
		  GetExitCodeThread(thread_id,(unsigned long *)thread_return));
  default:
    return THREAD_ERROR+1;
  }
  }
  
  int kill(int signo) {
    if(thread_id==0)
      return THREAD_ERROR;
    return map_windows_error_status_to_pthreads(TerminateThread(thread_id,signo));
  }

};

class MutexImpl : public Mutex {
private:
  HANDLE mhandle;
public:
  MutexImpl():mhandle(0){
    mhandle=CreateMutex(0,false,0);
    if(mhandle==0)
      throw("CreateMutex for failed");
  }
  ~MutexImpl(){
    if((mhandle!=0)&&(!CloseHandle(mhandle))) 
      throw("CloseHandle for CondWaitImpl failed");
  }
  int lock() {
   int rc=WaitForSingleObject(mhandle,INFINITE);
   switch(rc) {
     case WAIT_ABANDONED:
     case WAIT_OBJECT_0:
       return 0;
     default:
       return map_windows_error_status_to_pthreads(0);
   }
  }
  int unlock() {
    return map_windows_error_status_to_pthreads(ReleaseMutex(mhandle));
  }
};

class CondWaitImpl : public CondWait {
  private:
    HANDLE cond;

  public:
    CondWaitImpl():cond(CreateEvent(0,false,false,0)){
      if(cond==0)
	throw("CreateEvent for CondWaitImpl failed");
    };

  ~CondWaitImpl() {
    if((cond!=0)&&(!CloseHandle(cond))) 
      throw("CloseHandle for CondWaitImpl failed");
  }

  int wait(Mutex* mutex) {
    return timedwait(mutex,INFINITE);
  }

  int signal() {
    if(!SetEvent(cond))
     return map_windows_error_status_to_pthreads(0);
    return 0;
  }
  int broadcast() {
    throw("CondWaitImpl not implemented on win32");
  }

  // wait for myself to signal and this mutex or the timeout
  int timedwait(Mutex* mutex, int delay_seconds) {
    int rc=mutex->unlock();
    if(rc!=0)
      return rc;

    int delay_ms=delay_seconds;
    if(delay_seconds!=INFINITE)
      delay_ms*=1000;
    rc=WaitForSingleObject(cond,delay_ms);
    {
      int rc2=mutex->lock();
      if(rc2!=0)
        return rc2;
    }
    switch(rc) {
    case WAIT_ABANDONED:
    case WAIT_OBJECT_0:
    case WAIT_TIMEOUT:
      return 0;
    default:
      return map_windows_error_status_to_pthreads(0);
    }
    return 0;
  }
};

class RWLockImpl : public RWLock {
private:
  // used to protect read or write to the data below
  critical_section cs;
  // event handle threads wait on when the lock they want is busy
  // normaly set to signaled all the time, if some thread cant get what
  // they want they reset it and sleep.  on releasing a lock set it to
  // signaled if someone may have wanted what you just released
  HANDLE wake_waiters;
  // number of threads holding a read lock
  int num_readers;
  // true iff there a writer has our lock
  bool have_writer;

public:
  RWLockImpl():wake_waiters(0),num_readers(0),have_writer(true) {
    with_crit_section acs(cs);
    wake_waiters=CreateEvent(0,true,true,0);
    have_writer=false;
    if(wake_waiters==0)
      throw("CreateEvent for RWLockImpl failed");
  }
  ~RWLockImpl() { 
     with_crit_section acs(cs);
     if((wake_waiters!=0)&&(!CloseHandle(wake_waiters))) 
       throw("CloseHandle for RWLockImpl failed");
     wake_waiters=0;
   }

  int rdlock() {
    while(1) {
     // wait for the lock maybe being availible
     // we will find out for sure inside the critical section
     if(WaitForSingleObject(wake_waiters,INFINITE)!=WAIT_OBJECT_0) 
       return map_windows_error_status_to_pthreads(0);
     {
       with_crit_section alock(cs);
      // invariant not locked for reading and writing
       if((num_readers!=0)&&(have_writer))
	       return THREAD_ERROR;
       // if no writer we can join any existing readers
       if(!have_writer) {
         num_readers++;
	 return 0;
       }
       // have a writer, mark the syncronization object
       // so everyone waits, when the writer unlocks it will wake us
       if(!ResetEvent(wake_waiters))
         return map_windows_error_status_to_pthreads(0);
     }
    }
    return THREAD_ERROR+2;
  }

  int wrlock() {
    while(1) {
    // wait for the lock maybe being availible
    // we will find out for sure inside the critical section
    if(WaitForSingleObject(wake_waiters,INFINITE)!=WAIT_OBJECT_0) 
      return map_windows_error_status_to_pthreads(0);
    {
     with_crit_section bla(cs);
    // invariant not locked for reading and writing
     if((num_readers!=0)&&(have_writer))
	     return THREAD_ERROR;
     // if no writer and no readers we can become the writer
    if((num_readers==0)&&(!have_writer)) {
      have_writer=true;
      return 0;
     }
     // lock is busy, the unlocker will wake us
     if(!ResetEvent(wake_waiters))
       return map_windows_error_status_to_pthreads(0);
    }
    }
    return THREAD_ERROR+2;
  }

  int unlock() {
    with_crit_section mumble(cs);
    // invariant not locked for reading and writing
    if((num_readers!=0)&&(have_writer))
      return THREAD_ERROR;
    // error if nothing locked
    if((num_readers==0)&&(!have_writer))
      return THREAD_ERROR+1;
    // if there was a writer it has to be us so unlock write lock 
    have_writer=false;
    // if there where any reades there is one less now
    if(num_readers>0)
      num_readers--;
    // if no readers left wake up any readers/writers waiting
    // to have a go at it
    if(num_readers==0)
      if(!SetEvent(wake_waiters))
	  return map_windows_error_status_to_pthreads(0);
    return 0;
  }
};

typedef void (*destroy_hook_type)(void*);

class ThreadKeyImpl : public ThreadKey {
private:
  destroy_hook_type destroy_hook;
  DWORD key;

public:
  ThreadKeyImpl(void (*destroy_fcn)(void*)) : destroy_hook(destroy_fcn) { key=TlsAlloc(); };
  virtual ~ThreadKeyImpl() { if (destroy_hook) destroy_hook(TlsGetValue(key)); TlsFree(key); }

  int setData(void* data) { TlsSetValue(key,data); return 0;}
  void* getData() { return TlsGetValue(key); }
  };

//
// public "static" creation functions
//

void Thread::mask_all_signals(void)
{
}

Thread* Thread::create(void* (*start_routine)(void*), void* arg)
{
  return new ThreadImpl(start_routine, arg);
}

void Thread::exit(void* return_val)
{
  ExitThread((DWORD)return_val);
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
