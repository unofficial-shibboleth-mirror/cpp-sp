// shibthreadswin32test.cpp : by Aaron Wohl xshib@awohl.com.
//

#ifdef RUBBISH
CondWait broadcast is not implemented on win32. The semantics are different for
broadcast like events on win32.  If waking multiple waiters is needed then
need to think about it.
   
CondWait lock realease/wake up/lock get are not atomic on win32.  I dont think
that matters the way its used.  On wake up CondWait waits for the condition event or timeout.  After wake up it locks the mutex again.  Its not guarenteed that the one process that was signaled is the one that gets the lock next.
#endif

#include "stdafx.h"
#include "shib-threads.h"
#include "windows.h"
#include <list>
#include <iostream>

using namespace shibboleth;
using namespace std;

#define ASSERT(xxx) \
do { \
if(!(xxx)) { \
	fprintf(stderr,"assert failed " #xxx); \
        do_exit(1); \
} \
}while (0)

static volatile int basic_loop_count;
#define NUM_BASIC_LOOP (100)

static do_exit(int rc)
{
  char ch;
  cout << "press a key to exit" << endl;
  cout << "exit code is " << rc << " (0 is good)" << endl;
  cin >> ch;
  exit(rc);
}

static void *basic_loop_thread(void *x)
{
  for(int i=0;i<NUM_BASIC_LOOP;i++)
    basic_loop_count++;
  return 0;
}

static void test_basic_loop(void)
{
  Thread *athr=Thread::create(&basic_loop_thread,0);
  ASSERT(athr!=0);
  void *return_val;
  athr->join(&return_val);
  ASSERT(basic_loop_count==NUM_BASIC_LOOP);
}

static RWLock *arwlock;

static int roll(int n)
{
  return rand() % n;
}

static int shared_count;
#define NUM_READERS (3)
static volatile bool in_readern[NUM_READERS];

static void check_shared(void)
{
  int share_count=0;
  for(int i=0;i<NUM_READERS;i++)
    if(in_readern[i])
      share_count++;
  ASSERT(share_count>0);
  ASSERT(share_count<=NUM_READERS);
  if(share_count>1)
    shared_count++;
}

static int num_keys_disposed;

static void key_test_fcn(void *x)
{
  num_keys_disposed++;
}

static void *lock_reader(void *x)
{
  int locker_num=int(x);
  ThreadKey *akey=ThreadKey::create(key_test_fcn);
  ASSERT(akey!=0);
  akey->setData(x);
  for(int i=0;i<NUM_BASIC_LOOP;i++) {
    ASSERT(arwlock->rdlock()==0);
    in_readern[locker_num]=true;
    Sleep(roll(500));
    // make sure the thread local storage really is thread local
    // if its not some other reader will trash it
    ASSERT(akey->getData()==x);
    check_shared();
    in_readern[locker_num]=false;
    ASSERT(arwlock->unlock()==0);
    Sleep(roll(500));
  }
  delete akey;
  return 0;
}

static void *lock_writer(void *y)
{
 for(int i=0;i<NUM_BASIC_LOOP;i++) {
  ASSERT(arwlock->wrlock()==0);
  Sleep(roll(500));
  ASSERT(arwlock->unlock()==0);
  Sleep(roll(500));
  }
 return 0;
}

static void test_rwlock()
{
 arwlock=RWLock::create();
 {
  bool cant_unlock_an_unlocked_lock=(arwlock->unlock()!=0);
  ASSERT(cant_unlock_an_unlocked_lock);
 }
 list<Thread*> tl;
 for(int i=0;i<NUM_READERS;i++) {
   Thread *athr=Thread::create(&lock_reader,(void *)i);
   tl.push_back(athr);
   ASSERT(athr!=0);
   Thread *athw=Thread::create(&lock_writer,0);
   ASSERT(athw!=0);
   tl.push_back(athw);
 }
 while(!tl.empty()) {
    Thread *some_thread=tl.front();
    void *return_val;
    some_thread->join(&return_val);
    tl.pop_front();
 }
 delete arwlock;
 ASSERT(num_keys_disposed==NUM_READERS);
}

static void *empty_thread(void *x)
{
  return 0;
}

static void test_detach(void)
{
  Thread *ath=Thread::create(empty_thread,0);
  ASSERT(ath->detach()==0);
  // cant detch or join after already detach
  ASSERT(ath->detach()!=0);
  void *return_val;
  ASSERT(ath->join(&return_val)!=0);
  ASSERT(ath->detach()!=0);
  delete ath;
}

static int in_kill_proc;

static void *kill_me(void *x)
{
  while(1) {
    in_kill_proc++;
    Sleep(5);
  }
  return 0;
}

static void test_kill(void)
{
  Thread *ath=Thread::create(kill_me,0);
  while(in_kill_proc<3)
    Sleep(5);

  ASSERT(ath->kill(23)==0);
  delete ath;
}

static void test_detach_kill(void)
{
  test_detach();
  test_kill();
}

static void test_cond_timeout(void)
{
  Mutex *m=Mutex::create();
  ASSERT(m!=0);
  CondWait *cw=CondWait::create();  
  ASSERT(cw!=0);
  ASSERT(m->lock()==0);
  time_t start_time=time(0L);
#define DELAY_TIME (7)
  ASSERT(cw->timedwait(m,DELAY_TIME)==0);
  int slept_for=time(0L)-start_time;
  ASSERT(m->unlock()==0);
  delete cw;
  delete m;
  int delta_time=abs(DELAY_TIME-slept_for);
  if(delta_time>2)
    do_exit(1);
  cout << "CondWait: timed test ok" << endl;
}


static int cond_counter;
static CondWait *cond_wait;

static void *cond_incrementer(void *x)
{
  Mutex *cm=(Mutex *)(x);
  for(int i=0;i<NUM_BASIC_LOOP;i++) {
    ASSERT(cm->lock()==0);
    cond_counter++;
    if(cond_counter==(NUM_BASIC_LOOP+NUM_BASIC_LOOP/2))
      ASSERT(cond_wait->signal()==0);
    ASSERT(cm->lock()==0);
  }
  return 0;
}

static void test_cond_signal(void)
{
  Mutex *cm=Mutex::create();
  ASSERT(cm!=0);
  ASSERT(cm->lock()==0);
  cond_wait=CondWait::create();
  list<Thread*> tl;
  for(int i=0;i<2;i++) {
    Thread *athr=Thread::create(&cond_incrementer,(void *)cm);
    tl.push_back(athr);
    ASSERT(athr!=0);
  }
  ASSERT(cond_wait->wait(cm)==0);
  ASSERT(cm->unlock()==0);
  while(!tl.empty()) {
    Thread *some_thread=tl.front();
    void *return_val;
    some_thread->join(&return_val);
    tl.pop_front();
  }
  delete cond_wait;
  delete cm;
  cout << "CondWait: signal test ok" << endl;
}

static void test_cond_wait(void)
{
  test_cond_timeout();
  test_cond_signal();
}

static void protected_run_tests(void)
{
  test_cond_wait();
  test_detach_kill();
  test_basic_loop();
  test_rwlock();
}

static void run_tests(void)
{
	try {
		protected_run_tests();
	} catch (char *s) {
		cout << "caught error" << s << endl;
		do_exit(1);
	} catch (...) {
		cout << "caught unknown error" << endl;
		do_exit(1);
	}

}

int main(int argc, char* argv[])
{
  cout << "testing shib-threads, will take like 5min, look for an ok at the end\n";
  run_tests();
  cout << "tests done\n";
  cout << "readers shared " << shared_count << " times (0 shares is bad)" << endl;
  if(shared_count<1)
    do_exit(1);
  do_exit(0);
  return 0;
}

