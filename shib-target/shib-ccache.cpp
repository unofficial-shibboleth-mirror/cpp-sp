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
 * shib-ccache.cpp -- SHAR Credential Cache
 *
 * Originally from mod_shib
 * Modified by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "shib-target.h"
#include "ccache-utils.h"
#include <shib/shib-threads.h>

#include <log4cpp/Category.hh>

#include <sstream>
#include <stdexcept>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class InternalCCache;
class InternalCCacheEntry : public CCacheEntry
{
public:
  InternalCCacheEntry(SAMLAuthenticationStatement *s, const char *client_addr);
  ~InternalCCacheEntry();

  virtual Iterator<SAMLAssertion*> getAssertions(Resource& resource);
  virtual void preFetch(Resource& resource, int prefetch_window);
  virtual bool isSessionValid(time_t lifetime, time_t timeout);
  virtual const char* getClientAddress() { return m_clientAddress.c_str(); }
  virtual void release() { cacheitem_lock->unlock(); }

  void setCache(InternalCCache *cache) { m_cache = cache; }
  time_t lastAccess() { Lock lock(access_lock); return m_lastAccess; }
  void rdlock() { cacheitem_lock->rdlock(); }
  void wrlock() { cacheitem_lock->wrlock(); }

  static vector<SAMLAssertion*> g_emptyVector;

private:
  ResourceEntry* populate(Resource& resource, int slop);
  ResourceEntry* find(const char* resource);
  void insert(const char* resource, ResourceEntry* entry);
  void remove(const char* resource);

  string m_originSite;
  string m_handle;
  string m_clientAddress;
  time_t m_sessionCreated;
  time_t m_lastAccess;
  bool m_hasbinding;

  const SAMLSubject* m_subject;
  SAMLAuthenticationStatement* p_auth;
  InternalCCache *m_cache;

  map<string,ResourceEntry*> m_resources;

  log4cpp::Category* log;

  // This is used to keep track of in-process "populate()" calls,
  // to make sure that we don't try to populate the same resource
  // in multiple threads.
  map<string,Mutex*>	populate_locks;
  Mutex*	pop_locks_lock;

  Mutex*	access_lock;
  RWLock*	resource_lock;
  RWLock*	cacheitem_lock;

  class ResourceLock
  {
  public:
    ResourceLock(InternalCCacheEntry* entry, string resource);
    ~ResourceLock();

  private:
    Mutex*			find(string& resource);
    InternalCCacheEntry*	entry;
    string			resource;
  };

  friend class ResourceLock;
};

class InternalCCache : public CCache
{
public:
  InternalCCache();
  virtual ~InternalCCache();

  virtual SAMLBinding* getBinding(const XMLCh* bindingProt);
  virtual CCacheEntry* find(const char* key);
  virtual void insert(const char* key, SAMLAuthenticationStatement *s,
		      const char *client_addr);
  virtual void remove(const char* key);

  InternalCCacheEntry* findi(const char* key);
  void	cleanup();

private:
  RWLock *lock;

  SAMLBinding* m_SAMLBinding;
  map<string,InternalCCacheEntry*> m_hashtable;

  log4cpp::Category* log;

  static void*	cleanup_fcn(void*); // XXX Assumed an InternalCCache
  bool		shutdown;
  CondWait*	shutdown_wait;
  Thread*	cleanup_thread;
};

namespace {
  map<string,CCache::CCacheFactory> g_ccacheFactoryDB;
};

// Global Constructors & Destructors
CCache::~CCache() { }

void CCache::registerFactory(const char* name, CCache::CCacheFactory factory)
{
  string ctx = "shibtarget.CCache";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);
  saml::NDC ndc("registerFactory");

  log.info ("Registered factory %p for CCache %s", factory, name);
  g_ccacheFactoryDB[name] = factory;
}

CCache* CCache::getInstance(const char* type)
{
  string ctx = "shibtarget.CCache";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);
  saml::NDC ndc("getInstance");

  map<string,CCache::CCacheFactory>::const_iterator i=g_ccacheFactoryDB.find(type);
  if (i!=g_ccacheFactoryDB.end()) {
    log.info ("Loading CCache: %s at %p", type, i->second);
    return ((i->second)());
  }

  log.info ("Loading default memory CCache");
  return (CCache*) new InternalCCache();
}

// static members
vector<SAMLAssertion*> InternalCCacheEntry::g_emptyVector;


/******************************************************************************/
/* InternalCCache:  A Credential Cache                                        */
/******************************************************************************/

InternalCCache::InternalCCache()
{
  m_SAMLBinding=SAMLBindingFactory::getInstance();
  string ctx="shibtarget.InternalCCache";
  log = &(log4cpp::Category::getInstance(ctx));
  lock = RWLock::create();

  shutdown_wait = CondWait::create();
  shutdown = false;
  cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

InternalCCache::~InternalCCache()
{
  // Shut down the cleanup thread and let it know...
  shutdown = true;
  shutdown_wait->signal();
  cleanup_thread->join(NULL);

  delete m_SAMLBinding;
  for (map<string,InternalCCacheEntry*>::iterator i=m_hashtable.begin(); i!=m_hashtable.end(); i++)
    delete i->second;
  delete lock;
  delete shutdown_wait;
}

SAMLBinding* InternalCCache::getBinding(const XMLCh* bindingProt)
{
  log->debug("looking for binding...");
  if (!XMLString::compareString(bindingProt,SAMLBinding::SAML_SOAP_HTTPS)) {
    log->debug("https binding found");
    return m_SAMLBinding;
  }
  return NULL;
}

// assumed a lock is held..
InternalCCacheEntry* InternalCCache::findi(const char* key)
{
  log->debug("FindI: \"%s\"", key);

  map<string,InternalCCacheEntry*>::const_iterator i=m_hashtable.find(key);
  if (i==m_hashtable.end()) {
    log->debug("No Match found");
    return NULL;
  }
  log->debug("Match Found.");

  return i->second;
}

CCacheEntry* InternalCCache::find(const char* key)
{
  log->debug("Find: \"%s\"", key);
  ReadLock rwlock(lock);

  InternalCCacheEntry* entry = findi(key);
  if (!entry) return NULL;

  // Lock the database for the caller -- they have to release the item.
  entry->rdlock();
  return dynamic_cast<CCacheEntry*>(entry);
}

void InternalCCache::insert(const char* key, SAMLAuthenticationStatement *s,
			    const char *client_addr)
{
  log->debug("caching new entry for \"%s\"", key);

  InternalCCacheEntry* entry = new InternalCCacheEntry (s, client_addr);
  entry->setCache(this);

  lock->wrlock();
  m_hashtable[key]=entry;
  lock->unlock();
}

// remove the entry from the database and then destroy the cacheentry
void InternalCCache::remove(const char* key)
{
  log->debug("removing cache entry \"key\"", key);

  // grab the entry from the database.  We'll have a readlock on it.
  CCacheEntry* entry = findi(key);

  if (!entry)
    return;

  // grab the cache write lock
  lock->wrlock();

  // verify we've still got the same entry.
  if (entry != findi(key)) {
    // Nope -- must've already been removed.
    lock->unlock();
    return;
  }

  // ok, remove the entry.
  m_hashtable.erase(key);
  lock->unlock();

  // now grab the write lock on the cacheitem.
  // This will make sure all other threads have released this item.
  InternalCCacheEntry* ientry = dynamic_cast<InternalCCacheEntry*>(entry);
  ientry->wrlock();

  // we can release immediately because we know we're not in the database!
  ientry->release();

  // Now delete the entry
  delete ientry;
}

void InternalCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("InternalCCache::cleanup()");

  ShibTargetConfig& config = ShibTargetConfig::getConfig();
  ShibINI& ini = config.getINI();

  int rerun_timer = 0;
  int timeout_life = 0;

  string tag;
  if (ini.get_tag (SHIBTARGET_SHAR, SHIBTARGET_TAG_CACHECLEAN, true, &tag))
    rerun_timer = atoi(tag.c_str());
  if (ini.get_tag (SHIBTARGET_SHAR, SHIBTARGET_TAG_CACHETIMEOUT, true, &tag))
    timeout_life = atoi(tag.c_str());

  if (rerun_timer <= 0)
    rerun_timer = 300;		// rerun every 5 minutes

  if (timeout_life <= 0)
    timeout_life = 28800;	// timeout after 8 hours

  mutex->lock();

  log->debug("Cleanup thread started...  Run every %d secs; timeout after %d secs",
	     rerun_timer, timeout_life);

  while (shutdown == false) {
    struct timespec ts;
    memset (&ts, 0, sizeof(ts));
    ts.tv_sec = time(NULL) + rerun_timer;

    shutdown_wait->timedwait(mutex, &ts);

    if (shutdown == true)
      break;

    log->info("Cleanup thread running...");

    // Ok, let's run through the cleanup process and clean out
    // really old sessions.  This is a two-pass process.  The
    // first pass is done holding a read-lock while we iterate over
    // the database.  The second pass doesn't need a lock because
    // the 'deletes' will lock the database.

    // Pass 1: iterate over the map and find all entries that have not been
    // used in X hours
    vector<string> stale_keys;
    time_t stale = time(NULL) - timeout_life;

    lock->rdlock();
    for (map<string,InternalCCacheEntry*>::iterator i=m_hashtable.begin();
	 i != m_hashtable.end(); i++)
    {
      // If the last access was BEFORE the stale timeout...
      time_t last=i->second->lastAccess();
      if (last < stale)
        stale_keys.push_back(i->first);
    }
    lock->unlock();

    log->info("deleting %d old items.", stale_keys.size());

    // Pass 2: walk through the list of stale entries and remove them from
    // the database
    for (vector<string>::iterator j = stale_keys.begin();
	 j != stale_keys.end(); j++)
    {
      remove (j->c_str());
    }

  }

  log->debug("Cleanup thread finished.");

  mutex->unlock();
  delete mutex;
  Thread::exit(NULL);
}

void* InternalCCache::cleanup_fcn(void* cache_p)
{
  InternalCCache* cache = (InternalCCache*)cache_p;

  // First, let's block all signals
  sigset_t sigmask;
  sigfillset(&sigmask);
  Thread::mask_signals(SIG_BLOCK, &sigmask, NULL);

  // Now run the cleanup process.
  cache->cleanup();
}

/******************************************************************************/
/* InternalCCacheEntry:  A Credential Cache Entry                             */
/******************************************************************************/

InternalCCacheEntry::InternalCCacheEntry(SAMLAuthenticationStatement *s, const char *client_addr)
  : m_hasbinding(false)
{
  string ctx = "shibtarget::InternalCCacheEntry";
  log = &(log4cpp::Category::getInstance(ctx));
  pop_locks_lock = Mutex::create();
  access_lock = Mutex::create();
  resource_lock = RWLock::create();
  cacheitem_lock = RWLock::create();

  if (s == NULL) {
    log->error("NULL auth statement");
    throw runtime_error("InternalCCacheEntry() was passed an empty SAML Statement");
  }

  m_subject = s->getSubject();

  xstring name = m_subject->getName();
  xstring qual = m_subject->getNameQualifier();

  auto_ptr<char> h(XMLString::transcode(name.c_str()));
  auto_ptr<char> d(XMLString::transcode(qual.c_str()));

  m_handle = h.get();
  m_originSite = d.get();

  Iterator<SAMLAuthorityBinding*> bindings = s->getBindings();
  if (bindings.hasNext())
    m_hasbinding = true;

  m_clientAddress = client_addr;
  m_sessionCreated = m_lastAccess = time(NULL);

  // Save for later.
  p_auth = s;

  log->info("New Session Created...");
  log->debug("Handle: \"%s\", Site: \"%s\", Address: %s", h.get(), d.get(),
	     client_addr);
}

InternalCCacheEntry::~InternalCCacheEntry()
{
  log->debug("deleting entry for %s@%s", m_handle.c_str(), m_originSite.c_str());
  delete p_auth;
  for (map<string,ResourceEntry*>::iterator i=m_resources.begin();
       i!=m_resources.end(); i++)
    delete i->second;

  for (map<string,Mutex*>::iterator j=populate_locks.begin();
       j!=populate_locks.end(); j++)
    delete j->second;

  delete pop_locks_lock;
  delete cacheitem_lock;
  delete resource_lock;
  delete access_lock;
}

bool InternalCCacheEntry::isSessionValid(time_t lifetime, time_t timeout)
{
  saml::NDC ndc("isSessionValid");
  log->debug("test session %s@%s, (lifetime=%ld, timeout=%ld)",
	     m_handle.c_str(), m_originSite.c_str(), lifetime, timeout);
  time_t now=time(NULL);
  if (lifetime > 0 && now > m_sessionCreated+lifetime) {
    log->debug("session beyond lifetime");
    return false;
  }

  // Lock the access-time from here until we return
  Lock lock(access_lock);
  if (timeout > 0 && now-m_lastAccess >= timeout) {
    log->debug("session timed out");
    return false;
  }
  m_lastAccess=now;
  return true;
}

Iterator<SAMLAssertion*> InternalCCacheEntry::getAssertions(Resource& resource)
{
  saml::NDC ndc("getAssertions");
  ResourceEntry* entry = populate(resource, 0);
  if (entry)
    return entry->getAssertions();
  return Iterator<SAMLAssertion*>(InternalCCacheEntry::g_emptyVector);
}

void InternalCCacheEntry::preFetch(Resource& resource, int prefetch_window)
{
  saml::NDC ndc("preFetch");
  ResourceEntry* entry = populate(resource, prefetch_window);
}

ResourceEntry* InternalCCacheEntry::populate(Resource& resource, int slop)
{
  saml::NDC ndc("populate");
  log->debug("populating entry for %s (%s)",
	     resource.getResource(), resource.getURL());

  // Lock the resource within this entry...
  InternalCCacheEntry::ResourceLock lock(this, resource.getResource());

  // Can we use what we have?
  ResourceEntry *entry = find(resource.getResource());
  if (entry) {
    log->debug("found resource");
    if (entry->isValid(slop))
      return entry;

    // entry is invalid (expired) -- go fetch a new one.
    log->debug("removing resource cache; assertion is invalid");
    remove (resource.getResource());
    delete entry;
  }

  // Nope, no entry.. Create a new resource entry

  if (!m_hasbinding) {
    log->error("No binding!");
    return NULL;
  }

  log->info("trying to request attributes for %s@%s -> %s",
	    m_handle.c_str(), m_originSite.c_str(), resource.getURL());

  try {
    entry = new ResourceEntry(resource, *m_subject, m_cache, p_auth->getBindings());
  } catch (ShibTargetException &e) {
    return NULL;
  }
  insert (resource.getResource(), entry);

  log->info("fetched and stored SAML response");
  return entry;
}

ResourceEntry* InternalCCacheEntry::find(const char* resource_url)
{
  ReadLock rwlock(resource_lock);

  log->debug("find: %s", resource_url);
  map<string,ResourceEntry*>::const_iterator i=m_resources.find(resource_url);
  if (i==m_resources.end()) {
    log->debug("no match found");
    return NULL;
  }
  log->debug("match found");
  return i->second;
}

void InternalCCacheEntry::insert(const char* resource, ResourceEntry* entry)
{
  log->debug("inserting %s", resource);

  resource_lock->wrlock();
  m_resources[resource]=entry;
  resource_lock->unlock();
}

// caller will delete the entry.. don't worry about that here.
void InternalCCacheEntry::remove(const char* resource)
{
  log->debug("removing %s", resource);

  resource_lock->wrlock();
  m_resources.erase(resource);
  resource_lock->unlock();
}


// a lock on a resource.  This is a specific "table of locks" that
// will provide a mutex on a particular resource within a Cache Entry.
// Just instantiate a ResourceLock within scope of the function and it
// will obtain and hold the proper lock until it goes out of scope and
// deconstructs.

InternalCCacheEntry::ResourceLock::ResourceLock(InternalCCacheEntry* entry,
						string resource) :
  entry(entry), resource(resource)
{
  Mutex *mutex = find(resource);
  mutex->lock();
}

InternalCCacheEntry::ResourceLock::~ResourceLock()
{
  Mutex *mutex = find(resource);
  mutex->unlock();
}

Mutex* InternalCCacheEntry::ResourceLock::find(string& resource)
{
  Lock(entry->pop_locks_lock);
  
  map<string,Mutex*>::const_iterator i=entry->populate_locks.find(resource);
  if (i==entry->populate_locks.end()) {
    Mutex* mutex = Mutex::create();
    entry->populate_locks[resource] = mutex;
    return mutex;
  }
  return i->second;
}
