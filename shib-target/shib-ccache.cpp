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

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"
#include "shib-threads.h"

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

class ResourceEntry
{
public:
  ResourceEntry(SAMLResponse* response);
  ~ResourceEntry();

  bool isValid();
  Iterator<SAMLAssertion*> getAssertions();

  static vector<SAMLAssertion*> g_emptyVector;

private:
  SAMLResponse* m_response;

  log4cpp::Category* log;
};

class InternalCCache;
class InternalCCacheEntry : public CCacheEntry
{
public:
  InternalCCacheEntry(SAMLAuthenticationStatement *s, const char *client_addr);
  ~InternalCCacheEntry();

  virtual Iterator<SAMLAssertion*> getAssertions(Resource& resource);
  virtual bool isSessionValid(time_t lifetime, time_t timeout);
  virtual const char* getClientAddress() { return m_clientAddress.c_str(); }

  void setCache(InternalCCache *cache) { m_cache = cache; }
  time_t lastAccess() { Lock lock(access_lock); return m_lastAccess; }

private:
  ResourceEntry* populate(Resource& resource);
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

  static saml::QName g_authorityKind;
  static saml::QName g_respondWith;

  log4cpp::Category* log;

  // This is used to keep track of in-process "populate()" calls,
  // to make sure that we don't try to populate the same resource
  // in multiple threads.
  map<string,Mutex*>	populate_locks;
  Mutex*	pop_locks_lock;

  Mutex*	access_lock;
  RWLock*	resource_lock;

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

  void	cleanup();
private:
  SAMLBinding* m_SAMLBinding;
  map<string,InternalCCacheEntry*> m_hashtable;

  log4cpp::Category* log;
  RWLock *lock;

  static void*	cleanup_fcn(void*); // XXX Assumed an InternalCCache
  bool		shutdown;
  CondWait*	shutdown_wait;
  Thread*	cleanup_thread;
};

// Global Constructors & Destructors
CCache::~CCache() { }

CCache* CCache::getInstance(const char* type)
{
  return (CCache*) new InternalCCache();
}

// static members
saml::QName InternalCCacheEntry::g_authorityKind(saml::XML::SAMLP_NS,L(AttributeQuery));
saml::QName InternalCCacheEntry::g_respondWith(saml::XML::SAML_NS,L(AttributeStatement));
vector<SAMLAssertion*> ResourceEntry::g_emptyVector;


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

CCacheEntry* InternalCCache::find(const char* key)
{
  log->debug("Find: \"%s\"", key);
  ReadLock rwlock(lock);

  map<string,InternalCCacheEntry*>::const_iterator i=m_hashtable.find(key);
  if (i==m_hashtable.end()) {
    log->debug("No Match found");
    return NULL;
  }
  log->debug("Match Found.");
  return dynamic_cast<CCacheEntry*>(i->second);
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

void InternalCCache::remove(const char* key)
{
  log->debug("removing cache entry \"key\"", key);

  // XXX: FIXME? do we need to delete the CacheEntry?

  lock->wrlock();
  m_hashtable.erase(key);
  lock->unlock();
}

void InternalCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("InternalCCache::cleanup()");

  mutex->lock();

  log->debug("Cleanup thread started...");

  while (shutdown == false) {
    struct timespec ts;
    memset (&ts, 0, sizeof(ts));
    ts.tv_sec = time(NULL) + 3600;	// run every hour

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
    time_t stale = time(NULL) - 8 * 3600; // XXX: 8 hour timeout.

    lock->rdlock();
    for (map<string,InternalCCacheEntry*>::iterator i=m_hashtable.begin();
	 i != m_hashtable.end(); i++)
    {
      // If the last access was BEFORE the stale timeout...
      if (i->second->lastAccess() < stale)
	stale_keys.push_back(i->first);
    }
    lock->unlock();

    log->info("deleting %d old items.", stale_keys.size());

    // Pass 2: walk through the list of stale entries and remove them from
    // the database
    for (vector<string>::iterator i = stale_keys.begin();
	 i != stale_keys.end(); i++)
    {
      remove (i->c_str());
    }

  }

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

  for (map<string,Mutex*>::iterator i=populate_locks.begin();
       i!=populate_locks.end(); i++)
    delete i->second;

  delete pop_locks_lock;
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
  ResourceEntry* entry = populate(resource);
  if (entry)
    return entry->getAssertions();
  return Iterator<SAMLAssertion*>(ResourceEntry::g_emptyVector);
}

ResourceEntry* InternalCCacheEntry::populate(Resource& resource)
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
    if (entry->isValid())
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

  auto_ptr<XMLCh> resourceURL(XMLString::transcode(resource.getURL()));
  Iterator<saml::QName> respond_withs = ArrayIterator<saml::QName>(&g_respondWith);

  // Clone the subject...
  // 1) I know the static_cast is safe from clone()
  // 2) the AttributeQuery will destroy this new subject.
  SAMLSubject* subject=static_cast<SAMLSubject*>(m_subject->clone());

  // Build a SAML Request....
  SAMLAttributeQuery* q=new SAMLAttributeQuery(subject,resourceURL.get(),
					       resource.getDesignators());
  SAMLRequest* req=new SAMLRequest(respond_withs,q);

  // Try this request against all the bindings in the AuthenticationStatement
  // (i.e. send it to each AA in the list of bindings)
  Iterator<SAMLAuthorityBinding*> bindings = p_auth->getBindings();
  SAMLResponse* response = NULL;

  while (!response && bindings.hasNext()) {
    SAMLAuthorityBinding* binding = bindings.next();

    log->debug("Trying binding...");
    SAMLBinding* pBinding=m_cache->getBinding(binding->getBinding());
    log->debug("Sending request");
    response=pBinding->send(*binding,*req);
  }

  // ok, we can delete the request now.
  delete req;

  // Make sure we got a response
  if (!response) {
    log->info ("No Response");
    return NULL;
  }

  entry = new ResourceEntry(response);
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

/******************************************************************************/
/* ResourceEntry:  A Credential Cache Entry for a particular Resource URL     */
/******************************************************************************/

ResourceEntry::ResourceEntry(SAMLResponse* response)
{
  string ctx = "shibtarget::ResourceEntry";
  log = &(log4cpp::Category::getInstance(ctx));

  log->info("caching resource entry");

  m_response = response;
}

ResourceEntry::~ResourceEntry()
{
  delete m_response;
}

Iterator<SAMLAssertion*> ResourceEntry::getAssertions()
{
  saml::NDC ndc("getAssertions");
  return m_response->getAssertions();
}

bool ResourceEntry::isValid()
{
  saml::NDC ndc("isValid");

  log->info("checking validity");

  // This is awful, but the XMLDateTime class is truly horrible.
  time_t now=time(NULL);
#ifdef WIN32
  struct tm* ptime=gmtime(&now);
#else
  struct tm res;
  struct tm* ptime=gmtime_r(&now,&res);
#endif
  char timebuf[32];
  strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
  auto_ptr<XMLCh> timeptr(XMLString::transcode(timebuf));
  XMLDateTime curDateTime(timeptr.get());

  Iterator<SAMLAssertion*> iter = getAssertions();

  while (iter.hasNext()) {
    SAMLAssertion* assertion = iter.next();

    log->debug ("testing assertion...");

    if (! assertion->getNotOnOrAfter()) {
      log->debug ("getNotOnOrAfter failed.");
      return false;
    }

    int result=XMLDateTime::compareOrder(&curDateTime,
					 assertion->getNotOnOrAfter());
    if (result != XMLDateTime::LESS_THAN) {
      log->debug("nope, not still valid");
      return false;
    }
  } // while

  log->debug("yep, all still valid");
  return true;
}
