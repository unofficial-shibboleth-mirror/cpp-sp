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

#include "internal.h"

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <shib/shib-threads.h>

#include <log4cpp/Category.hh>

#include <sstream>
#include <stdexcept>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class InternalCCache;
class InternalCCacheEntry : public CCacheEntry
{
public:
  InternalCCacheEntry(const char* application_id, SAMLAuthenticationStatement* s, const char *client_addr, SAMLResponse* r=NULL);
  ~InternalCCacheEntry();

  virtual bool isSessionValid(time_t lifetime, time_t timeout);
  virtual const char* getClientAddress() { return m_clientAddress.c_str(); }
  virtual const char* getSerializedStatement() { return m_statement.c_str(); }
  virtual const SAMLAuthenticationStatement* getStatement() { return p_auth; }

  virtual Iterator<SAMLAssertion*> getAssertions();
  virtual void preFetch(int prefetch_window);

  virtual void release() { m_lock->unlock(); }

  void setCache(InternalCCache *cache) { m_cache = cache; }
  void lock() { m_lock->lock(); }
  time_t lastAccess() { return m_lastAccess; }

private:
  bool responseValid(int slop);
  void populate(int slop);
  SAMLResponse* getNewResponse();
              
  string m_application_id;
  string m_statement;
  string m_originSite;
  string m_handle;
  string m_clientAddress;
  time_t m_sessionCreated;
  time_t m_responseCreated;
  time_t m_lastAccess;
  time_t m_lastRetry;

  const SAMLSubject* m_subject;
  SAMLAuthenticationStatement* p_auth;
  SAMLResponse* m_response;
  InternalCCache *m_cache;

  log4cpp::Category* log;
  
  Mutex* m_lock;
};

class InternalCCache : public CCache
{
public:
  InternalCCache();
  virtual ~InternalCCache();

  virtual CCacheEntry* find(const char* key);
  virtual void insert(const char* key, const char* application_id, SAMLAuthenticationStatement* s, const char *client_addr, SAMLResponse* r=NULL);
  virtual void remove(const char* key);

  InternalCCacheEntry* findi(const char* key);
  void	cleanup();

private:
  RWLock *lock;

  map<string,InternalCCacheEntry*> m_hashtable;

  log4cpp::Category* log;

  static void*	cleanup_fcn(void*); // XXX Assumed an InternalCCache
  bool		shutdown;
  CondWait*	shutdown_wait;
  Thread*	cleanup_thread;
  
  // cached config settings
  int defaultLifetime,retryInterval;
  bool strictValidity,propagateErrors;
  friend class InternalCCacheEntry;
};

namespace {
  map<string,CCache::CCacheFactory> g_ccacheFactoryDB;
};

// Global Constructors & Destructors
CCache::~CCache() { }

void CCache::registerFactory(const char* name, CCache::CCacheFactory factory)
{
  log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.CCache");
  saml::NDC ndc("registerFactory");

  log.info ("Registered factory %p for CCache %s", factory, name);
  g_ccacheFactoryDB[name] = factory;
}

CCache* CCache::getInstance(const char* type)
{
  log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.CCache");
  saml::NDC ndc("getInstance");

  map<string,CCache::CCacheFactory>::const_iterator i=g_ccacheFactoryDB.find(type);
  if (i!=g_ccacheFactoryDB.end()) {
    log.info ("Loading CCache: %s at %p", type, i->second);
    return ((i->second)());
  }

  log.info ("Loading default memory CCache");
  return (CCache*) new InternalCCache();
}


/******************************************************************************/
/* InternalCCache:  A Credential Cache                                        */
/******************************************************************************/

InternalCCache::InternalCCache() : defaultLifetime(1800), retryInterval(300), strictValidity(true), propagateErrors(false)
{
  log = &(log4cpp::Category::getInstance("shibtarget.InternalCCache"));
  lock = RWLock::create();

  string tag;
  ShibINI& ini = ShibTargetConfig::getConfig().getINI();
  if (ini.get_tag(SHIBTARGET_SHAR, "defaultLifetime", false, &tag))
    defaultLifetime=atoi(tag.c_str());
  if (ini.get_tag(SHIBTARGET_SHAR, "retryInterval", false, &tag))
    retryInterval=atoi(tag.c_str());
  if (ini.get_tag(SHIBTARGET_SHAR, "strictValidity", false, &tag))
    strictValidity=ShibINI::boolean(tag);
  if (ini.get_tag(SHIBTARGET_SHAR, "propagateErrors", false, &tag))
    propagateErrors=ShibINI::boolean(tag);

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

  for (map<string,InternalCCacheEntry*>::iterator i=m_hashtable.begin(); i!=m_hashtable.end(); i++)
    delete i->second;
  delete lock;
  delete shutdown_wait;
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

  // Lock the "database record" for the caller -- they have to release the item.
  entry->lock();
  return entry;
}

void InternalCCache::insert(const char* key, const char* application_id, SAMLAuthenticationStatement* s, const char* client_addr, SAMLResponse* r)
{
  log->debug("caching new entry for application %s: \"%s\"", application_id, key);

  InternalCCacheEntry* entry = new InternalCCacheEntry(application_id, s, client_addr, r);
  entry->setCache(this);

  lock->wrlock();
  m_hashtable[key]=entry;
  lock->unlock();
}

// remove the entry from the database and then destroy the cacheentry
void InternalCCache::remove(const char* key)
{
  log->debug("removing cache entry \"key\"", key);

  // lock the cache for writing, which means we know nobody is sitting in find()
  lock->wrlock();

  // grab the entry from the database.
  CCacheEntry* entry = findi(key);

  if (!entry) {
    lock->unlock();
    return;
  }

  // ok, remove the entry and lock it
  m_hashtable.erase(key);
  dynamic_cast<InternalCCacheEntry*>(entry)->lock();
  lock->unlock();

  // we can release the entry lock because we know we're not in the cache anymore
  entry->release();

  // Now delete the entry
  delete entry;
}

void InternalCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("InternalCCache::cleanup()");

  ShibINI& ini = ShibTargetConfig::getConfig().getINI();

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
    shutdown_wait->timedwait(mutex,rerun_timer);

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
      i->second->lock();
      time_t last=i->second->lastAccess();
      i->second->release();
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
  Thread::mask_all_signals();

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

/******************************************************************************/
/* InternalCCacheEntry:  A Credential Cache Entry                             */
/******************************************************************************/

InternalCCacheEntry::InternalCCacheEntry(const char* application_id, SAMLAuthenticationStatement *s, const char* client_addr, SAMLResponse* r)
  : m_response(r), m_responseCreated(r ? time(NULL) : 0), m_lastRetry(0)
{
  log = &(log4cpp::Category::getInstance("shibtarget::InternalCCacheEntry"));

  if (s == NULL) {
    log->error("NULL auth statement");
    throw runtime_error("InternalCCacheEntry() was passed an empty SAML Statement");
  }

  if (application_id)
    m_application_id=application_id;

  m_subject = s->getSubject();

  auto_ptr_char h(m_subject->getName());
  auto_ptr_char d(m_subject->getNameQualifier());

  m_handle = h.get();
  m_originSite = d.get();

  m_clientAddress = client_addr;
  m_sessionCreated = m_lastAccess = time(NULL);

  // Save for later.
  p_auth = s;
  
  // Save the serialized version of the auth statement
  ostringstream os;
  os << *s;
  m_statement = os.str();

  if (r) {
    // Run pushed data through the AAP. Note that we could end up with an empty response!
    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    Metadata m(conf.getMetadataProviders());
    const IProvider* site=m.lookup(m_subject->getNameQualifier());
    if (!site)
        throw MetadataException("unable to locate origin site's metadata during attribute acceptance processing");
    Iterator<SAMLAssertion*> assertions=r->getAssertions();
    for (unsigned long i=0; i < assertions.size();) {
        try {
            AAP::apply(conf.getAAPProviders(),site,*(assertions[i]));
            i++;
        }
        catch (SAMLException&) {
            log->info("no statements remain, removing assertion");
            r->removeAssertion(i);
        }
    }
  }

  m_lock = Mutex::create();

  log->info("New Session Created...");
  log->debug("Handle: \"%s\", Site: \"%s\", Address: %s", h.get(), d.get(), client_addr);
}

InternalCCacheEntry::~InternalCCacheEntry()
{
  log->debug("deleting entry for %s@%s", m_handle.c_str(), m_originSite.c_str());
  delete m_response;
  delete p_auth;
  delete m_lock;
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

  if (timeout > 0 && now-m_lastAccess >= timeout) {
    log->debug("session timed out");
    return false;
  }
  m_lastAccess=now;
  return true;
}

Iterator<SAMLAssertion*> InternalCCacheEntry::getAssertions()
{
  saml::NDC ndc("getAssertions");
  populate(0);
  
  if (m_response)
    return m_response->getAssertions();
  return EMPTY(SAMLAssertion*);
}

void InternalCCacheEntry::preFetch(int prefetch_window)
{
  saml::NDC ndc("preFetch");
  populate(prefetch_window);
}

bool InternalCCacheEntry::responseValid(int slop)
{
  saml::NDC ndc("responseValid");

  log->info("checking AA response validity");

  // This is awful, but the XMLDateTime class is truly horrible.
  time_t now=time(NULL)+slop;
#ifdef WIN32
  struct tm* ptime=gmtime(&now);
#else
  struct tm res;
  struct tm* ptime=gmtime_r(&now,&res);
#endif
  char timebuf[32];
  strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
  auto_ptr_XMLCh timeptr(timebuf);
  XMLDateTime curDateTime(timeptr.get());
  curDateTime.parseDateTime();

  int count = 0;
  Iterator<SAMLAssertion*> iter = m_response->getAssertions();
  while (iter.hasNext()) {
    SAMLAssertion* assertion = iter.next();

    log->debug ("testing assertion...");

    const XMLDateTime* thistime = assertion->getNotOnOrAfter();

    // If there is no time, then just continue and ignore this assertion.
    if (!thistime)
      continue;

    count++;
    auto_ptr_char nowptr(curDateTime.getRawData());
    auto_ptr_char assnptr(thistime->getRawData());

    log->debug ("comparing now (%s) to %s", nowptr.get(), assnptr.get());
    int result=XMLDateTime::compareOrder(&curDateTime, thistime);

    if (result != XMLDateTime::LESS_THAN) {
      log->debug("nope, not still valid");
      return false;
    }
  }

  // If we didn't find any assertions with times, then see if we're
  // older than the default response lifetime.
  if (!count) {
      if ((now - m_responseCreated) > m_cache->defaultLifetime) {
        log->debug("response is beyond default life, so it's invalid");
        return false;
      }
  }
  
  log->debug("yep, response still valid");
  return true;
}

void InternalCCacheEntry::populate(int slop)
{
  saml::NDC ndc("populate");
  log->debug("populating session cache for application %s", m_application_id.c_str());

  // Do we have any data cached?
  if (m_response) {
      // Can we use what we have?
      if (responseValid(slop))
        return;
      
      // If we're being strict, dump what we have and reset timestamps.
      if (m_cache->strictValidity) {
        log->info("strictly enforcing attribute validity, dumping expired data");
        delete m_response;
        m_response=NULL;
        m_responseCreated=0;
        m_lastRetry=0; 
      }
  }

  // Need to try and get a new response.

  try {
    SAMLResponse* new_response=getNewResponse();
    if (new_response) {
        delete m_response;
        m_response=new_response;
        m_responseCreated=time(NULL);
        m_lastRetry=0;
        log->debug("fetched and stored new response");
    }
  }
  catch (...) {
    if (m_cache->propagateErrors)
        throw;
    log->warn("suppressed exception caught while trying to fetch attributes");
  }
}

SAMLResponse* InternalCCacheEntry::getNewResponse()
{
    // The retryInterval determines how often to poll an AA that might be down.
    if ((time(NULL) - m_lastRetry) < m_cache->retryInterval)
        return NULL;
    if (m_lastRetry)
        log->debug("retry interval exceeded, so trying again");
    m_lastRetry=time(NULL);
    
    if (p_auth->getBindings().size()==0) {
        // XXX: need to start using metadata for this...
        log->error("no AA bindings available");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"No AA bindings available.",m_subject->getNameQualifier());
    }

    log->info("trying to request attributes for %s@%s -> %s", m_handle.c_str(), m_originSite.c_str(), m_application_id.c_str());

    string tag;
    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    ShibINI& ini = conf.getINI();
    if (!ini.get_tag(m_application_id, "providerID", true, &tag))
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,string("unable to determine ProviderID for request, not set?"));
    auto_ptr_XMLCh providerID(tag.c_str());

    vector<SAMLAttributeDesignator*> designators;

    // Look up attributes to request based on resource ID
    if (ini.get_tag(m_application_id, SHIBTARGET_TAG_REQATTRS, true, &tag)) {
        // Now parse the request attributes tag...
        log->debug("Request Attributes: \"%s\"", tag.c_str());

        auto_ptr<char> tag_str(strdup(tag.c_str()));
        char *tags = tag_str.get(), *tagptr = NULL, *the_tag;
#ifdef HAVE_STRTOK_R
        while ((the_tag = strtok_r(tags, " \t\r\n", &tagptr)) != NULL && *the_tag) {
#else
        while ((the_tag = strtok(tags, " \t\r\n")) != NULL && *the_tag) {
#endif
            // Make sure we don't loop ad-infinitum
            tags = NULL;
      
            // transcode the attribute string from the tag
            auto_ptr_XMLCh temp(the_tag);

            // Now create the SAML AttributeDesignator from this name
            designators.push_back(new SAMLAttributeDesignator(temp.get(),shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI));
        }
    }
    else
        log->debug ("No request-attributes found, requesting any/all");

    // Build a SAML Request....
    SAMLAttributeQuery* q=new SAMLAttributeQuery(
        static_cast<SAMLSubject*>(m_subject->clone()),providerID.get(),designators
        );
    auto_ptr<SAMLRequest> req(new SAMLRequest(EMPTY(QName),q));
    
    // Try this request. The wrapper class handles all of the details.
    Metadata m(conf.getMetadataProviders());
    const IProvider* site=m.lookup(m_subject->getNameQualifier());
    if (!site)
        throw MetadataException("unable to locate origin site's metadata during attribute query");

    log->debug("Trying to query an AA...");
    SAMLResponse* response = NULL;
    ShibBinding binding(conf.getRevocationProviders(),conf.getTrustProviders(),conf.getCredentialProviders());
    try {
        response=binding.send(*req,site,NULL,p_auth->getBindings());
    }
    catch (SAMLException& e) {
        log->error("caught SAML exception during query to AA: %s", e.what());
    }
    // See if we got a response.
    if (!response) {
        log->error("No response obtained");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to obtain attributes from user's origin site.",site->getId());
    }

    // Run it through the AAP. Note that we could end up with an empty response!
    Iterator<SAMLAssertion*> a=response->getAssertions();
    for (unsigned long i=0; i < a.size();) {
        try {
            AAP::apply(conf.getAAPProviders(),site,*(a[i]));
            i++;
        }
        catch (SAMLException&) {
            log->info("no statements remain, removing assertion");
            response->removeAssertion(i);
        }
    }

    return response;
}
