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

static const XMLCh cleanupInterval[] =
{ chLatin_c, chLatin_l, chLatin_e, chLatin_a, chLatin_n, chLatin_u, chLatin_p,
  chLatin_I, chLatin_n, chLatin_t, chLatin_e, chLatin_r, chLatin_v, chLatin_a, chLatin_l, chNull
};
static const XMLCh cacheTimeout[] =
{ chLatin_c, chLatin_a, chLatin_c, chLatin_h, chLatin_e,
  chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull
};
static const XMLCh AAConnectTimeout[] =
{ chLatin_A, chLatin_A, chLatin_C, chLatin_o, chLatin_n, chLatin_n, chLatin_e, chLatin_c, chLatin_t,
  chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull
};
static const XMLCh AATimeout[] =
{ chLatin_A, chLatin_A, chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull };

static const XMLCh defaultLifetime[] =
{ chLatin_d, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t,
  chLatin_L, chLatin_i, chLatin_f, chLatin_e, chLatin_t, chLatin_i, chLatin_m, chLatin_e, chNull
};
static const XMLCh retryInterval[] =
{ chLatin_r, chLatin_e, chLatin_t, chLatin_r, chLatin_y,
  chLatin_I, chLatin_n, chLatin_t, chLatin_e, chLatin_r, chLatin_v, chLatin_a, chLatin_l, chNull
};
static const XMLCh strictValidity[] =
{ chLatin_s, chLatin_t, chLatin_r, chLatin_i, chLatin_c, chLatin_t,
  chLatin_V, chLatin_a, chLatin_l, chLatin_i, chLatin_d, chLatin_i, chLatin_t, chLatin_y, chNull
};
static const XMLCh propagateErrors[] =
{ chLatin_p, chLatin_r, chLatin_o, chLatin_p, chLatin_a, chLatin_g, chLatin_a, chLatin_t, chLatin_e,
  chLatin_E, chLatin_r, chLatin_r, chLatin_o, chLatin_r, chLatin_s, chNull
};

class InternalCCache;
class InternalCCacheEntry : public ISessionCacheEntry
{
public:
  InternalCCacheEntry(
    const char* id,
    const IApplication* application,
    SAMLAuthenticationStatement* s,
    const char *client_addr,
    SAMLResponse* r=NULL
    );
  ~InternalCCacheEntry();

  void lock() { m_lock->lock(); }
  void unlock() { m_lock->unlock(); }

  bool isValid(time_t lifetime, time_t timeout) const;
  const char* getClientAddress() const { return m_clientAddress.c_str(); }
  const char* getSerializedStatement() const { return m_statement.c_str(); }
  const SAMLAuthenticationStatement* getStatement() const { return p_auth; }

  Iterator<SAMLAssertion*> getAssertions();
  void preFetch(int prefetch_window);

  void setCache(InternalCCache *cache) { m_cache = cache; }
  time_t lastAccess() const { return m_lastAccess; }

private:
  bool responseValid(int slop);
  void populate(int slop);
  SAMLResponse* getNewResponse();
  
  string m_id;
  string m_application_id;
  string m_statement;
  string m_originSite;
  string m_clientAddress;
  time_t m_sessionCreated;
  time_t m_responseCreated;
  mutable time_t m_lastAccess;
  time_t m_lastRetry;

  const SAMLNameIdentifier* m_nameid;
  SAMLAuthenticationStatement* p_auth;
  SAMLResponse* m_response;
  InternalCCache *m_cache;

  log4cpp::Category* log;
  Mutex* m_lock;
};

class InternalCCache : public ISessionCache
{
public:
  InternalCCache(const DOMElement* e);
  virtual ~InternalCCache();

  void thread_init() {};
  void thread_end() {};

  string generateKey() const;
  ISessionCacheEntry* find(const char* key);
  void insert(
    const char* key, const IApplication* application, SAMLAuthenticationStatement* s, const char *client_addr, SAMLResponse* r=NULL
    );
  void remove(const char* key);

  InternalCCacheEntry* findi(const char* key);
  void	cleanup();

private:
  const DOMElement* m_root;         // Only valid during initialization
  RWLock *lock;
  map<string,InternalCCacheEntry*> m_hashtable;

  log4cpp::Category* log;

  static void*	cleanup_fcn(void*); // XXX Assumed an InternalCCache
  bool		shutdown;
  CondWait*	shutdown_wait;
  Thread*	cleanup_thread;
  
  // extracted config settings
  unsigned int m_AATimeout,m_AAConnectTimeout;
  unsigned int m_defaultLifetime,m_retryInterval;
  bool m_strictValidity,m_propagateErrors;
  friend class InternalCCacheEntry;
};

IPlugIn* MemoryCacheFactory(const DOMElement* e)
{
    return new InternalCCache(e);
}

/******************************************************************************/
/* InternalCCache:  in memory session cache                                   */
/******************************************************************************/

InternalCCache::InternalCCache(const DOMElement* e)
    : m_root(e), m_AATimeout(30), m_AAConnectTimeout(15), m_defaultLifetime(1800), m_retryInterval(300),
        m_strictValidity(true), m_propagateErrors(false), lock(RWLock::create()),
        log (&Category::getInstance("shibtarget.InternalCCache"))
{
    const XMLCh* tag=m_root->getAttributeNS(NULL,AATimeout);
    if (tag && *tag) {
        m_AATimeout = XMLString::parseInt(tag);
        if (!m_AATimeout)
            m_AATimeout=30;
    }

    tag=m_root->getAttributeNS(NULL,AAConnectTimeout);
    if (tag && *tag) {
        m_AAConnectTimeout = XMLString::parseInt(tag);
        if (!m_AAConnectTimeout)
            m_AAConnectTimeout=15;
    }
    
    tag=m_root->getAttributeNS(NULL,defaultLifetime);
    if (tag && *tag) {
        m_defaultLifetime = XMLString::parseInt(tag);
        if (!m_defaultLifetime)
            m_defaultLifetime=1800;
    }

    tag=m_root->getAttributeNS(NULL,retryInterval);
    if (tag && *tag) {
        m_retryInterval = XMLString::parseInt(tag);
        if (!m_retryInterval)
            m_retryInterval=300;
    }
    
    tag=m_root->getAttributeNS(NULL,strictValidity);
    if (tag && (*tag==chDigit_0 || *tag==chLatin_f))
        m_strictValidity=false;
        
    tag=m_root->getAttributeNS(NULL,propagateErrors);
    if (tag && (*tag==chDigit_1 || *tag==chLatin_t))
        m_propagateErrors=true;

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

string InternalCCache::generateKey() const
{
    SAMLIdentifier id,id2;
    auto_ptr_char c(id);
    auto_ptr_char c2(id2);
    return string(c.get()) + c2.get();
}

// assumes a lock is held..
InternalCCacheEntry* InternalCCache::findi(const char* key)
{
  log->debug("findI: \"%s\"", key);

  map<string,InternalCCacheEntry*>::const_iterator i=m_hashtable.find(key);
  if (i==m_hashtable.end()) {
    log->debug("No Match found");
    return NULL;
  }
  log->debug("Match Found.");

  return i->second;
}

ISessionCacheEntry* InternalCCache::find(const char* key)
{
  log->debug("Find: \"%s\"", key);
  ReadLock rwlock(lock);

  InternalCCacheEntry* entry = findi(key);
  if (!entry) return NULL;

  // Lock the "database record" for the caller -- they have to unlock the item.
  entry->lock();
  return entry;
}

void InternalCCache::insert(
    const char* key, const IApplication* application, SAMLAuthenticationStatement* s, const char* client_addr, SAMLResponse* r
    )
{
  log->debug("caching new entry for application %s: \"%s\"", application->getId(), key);

  InternalCCacheEntry* entry = new InternalCCacheEntry(key, application, s, client_addr, r);
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
  ISessionCacheEntry* entry = findi(key);

  if (!entry) {
    lock->unlock();
    return;
  }

  // ok, remove the entry and lock it
  m_hashtable.erase(key);
  dynamic_cast<InternalCCacheEntry*>(entry)->lock();
  lock->unlock();

  // we can release the entry lock because we know we're not in the cache anymore
  entry->unlock();

  // Now delete the entry
  delete entry;
}

void InternalCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("InternalCCache::cleanup()");

  int rerun_timer = 0;
  int timeout_life = 0;

  // Load our configuration details...
  const XMLCh* tag=m_root->getAttributeNS(NULL,cleanupInterval);
  if (tag && *tag)
    rerun_timer = XMLString::parseInt(tag);

  tag=m_root->getAttributeNS(NULL,cacheTimeout);
  if (tag && *tag)
    timeout_life = XMLString::parseInt(tag);
  
  if (rerun_timer <= 0)
    rerun_timer = 300;        // rerun every 5 minutes

  if (timeout_life <= 0)
    timeout_life = 28800; // timeout after 8 hours

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
      i->second->unlock();
      if (last < stale)
        stale_keys.push_back(i->first);
    }
    lock->unlock();

    log->info("deleting %d old items.", stale_keys.size());

    // Pass 2: walk through the list of stale entries and remove them from
    // the database
    for (vector<string>::iterator j = stale_keys.begin(); j != stale_keys.end(); j++) {
      remove (j->c_str());
      // Transaction Logging
      STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
      stc.getTransactionLog().infoStream() << "Purged expired session from memory (ID: " << j->c_str() << ")";
      stc.releaseTransactionLog();
    }
  }

  log->debug("Cleanup thread finished.");

  mutex->unlock();
  delete mutex;
  Thread::exit(NULL);
}

void* InternalCCache::cleanup_fcn(void* cache_p)
{
  InternalCCache* cache = reinterpret_cast<InternalCCache*>(cache_p);

  // First, let's block all signals 
  Thread::mask_all_signals();

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

/******************************************************************************/
/* InternalCCacheEntry:  A Credential Cache Entry                             */
/******************************************************************************/

InternalCCacheEntry::InternalCCacheEntry(
    const char* id, const IApplication* application, SAMLAuthenticationStatement *s, const char* client_addr, SAMLResponse* r
    ) : m_response(r), m_responseCreated(r ? time(NULL) : 0), m_lastRetry(0),
        log(&Category::getInstance("shibtarget::InternalCCacheEntry"))
{
  if (!id || !s) {
    log->error("NULL session ID or auth statement");
    throw SAMLException("InternalCCacheEntry() passed an empty session ID or SAML Statement");
  }

  m_id=id;
  m_application_id=application->getId();

  m_nameid = s->getSubject()->getNameIdentifier();
  auto_ptr_char d(m_nameid->getNameQualifier());
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
    Metadata m(application->getMetadataProviders());
    const IProvider* site=m.lookup(m_nameid->getNameQualifier());
    if (!site)
        throw MetadataException("unable to locate origin site's metadata during attribute acceptance processing");
    Iterator<SAMLAssertion*> assertions=r->getAssertions();
    for (unsigned long i=0; i < assertions.size();) {
        try {
            AAP::apply(application->getAAPProviders(),site,*(assertions[i]));
            i++;
        }
        catch (SAMLException&) {
            log->info("no statements remain, removing assertion");
            r->removeAssertion(i);
        }
    }
  }

  m_lock = Mutex::create();

  log->info("new session created (ID: %s)", id);
  if (log->isDebugEnabled()) {
      auto_ptr_char h(m_nameid->getName());
      log->debug("Handle: \"%s\", Origin: \"%s\", Address: %s", h.get(), d.get(), client_addr);
  }
}

InternalCCacheEntry::~InternalCCacheEntry()
{
  log->debug("deleting session (ID: %s)", m_id.c_str());
  delete m_response;
  delete p_auth;
  delete m_lock;
}

bool InternalCCacheEntry::isValid(time_t lifetime, time_t timeout) const
{
  saml::NDC ndc("isValid");
  log->debug("testing session (ID: %s) (lifetime=%ld, timeout=%ld)", m_id.c_str(), lifetime, timeout);
  time_t now=time(NULL);
  if (lifetime > 0 && now > m_sessionCreated+lifetime) {
    log->debug("session beyond lifetime (ID: %s)", m_id.c_str());
    return false;
  }

  if (timeout > 0 && now-m_lastAccess >= timeout) {
    log->debug("session timed out (ID: %s)", m_id.c_str());
    return false;
  }
  m_lastAccess=now;
  return true;
}

Iterator<SAMLAssertion*> InternalCCacheEntry::getAssertions()
{
  saml::NDC ndc("getAssertions");
  populate(0);
  return (m_response) ? m_response->getAssertions() : EMPTY(SAMLAssertion*);
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
      if ((now - m_responseCreated) > m_cache->m_defaultLifetime) {
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
  log->debug("populating attributes for session (ID: %s)", m_id.c_str());

  // Do we have any data cached?
  if (m_response) {
      // Can we use what we have?
      if (responseValid(slop))
        return;
      
      // If we're being strict, dump what we have and reset timestamps.
      if (m_cache->m_strictValidity) {
        log->info("strictly enforcing attribute validity, dumping expired data");
        delete m_response;
        m_response=NULL;
        m_responseCreated=0;
        m_lastRetry=0; 
      }
  }

  // Need to try and get a new response.

  try {

    // Transaction Logging
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getTransactionLog().infoStream() <<
        "Making attribute query for session (ID: " <<
            m_id <<
        ") on (applicationId: " <<
            m_application_id <<
        ") for principal from (IdP: " <<
            m_originSite <<
        ")";
    stc.releaseTransactionLog();

    SAMLResponse* new_response=getNewResponse();
    if (new_response) {
        delete m_response;
        m_response=new_response;
        m_responseCreated=time(NULL);
        m_lastRetry=0;
        log->debug("fetched and stored new response");
        stc.getTransactionLog().infoStream() <<  "Successful attribute query for session (ID: " << m_id << ")";
        stc.releaseTransactionLog();
    }
  }
  catch (SAMLException& e) {
    if (typeid(e)==typeid(InvalidHandleException) || m_cache->m_propagateErrors)
        throw;
    log->warn("suppressed SAML exception caught while trying to fetch attributes");
  }
  catch (...) {
    if (m_cache->m_propagateErrors)
        throw;
    log->warn("suppressed exception caught while trying to fetch attributes");
  }
}

SAMLResponse* InternalCCacheEntry::getNewResponse()
{
    saml::NDC ndc("getNewResponse");

    // The retryInterval determines how often to poll an AA that might be down.
    if ((time(NULL) - m_lastRetry) < m_cache->m_retryInterval)
        return NULL;
    if (m_lastRetry)
        log->debug("retry interval exceeded, so trying again");
    m_lastRetry=time(NULL);
    
    log->info("trying to get new attributes for session (ID=%s)", m_id.c_str());

    // Lookup application for session to get providerId and attributes to request.
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IApplication* application=conf->getApplication(m_application_id.c_str());
    if (!application) {
        log->crit("unable to locate application for session, deleted?");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to locate application for session, deleted?");
    }
    pair<bool,const XMLCh*> providerID=application->getXMLString("providerId");
    if (!providerID.first) {
        log->crit("unable to determine ProviderID for application, not set?");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to determine ProviderID for application, not set?");
    }

    // Get signing policies.
    bool signRequest=false;
    bool signedResponse=false;
    bool signedAssertions=false;
    const IPropertySet* props=application->getPropertySet("Policy");
    if (props) {
        pair<bool,bool> flag=props->getBool("signRequest");
        if (flag.first)
            signRequest=flag.second;
        flag=props->getBool("signedResponse");
        if (flag.first)
            signedResponse=flag.second;
        flag=props->getBool("signedAssertions");
        if (flag.first)
            signedAssertions=flag.second;
    }
    
    // Try this request. The binding wrapper class handles most of the details.
    Metadata m(application->getMetadataProviders());
    const IProvider* site=m.lookup(m_nameid->getNameQualifier());
    if (!site) {
        log->error("unable to locate origin site's metadata during attribute query");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to locate origin site's metadata during attribute query.");
    }

    // Try to locate an AA role.
    const IAttributeAuthorityRole* AA=NULL;
    Iterator<const IProviderRole*> roles=site->getRoles();
    while (!AA && roles.hasNext()) {
        const IProviderRole* role=roles.next();
        if (dynamic_cast<const IAttributeAuthorityRole*>(role)) {
            // Check for SAML 1.x protocol support.
            if (role->hasSupport(saml::XML::SAMLP_NS))
                AA=dynamic_cast<const IAttributeAuthorityRole*>(role);
        }
    }
    if (!AA) {
        log->error("unable to locate metadata for origin site's Attribute Authority");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to locate metadata for origin site's Attribute Authority.",site);
    }


    SAMLResponse* response = NULL;
    try {
        // Build a SAML Request....
        SAMLAttributeQuery* q=new SAMLAttributeQuery(
            new SAMLSubject(static_cast<SAMLNameIdentifier*>(m_nameid->clone())),
            providerID.second,
            application->getAttributeDesignators().clone()
            );
        auto_ptr<SAMLRequest> req(new SAMLRequest(EMPTY(QName),q));
        
        // Sign it? Highly doubtful we'll ever use this, but just for fun...
        if (signRequest) {
            Credentials creds(conf->getCredentialsProviders());
            const ICredResolver* signingCred=creds.lookup(application->getSigningCred(site));
            req->sign(SIGNATURE_RSA,signingCred->getKey(),signingCred->getCertificates());
        }
            
        log->debug("trying to query an AA...");

        SAMLConfig::SAMLBindingConfig bindconf;
        bindconf.timeout=m_cache->m_AATimeout;
        bindconf.conn_timeout=m_cache->m_AAConnectTimeout;
        ShibBinding binding(application->getRevocationProviders(),application->getTrustProviders(),conf->getCredentialsProviders());
        response=binding.send(*req,AA,application->getTLSCred(site),application->getAudiences(),p_auth->getBindings(),bindconf);
    }
    catch (SAMLException& e) {
        log->error("caught SAML exception during query to AA: %s", e.what());
        if (typeid(e)==typeid(InvalidHandleException))
            throw;
        ostringstream os;
        os << e;
        throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str().c_str(), AA);
    }
    
    // See if we got a response.
    if (!response) {
        log->error("no response obtained");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to obtain attributes from user's origin site.",AA);
    }
    else if (signedResponse && !response->isSigned()) {
        delete response;
        log->error("unsigned response obtained, but we were told it must be signed.");
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to obtain attributes from user's origin site.",AA);
    }

    // Run it through the AAP. Note that we could end up with an empty response!
    Iterator<SAMLAssertion*> a=response->getAssertions();
    for (unsigned long i=0; i < a.size();) {
        try {
            if (signedAssertions && !(a[i]->isSigned())) {
                log->warn("removing unsigned assertion from response, in accordance with signedAssertions policy");
                response->removeAssertion(i);
                continue;
            }
            AAP::apply(application->getAAPProviders(),site,*(a[i]));
            i++;
        }
        catch (SAMLException&) {
            log->info("no statements remain, removing assertion");
            response->removeAssertion(i);
        }
    }

    return response;
}
