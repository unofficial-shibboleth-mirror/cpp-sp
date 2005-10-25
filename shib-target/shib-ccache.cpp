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
    InternalCCache* cache,
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    const SAMLAuthenticationStatement* s,
    SAMLResponse* r=NULL,
    const IRoleDescriptor* source=NULL,
    time_t created=0,
    time_t accessed=0
    );
  ~InternalCCacheEntry();

  void lock() { m_lock->lock(); }
  void unlock() { m_lock->unlock(); }

  bool isValid(time_t lifetime, time_t timeout) const;
  const char* getClientAddress() const { return m_clientAddress.c_str(); }
  ShibProfile getProfile() const { return m_profile; }
  const char* getProviderId() const { return m_provider_id.c_str(); }
  const char* getAuthnStatementXML() const { return m_auth_statement.c_str(); }
  CachedResponseXML getResponseXML();
  const SAMLAuthenticationStatement* getAuthnStatementSAML() const { throw SAMLException("unsupported operation"); }
  CachedResponseSAML getResponseSAML() { throw SAMLException("unsupported operation"); }

  time_t lastAccess() const { return m_lastAccess; }
  
  bool checkApplication(const IApplication* application) { return (m_application_id==application->getId()); }

private:
  void populate();                  // wraps process of checking cache, and repopulating if need be
  bool responseValid();             // checks validity of existing response
  pair<SAMLResponse*,SAMLResponse*> getNewResponse();   // wraps an actual query
  
  SAMLResponse* filter(SAMLResponse* r, const IApplication* application, const IRoleDescriptor* source);
  time_t calculateExpiration(const SAMLResponse& r) const;
  
  string m_id;
  string m_application_id;
  string m_provider_id;
  string m_clientAddress;
  time_t m_sessionCreated;
  time_t m_responseExpiration;
  mutable time_t m_lastAccess;
  time_t m_lastRetry;

  ShibProfile m_profile;
  string m_auth_statement;
  string m_response_pre;
  string m_response_post;
  InternalCCache *m_cache;

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
  ISessionCacheEntry* find(const char* key, const IApplication* application);
  void insert(
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    const SAMLAuthenticationStatement* s,
    SAMLResponse* r=NULL,
    const IRoleDescriptor* source=NULL,
    time_t created=0,
    time_t accessed=0
    );
  void remove(const char* key);

  InternalCCacheEntry* findi(const char* key);
  void	cleanup();

private:
  const DOMElement* m_root;         // Only valid during initialization
  RWLock *lock;
  map<string,InternalCCacheEntry*> m_hashtable;

  log4cpp::Category* log;

  static void*	cleanup_fcn(void*); // Assumes an InternalCCache
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
        log (&Category::getInstance(SHIBT_LOGCAT".SessionCache"))
{
    const XMLCh* tag=m_root->getAttributeNS(NULL,AATimeout);
    if (tag && *tag) {
        m_AATimeout = XMLString::parseInt(tag);
        if (!m_AATimeout)
            m_AATimeout=30;
    }
    SAMLConfig::getConfig().timeout = m_AATimeout;

    tag=m_root->getAttributeNS(NULL,AAConnectTimeout);
    if (tag && *tag) {
        m_AAConnectTimeout = XMLString::parseInt(tag);
        if (!m_AAConnectTimeout)
            m_AAConnectTimeout=15;
    }
    SAMLConfig::getConfig().conn_timeout = m_AAConnectTimeout;
    
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
    SAMLIdentifier id;
    auto_ptr_char c(id);
    return c.get();
}

// assumes a lock is held..
InternalCCacheEntry* InternalCCache::findi(const char* key)
{
  map<string,InternalCCacheEntry*>::const_iterator i=m_hashtable.find(key);
  if (i==m_hashtable.end()) {
    log->debug("No match found");
    return NULL;
  }
  log->debug("Match found");

  return i->second;
}

ISessionCacheEntry* InternalCCache::find(const char* key, const IApplication* application)
{
  log->debug("searching memory cache for key (%s)", key);
  ReadLock rwlock(lock);

  InternalCCacheEntry* entry = findi(key);
  if (!entry)
    return NULL;
  else if (!entry->checkApplication(application)) {
    log->crit("An application (%s) attempted to access another application's session!", application->getId());
    return NULL;
  }

  // Lock the "database record" for the caller -- they have to unlock the item.
  entry->lock();
  return entry;
}

void InternalCCache::insert(
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    const SAMLAuthenticationStatement* s,
    SAMLResponse* r,
    const IRoleDescriptor* source,
    time_t created,
    time_t accessed
    )
{
  log->debug("caching new entry for application %s: \"%s\"", application->getId(), key);

  InternalCCacheEntry* entry = new InternalCCacheEntry(
    this,
    key,
    application,
    client_addr,
    profile,
    providerId,
    s,
    r,
    source,
    created,
    accessed
    );

  lock->wrlock();
  m_hashtable[key]=entry;
  lock->unlock();
}

// remove the entry from the database and then destroy the cacheentry
void InternalCCache::remove(const char* key)
{
  log->debug("removing cache entry with key (%s)", key);

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
#ifdef _DEBUG
  saml::NDC ndc("cleanup()");
#endif

  int rerun_timer = 0;
  int timeout_life = 0;
  Mutex* mutex = Mutex::create();
  
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

  log->info("Cleanup thread started...  Run every %d secs; timeout after %d secs",
	     rerun_timer, timeout_life);

  while (shutdown == false) {
    shutdown_wait->timedwait(mutex,rerun_timer);

    if (shutdown == true)
      break;

    log->debug("Cleanup thread running...");

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

  log->info("Cleanup thread finished.");

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
    InternalCCache* cache,
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    const SAMLAuthenticationStatement* s,
    SAMLResponse* r,
    const IRoleDescriptor* source,
    time_t created,
    time_t accessed
    ) : m_cache(cache), m_application_id(application->getId()), m_profile(profile),
        m_responseExpiration(0), m_lastRetry(0)
{
  if (!cache || !key || !s || !client_addr || !providerId) {
    if (cache) cache->log->error("missing required cache entry details");
    throw SAMLException("InternalCCacheEntry() missing required cache entry details");
  }

  m_id=key;
  m_clientAddress = client_addr;
  m_provider_id = providerId;
  m_sessionCreated = (created==0) ? time(NULL) : created;
  m_lastAccess = (accessed==0) ? time(NULL) : accessed;

  // Save authentication statement XML.
  ostringstream ostr;
  ostr << *s;
  m_auth_statement=ostr.str();

  // If pushing attributes, filter the response.
  if (r) {
    m_cache->log->debug("filtering pushed attribute information");
    auto_ptr<SAMLResponse> r2(filter(r, application, source));
    
    // Calculate expiration.
    m_responseExpiration=calculateExpiration(*(r2.get()));
    
    // Serialize unfiltered assertions.
    ostr.str("");
    ostr << *r;
    m_response_pre=ostr.str();
    
    // Serialize filtered assertions (if changes were made).
    ostr.str("");
    ostr << *(r2.get());
    m_response_post=ostr.str();
    if (m_response_post == m_response_pre)
        m_response_post.erase();
  }

  m_lock = Mutex::create();

  m_cache->log->info("new session created with session ID (%s)", key);
  if (m_cache->log->isDebugEnabled()) {
      auto_ptr_char h(s->getSubject()->getNameIdentifier()->getName());
      m_cache->log->debug("NameID (%s), IdP (%s), Address (%s)", h.get(), providerId, client_addr);
  }
}

InternalCCacheEntry::~InternalCCacheEntry()
{
  m_cache->log->debug("deleting session (ID: %s)", m_id.c_str());
  delete m_lock;
}

bool InternalCCacheEntry::isValid(time_t lifetime, time_t timeout) const
{
#ifdef _DEBUG
  saml::NDC ndc("isValid");
#endif
  
  m_cache->log->debug("testing session (ID: %s) (lifetime=%ld, timeout=%ld)",
    m_id.c_str(), lifetime, timeout);
    
  time_t now=time(NULL);
  if (lifetime > 0 && now > m_sessionCreated+lifetime) {
    m_cache->log->info("session beyond lifetime (ID: %s)", m_id.c_str());
    return false;
  }

  if (timeout > 0 && now-m_lastAccess >= timeout) {
    m_cache->log->info("session timed out (ID: %s)", m_id.c_str());
    return false;
  }
  m_lastAccess=now;
  return true;
}

ISessionCacheEntry::CachedResponseXML InternalCCacheEntry::getResponseXML()
{
    populate();
    return CachedResponseXML(m_response_pre.c_str(),m_response_post.c_str());
}

time_t InternalCCacheEntry::calculateExpiration(const SAMLResponse& r) const
{
    time_t expiration=0;
    Iterator<SAMLAssertion*> assertions = r.getAssertions();
    while (assertions.hasNext()) {
        SAMLAssertion* assertion = assertions.next();
        
        // Only examine this assertion if it contains an attribute statement.
        Iterator<SAMLStatement*> statements = assertion->getStatements();
        while (statements.hasNext()) {
            if (dynamic_cast<SAMLAttributeStatement*>(statements.next())) {
                const SAMLDateTime* thistime = assertion->getNotOnOrAfter();
        
                // If there is no time, then just continue and ignore this assertion.
                if (!thistime)
                    break;
                
                // If this is a tighter expiration, cache it.   
                if (expiration == 0 || thistime->getEpoch() < expiration)
                    expiration = thistime->getEpoch();
            }
        }
    }

    // If we didn't find any assertions with times, then use the default.
    if (expiration == 0)
        expiration = time(NULL) + m_cache->m_defaultLifetime;
  
    return expiration;
}

void InternalCCacheEntry::populate()
{
#ifdef _DEBUG
  saml::NDC ndc("populate");
#endif
  m_cache->log->debug("populating attributes for session (ID: %s)", m_id.c_str());

  // Do we have any data cached?
  if (!m_response_pre.empty()) {
      // Can we use what we have?
      if (time(NULL) < m_responseExpiration)
        return;
      
      // If we're being strict, dump what we have and reset timestamps.
      if (m_cache->m_strictValidity) {
        m_cache->log->info("strictly enforcing attribute validity, dumping expired data");
        m_response_pre.erase();
        m_response_post.erase();
        m_responseExpiration=0;
        m_lastRetry=0; 
      }
  }

  try {
    pair<SAMLResponse*,SAMLResponse*> new_responses=getNewResponse();
    auto_ptr<SAMLResponse> r1(new_responses.first),r2(new_responses.second);
    if (new_responses.first) {
        m_response_pre.erase();
        m_response_post.erase();
        
        // Serialize unfiltered assertions.
        ostringstream ostr;
        ostr << *new_responses.first;
        m_response_pre=ostr.str();
        
        // Serialize filtered assertions (if changes were made).
        ostr.str("");
        ostr << *new_responses.second;
        m_response_post=ostr.str();
        if (m_response_post == m_response_pre)
            m_response_post.erase();

        m_responseExpiration=calculateExpiration(*new_responses.second);
        m_lastRetry=0;
        m_cache->log->debug("fetched and stored new response");
    	STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
        stc.getTransactionLog().infoStream() <<  "Successful attribute query for session (ID: " << m_id << ")";
        stc.releaseTransactionLog();
    }
  }
  catch (SAMLException&) {
    if (m_cache->m_propagateErrors)
        throw;
    m_cache->log->warn("suppressed SAML exception caught while trying to fetch attributes");
  }
#ifndef _DEBUG
  catch (...) {
    if (m_cache->m_propagateErrors)
        throw;
    m_cache->log->warn("suppressed unknown exception caught while trying to fetch attributes");
  }
#endif
}

pair<SAMLResponse*,SAMLResponse*> InternalCCacheEntry::getNewResponse()
{
#ifdef _DEBUG
    saml::NDC ndc("getNewResponse");
#endif

    // The retryInterval determines how often to poll an AA that might be down.
    time_t now=time(NULL);
    if ((now - m_lastRetry) < m_cache->m_retryInterval)
        return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
    if (m_lastRetry)
        m_cache->log->debug("retry interval exceeded, so trying again");
    m_lastRetry=now;

    m_cache->log->info("trying to get new attributes for session (ID=%s)", m_id.c_str());
    
    // Transaction Logging
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getTransactionLog().infoStream() <<
        "Making attribute query for session (ID: " <<
            m_id <<
        ") on (applicationId: " <<
            m_application_id <<
        ") for principal from (IdP: " <<
            m_provider_id <<
        ")";
    stc.releaseTransactionLog();


    // Caller must be holding the config lock.
    // Lookup application for session to get providerId and attributes to request.
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    const IApplication* application=conf->getApplication(m_application_id.c_str());
    if (!application) {
        m_cache->log->crit("unable to locate application for session, deleted?");
        throw SAMLException("Unable to locate application for session, deleted?");
    }
    pair<bool,const XMLCh*> providerID=application->getXMLString("providerId");
    if (!providerID.first) {
        m_cache->log->crit("unable to determine ProviderID for application, not set?");
        throw SAMLException("Unable to determine ProviderID for application, not set?");
    }

    // Try this request.
    Metadata m(application->getMetadataProviders());
    const IEntityDescriptor* site=m.lookup(m_provider_id.c_str());
    if (!site) {
        m_cache->log->error("unable to locate identity provider's metadata during attribute query");
        return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
    }

    // Try to locate an AA role.
    int minorVersion=1;
    const IAttributeAuthorityDescriptor* AA=site->getAttributeAuthorityDescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
    if (!AA) {
        AA=site->getAttributeAuthorityDescriptor(saml::XML::SAML10_PROTOCOL_ENUM);
        if (!AA) {
            m_cache->log->warn("unable to locate metadata for identity provider's Attribute Authority");
            return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
        }
        minorVersion=0;
    }

    // Get protocol signing policy.
    const IPropertySet* credUse=application->getCredentialUse(site);
    pair<bool,bool> signRequest=credUse ? credUse->getBool("signRequest") : make_pair(false,false);
    pair<bool,const char*> signatureAlg=credUse ? credUse->getString("signatureAlg") : pair<bool,const char*>(false,NULL);
    if (!signatureAlg.first)
        signatureAlg.second=URI_ID_RSA_SHA1;
    pair<bool,const char*> digestAlg=credUse ? credUse->getString("digestAlg") : pair<bool,const char*>(false,NULL);
    if (!digestAlg.first)
        digestAlg.second=URI_ID_SHA1;
    pair<bool,bool> signedResponse=credUse ? credUse->getBool("signedResponse") : make_pair(false,false);
    pair<bool,const char*> signingCred=credUse ? credUse->getString("Signing") : pair<bool,const char*>(false,NULL);
    
    SAMLResponse* response = NULL;
    try {
        istringstream instr(m_auth_statement);
        auto_ptr<SAMLAuthenticationStatement> authn(new SAMLAuthenticationStatement(instr));

        // Build a SAML Request....
        SAMLAttributeQuery* q=new SAMLAttributeQuery(
            new SAMLSubject(static_cast<SAMLNameIdentifier*>(authn->getSubject()->getNameIdentifier()->clone())),
            providerID.second,
            application->getAttributeDesignators().clone()
            );
        auto_ptr<SAMLRequest> req(new SAMLRequest(q));
        req->setMinorVersion(minorVersion);
        
        // Sign it? Highly doubtful we'll ever use this, but just for fun...
        if (signRequest.first && signRequest.second && signingCred.first) {
            if (req->getMinorVersion()==1) {
                Credentials creds(conf->getCredentialsProviders());
                const ICredResolver* cr=creds.lookup(signingCred.second);
                if (cr)
                    req->sign(cr->getKey(),cr->getCertificates(),signatureAlg.second,digestAlg.second);
                else
                    m_cache->log->error("unable to sign attribute query, specified credential (%s) was not found",signingCred.second);
            }
            else
                m_cache->log->error("unable to sign SAML 1.0 attribute query, only SAML 1.1 defines signing adequately");
        }
            
        m_cache->log->debug("trying to query an AA...");

        // Call context object
        Trust t(application->getTrustProviders());
        ShibHTTPHook::ShibHTTPHookCallContext ctx(credUse,AA);
        
        // Use metadata to locate endpoints.
        Iterator<const IEndpoint*> endpoints=AA->getAttributeServiceManager()->getEndpoints();
        while (!response && endpoints.hasNext()) {
            const IEndpoint* ep=endpoints.next();
            try {
                // Get a binding object for this protocol.
                const SAMLBinding* binding = application->getBinding(ep->getBinding());
                if (!binding) {
                    auto_ptr_char prot(ep->getBinding());
                    m_cache->log->warn("skipping binding on unsupported protocol (%s)", prot.get());
                    continue;
                }
                static const XMLCh https[] = {chLatin_h, chLatin_t, chLatin_t, chLatin_p, chLatin_s, chColon, chNull};
                auto_ptr<SAMLResponse> r(binding->send(ep->getLocation(), *(req.get()), &ctx));
                if (r->isSigned()) {
                	if (!t.validate(*r,AA))
	                    throw TrustException("Unable to verify signed response message.");
                }
                else if (!ctx.isAuthenticated() || XMLString::compareNString(ep->getLocation(),https,6))
                	throw TrustException("Response message was unauthenticated.");
                response = r.release();
            }
            catch (SAMLException& e) {
                m_cache->log->error("caught SAML exception during SAML attribute query: %s", e.what());
                // Check for shib:InvalidHandle error and propagate it out.
                Iterator<saml::QName> codes=e.getCodes();
                if (codes.size()>1) {
                    const saml::QName& code=codes[1];
                    if (!XMLString::compareString(code.getNamespaceURI(),shibboleth::Constants::SHIB_NS) &&
                        !XMLString::compareString(code.getLocalName(), shibboleth::Constants::InvalidHandle)) {
                        codes.reset();
                        throw InvalidHandleException(e.what(),params(),codes);
                    }
                }
            }
        }

        if (response) {
            if (signedResponse.first && signedResponse.second && !response->isSigned()) {
                delete response;
                m_cache->log->error("unsigned response obtained, but we were told it must be signed.");
                throw TrustException("Unable to obtain a signed response message.");
            }
            
            // Run it through the filter.
            return make_pair(response,filter(response,application,AA));
        }
    }
    catch (SAMLException& e) {
        m_cache->log->error("caught SAML exception during query to AA: %s", e.what());
        annotateException(&e,AA);
    }
    
    m_cache->log->error("no response obtained");
    return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
}

SAMLResponse* InternalCCacheEntry::filter(SAMLResponse* r, const IApplication* application, const IRoleDescriptor* source)
{
    const IPropertySet* credUse=application->getCredentialUse(source->getEntityDescriptor());
    pair<bool,bool> signedAssertions=credUse ? credUse->getBool("signedAssertions") : make_pair(false,false);
    Trust t(application->getTrustProviders());

    // Examine each original assertion...
    Iterator<SAMLAssertion*> assertions=r->getAssertions();
    for (unsigned long i=0; i < assertions.size();) {
        // Check signing policy.
        if (signedAssertions.first && signedAssertions.second && !(assertions[i]->isSigned())) {
            m_cache->log->warn("removing unsigned assertion from response, in accordance with signedAssertions policy");
            r->removeAssertion(i);
            continue;
        }

        // Check any conditions.
        bool pruned=false;
        Iterator<SAMLCondition*> conds=assertions[i]->getConditions();
        while (conds.hasNext()) {
            SAMLAudienceRestrictionCondition* cond=dynamic_cast<SAMLAudienceRestrictionCondition*>(conds.next());
            if (!cond || !cond->eval(application->getAudiences())) {
                m_cache->log->warn("assertion condition invalid, removing it");
                r->removeAssertion(i);
                pruned=true;
                break;
            }
        }
        if (pruned)
            continue;
        
        // Check token signature.
        if (assertions[i]->isSigned() && !t.validate(*(assertions[i]),source)) {
            m_cache->log->warn("signed assertion failed to validate, removing it");
            r->removeAssertion(i);
            continue;
        }
        i++;
    }

    // Make a copy of whatever's left and process that against the AAP.
    auto_ptr<SAMLResponse> copy(static_cast<SAMLResponse*>(r->clone()));
    copy->toDOM();

    Iterator<SAMLAssertion*> copies=copy->getAssertions();
    for (unsigned long j=0; j < copies.size();) {
        try {
            // Finally, filter the content.
            AAP::apply(application->getAAPProviders(),*(copies[j]),source);
            j++;

        }
        catch (SAMLException&) {
            m_cache->log->info("no statements remain after AAP, removing assertion");
            copy->removeAssertion(j);
        }
    }

    // Audit the results.    
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    Category& tran=stc.getTransactionLog();
    if (tran.isInfoEnabled()) {
        tran.infoStream() <<
            "Caching the following attributes after AAP applied for session (ID: " <<
                m_id <<
            ") on (applicationId: " <<
                m_application_id <<
            ") for principal from (IdP: " <<
                m_provider_id <<
            ") {";

        Iterator<SAMLAssertion*> loggies=copy->getAssertions();
        while (loggies.hasNext()) {
            SAMLAssertion* logit=loggies.next();
            Iterator<SAMLStatement*> states=logit->getStatements();
            while (states.hasNext()) {
                SAMLAttributeStatement* state=dynamic_cast<SAMLAttributeStatement*>(states.next());
                Iterator<SAMLAttribute*> attrs=state ? state->getAttributes() : EMPTY(SAMLAttribute*);
                while (attrs.hasNext()) {
                    SAMLAttribute* attr=attrs.next();
                    auto_ptr_char attrname(attr->getName());
                    tran.infoStream() << "\t" << attrname.get() << " (" << attr->getValues().size() << " values)";
                }
            }
        }
        tran.info("}");
    }
    stc.releaseTransactionLog();
    
    return copy.release();
}
