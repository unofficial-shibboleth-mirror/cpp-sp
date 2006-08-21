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
 * shib-ccache.cpp -- in-memory session cache plugin
 *
 * $Id$
 */

#include "internal.h"

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <shib/shib-threads.h>

#include <log4cpp/Category.hh>

#include <algorithm>
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
static const XMLCh writeThrough[] =
{ chLatin_w, chLatin_r, chLatin_i, chLatin_t, chLatin_e,
  chLatin_T, chLatin_h, chLatin_r, chLatin_o, chLatin_u, chLatin_g, chLatin_h, chNull
};


/*
 * Stubbed out, inproc version of an ISessionCacheEntry
 */
class StubCacheEntry : public virtual ISessionCacheEntry
{
public:
    StubCacheEntry(Category* log) : m_log(log), m_pSubject(NULL), m_pUnfiltered(NULL), m_pFiltered(NULL) {}
    StubCacheEntry(DDF& obj, Category* log)
        : m_log(log), m_obj(obj), m_pSubject(NULL), m_pUnfiltered(NULL), m_pFiltered(NULL) {}
    ~StubCacheEntry() { m_obj.destroy(); delete m_pSubject; delete m_pUnfiltered; delete m_pFiltered; }
    void lock() {}
    void unlock() { delete this; }
    const char* getClientAddress() const { return m_obj["client_address"].string(); }
    const char* getProviderId() const { return m_obj["provider_id"].string(); }
    const char* getAuthnContext() const { return m_obj["authn_context"].string(); }
    pair<const char*,const SAMLSubject*> getSubject(bool xml=true, bool obj=false) const;
    pair<const char*,const SAMLResponse*> getTokens(bool xml=true, bool obj=false) const;
    pair<const char*,const SAMLResponse*> getFilteredTokens(bool xml=true, bool obj=false) const;

protected:
    Category* m_log;
    mutable DDF m_obj;
    mutable SAMLSubject* m_pSubject;
    mutable SAMLResponse* m_pUnfiltered;
    mutable SAMLResponse* m_pFiltered;
};

pair<const char*,const SAMLSubject*> StubCacheEntry::getSubject(bool xml, bool obj) const
{
    const char* raw=m_obj["subject"].string();
    pair<const char*,const SAMLSubject*> ret=pair<const char*,const SAMLSubject*>(NULL,NULL);
    if (xml)
        ret.first=raw;
    if (obj) {
        if (!m_pSubject) {
            istringstream in(raw);
            m_log->debugStream() << "decoding subject: " << (raw ? raw : "(none)") << CategoryStream::ENDLINE;
            m_pSubject=raw ? new SAMLSubject(in) : NULL;
        }
        ret.second=m_pSubject;
    }
    return ret;
}

pair<const char*,const SAMLResponse*> StubCacheEntry::getTokens(bool xml, bool obj) const
{
    const char* unfiltered=m_obj["tokens.unfiltered"].string();
    pair<const char*,const SAMLResponse*> ret = pair<const char*,const SAMLResponse*>(NULL,NULL);
    if (xml)
        ret.first=unfiltered;
    if (obj) {
        if (!m_pUnfiltered) {
            if (unfiltered) {
                istringstream in(unfiltered);
                m_log->debugStream() << "decoding unfiltered tokens: " << unfiltered << CategoryStream::ENDLINE;
                m_pUnfiltered=new SAMLResponse(in,m_obj["minor_version"].integer());
            }
        }
        ret.second=m_pUnfiltered;
    }
    return ret;
}

pair<const char*,const SAMLResponse*> StubCacheEntry::getFilteredTokens(bool xml, bool obj) const
{
    const char* filtered=m_obj["tokens.filtered"].string();
    if (!filtered)
        return getTokens(xml,obj);
    pair<const char*,const SAMLResponse*> ret = pair<const char*,const SAMLResponse*>(NULL,NULL);
    if (xml)
        ret.first=filtered;
    if (obj) {
        if (!m_pFiltered) {
            istringstream in(filtered);
            m_log->debugStream() << "decoding filtered tokens: " << filtered << CategoryStream::ENDLINE;
            m_pFiltered=new SAMLResponse(in,m_obj["minor_version"].integer());
        }
        ret.second=m_pFiltered;
    }
    return ret;
}

/*
 * Remoting front-half of session cache, drops out in single process deployments.
 *  TODO: Add buffering of frequently-used entries.
 */
class StubCache : public virtual ISessionCache
{
public:
    StubCache(const DOMElement* e);

    string insert(
        const IApplication* application,
        const IEntityDescriptor* source,
        const char* client_addr,
        const SAMLSubject* subject,
        const char* authnContext,
        const SAMLResponse* tokens
    );
    ISessionCacheEntry* find(const char* key, const IApplication* application, const char* client_addr);
    void remove(const char* key, const IApplication* application, const char* client_addr);

    bool setBackingStore(ISessionCacheStore*) { return false; }

private:
    Category* m_log;
};

StubCache::StubCache(const DOMElement* e) : m_log(&Category::getInstance(SHIBT_LOGCAT".SessionCache")) {}

/*
 * The public methods are remoted using the message passing system.
 * In practice, insert is unlikely to be used remotely, but just in case...
 */

string StubCache::insert(
    const IApplication* application,
    const IEntityDescriptor* source,
    const char* client_addr,
    const SAMLSubject* subject,
    const char* authnContext,
    const SAMLResponse* tokens
    )
{
    DDF in("SessionCache::insert"),out;
    DDFJanitor jin(in),jout(out);
    in.structure();
    in.addmember("application_id").string(application->getId());
    in.addmember("client_address").string(client_addr);
    auto_ptr_char provid(source->getId());
    in.addmember("provider_id").string(provid.get());
    in.addmember("major_version").integer(1);
    in.addmember("minor_version").integer(tokens->getMinorVersion());
    in.addmember("authn_context").string(authnContext);
    
    ostringstream os;
    os << *subject;
    in.addmember("subject").string(os.str().c_str());
    os.str("");
    os << *tokens;
    in.addmember("tokens.unfiltered").string(os.str().c_str());

    out=ShibTargetConfig::getConfig().getINI()->getListener()->send(in);
    if (out["key"].isstring())
        return out["key"].string();
    throw InvalidSessionException("A remoted cache insertion operation did not return a usable session key.");
}

ISessionCacheEntry* StubCache::find(const char* key, const IApplication* application, const char* client_addr)
{
    DDF in("SessionCache::find"),out;
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(key);
    in.addmember("application_id").string(application->getId());
    in.addmember("client_address").string(client_addr);
    
    try {
        out=ShibTargetConfig::getConfig().getINI()->getListener()->send(in);
        if (!out.isstruct()) {
            out.destroy();
            return NULL;
        }
        
        // Wrap the results in a stub entry and return it to the caller.
        return new StubCacheEntry(out,m_log);
    }
    catch (...) {
        out.destroy();
        throw;
    }
}

void StubCache::remove(const char* key, const IApplication* application, const char* client_addr)
{
    DDF in("SessionCache::remove");
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(key);
    in.addmember("application_id").string(application->getId());
    in.addmember("client_address").string(client_addr);
    
    ShibTargetConfig::getConfig().getINI()->getListener()->send(in);
}

/*
 * Long-lived cache entries that store the actual sessions and
 * wrap attribute query/refresh/filtering
 */
class MemorySessionCache;
class MemorySessionCacheEntry : public virtual ISessionCacheEntry, public virtual StubCacheEntry
{
public:
    MemorySessionCacheEntry(
        MemorySessionCache* cache,
        const char* key,
        const IApplication* application,
        const IEntityDescriptor* source,
        const char* client_addr,
        const SAMLSubject* subject,
        const char* authnContext,
        const SAMLResponse* tokens
        );
    MemorySessionCacheEntry(
        MemorySessionCache* cache,
        const char* key,
        const IApplication* application,
        const IEntityDescriptor* source,
        const char* client_addr,
        const char* subject,
        const char* authnContext,
        const char* tokens,
        int majorVersion,
        int minorVersion,
        time_t created,
        time_t accessed
        );
    ~MemorySessionCacheEntry();

    void lock() { m_lock->lock(); }
    void unlock() { m_lock->unlock(); }
    
    HRESULT isValid(const IApplication* application, const char* client_addr) const;
    void populate(const IApplication* application, const IEntityDescriptor* source, bool initial=false) const;
    bool checkApplication(const IApplication* application) { return (m_obj["application_id"]==application->getId()); }
    time_t created() const { return m_sessionCreated; }
    time_t lastAccess() const { return m_lastAccess; }
    const DDF& getDDF() const { return m_obj; }
  
private:
    bool hasAttributes(const SAMLResponse& r) const;
    time_t calculateExpiration(const SAMLResponse& r) const;
    pair<SAMLResponse*,SAMLResponse*> getNewResponse(const IApplication* application, const IEntityDescriptor* source) const;
    SAMLResponse* filter(const SAMLResponse* r, const IApplication* application, const IEntityDescriptor* source) const;
  
    time_t m_sessionCreated;
    mutable time_t m_responseExpiration, m_lastAccess, m_lastRetry;

    MemorySessionCache* m_cache;
    Mutex* m_lock;
};

/*
 * The actual in-memory session cache implementation.
 */
class MemorySessionCache : public virtual ISessionCache, public virtual IRemoted
{
public:
    MemorySessionCache(const DOMElement* e);
    virtual ~MemorySessionCache();

    DDF receive(const DDF& in);

    string insert(
        const IApplication* application,
        const IEntityDescriptor* source,
        const char* client_addr,
        const SAMLSubject* subject,
        const char* authnContext,
        const SAMLResponse* tokens
    );
    ISessionCacheEntry* find(const char* key, const IApplication* application, const char* client_addr);
    void remove(const char* key, const IApplication* application, const char* client_addr);

    void cleanup();

    bool setBackingStore(ISessionCacheStore* store);

private:
    const DOMElement* m_root;         // Only valid during initialization
    RWLock* m_lock;
    map<string,MemorySessionCacheEntry*> m_hashtable;

    Category* m_log;
    IRemoted* restoreInsert;
    IRemoted* restoreFind;
    IRemoted* restoreRemove;
    ISessionCacheStore* m_sink;

    void dormant(const char* key);
    static void* cleanup_fcn(void*);
    bool shutdown;
    CondWait* shutdown_wait;
    Thread* cleanup_thread;
  
    // extracted config settings
    unsigned int m_AATimeout,m_AAConnectTimeout;
    unsigned int m_defaultLifetime,m_retryInterval;
    bool m_strictValidity,m_propagateErrors,m_writeThrough;
    friend class MemorySessionCacheEntry;
};

MemorySessionCacheEntry::MemorySessionCacheEntry(
    MemorySessionCache* cache,
    const char* key,
    const IApplication* application,
    const IEntityDescriptor* source,
    const char* client_addr,
    const SAMLSubject* subject,
    const char* authnContext,
    const SAMLResponse* tokens
    ) : StubCacheEntry(cache->m_log), m_cache(cache), m_responseExpiration(0), m_lastRetry(0)
{
    m_sessionCreated = m_lastAccess = time(NULL);

    // Store session properties in DDF.
    m_obj=DDF(NULL).structure();
    m_obj.addmember("key").string(key);
    m_obj.addmember("client_address").string(client_addr);
    m_obj.addmember("application_id").string(application->getId());
    auto_ptr_char pid(source->getId());
    m_obj.addmember("provider_id").string(pid.get());
    m_obj.addmember("major_version").integer(1);
    m_obj.addmember("minor_version").integer(tokens->getMinorVersion());

    // Save the subject as XML.
    ostringstream os;
    os << *subject;
    m_obj.addmember("subject").string(os.str().c_str());
    
    // Save the authn method.
    m_obj.addmember("authn_context").string(authnContext);

    // Serialize unfiltered assertions.
    os.str("");
    os << *tokens;
    m_obj.addmember("tokens.unfiltered").string(os.str().c_str());

    if (hasAttributes(*tokens)) {
        // Filter attributes in the response.
        auto_ptr<SAMLResponse> filtered(filter(tokens, application, source));
        
        // Calculate expiration.
        m_responseExpiration=calculateExpiration(*(filtered.get()));
        
        // Serialize filtered assertions (if changes were made).
        os.str("");
        os << *(filtered.get());
        string fstr=os.str();
        if (fstr.length() != m_obj["tokens.unfiltered"].strlen())
            m_obj.addmember("tokens.filtered").string(fstr.c_str());

        // Save actual objects only if we're running inprocess. The subject needs to be
        // owned by the entry, so we'll defer creation of a cloned copy.
        if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::InProcess)) {
            if (m_obj["tokens.filtered"].isstring())
                m_pFiltered=filtered.release();
        }
    }
    
    m_lock = Mutex::create();

    if (m_log->isDebugEnabled()) {
        m_log->debug("new cache entry created: SessionID (%s) IdP (%s) Address (%s)", key, pid.get(), client_addr);
    }

    // Transaction Logging
    auto_ptr_char hname(subject->getNameIdentifier()->getName());
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getTransactionLog().infoStream() <<
        "New session (ID: " <<
            key <<
        ") with (applicationId: " <<
            application->getId() <<
        ") for principal from (IdP: " <<
            pid.get() <<
        ") at (ClientAddress: " <<
            client_addr <<
        ") with (NameIdentifier: " <<
            hname.get() <<
        ")";
    stc.releaseTransactionLog();
}

MemorySessionCacheEntry::MemorySessionCacheEntry(
    MemorySessionCache* cache,
    const char* key,
    const IApplication* application,
    const IEntityDescriptor* source,
    const char* client_addr,
    const char* subject,
    const char* authnContext,
    const char* tokens,
    int majorVersion,
    int minorVersion,
    time_t created,
    time_t accessed
    ) : StubCacheEntry(cache->m_log), m_cache(cache), m_responseExpiration(0), m_lastRetry(0)
{
    m_sessionCreated = created;
    m_lastAccess = accessed;

    // Reconstitute the tokens for filtering.
    istringstream is(tokens);
    auto_ptr<SAMLResponse> unfiltered(new SAMLResponse(is,minorVersion));

    // Store session properties in DDF.
    m_obj=DDF(NULL).structure();
    m_obj.addmember("key").string(key);
    m_obj.addmember("client_address").string(client_addr);
    m_obj.addmember("application_id").string(application->getId());
    auto_ptr_char pid(source->getId());
    m_obj.addmember("provider_id").string(pid.get());
    m_obj.addmember("subject").string(subject);
    m_obj.addmember("authn_context").string(authnContext);
    m_obj.addmember("tokens.unfiltered").string(tokens);
    m_obj.addmember("major_version").integer(majorVersion);
    m_obj.addmember("minor_version").integer(minorVersion);

    if (hasAttributes(*(unfiltered.get()))) {
        auto_ptr<SAMLResponse> filtered(filter(unfiltered.get(), application, source));
    
        // Calculate expiration.
        m_responseExpiration=calculateExpiration(*(filtered.get()));
    
        // Serialize filtered assertions (if changes were made).
        ostringstream os;
        os << *(filtered.get());
        string fstr=os.str();
        if (fstr.length() != strlen(tokens))
            m_obj.addmember("tokens.filtered").string(fstr.c_str());

        // Save actual objects only if we're running inprocess.
        if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::InProcess)) {
            m_pUnfiltered=unfiltered.release();
            if (m_obj["tokens.filtered"].isstring())
                m_pFiltered=filtered.release();
        }
    }
    
    m_lock = Mutex::create();

    if (m_log->isDebugEnabled())
        m_log->debug("session loaded from secondary cache (ID: %s)", key);
}


MemorySessionCacheEntry::~MemorySessionCacheEntry()
{
    delete m_lock;
}

HRESULT MemorySessionCacheEntry::isValid(const IApplication* app, const char* client_addr) const
{
#ifdef _DEBUG
    saml::NDC ndc("isValid");
#endif

    // Obtain validation rules from application settings.
    bool consistentIPAddress=true;
    int lifetime=0,timeout=0;
    const IPropertySet* props=app->getPropertySet("Sessions");
    if (props) {
        pair<bool,unsigned int> p=props->getUnsignedInt("lifetime");
        if (p.first)
            lifetime = p.second;
        p=props->getUnsignedInt("timeout");
        if (p.first)
            timeout = p.second;
        pair<bool,bool> pcheck=props->getBool("consistentIPAddress");
        if (pcheck.first)
            consistentIPAddress = pcheck.second;
    }
    
    if (m_log->isDebugEnabled())
        m_log->debug("checking validity of session (ID: %s)", m_obj["key"].string());
    
    time_t now=time(NULL);
    if (lifetime > 0 && now > m_sessionCreated+lifetime) {
        if (m_log->isInfoEnabled())
            m_log->info("session expired (ID: %s)", m_obj["key"].string());
        return SESSION_E_EXPIRED;
    }

    if (timeout > 0 && now-m_lastAccess >= timeout) {
        // May need to query sink first to find out if another cluster member has been used.
        if (m_cache->m_sink && m_cache->m_writeThrough) {
            if (NOERROR!=m_cache->m_sink->onRead(m_obj["key"].string(),m_lastAccess))
                m_log->error("cache store failed to return last access timestamp");
            if (now-m_lastAccess >= timeout) {
                m_log->info("session timed out (ID: %s)", m_obj["key"].string());
                return SESSION_E_EXPIRED;
            }
        }
        else {
            m_log->info("session timed out (ID: %s)", m_obj["key"].string());
            return SESSION_E_EXPIRED;
        }
    }

    if (consistentIPAddress) {
        if (m_log->isDebugEnabled())
            m_log->debug("comparing client address %s against %s", client_addr, getClientAddress());
        if (strcmp(client_addr, getClientAddress())) {
            m_log->debug("client address mismatch");
            return SESSION_E_ADDRESSMISMATCH;
        }
    }

    m_lastAccess=now;

    if (m_cache->m_sink && m_cache->m_writeThrough && timeout > 0) {
        // Update sink with last access data, if possible.
        if (FAILED(m_cache->m_sink->onUpdate(m_obj["key"].string(),NULL,m_lastAccess)))
            m_log->error("cache store failed to update last access timestamp");
    }

    return NOERROR;
}

bool MemorySessionCacheEntry::hasAttributes(const SAMLResponse& r) const
{
    Iterator<SAMLAssertion*> assertions=r.getAssertions();
    while (assertions.hasNext()) {
        Iterator<SAMLStatement*> statements=assertions.next()->getStatements();
        while (statements.hasNext()) {
            if (dynamic_cast<SAMLAttributeStatement*>(statements.next()))
                return true;
        }
    }
    return false;
}

time_t MemorySessionCacheEntry::calculateExpiration(const SAMLResponse& r) const
{
    time_t expiration=0;
    Iterator<SAMLAssertion*> assertions = r.getAssertions();
    while (assertions.hasNext()) {
        SAMLAssertion* assertion = assertions.next();
        
        // Only examine this assertion if it contains an attribute statement.
        // We know at least one such statement exists, or this is a query response.
        Iterator<SAMLStatement*> statements = assertion->getStatements();
        while (statements.hasNext()) {
            if (dynamic_cast<SAMLAttributeStatement*>(statements.next())) {
                const SAMLDateTime* thistime = assertion->getNotOnOrAfter();
        
                // If there is no time, then just continue and ignore this assertion.
                if (thistime) {    
                    // If this is a tighter expiration, cache it.   
                    if (expiration == 0 || thistime->getEpoch() < expiration)
                        expiration = thistime->getEpoch();
                }

                // No need to continue with this assertion.
                break;
            }
        }
    }

    // If we didn't find any assertions with times, then use the default.
    if (expiration == 0)
        expiration = time(NULL) + m_cache->m_defaultLifetime;
  
    return expiration;
}

void MemorySessionCacheEntry::populate(const IApplication* application, const IEntityDescriptor* source, bool initial) const
{
#ifdef _DEBUG
    saml::NDC ndc("populate");
#endif

    // Do we have any attribute data cached?
    if (m_responseExpiration > 0) {
        // Can we use what we have?
        if (time(NULL) < m_responseExpiration)
            return;
        
        // Possibly check the sink in case another cluster member already refreshed it.
        if (m_cache->m_sink && m_cache->m_writeThrough) {
            string tokensFromSink;
            HRESULT hr=m_cache->m_sink->onRead(m_obj["key"].string(),tokensFromSink);
            if (FAILED(hr))
                m_log->error("cache store failed to return updated tokens");
            else if (hr==NOERROR && tokensFromSink!=m_obj["tokens.unfiltered"].string()) {
                // The tokens in the sink were different.
                istringstream is(tokensFromSink);
                auto_ptr<SAMLResponse> respFromSink(new SAMLResponse(is,m_obj["minor_version"].integer()));
                auto_ptr<SAMLResponse> filteredFromSink(filter(respFromSink.get(),application,source));
                time_t expFromSink=calculateExpiration(*(filteredFromSink.get()));
                
                // Recheck to see if the new tokens are valid.
                if (expFromSink < time(NULL)) {
                    m_log->info("loading replacement tokens into memory from cache store");
                    m_obj["tokens"].destroy();
                    delete m_pUnfiltered;
                    delete m_pFiltered;
                    m_pUnfiltered=m_pFiltered=NULL;
                    m_obj.addmember("tokens.unfiltered").string(tokensFromSink.c_str());

                    // Serialize filtered assertions (if changes were made).
                    ostringstream os;
                    os << *(filteredFromSink.get());
                    string fstr=os.str();
                    if (fstr.length() != m_obj.getmember("tokens.unfiltered").strlen())
                        m_obj.addmember("tokens.filtered").string(fstr.c_str());
                    
                    // Save actual objects only if we're running inprocess.
                    if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::InProcess)) {
                        m_pUnfiltered=respFromSink.release();
                        if (m_obj["tokens.filtered"].isstring())
                            m_pFiltered=filteredFromSink.release();
                    }

                    m_responseExpiration=expFromSink;
                    m_lastRetry=0;
                    return;
                }
            }
        }

        // If we're being strict, dump what we have and reset timestamps.
        if (m_cache->m_strictValidity) {
            m_log->info("strictly enforcing attribute validity, dumping expired data");
            m_obj["tokens"].destroy();
            delete m_pUnfiltered;
            delete m_pFiltered;
            m_pUnfiltered=m_pFiltered=NULL;
            m_responseExpiration=0;
            m_lastRetry=0;
            if (m_cache->m_sink) {
                if (FAILED(m_cache->m_sink->onUpdate(m_obj["key"].string(),"")))
                    m_log->error("cache store returned failure while clearing tokens from entry");
            }
        }
    }

    try {
        pair<SAMLResponse*,SAMLResponse*> new_responses=getNewResponse(application,source);
        auto_ptr<SAMLResponse> r1(new_responses.first),r2(new_responses.second);
        if (new_responses.first) {
            m_obj["tokens"].destroy();
            delete m_pUnfiltered;
            delete m_pFiltered;
            m_pUnfiltered=m_pFiltered=NULL;
            m_responseExpiration=0;
            
            // Serialize unfiltered assertions.
            ostringstream os;
            os << *new_responses.first;
            m_obj.addmember("tokens.unfiltered").string(os.str().c_str());
            
            // Serialize filtered assertions (if changes were made).
            os.str("");
            os << *new_responses.second;
            string fstr=os.str();
            if (fstr.length() != m_obj.getmember("tokens.unfiltered").strlen())
                m_obj.addmember("tokens.filtered").string(fstr.c_str());
            
            // Update expiration.
            m_responseExpiration=calculateExpiration(*new_responses.second);

            // Save actual objects only if we're running inprocess.
            if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::InProcess)) {
                m_pUnfiltered=r1.release();
                if (m_obj["tokens.filtered"].isstring())
                    m_pFiltered=r2.release();
            }

            // Update backing store.
            if (!initial && m_cache->m_sink) {
                if (FAILED(m_cache->m_sink->onUpdate(m_obj["key"].string(),m_obj["tokens.unfiltered"].string())))
                    m_log->error("cache store returned failure while updating tokens in entry");
            }

            m_lastRetry=0;
            m_log->debug("fetched and stored new response");
            STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
            stc.getTransactionLog().infoStream() <<  "Successful attribute query for session (ID: " << m_obj["key"].string() << ")";
            stc.releaseTransactionLog();
        }
    }
    catch (SAMLException&) {
        if (m_cache->m_propagateErrors)
            throw;
        m_log->warn("suppressed SAML exception caught while trying to fetch attributes");
    }
#ifndef _DEBUG
    catch (...) {
        if (m_cache->m_propagateErrors)
            throw;
        m_log->warn("suppressed unknown exception caught while trying to fetch attributes");
    }
#endif
}

pair<SAMLResponse*,SAMLResponse*> MemorySessionCacheEntry::getNewResponse(
    const IApplication* application, const IEntityDescriptor* source
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("getNewResponse");
#endif

    // The retryInterval determines how often to poll an AA that might be down.
    time_t now=time(NULL);
    if ((now - m_lastRetry) < m_cache->m_retryInterval)
        return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
    if (m_lastRetry)
        m_log->debug("retry interval exceeded, trying for attributes again");
    m_lastRetry=now;

    m_log->info("trying to get new attributes for session (ID: %s)", m_obj["key"].string());
    
    // Transaction Logging
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getTransactionLog().infoStream() <<
        "Making attribute query for session (ID: " <<
            m_obj["key"].string() <<
        ") on (applicationId: " <<
            m_obj["application_id"].string() <<
        ") for principal from (IdP: " <<
            m_obj["provider_id"].string() <<
        ")";
    stc.releaseTransactionLog();


    pair<bool,const XMLCh*> providerID=application->getXMLString("providerId");
    if (!providerID.first) {
        m_log->crit("unable to determine ProviderID for application, not set?");
        throw SAMLException("Unable to determine ProviderID for application, not set?");
    }

    // Try to locate an AA role.
    const IAttributeAuthorityDescriptor* AA=source->getAttributeAuthorityDescriptor(
        m_obj["minor_version"].integer()==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
        );
    if (!AA) {
        m_log->warn("unable to locate metadata for identity provider's Attribute Authority");
        return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
    }

    // Get protocol signing policy.
    const IPropertySet* credUse=application->getCredentialUse(source);
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
        // Copy NameID from subject (may need to reconstitute it).
        SAMLNameIdentifier* nameid=NULL;
        if (m_pSubject)
            nameid=static_cast<SAMLNameIdentifier*>(m_pSubject->getNameIdentifier()->clone());
        else {
            istringstream instr(m_obj["subject"].string());
            auto_ptr<SAMLSubject> sub(new SAMLSubject(instr));
            nameid=static_cast<SAMLNameIdentifier*>(sub->getNameIdentifier()->clone());
        }

        // Build a SAML Request....
        SAMLAttributeQuery* q=new SAMLAttributeQuery(
            new SAMLSubject(nameid),
            providerID.second,
            application->getAttributeDesignators().clone()
            );
        auto_ptr<SAMLRequest> req(new SAMLRequest(q));
        req->setMinorVersion(m_obj["minor_version"].integer());
        
        // Sign it?
        if (signRequest.first && signRequest.second && signingCred.first) {
            if (req->getMinorVersion()==1) {
                Credentials creds(ShibTargetConfig::getConfig().getINI()->getCredentialsProviders());
                const ICredResolver* cr=creds.lookup(signingCred.second);
                if (cr)
                    req->sign(cr->getKey(),cr->getCertificates(),signatureAlg.second,digestAlg.second);
                else
                    m_log->error("unable to sign attribute query, specified credential (%s) was not found",signingCred.second);
            }
            else
                m_log->error("unable to sign SAML 1.0 attribute query, only SAML 1.1 defines signing adequately");
        }
            
        m_log->debug("trying to query an AA...");

        // Call context object
        ShibHTTPHook::ShibHTTPHookCallContext ctx(credUse,AA);
        Trust t(application->getTrustProviders());
        
        // Use metadata to locate endpoints.
        Iterator<const IEndpoint*> endpoints=AA->getAttributeServiceManager()->getEndpoints();
        while (!response && endpoints.hasNext()) {
            const IEndpoint* ep=endpoints.next();
            try {
                // Get a binding object for this protocol.
                const SAMLBinding* binding = application->getBinding(ep->getBinding());
                if (!binding) {
                    auto_ptr_char prot(ep->getBinding());
                    m_log->warn("skipping binding on unsupported protocol (%s)", prot.get());
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
                m_log->error("caught SAML exception during SAML attribute query: %s", e.what());
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
                m_log->error("unsigned response obtained, but we were told it must be signed.");
                throw TrustException("Unable to obtain a signed response message.");
            }
            
            // Iterate over the tokens and apply basic validation.
            time_t now=time(NULL);
            Iterator<SAMLAssertion*> assertions=response->getAssertions();
            for (unsigned int a=0; a<assertions.size();) {
                // Discard any assertions not issued by the right entity.
                if (XMLString::compareString(source->getId(),assertions[a]->getIssuer())) {
                    auto_ptr_char bad(assertions[a]->getIssuer());
                    m_log->warn("discarding assertion not issued by (%s), instead by (%s)",m_obj["provider_id"].string(),bad.get());
                    response->removeAssertion(a);
                    continue;
                }

                // Validate the token.
                try {
                    application->validateToken(assertions[a],now,AA,application->getTrustProviders());
                    a++;
                }
                catch (SAMLException&) {
                    m_log->warn("assertion failed to validate, removing it from response");
                    response->removeAssertion(a);
                }
            }

            // Run it through the filter.
            return make_pair(response,filter(response,application,source));
        }
    }
    catch (SAMLException& e) {
        m_log->error("caught SAML exception during query to AA: %s", e.what());
        annotateException(&e,AA);
    }
    
    m_log->error("no response obtained");
    return pair<SAMLResponse*,SAMLResponse*>(NULL,NULL);
}

SAMLResponse* MemorySessionCacheEntry::filter(
    const SAMLResponse* r, const IApplication* application, const IEntityDescriptor* source
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("filter");
#endif

    // Make a copy of the original and process that against the AAP.
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
            m_log->info("no statements remain after AAP, removing assertion");
            copy->removeAssertion(j);
        }
    }

    // Audit the results.    
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    Category& tran=stc.getTransactionLog();
    if (tran.isInfoEnabled()) {
        tran.infoStream() <<
            "Caching the following attributes after AAP applied for session (ID: " <<
                m_obj["key"].string() <<
            ") on (applicationId: " <<
                m_obj["application_id"].string() <<
            ") for principal from (IdP: " <<
                m_obj["provider_id"].string() <<
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

MemorySessionCache::MemorySessionCache(const DOMElement* e)
    : m_root(e), m_AATimeout(30), m_AAConnectTimeout(15), m_defaultLifetime(1800), m_retryInterval(300),
        m_strictValidity(true), m_propagateErrors(false), m_writeThrough(false), m_lock(RWLock::create()),
        m_log(&Category::getInstance(SHIBT_LOGCAT".SessionCache")),
        restoreInsert(NULL), restoreFind(NULL), restoreRemove(NULL), m_sink(NULL)
{
    if (m_root) {
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

        tag=m_root->getAttributeNS(NULL,writeThrough);
        if (tag && (*tag==chDigit_1 || *tag==chLatin_t))
            m_writeThrough=true;
    }

    SAMLConfig::getConfig().timeout = m_AATimeout;
    SAMLConfig::getConfig().conn_timeout = m_AAConnectTimeout;

    // Register for remoted messages.
    IListener* listener=ShibTargetConfig::getConfig().getINI()->getListener();
    if (listener && ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::OutOfProcess)) {
        restoreInsert=listener->regListener("SessionCache::insert",this);
        restoreFind=listener->regListener("SessionCache::find",this);
        restoreRemove=listener->regListener("SessionCache::remove",this);
    }
    else
        m_log->info("no listener interface available, cache remoting is disabled");

    shutdown_wait = CondWait::create();
    shutdown = false;
    cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

MemorySessionCache::~MemorySessionCache()
{
    // Shut down the cleanup thread and let it know...
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(NULL);

    // Unregister remoted messages.
    IListener* listener=ShibTargetConfig::getConfig().getINI()->getListener();
    if (listener && ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::OutOfProcess)) {
        listener->unregListener("SessionCache::insert",this,restoreInsert);
        listener->unregListener("SessionCache::find",this,restoreFind);
        listener->unregListener("SessionCache::remove",this,restoreRemove);
    }

    for_each(m_hashtable.begin(),m_hashtable.end(),shibtarget::cleanup_pair<string,MemorySessionCacheEntry>());
    delete m_lock;
    delete shutdown_wait;
}

bool MemorySessionCache::setBackingStore(ISessionCacheStore* store)
{
    if (m_sink && store!=m_sink)
        return false;
    m_sink=store;
    return true;
}

/*
 * IPC message definitions:
 * 
 *  SessionCache::insert
 * 
 *      IN
 *      application_id
 *      client_address
 *      provider_id
 *      major_version
 *      minor_version
 *      authn_context
 *      subject
 *      tokens.unfiltered
 * 
 *      OUT
 *      key
 * 
 *  SessionCache::find
 * 
 *      IN
 *      key
 *      application_id
 *      client_address
 * 
 *      OUT
 *      client_address
 *      provider_id
 *      major_version
 *      minor_version
 *      authn_context
 *      subject
 *      tokens.unfiltered
 *      tokens.filtered
 * 
 *  SessionCache::remove
 * 
 *      IN
 *      key
 *      application_id
 *      client_address
 */

DDF MemorySessionCache::receive(const DDF& in)
{
#ifdef _DEBUG
    saml::NDC ndc("receive");
#endif

    // Find application.
    const char* aid=in["application_id"].string();
    const IApplication* app=aid ? ShibTargetConfig::getConfig().getINI()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log->error("couldn't find application (%s) for session", aid ? aid : "(missing)");
        throw SAMLException("Unable to locate application for session, deleted?");
    }

    if (!strcmp(in.name(),"SessionCache::find")) {
        // Check required parameters.
        const char* key=in["key"].string();
        const char* client_address=in["client_address"].string();
        if (!key || !client_address)
            throw SAMLException("Required parameters missing in call to SessionCache::find");
        
        try {        
            // Lookup the session and cast down to the internal type.
            MemorySessionCacheEntry* entry=dynamic_cast<MemorySessionCacheEntry*>(find(key,app,client_address));
            if (!entry)
                return DDF();
            DDF dup=entry->getDDF().copy();
            entry->unlock();
            return dup;
        }
        catch (SAMLException&) {
            remove(key,app,client_address);
            throw;
        }
    }
    else if (!strcmp(in.name(),"SessionCache::remove")) {
        // Check required parameters.
        const char* key=in["key"].string();
        const char* client_address=in["client_address"].string();
        if (!key || !client_address)
            throw SAMLException("Required parameters missing in call to SessionCache::remove");
        
        remove(key,app,client_address);
        return DDF();
    }
    else if (!strcmp(in.name(),"SessionCache::insert")) {
        // Check required parameters.
        const char* client_address=in["client_address"].string();
        const char* provider_id=in["provider_id"].string();
        const char* authn_context=in["authn_context"].string();
        const char* subject=in["subject"].string();
        const char* tokens=in["tokens.unfiltered"].string();
        if (!client_address || !provider_id || !authn_context || !subject || !tokens)
            throw SAMLException("Required parameters missing in call to SessionCache::insert");
        int minor=in["minor_version"].integer();
        
        // Locate role descriptor to use in filtering.
        Metadata m(app->getMetadataProviders());
        const IEntityDescriptor* site=m.lookup(provider_id);
        if (!site) {
            m_log->error("unable to locate issuing identity provider's metadata");
            throw MetadataException("Unable to locate identity provider's metadata.");
        }
        // Deserialize XML for insert method.
        istringstream subis(subject);
        auto_ptr<SAMLSubject> pSubject(new SAMLSubject(subis));
        istringstream tokis(tokens);
        auto_ptr<SAMLResponse> pTokens(new SAMLResponse(tokis,minor));
        
        // Insert the data and return the cache key.
        string key=insert(app,site,client_address,pSubject.get(),authn_context,pTokens.get());
        
        DDF out(NULL);
        out.structure();
        out.addmember("key").string(key.c_str());
        return out;
    }
    throw ListenerException("Unsupported operation ($1)",params(1,in.name()));
}

string MemorySessionCache::insert(
    const IApplication* application,
    const IEntityDescriptor* source,
    const char* client_addr,
    const SAMLSubject* subject,
    const char* authnContext,
    const SAMLResponse* tokens
    )
{
#ifdef _DEBUG
    saml::NDC ndc("insert");
#endif

    SAMLIdentifier id;
    auto_ptr_char key(id);

    if (m_log->isDebugEnabled())
        m_log->debug("creating new cache entry for application %s: \"%s\"", application->getId(), key.get());

    auto_ptr<MemorySessionCacheEntry> entry(
        new MemorySessionCacheEntry(
            this,
            key.get(),
            application,
            source,
            client_addr,
            subject,
            authnContext,
            tokens
            )
        );
    entry->populate(application,source,true);

    if (m_sink) {
        HRESULT hr=m_sink->onCreate(key.get(),application,entry.get(),1,tokens->getMinorVersion(),entry->created());
        if (FAILED(hr)) {
            m_log->error("cache store returned failure while storing new entry");
            throw SAMLException(hr,"Unable to record new session in cache store.");
        }
    }

    m_lock->wrlock();
    m_hashtable[key.get()]=entry.release();
    m_lock->unlock();

    return key.get();
}

ISessionCacheEntry* MemorySessionCache::find(const char* key, const IApplication* application, const char* client_addr)
{
#ifdef _DEBUG
    saml::NDC ndc("find");
#endif

    m_log->debug("searching memory cache for key (%s)", key);
    m_lock->rdlock();

    map<string,MemorySessionCacheEntry*>::const_iterator i=m_hashtable.find(key);
    if (i==m_hashtable.end()) {
        m_lock->unlock();
        m_log->debug("no match found");
        if (!m_sink)
            return NULL;    // no backing store to search

        m_log->debug("searching backing store");
        string appid,addr,pid,sub,ac,tokens;
        int major,minor;
        time_t created,accessed;
        HRESULT hr=m_sink->onRead(key,appid,addr,pid,sub,ac,tokens,major,minor,created,accessed);
        if (hr==S_FALSE)
            return NULL;
        else if (FAILED(hr)) {
            m_log->error("cache store returned failure during search");
            return NULL;
        }
        const IApplication* eapp=ShibTargetConfig::getConfig().getINI()->getApplication(appid.c_str());
        if (!eapp) {
            // Something's horribly wrong.
            m_log->error("couldn't find application (%s) for session", appid.c_str());
            if (FAILED(m_sink->onDelete(key)))
                m_log->error("cache store returned failure during delete");
            return NULL;
        }
        if (m_log->isDebugEnabled())
            m_log->debug("loading cache entry (ID: %s) back into memory for application (%s)", key, appid.c_str());

        // Locate role descriptor to use in filtering.
        Metadata m(eapp->getMetadataProviders());
        const IEntityDescriptor* site=m.lookup(pid.c_str());
        if (!site) {
            m_log->error("unable to locate issuing identity provider's metadata");
            if (FAILED(m_sink->onDelete(key)))
                m_log->error("cache store returned failure during delete");
            return NULL;
        }
        MemorySessionCacheEntry* entry = new MemorySessionCacheEntry(
            this,
            key,
            eapp,
            site,
            addr.c_str(),
            sub.c_str(),
            ac.c_str(),
            tokens.c_str(),
            major,
            minor,
            created,
            accessed
            );
        m_lock->wrlock();
        m_hashtable[key]=entry;
        m_lock->unlock();

        // Downgrade to a read lock and repeat the initial search.
        m_lock->rdlock();
        i=m_hashtable.find(key);
        if (i==m_hashtable.end()) {
            m_lock->unlock();
            m_log->warn("cache entry was loaded from backing store, but disappeared after lock downgrade");
            return NULL;
        }
    }
    else
        m_log->debug("match found");

    // Check for application mismatch (could also do this with partitioned caches by application ID)
    if (!i->second->checkApplication(application)) {
        m_lock->unlock();
        m_log->crit("An application (%s) attempted to access another application's session!", application->getId());
        return NULL;
    }
    
    // Check for timeouts, expiration, address mismatch, etc (also updates last access)
    // Use the return code to assign specific error messages.
    try {
        HRESULT hr=i->second->isValid(application, client_addr);
        if (FAILED(hr)) {
            Metadata m(application->getMetadataProviders());
            switch (hr) {
                case SESSION_E_EXPIRED: {
                    InvalidSessionException ex(SESSION_E_EXPIRED, "Your session has expired, and you must re-authenticate.");
                    annotateException(&ex,m.lookup(i->second->getProviderId())); // throws it
                }
                
                case SESSION_E_ADDRESSMISMATCH: {
                    InvalidSessionException ex(
                        SESSION_E_ADDRESSMISMATCH,
                        "Your IP address ($1) does not match the address recorded at the time the session was established.",
                        params(1,client_addr)
                        );
                    annotateException(&ex,m.lookup(i->second->getProviderId())); // throws it
                }
                
                default: {
                    InvalidSessionException ex(hr, "Your session is invalid.");
                    annotateException(&ex,m.lookup(i->second->getProviderId())); // throws it
                }
            }
        }
    }
    catch (...) {
        m_lock->unlock();
        throw;
    }

    // Lock the cache entry for the caller -- they have to unlock it.
    i->second->lock();
    m_lock->unlock();

    try {
        // Make sure the entry has valid tokens.
        Metadata m(application->getMetadataProviders());
        i->second->populate(application,m.lookup(i->second->getProviderId()));
    }
    catch (...) {
        i->second->unlock();
        throw;
    }

    return i->second;
}

void MemorySessionCache::remove(const char* key, const IApplication* application, const char* client_addr)
{
#ifdef _DEBUG
    saml::NDC ndc("remove");
#endif

    m_log->debug("removing cache entry with key (%s)", key);

    // lock the cache for writing, which means we know nobody is sitting in find()
    m_lock->wrlock();

    // grab the entry from the database.
    map<string,MemorySessionCacheEntry*>::const_iterator i=m_hashtable.find(key);
    if (i==m_hashtable.end()) {
        m_lock->unlock();
        return;
    }

    // ok, remove the entry and lock it
    MemorySessionCacheEntry* entry=i->second;
    m_hashtable.erase(key);
    entry->lock();
    
    // unlock the cache
    m_lock->unlock();

    entry->unlock();

    // Notify sink. Smart ptr will make sure entry gets deleted.
    auto_ptr<ISessionCacheEntry> entrywrap(entry);
    if (m_sink) {
        if (FAILED(m_sink->onDelete(key)))
            m_log->error("cache store failed to delete entry");
    }

    // Transaction Logging
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getTransactionLog().infoStream() << "Destroyed session (ID: " << key << ")";
    stc.releaseTransactionLog();
}

void MemorySessionCache::dormant(const char* key)
{
#ifdef _DEBUG
    saml::NDC ndc("dormant");
#endif

    m_log->debug("purging old cache entry with key (%s)", key);

    // lock the cache for writing, which means we know nobody is sitting in find()
    m_lock->wrlock();

    // grab the entry from the database.
    map<string,MemorySessionCacheEntry*>::const_iterator i=m_hashtable.find(key);
    if (i==m_hashtable.end()) {
        m_lock->unlock();
        return;
    }

    // ok, remove the entry and lock it
    MemorySessionCacheEntry* entry=i->second;
    m_hashtable.erase(key);
    entry->lock();
    
    // unlock the cache
    m_lock->unlock();

    // we can release the cache entry lock because we know we're not in the cache anymore
    entry->unlock();

    auto_ptr<ISessionCacheEntry> entrywrap(entry);
    if (m_sink && !m_writeThrough) {
        // Update sink with last access data. Wrapper will make sure entry gets deleted.
        if (FAILED(m_sink->onUpdate(key,NULL,entry->lastAccess())))
            m_log->error("cache store failed to update last access timestamp");
    }
}

void MemorySessionCache::cleanup()
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

    m_log->info("cleanup thread started...Run every %d secs; timeout after %d secs", rerun_timer, timeout_life);

    while (!shutdown) {
        shutdown_wait->timedwait(mutex,rerun_timer);
        if (shutdown)
            break;

        // Ok, let's run through the cleanup process and clean out
        // really old sessions.  This is a two-pass process.  The
        // first pass is done holding a read-lock while we iterate over
        // the cache.  The second pass doesn't need a lock because
        // the 'deletes' will lock the cache.
    
        // Pass 1: iterate over the map and find all entries that have not been
        // used in X hours
        vector<string> stale_keys;
        time_t stale = time(NULL) - timeout_life;
    
        m_lock->rdlock();
        for (map<string,MemorySessionCacheEntry*>::const_iterator i=m_hashtable.begin(); i!=m_hashtable.end(); i++)
        {
            // If the last access was BEFORE the stale timeout...
            i->second->lock();
            time_t last=i->second->lastAccess();
            i->second->unlock();
            if (last < stale)
                stale_keys.push_back(i->first);
        }
        m_lock->unlock();
    
        if (!stale_keys.empty()) {
            m_log->info("purging %d old sessions", stale_keys.size());
    
            // Pass 2: walk through the list of stale entries and remove them from the cache
            for (vector<string>::const_iterator j = stale_keys.begin(); j != stale_keys.end(); j++)
                dormant(j->c_str());
        }
    }

    m_log->info("cleanup thread finished.");

    mutex->unlock();
    delete mutex;
    Thread::exit(NULL);
}

void* MemorySessionCache::cleanup_fcn(void* cache_p)
{
    MemorySessionCache* cache = reinterpret_cast<MemorySessionCache*>(cache_p);

    // First, let's block all signals 
    Thread::mask_all_signals();

    // Now run the cleanup process.
    cache->cleanup();
    return NULL;
}

IPlugIn* MemoryCacheFactory(const DOMElement* e)
{
    // If this is a long-lived process, we return the "real" cache.
    if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::OutOfProcess))
        return new MemorySessionCache(e);
    // Otherwise, we return a stubbed front-end that remotes calls to the real cache.
    return new StubCache(e);
}
