/*
 * ccache-utils.h -- utility classes used by the credential cache.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHIB_CCACHE_UTILS_H
#define SHIB_CCACHE_UTILS_H

namespace shibtarget {

  class CCacheEntry
  {
  public:
    virtual saml::Iterator<saml::SAMLAssertion*> getAssertions(Resource& resource) = 0;
    virtual void preFetch(Resource& resource, int prefetch_window) = 0;

    virtual bool isSessionValid(time_t lifetime, time_t timeout) = 0;
    virtual const char* getClientAddress() = 0;
    virtual const char* getSerializedStatement() = 0;
    virtual const saml::SAMLAuthenticationStatement* getStatement() = 0;
    virtual void release() = 0;
  };
    
  class CCache
  {
  public:
    virtual ~CCache() = 0;

    virtual saml::SAMLBinding* getBinding(const XMLCh* bindingProt) = 0;

    // insert() the Auth Statement into the CCache.
    //
    // Make sure you do not hold any open CCacheEntry objects before
    // you call this method.
    //
    virtual void insert(const char* key, saml::SAMLAuthenticationStatement *s,
			const char *client_addr) = 0;

    // find() a CCacheEntry in the CCache for the given key.
    //
    // This returns a LOCKED cache entry.  You should release() it
    // when you are done using it.
    //
    // Note that you MUST NOT call any other CCache methods while you
    // are holding this CCacheEntry!
    //
    virtual CCacheEntry* find(const char* key) = 0;

    // remove() a key from the CCache
    //
    // NOTE: If you previously executed a find(), make sure you
    // "release()" the CCacheEntry before you try to remove it!
    //
    virtual void remove(const char* key) = 0;
    
    // Call this first method when you want to access the cache from a
    // new thread and the second method just before the thread is
    // going to exit.  This is necessary for some sub-classes.
    virtual void thread_init() { }
    virtual void thread_end() { }

    // create a CCache instance of the provided type.  A NULL type
    // implies that it should create the default cache type.
    //
    static CCache* getInstance(const char* type);

    // register a CCache type with the system.
    typedef CCache*(*CCacheFactory)(void);
    static void registerFactory(const char* name, CCacheFactory factory);
  };    

  /* A low-level memory cache of a SAMLResponse object */
  class ResourceEntryPriv;
  class ResourceEntry
  {
  public:
    ResourceEntry(const Resource&, const saml::SAMLSubject&, CCache *,
		  const saml::Iterator<saml::SAMLAuthorityBinding*>);
    ~ResourceEntry();

    // Is this ResourceEntry going to be valid for the next <int> seconds?
    bool isValid(int);
    saml::Iterator<saml::SAMLAssertion*> getAssertions();
  private:
    ResourceEntryPriv *m_priv;
  };

  //*******************************************************************
  // "Global storage"

  extern CCache* g_shibTargetCCache;
};

#endif /* SHIB_CCACHE_UTILS_H */
