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
 * ccache-utils.h -- utility classes used by the credential cache.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHIB_CCACHE_UTILS_H
#define SHIB_CCACHE_UTILS_H

#ifdef WIN32
# ifndef SHIBTARGET_EXPORTS
#  define SHIBTARGET_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIBTARGET_EXPORTS
#endif

namespace shibtarget {

  class SHIBTARGET_EXPORTS CCacheEntry
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
    
  class SHIBTARGET_EXPORTS CCache
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

  SHIBTARGET_EXPORTS extern CCache* g_shibTargetCCache;
};

#endif /* SHIB_CCACHE_UTILS_H */
