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

#include <unistd.h>

#include "shib-target.h"

#include <xercesc/util/Base64.hpp>
#include <log4cpp/Category.hh>

#include <strstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class ResourceEntry
{
public:
  ResourceEntry(SAMLResponse* response);
  ~ResourceEntry();

  bool isAssertionValid();
  Iterator<SAMLAttribute*> getAttributes();
  const char* getSerializedAssertion();

  static vector<SAMLAttribute*> g_emptyVector;

private:
  SAMLResponse* m_response;
  SAMLAssertion* m_assertion;
  char* m_serialized;

  log4cpp::Category* log;
};

class InternalCCache;
class InternalCCacheEntry : public CCacheEntry
{
public:
  InternalCCacheEntry(SAMLAuthenticationStatement *s, const char *client_addr);
  virtual ~InternalCCacheEntry();

  virtual Iterator<SAMLAttribute*> getAttributes(const char* resource_url);
  virtual const char* getSerializedAssertion(const char* resource_url);
  virtual bool isSessionValid(time_t lifetime, time_t timeout);
  virtual const char* getClientAddress() { return m_clientAddress.c_str(); }

  virtual void setCache(CCache *cache);

private:
  ResourceEntry* populate(const char* resource_url);
  ResourceEntry* find(const char* resource_url);
  void insert(const char* resource_url, ResourceEntry* entry);
  void remove(const char* resource_url);

  string m_originSite;
  string m_handle;
  string m_clientAddress;
  time_t m_sessionCreated;
  time_t m_lastAccess;
  bool m_hasbinding;

  const SAMLSubject* m_subject;
  SAMLAuthenticationStatement* p_auth;
  CCache *m_cache;

  map<string,ResourceEntry*> m_resources;

  static saml::QName g_authorityKind;
  static saml::QName g_respondWith;

  log4cpp::Category* log;
};

class InternalCCache : public CCache
{
public:
  InternalCCache();
  virtual ~InternalCCache();

  virtual SAMLBinding* getBinding(const XMLCh* bindingProt);
  virtual CCacheEntry* find(const char* key);
  virtual void insert(const char* key, CCacheEntry* entry);
  virtual void remove(const char* key);

private:
  SAMLBinding* m_SAMLBinding;
  map<string,CCacheEntry*> m_hashtable;

  log4cpp::Category* log;
};

// Global Constructors & Destructors
CCache::~CCache() {}
CCacheEntry::~CCacheEntry() {}

CCache* CCache::getInstance()
{
  return (CCache*) new InternalCCache();
}

CCacheEntry* CCacheEntry::getInstance(saml::SAMLAuthenticationStatement *s,
				      const char *client_addr)
{
  return (CCacheEntry*) new InternalCCacheEntry(s, client_addr);
}

void CCache::setCache(CCacheEntry* entry)
{
  entry->setCache(this);
}

// static members
saml::QName InternalCCacheEntry::g_authorityKind(saml::XML::SAMLP_NS,L(AttributeQuery));
saml::QName InternalCCacheEntry::g_respondWith(saml::XML::SAML_NS,L(AttributeStatement));
vector<SAMLAttribute*> ResourceEntry::g_emptyVector;


/******************************************************************************/
/* InternalCCache:  A Credential Cache                                        */
/******************************************************************************/

InternalCCache::InternalCCache()
{
  m_SAMLBinding=SAMLBindingFactory::getInstance();
  string ctx="shibtarget.InternalCCache";
  log = &(log4cpp::Category::getInstance(ctx));
}

InternalCCache::~InternalCCache()
{
  delete m_SAMLBinding;
  for (map<string,CCacheEntry*>::iterator i=m_hashtable.begin(); i!=m_hashtable.end(); i++)
    delete i->second;
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
  map<string,CCacheEntry*>::const_iterator i=m_hashtable.find(key);
  if (i==m_hashtable.end()) {
    log->debug("No Match found");
    return NULL;
  }
  log->debug("Match Found.");
  return i->second;
}

void InternalCCache::insert(const char* key, CCacheEntry* entry)
{
  log->debug("caching new entry for \"%s\"", key);
  m_hashtable[key]=entry;
  setCache(entry);
}

void InternalCCache::remove(const char* key)
{
  log->debug("removing cache entry \"key\"", key);
  m_hashtable.erase(key);
}

/******************************************************************************/
/* InternalCCacheEntry:  A Credential Cache Entry                             */
/******************************************************************************/

InternalCCacheEntry::InternalCCacheEntry(SAMLAuthenticationStatement *s, const char *client_addr)
  : m_hasbinding(false)
{
  string ctx = "shibtarget::InternalCCacheEntry";
  log = &(log4cpp::Category::getInstance(ctx));

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

void InternalCCacheEntry::setCache(CCache *cache)
{
  m_cache = cache;
}

Iterator<SAMLAttribute*> InternalCCacheEntry::getAttributes(const char* resource_url)
{
  saml::NDC ndc("getAttributes");
  ResourceEntry* entry = populate(resource_url);
  if (entry)
    return entry->getAttributes();
  return Iterator<SAMLAttribute*>(ResourceEntry::g_emptyVector);
}

const char* InternalCCacheEntry::getSerializedAssertion(const char* resource_url)
{
  saml::NDC ndc("getSerializedAssertion");
  ResourceEntry* entry = populate(resource_url);
  if (entry)
    return entry->getSerializedAssertion();
  return NULL;
}

ResourceEntry* InternalCCacheEntry::populate(const char* resource_url)
{
  saml::NDC ndc("populate");
  log->debug("populating entry for %s", resource_url);

  // Can we use what we have?
  ResourceEntry *entry = find(resource_url);
  if (entry) {
    log->debug("found resource");
    if (entry->isAssertionValid())
      return entry;

    // entry is invalid (expired) -- go fetch a new one.
    log->debug("removing resource cache; assertion is invalid");
    remove (resource_url);
    delete entry;
  }

  // Nope entry.. Create a new resource entry

  if (!m_hasbinding) {
    log->error("No binding!");
    return NULL;
  }

  log->info("trying to request attributes for %s@%s -> %s",
	    m_handle.c_str(), m_originSite.c_str(), resource_url);

  auto_ptr<XMLCh> resource(XMLString::transcode(resource_url));
  Iterator<saml::QName> respond_withs = ArrayIterator<saml::QName>(&g_respondWith);

  // Clone the subject...
  // 1) I know the static_cast is safe from clone()
  // 2) the AttributeQuery will destroy this new subject.
  SAMLSubject* subject=static_cast<SAMLSubject*>(m_subject->clone());

  // Build a SAML Request....
  SAMLAttributeQuery* q=new SAMLAttributeQuery(subject,resource.get());
  SAMLRequest* req=new SAMLRequest(q,respond_withs);

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
  insert (resource_url, entry);

  log->info("fetched and stored SAML response");
  return entry;
}

ResourceEntry* InternalCCacheEntry::find(const char* resource_url)
{
  log->debug("find: %s", resource_url);
  map<string,ResourceEntry*>::const_iterator i=m_resources.find(resource_url);
  if (i==m_resources.end()) {
    log->debug("no match found");
    return NULL;
  }
  log->debug("match found");
  return i->second;
}

void InternalCCacheEntry::insert(const char* resource_url, ResourceEntry* entry)
{
  log->debug("inserting %s", resource_url);
  m_resources[resource_url]=entry;
}

void InternalCCacheEntry::remove(const char* resource_url)
{
  log->debug("removing %s", resource_url);
  m_resources.erase(resource_url);
}

/******************************************************************************/
/* ResourceEntry:  A Credential Cache Entry for a particular Resource URL     */
/******************************************************************************/

ResourceEntry::ResourceEntry(SAMLResponse* response)
  : m_assertion(NULL), m_serialized(NULL)
{
  string ctx = "shibtarget::ResourceEntry";
  log = &(log4cpp::Category::getInstance(ctx));

  log->info("caching resource entry");

  m_response = response;

  // Store off the assertion for quick access.
  // Memory mgmt is based on the response pointer.
  Iterator<SAMLAssertion*> i=m_response->getAssertions();
  if (i.hasNext())
    m_assertion=i.next();
}

ResourceEntry::~ResourceEntry()
{
  delete m_response;
  delete[] m_serialized;
}

Iterator<SAMLAttribute*> ResourceEntry::getAttributes()
{
  saml::NDC ndc("getAttributes");
  if (m_assertion)
    {
      Iterator<SAMLStatement*> i=m_assertion->getStatements();
      if (i.hasNext())
	{
	  SAMLAttributeStatement* s=static_cast<SAMLAttributeStatement*>(i.next());
	  if (s)
	    return s->getAttributes();
	}
    }
  return Iterator<SAMLAttribute*>(g_emptyVector);
}

const char* ResourceEntry::getSerializedAssertion()
{
  saml::NDC ndc("getSerializedAssertion");
  if (m_serialized)
    return m_serialized;
  if (!m_assertion)
    return NULL;
  ostrstream os;
  os << *m_assertion;
  unsigned int outlen;
  XMLByte* serialized=Base64::encode(reinterpret_cast<XMLByte*>(os.str()),os.pcount(),&outlen);
  return m_serialized=(char*)serialized;
}

bool ResourceEntry::isAssertionValid()
{
  saml::NDC ndc("isAssertionValid");

  log->info("checking validity");
  if (m_assertion && m_assertion->getNotOnOrAfter())
  {
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
    int result=XMLDateTime::compareOrder(&curDateTime,
					 m_assertion->getNotOnOrAfter());
    if (result == XMLDateTime::LESS_THAN) {
      log->debug("yes, still valid");
      return true;
    }
  }

  log->debug("not valid");
  return false;
}
