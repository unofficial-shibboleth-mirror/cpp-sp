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
 * shib-mysql-ccache.cpp: Shibboleth Credential Cache using MySQL.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

/* This file is loosely based off the Shibboleth Credential Cache.
 * This plug-in is designed as a two-layer cache.  Layer 1, the
 * long-term cache, stores data in a MySQL embedded database.
 *
 * Short-term data is cached in memory as SAML objects in the layer 2
 * cache.
 */

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define SHIBMYSQL_EXPORTS __declspec(dllexport)
#else
# define SHIBMYSQL_EXPORTS
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <shib-target/shib-target.h>
#include <shib/shib-threads.h>
#include <log4cpp/Category.hh>

#include <sstream>
#include <stdexcept>

#include <mysql.h>

// wanted to use MySQL codes for this, but can't seem to get back a 145
#define isCorrupt(s) strstr(s,"(errno: 145)")

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

#define PLUGIN_VER_MAJOR 2
#define PLUGIN_VER_MINOR 0

#define STATE_TABLE \
  "CREATE TABLE state (cookie VARCHAR(64) PRIMARY KEY, " \
  "application_id VARCHAR(255)," \
  "ctime TIMESTAMP," \
  "atime TIMESTAMP," \
  "addr VARCHAR(128)," \
  "profile INT," \
  "provider VARCHAR(256)," \
  "response_id VARCHAR(128)," \
  "response TEXT," \
  "statement TEXT)"

#define REPLAY_TABLE \
  "CREATE TABLE replay (id VARCHAR(255) PRIMARY KEY, " \
  "expires TIMESTAMP, " \
  "INDEX (expires))"

static const XMLCh Argument[] =
{ chLatin_A, chLatin_r, chLatin_g, chLatin_u, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chNull };
static const XMLCh cleanupInterval[] =
{ chLatin_c, chLatin_l, chLatin_e, chLatin_a, chLatin_n, chLatin_u, chLatin_p,
  chLatin_I, chLatin_n, chLatin_t, chLatin_e, chLatin_r, chLatin_v, chLatin_a, chLatin_l, chNull
};
static const XMLCh cacheTimeout[] =
{ chLatin_c, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull };
static const XMLCh mysqlTimeout[] =
{ chLatin_m, chLatin_y, chLatin_s, chLatin_q, chLatin_l, chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull };
static const XMLCh storeAttributes[] =
{ chLatin_s, chLatin_t, chLatin_o, chLatin_r, chLatin_e, chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chLatin_s, chNull };

class MySQLBase
{
public:
  MySQLBase(const DOMElement* e);
  virtual ~MySQLBase();

  void thread_init();
  void thread_end() {}

  MYSQL* getMYSQL() const;
  bool repairTable(MYSQL*&, const char* table);

  log4cpp::Category* log;

protected:
  ThreadKey* m_mysql;
  const DOMElement* m_root; // can only use this during initialization

  bool initialized;

  void createDatabase(MYSQL*, int major, int minor);
  void upgradeDatabase(MYSQL*);
  void getVersion(MYSQL*, int* major_p, int* minor_p);
};

// Forward declarations
static void mysqlInit(const DOMElement* e, Category& log);

extern "C" void shib_mysql_destroy_handle(void* data)
{
  MYSQL* mysql = (MYSQL*) data;
  if (mysql) mysql_close(mysql);
}

MySQLBase::MySQLBase(const DOMElement* e) : m_root(e)
{
#ifdef _DEBUG
  saml::NDC ndc("MySQLBase");
#endif
  log = &(Category::getInstance("shibmysql.MySQLBase"));

  m_mysql = ThreadKey::create(&shib_mysql_destroy_handle);

  initialized = false;
  mysqlInit(e,*log);
  thread_init();
  initialized = true;
}

MySQLBase::~MySQLBase()
{
  thread_end();

  delete m_mysql;
}

MYSQL* MySQLBase::getMYSQL() const
{
  return (MYSQL*)m_mysql->getData();
}

void MySQLBase::thread_init()
{
#ifdef _DEBUG
  saml::NDC ndc("thread_init");
#endif

  // Connect to the database
  MYSQL* mysql = mysql_init(NULL);
  if (!mysql) {
    log->error("mysql_init failed");
    mysql_close(mysql);
    throw SAMLException("MySQLBase::thread_init(): mysql_init() failed");
  }

  if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shar", 0, NULL, 0)) {
    if (initialized) {
      log->crit("mysql_real_connect failed: %s", mysql_error(mysql));
      mysql_close(mysql);
      throw SAMLException("MySQLBase::thread_init(): mysql_real_connect() failed");
    } else {
      log->info("mysql_real_connect failed: %s.  Trying to create", mysql_error(mysql));

      // This will throw an exception if it fails.
      createDatabase(mysql, PLUGIN_VER_MAJOR, PLUGIN_VER_MINOR);
    }
  }

  int major = -1, minor = -1;
  getVersion (mysql, &major, &minor);

  // Make sure we've got the right version
  if (major != PLUGIN_VER_MAJOR || minor != PLUGIN_VER_MINOR) {
   
    // If we're capable, try upgrading on the fly...
    if (major == 0  || major == 1) {
       upgradeDatabase(mysql);
    }
    else {
        mysql_close(mysql);
        log->crit("Unknown database version: %d.%d", major, minor);
        throw SAMLException("MySQLBase::thread_init(): Unknown database version");
    }
  }

  // We're all set.. Save off the handle for this thread.
  m_mysql->setData(mysql);
}

bool MySQLBase::repairTable(MYSQL*& mysql, const char* table)
{
  string q = string("REPAIR TABLE ") + table;
  if (mysql_query(mysql, q.c_str())) {
    log->error("Error repairing table %s: %s", table, mysql_error(mysql));
    return false;
  }

  // seems we have to recycle the connection to get the thread to keep working
  // other threads seem to be ok, but we should monitor that
  mysql_close(mysql);
  m_mysql->setData(NULL);
  thread_init();
  mysql=getMYSQL();
  return true;
}

void MySQLBase::createDatabase(MYSQL* mysql, int major, int minor)
{
  log->info("Creating database.");

  MYSQL* ms = NULL;
  try {
    ms = mysql_init(NULL);
    if (!ms) {
      log->crit("mysql_init failed");
      throw SAMLException("ShibMySQLCCache::createDatabase(): mysql_init failed");
    }

    if (!mysql_real_connect(ms, NULL, NULL, NULL, NULL, 0, NULL, 0)) {
      log->crit("cannot open DB file to create DB: %s", mysql_error(ms));
      throw SAMLException("ShibMySQLCCache::createDatabase(): mysql_real_connect failed");
    }

    if (mysql_query(ms, "CREATE DATABASE shar")) {
      log->crit("cannot create shar database: %s", mysql_error(ms));
      throw SAMLException("ShibMySQLCCache::createDatabase(): create db cmd failed");
    }

    if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shar", 0, NULL, 0)) {
      log->crit("cannot open SHAR database");
      throw SAMLException("ShibMySQLCCache::createDatabase(): mysql_real_connect to plugin db failed");
    }

    mysql_close(ms);
    
  }
  catch (SAMLException&) {
    if (ms)
      mysql_close(ms);
    mysql_close(mysql);
    throw;
  }

  // Now create the tables if they don't exist
  log->info("Creating database tables");

  if (mysql_query(mysql, "CREATE TABLE version (major INT, minor INT)")) {
    log->error ("Error creating version: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  if (mysql_query(mysql,STATE_TABLE)) {
    log->error ("Error creating state table: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  if (mysql_query(mysql,REPLAY_TABLE)) {
    log->error ("Error creating replay table: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  ostringstream q;
  q << "INSERT INTO version VALUES(" << major << "," << minor << ")";
  if (mysql_query(mysql, q.str().c_str())) {
    log->error ("Error setting version: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): version insert failed");
  }
}

void MySQLBase::upgradeDatabase(MYSQL* mysql)
{
    if (mysql_query(mysql, "DROP TABLE state")) {
        log->error("Error dropping old session state table: %s", mysql_error(mysql));
    }

    if (mysql_query(mysql,STATE_TABLE)) {
        log->error ("Error creating state table: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error creating state table");
    }

    if (mysql_query(mysql,REPLAY_TABLE)) {
        log->error ("Error creating replay table: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error creating replay table");
    }

    ostringstream q;
    q << "UPDATE version SET major = " << PLUGIN_VER_MAJOR;
    if (mysql_query(mysql, q.str().c_str())) {
        log->error ("Error updating version: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error updating version");
    }
}

void MySQLBase::getVersion(MYSQL* mysql, int* major_p, int* minor_p)
{
  // grab the version number from the database
  if (mysql_query(mysql, "SELECT * FROM version"))
    log->error ("Error reading version: %s", mysql_error(mysql));

  MYSQL_RES* rows = mysql_store_result(mysql);
  if (rows) {
    if (mysql_num_rows(rows) == 1 && mysql_num_fields(rows) == 2)  {
      MYSQL_ROW row = mysql_fetch_row(rows);

      int major = row[0] ? atoi(row[0]) : -1;
      int minor = row[1] ? atoi(row[1]) : -1;
      log->debug("opening database version %d.%d", major, minor);
      
      mysql_free_result (rows);

      *major_p = major;
      *minor_p = minor;
      return;

    } else {
      // Wrong number of rows or wrong number of fields...

      log->crit("Houston, we've got a problem with the database...");
      mysql_free_result (rows);
      throw SAMLException("ShibMySQLCCache::getVersion(): version verification failed");
    }
  }
  log->crit("MySQL Read Failed in version verificatoin");
  throw SAMLException("ShibMySQLCCache::getVersion(): error reading version");
}

static void mysqlInit(const DOMElement* e, Category& log)
{
  static bool done = false;
  if (done) {
    log.info("MySQL embedded server already initialized");
    return;
  }
  log.info("initializing MySQL embedded server");

  // Setup the argument array
  vector<string> arg_array;
  arg_array.push_back("shibboleth");

  // grab any MySQL parameters from the config file
  e=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,Argument);
  while (e) {
      auto_ptr_char arg(e->getFirstChild()->getNodeValue());
      if (arg.get())
          arg_array.push_back(arg.get());
      e=saml::XML::getNextSiblingElement(e,shibtarget::XML::SHIBTARGET_NS,Argument);
  }

  // Compute the argument array
  int arg_count = arg_array.size();
  const char** args=new const char*[arg_count];
  for (int i = 0; i < arg_count; i++)
    args[i] = arg_array[i].c_str();

  // Initialize MySQL with the arguments
  mysql_server_init(arg_count, (char **)args, NULL);

  delete[] args;
  done = true;
}  

class ShibMySQLCCache;
class ShibMySQLCCacheEntry : public ISessionCacheEntry
{
public:
  ShibMySQLCCacheEntry(const char* key, ISessionCacheEntry* entry, ShibMySQLCCache* cache)
    : m_cacheEntry(entry), m_key(key), m_cache(cache), m_responseId(NULL) {}
  ~ShibMySQLCCacheEntry() {if (m_responseId) XMLString::release(&m_responseId);}

  virtual void lock() {}
  virtual void unlock() { m_cacheEntry->unlock(); delete this; }
  virtual bool isValid(time_t lifetime, time_t timeout) const;
  virtual const char* getClientAddress() const { return m_cacheEntry->getClientAddress(); }
  virtual ShibProfile getProfile() const { return m_cacheEntry->getProfile(); }
  virtual const char* getProviderId() const { return m_cacheEntry->getProviderId(); }
  virtual const SAMLAuthenticationStatement* getAuthnStatement() const { return m_cacheEntry->getAuthnStatement(); }
  virtual CachedResponse getResponse();

private:
  bool touch() const;

  ShibMySQLCCache* m_cache;
  ISessionCacheEntry* m_cacheEntry;
  string m_key;
  XMLCh* m_responseId;
};

class ShibMySQLCCache : public MySQLBase, virtual public ISessionCache
{
public:
  ShibMySQLCCache(const DOMElement* e);
  virtual ~ShibMySQLCCache();

  virtual void thread_init() {MySQLBase::thread_init();}
  virtual void thread_end() {MySQLBase::thread_end();}

  virtual string generateKey() const {return m_cache->generateKey();}
  virtual ISessionCacheEntry* find(const char* key, const IApplication* application);
  virtual void insert(
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    saml::SAMLAuthenticationStatement* s,
    saml::SAMLResponse* r=NULL,
    const shibboleth::IRoleDescriptor* source=NULL,
    time_t created=0,
    time_t accessed=0
    );
  virtual void remove(const char* key);

  virtual void cleanup();

  bool m_storeAttributes;

private:
  ISessionCache* m_cache;
  CondWait* shutdown_wait;
  bool shutdown;
  Thread* cleanup_thread;

  static void* cleanup_fcn(void*); // XXX Assumed an ShibMySQLCCache
};

ShibMySQLCCache::ShibMySQLCCache(const DOMElement* e) : MySQLBase(e), m_storeAttributes(false)
{
#ifdef _DEBUG
  saml::NDC ndc("ShibMySQLCCache");
#endif

  log = &(Category::getInstance("shibmysql.SessionCache"));

  shutdown_wait = CondWait::create();
  shutdown = false;

  m_cache = dynamic_cast<ISessionCache*>(
      SAMLConfig::getConfig().getPlugMgr().newPlugin(
        "edu.internet2.middleware.shibboleth.sp.provider.MemorySessionCacheProvider", e
        )
    );
    
  // Load our configuration details...
  const XMLCh* tag=m_root->getAttributeNS(NULL,storeAttributes);
  if (tag && *tag && (*tag==chLatin_t || *tag==chDigit_1))
    m_storeAttributes=true;

  // Initialize the cleanup thread
  cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

ShibMySQLCCache::~ShibMySQLCCache()
{
  shutdown = true;
  shutdown_wait->signal();
  cleanup_thread->join(NULL);

  delete m_cache;
}

ISessionCacheEntry* ShibMySQLCCache::find(const char* key, const IApplication* application)
{
#ifdef _DEBUG
  saml::NDC ndc("find");
#endif

  ISessionCacheEntry* res = m_cache->find(key, application);
  if (!res) {

    log->debug("Looking in database...");

    // nothing cached; see if this exists in the database
    string q = string("SELECT application_id,UNIX_TIMESTAMP(ctime),UNIX_TIMESTAMP(atime),addr,profile,provider,statement,response FROM state WHERE cookie='") + key + "' LIMIT 1";

    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
      const char* err=mysql_error(mysql);
      log->error("Error searching for %s: %s", key, err);
      if (isCorrupt(err) && repairTable(mysql,"state")) {
        if (mysql_query(mysql, q.c_str()))
          log->error("Error retrying search for %s: %s", key, mysql_error(mysql));
      }
    }

    MYSQL_RES* rows = mysql_store_result(mysql);

    // Nope, doesn't exist.
    if (!rows)
      return NULL;

    // Make sure we got 1 and only 1 rows.
    if (mysql_num_rows(rows) != 1) {
      log->error("Select returned wrong number of rows: %d", mysql_num_rows(rows));
      mysql_free_result(rows);
      return NULL;
    }

    log->debug("Match found.  Parsing...");
    
    /* Columns in query:
        0: application_id
        1: ctime
        2: atime
        3: address
        4: profile
        5: provider
        6: statement
        7: response
     */

    // Pull apart the row and process the results
    MYSQL_ROW row = mysql_fetch_row(rows);
    if (strcmp(application->getId(),row[0])) {
        log->crit("An application (%s) attempted to access another application's (%s) session!", application->getId(), row[0]);
        mysql_free_result(rows);
        return NULL;
    }

    Metadata m(application->getMetadataProviders());
    const IEntityDescriptor* provider=m.lookup(row[5]);
    if (!provider) {
        log->crit("no metadata found for identity provider (%s) responsible for the session.", row[5]);
        mysql_free_result(rows);
        return NULL;
    }

    SAMLAuthenticationStatement* s=NULL;
    SAMLResponse* r=NULL;
    ShibProfile profile=static_cast<ShibProfile>(atoi(row[4]));
    const IRoleDescriptor* role=NULL;
    if (profile==SAML11_POST || profile==SAML11_ARTIFACT)
        role=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
    else if (profile==SAML10_POST || profile==SAML10_ARTIFACT)
        role=provider->getIDPSSODescriptor(saml::XML::SAML10_PROTOCOL_ENUM);
    if (!role) {
        log->crit(
            "no matching IdP role for profile (%s) found for identity provider (%s) responsible for the session.", row[4], row[5]
            );
        mysql_free_result(rows);
        return NULL;
    }

    // Try to parse the SAML data
    try {
        istringstream istr(row[6]);
        s = new SAMLAuthenticationStatement(istr);
        if (row[7]) {
            istringstream istr2(row[7]);
            r = new SAMLResponse(istr2);
        }
    }
    catch (SAMLException& e) {
        log->error(string("caught SAML exception while loading objects from SQL record: ") + e.what());
        delete s;
        delete r;
        mysql_free_result(rows);
        return NULL;
    }
#ifndef _DEBUG
    catch (...) {
        log->error("caught unknown exception while loading objects from SQL record");
        delete s;
        delete r;
        mysql_free_result(rows);
        return NULL;
    }
#endif

    // Insert it into the memory cache
    m_cache->insert(
        key,
        application,
        row[3],
        profile,
        row[5],
        s,
        r,
        role,
        atoi(row[1]),
        atoi(row[2])
        );

    // Free the results, and then re-run the 'find' query
    mysql_free_result(rows);
    res = m_cache->find(key,application);
    if (!res)
      return NULL;
  }

  return new ShibMySQLCCacheEntry(key, res, this);
}

void ShibMySQLCCache::insert(
    const char* key,
    const IApplication* application,
    const char* client_addr,
    ShibProfile profile,
    const char* providerId,
    saml::SAMLAuthenticationStatement* s,
    saml::SAMLResponse* r,
    const shibboleth::IRoleDescriptor* source,
    time_t created,
    time_t accessed
    )
{
#ifdef _DEBUG
  saml::NDC ndc("insert");
#endif
  
  ostringstream q;
  q << "INSERT INTO state VALUES('" << key << "','" << application->getId() << "',";
  if (created==0)
    q << "NOW(),";
  else
    q << "FROM_UNIXTIME(" << created << "),";
  if (accessed==0)
    q << "NOW(),'";
  else
    q << "FROM_UNIXTIME(" << accessed << "),'";
  q << client_addr << "'," << profile << ",'" << providerId << "',";
  if (m_storeAttributes && r) {
    auto_ptr_char id(r->getId());
    q << "'" << id.get() << "','" << *r << "','";
  }
  else
    q << "null,null,'";
  q << *s << "')";

  log->debug("Query: %s", q.str().c_str());

  // then add it to the database
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.str().c_str())) {
    const char* err=mysql_error(mysql);
    log->error("Error inserting %s: %s", key, err);
    if (isCorrupt(err) && repairTable(mysql,"state")) {
        // Try again...
        if (mysql_query(mysql, q.str().c_str())) {
          log->error("Error inserting %s: %s", key, mysql_error(mysql));
          throw SAMLException("ShibMySQLCCache::insert(): insertion failed");
        }
    }
    else
        throw SAMLException("ShibMySQLCCache::insert(): insertion failed");
  }

  // Add it to the memory cache
  m_cache->insert(key, application, client_addr, profile, providerId, s, r, source, created, accessed);
}

void ShibMySQLCCache::remove(const char* key)
{
#ifdef _DEBUG
  saml::NDC ndc("remove");
#endif

  // Remove the cached version
  m_cache->remove(key);

  // Remove from the database
  string q = string("DELETE FROM state WHERE cookie='") + key + "'";
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.c_str())) {
    const char* err=mysql_error(mysql);
    log->error("Error deleting entry %s: %s", key, err);
    if (isCorrupt(err) && repairTable(mysql,"state")) {
        // Try again...
        if (mysql_query(mysql, q.c_str()))
          log->error("Error deleting entry %s: %s", key, mysql_error(mysql));
    }
  }
}

void ShibMySQLCCache::cleanup()
{
#ifdef _DEBUG
  saml::NDC ndc("cleanup");
#endif

  Mutex* mutex = Mutex::create();
  MySQLBase::thread_init();

  int rerun_timer = 0;
  int timeout_life = 0;

  // Load our configuration details...
  const XMLCh* tag=m_root->getAttributeNS(NULL,cleanupInterval);
  if (tag && *tag)
    rerun_timer = XMLString::parseInt(tag);

  // search for 'mysql-cache-timeout' and then the regular cache timeout
  tag=m_root->getAttributeNS(NULL,mysqlTimeout);
  if (tag && *tag)
    timeout_life = XMLString::parseInt(tag);
  else {
      tag=m_root->getAttributeNS(NULL,cacheTimeout);
      if (tag && *tag)
        timeout_life = XMLString::parseInt(tag);
  }
  
  if (rerun_timer <= 0)
    rerun_timer = 300;		// rerun every 5 minutes

  if (timeout_life <= 0)
    timeout_life = 28800;	// timeout after 8 hours

  mutex->lock();

  MYSQL* mysql = getMYSQL();

  while (shutdown == false) {
    shutdown_wait->timedwait(mutex, rerun_timer);

    if (shutdown == true)
      break;

    // Find all the entries in the database that haven't been used
    // recently In particular, find all entries that have not been
    // accessed in 'timeout_life' seconds.
    ostringstream q;
    q << "SELECT cookie FROM state WHERE " <<
      "UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(atime) >= " << timeout_life;

    if (mysql_query(mysql, q.str().c_str())) {
      const char* err=mysql_error(mysql);
      log->error("Error searching for old items: %s", err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
          if (mysql_query(mysql, q.str().c_str()))
            log->error("Error re-searching for old items: %s", mysql_error(mysql));
        }
    }

    MYSQL_RES* rows = mysql_store_result(mysql);
    if (!rows)
      continue;

    if (mysql_num_fields(rows) != 1) {
      log->error("Wrong number of columns, 1 != %d", mysql_num_fields(rows));
      mysql_free_result(rows);
      continue;
    }

    // For each row, remove the entry from the database.
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(rows)) != NULL)
      remove(row[0]);

    mysql_free_result(rows);
  }

  log->info("cleanup thread exiting...");

  mutex->unlock();
  delete mutex;
  MySQLBase::thread_end();
  Thread::exit(NULL);
}

void* ShibMySQLCCache::cleanup_fcn(void* cache_p)
{
  ShibMySQLCCache* cache = (ShibMySQLCCache*)cache_p;

  // First, let's block all signals
  Thread::mask_all_signals();

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

/*************************************************************************
 * The CCacheEntry here is mostly a wrapper around the "memory"
 * cacheentry provided by shibboleth.  The only difference is that we
 * intercept isSessionValid() so that we can "touch()" the
 * database if the session is still valid and getResponse() so we can
 * store the data if we need to.
 */

bool ShibMySQLCCacheEntry::isValid(time_t lifetime, time_t timeout) const
{
  bool res = m_cacheEntry->isValid(lifetime, timeout);
  if (res == true)
    res = touch();
  return res;
}

bool ShibMySQLCCacheEntry::touch() const
{
  string q=string("UPDATE state SET atime=NOW() WHERE cookie='") + m_key + "'";

  MYSQL* mysql = m_cache->getMYSQL();
  if (mysql_query(mysql, q.c_str())) {
    m_cache->log->info("Error updating timestamp on %s: %s", m_key.c_str(), mysql_error(mysql));
    return false;
  }
  return true;
}

ISessionCacheEntry::CachedResponse ShibMySQLCCacheEntry::getResponse()
{
    // Let the memory cache do the work first.
    // If we're hands off, just pass it back.
    if (!m_cache->m_storeAttributes)
        return m_cacheEntry->getResponse();
    
    CachedResponse r=m_cacheEntry->getResponse();
    if (r.empty()) return r;
    
    // Load the key from state if needed.
    if (!m_responseId) {
        string qselect=string("SELECT response_id from state WHERE cookie='") + m_key + "' LIMIT 1";
        MYSQL* mysql = m_cache->getMYSQL();
        if (mysql_query(mysql, qselect.c_str())) {
            const char* err=mysql_error(mysql);
            m_cache->log->error("error accessing response ID for %s: %s", m_key.c_str(), err);
            if (isCorrupt(err) && m_cache->repairTable(mysql,"state")) {
                // Try again...
                if (mysql_query(mysql, qselect.c_str())) {
                    m_cache->log->error("error accessing response ID for %s: %s", m_key.c_str(), mysql_error(mysql));
                    return r;
                }
            }
        }
        MYSQL_RES* rows = mysql_store_result(mysql);
    
        // Make sure we got 1 and only 1 row.
        if (!rows || mysql_num_rows(rows) != 1) {
            m_cache->log->error("select returned wrong number of rows");
            if (rows) mysql_free_result(rows);
            return r;
        }
        
        MYSQL_ROW row=mysql_fetch_row(rows);
        if (row)
            m_responseId=XMLString::transcode(row[0]);
        mysql_free_result(rows);
    }
    
    // Compare it with what we have now.
    if (m_responseId && !XMLString::compareString(m_responseId,r.unfiltered->getId()))
        return r;
    
    // No match, so we need to update our copy.
    if (m_responseId) XMLString::release(&m_responseId);
    m_responseId = XMLString::replicate(r.unfiltered->getId());
    auto_ptr_char id(m_responseId);

    ostringstream q;
    q << "UPDATE state SET response_id='" << id.get() << "',response='" << *r.unfiltered << "' WHERE cookie='" << m_key << "'";
    m_cache->log->debug("Query: %s", q.str().c_str());

    MYSQL* mysql = m_cache->getMYSQL();
    if (mysql_query(mysql, q.str().c_str())) {
        const char* err=mysql_error(mysql);
        m_cache->log->error("Error updating response for %s: %s", m_key.c_str(), err);
        if (isCorrupt(err) && m_cache->repairTable(mysql,"state")) {
            // Try again...
            if (mysql_query(mysql, q.str().c_str()))
              m_cache->log->error("Error updating response for %s: %s", m_key.c_str(), mysql_error(mysql));
        }
    }
    
    return r;
}

class MySQLReplayCache : public MySQLBase, virtual public IReplayCache
{
public:
  MySQLReplayCache(const DOMElement* e);
  virtual ~MySQLReplayCache() {}

  void thread_init() {MySQLBase::thread_init();}
  void thread_end() {MySQLBase::thread_end();}

  bool check(const XMLCh* str, time_t expires) {auto_ptr_XMLCh temp(str); return check(temp.get(),expires);}
  bool check(const char* str, time_t expires);
};

MySQLReplayCache::MySQLReplayCache(const DOMElement* e) : MySQLBase(e)
{
#ifdef _DEBUG
  saml::NDC ndc("MySQLReplayCache");
#endif

  log = &(Category::getInstance("shibmysql.ReplayCache"));
}

bool MySQLReplayCache::check(const char* str, time_t expires)
{
#ifdef _DEBUG
    saml::NDC ndc("check");
#endif
  
    // Remove expired entries
    string q = string("DELETE FROM replay WHERE expires < NOW()");
    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("Error deleting expired entries: %s", err);
        if (isCorrupt(err) && repairTable(mysql,"replay")) {
            // Try again...
            if (mysql_query(mysql, q.c_str()))
                log->error("Error deleting expired entries: %s", mysql_error(mysql));
        }
    }
  
    string q2 = string("SELECT id FROM replay WHERE id='") + str + "'";
    if (mysql_query(mysql, q2.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("Error searching for %s: %s", str, err);
        if (isCorrupt(err) && repairTable(mysql,"replay")) {
            if (mysql_query(mysql, q2.c_str())) {
                log->error("Error retrying search for %s: %s", str, mysql_error(mysql));
                throw SAMLException("Replay cache failed, please inform application support staff.");
            }
        }
        else
            throw SAMLException("Replay cache failed, please inform application support staff.");
    }

    // Did we find it?
    MYSQL_RES* rows = mysql_store_result(mysql);
    if (rows && mysql_num_rows(rows)>0) {
      mysql_free_result(rows);
      return false;
    }

    ostringstream q3;
    q3 << "INSERT INTO replay VALUES('" << str << "'," << "FROM_UNIXTIME(" << expires << "))";

    // then add it to the database
    if (mysql_query(mysql, q3.str().c_str())) {
        const char* err=mysql_error(mysql);
        log->error("Error inserting %s: %s", str, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            // Try again...
            if (mysql_query(mysql, q3.str().c_str())) {
                log->error("Error inserting %s: %s", str, mysql_error(mysql));
                throw SAMLException("Replay cache failed, please inform application support staff.");
            }
        }
        else
            throw SAMLException("Replay cache failed, please inform application support staff.");
    }
    
    return true;
}

/*************************************************************************
 * The registration functions here...
 */

IPlugIn* new_mysql_ccache(const DOMElement* e)
{
  return new ShibMySQLCCache(e);
}

IPlugIn* new_mysql_replay(const DOMElement* e)
{
  return new MySQLReplayCache(e);
}

#define REPLAYPLUGINTYPE "edu.internet2.middleware.shibboleth.sp.provider.MySQLReplayCacheProvider"
#define SESSIONPLUGINTYPE "edu.internet2.middleware.shibboleth.sp.provider.MySQLSessionCacheProvider"

extern "C" int SHIBMYSQL_EXPORTS saml_extension_init(void*)
{
  // register this ccache type
  SAMLConfig::getConfig().getPlugMgr().regFactory(REPLAYPLUGINTYPE, &new_mysql_replay);
  SAMLConfig::getConfig().getPlugMgr().regFactory(SESSIONPLUGINTYPE, &new_mysql_ccache);
  return 0;
}

extern "C" void SHIBMYSQL_EXPORTS saml_extension_term()
{
  // Shutdown MySQL
  mysql_server_end();
  SAMLConfig::getConfig().getPlugMgr().unregFactory(REPLAYPLUGINTYPE);
  SAMLConfig::getConfig().getPlugMgr().unregFactory(SESSIONPLUGINTYPE);
}
