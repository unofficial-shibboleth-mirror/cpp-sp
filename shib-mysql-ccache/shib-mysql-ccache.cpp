/*
 * shib-mysql-ccache.cpp: Shibboleth Credential Cache using MySQL.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

/* This file is loosely based off the Shibboleth Credential Cache.
 * This plug-in is designed as a two-layer cache.  Layer 1, the
 * long-term cache, stores data in a MySQL embedded database.  The
 * data stored in layer 1 is only the session id (cookie), the
 * "posted" SAML statement (expanded into an XML string), and usage
 * timestamps.
 *
 * Short-term data is cached in memory as SAML objects in the layer 2
 * cache.  Data like Attribute Authority assertions are stored in
 * the layer 2 cache.
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

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

#define PLUGIN_VER_MAJOR 1
#define PLUGIN_VER_MINOR 0

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

class ShibMySQLCCache;
class ShibMySQLCCacheEntry : public ISessionCacheEntry
{
public:
  ShibMySQLCCacheEntry(const char*, ISessionCacheEntry*, ShibMySQLCCache*);
  ~ShibMySQLCCacheEntry() {}

  virtual void lock() {}
  virtual void unlock() { m_cacheEntry->unlock(); delete this; }
  virtual bool isValid(time_t lifetime, time_t timeout) const;
  virtual const char* getClientAddress() const { return m_cacheEntry->getClientAddress(); }
  virtual const char* getSerializedStatement() const { return m_cacheEntry->getSerializedStatement(); }
  virtual const SAMLAuthenticationStatement* getStatement() const { return m_cacheEntry->getStatement(); }
  virtual Iterator<SAMLAssertion*> getAssertions() { return m_cacheEntry->getAssertions(); }
  virtual void preFetch(int prefetch_window) { m_cacheEntry->preFetch(prefetch_window); }

private:
  bool touch() const;

  ShibMySQLCCache* m_cache;
  ISessionCacheEntry* m_cacheEntry;
  string m_key;
};

class ShibMySQLCCache : public ISessionCache
{
public:
  ShibMySQLCCache(const DOMElement* e);
  virtual ~ShibMySQLCCache();

  virtual void thread_init();
  virtual void thread_end() {}

  virtual string generateKey() const {return m_cache->generateKey();}
  virtual ISessionCacheEntry* find(const char* key, const IApplication* application);
  virtual void insert(
        const char* key,
        const IApplication* application,
        SAMLAuthenticationStatement *s,
        const char *client_addr,
        SAMLResponse* r=NULL,
        const IRoleDescriptor* source=NULL);
  virtual void remove(const char* key);

  void	cleanup();
  MYSQL* getMYSQL() const;

  log4cpp::Category* log;

private:
  ISessionCache* m_cache;
  ThreadKey* m_mysql;
  const DOMElement* m_root; // can only use this during initialization

  static void*	cleanup_fcn(void*); // XXX Assumed an ShibMySQLCCache
  CondWait* shutdown_wait;
  bool shutdown;
  Thread* cleanup_thread;

  bool initialized;

  void createDatabase(MYSQL*, int major, int minor);
  void upgradeDatabase(MYSQL*);
  void getVersion(MYSQL*, int* major_p, int* minor_p);
  void mysqlInit(void);
};

// Forward declarations
extern "C" void shib_mysql_destroy_handle(void* data);

/*************************************************************************
 * The CCache here talks to a MySQL database.  The database stores
 * three items: the cookie (session key index), the lastAccess time, and
 * the SAMLAuthenticationStatement.  All other access is performed
 * through the memory cache provided by shibboleth.
 */

MYSQL* ShibMySQLCCache::getMYSQL() const
{
  void* data = m_mysql->getData();
  return (MYSQL*)data;
}

void ShibMySQLCCache::thread_init()
{
  saml::NDC ndc("thread_init");

  // Connect to the database
  MYSQL* mysql = mysql_init(NULL);
  if (!mysql) {
    log->error("mysql_init failed");
    mysql_close(mysql);
    throw runtime_error("mysql_init()");
  }

  if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shar", 0, NULL, 0)) {
    if (initialized) {
      log->crit("mysql_real_connect failed: %s", mysql_error(mysql));
      throw runtime_error("mysql_real_connect");

    } else {
      log->info("mysql_real_connect failed: %s.  Trying to create",
		mysql_error(mysql));

      // This will throw a runtime error if it fails.
      createDatabase(mysql, PLUGIN_VER_MAJOR, PLUGIN_VER_MINOR);
    }
  }

  int major = -1, minor = -1;
  getVersion (mysql, &major, &minor);

  // Make sure we've got the right version
  if (major != PLUGIN_VER_MAJOR || minor != PLUGIN_VER_MINOR) {
   
    // If we're capable, try upgrading on the fly...
    if (major == 0 && minor == 0) {
       upgradeDatabase(mysql);
    }
    else {
        log->crit("Invalid database version: %d.%d", major, minor);
        throw runtime_error("Invalid Database version");
    }
  }

  // We're all set.. Save off the handle for this thread.
  m_mysql->setData((void*)mysql);
}

ShibMySQLCCache::ShibMySQLCCache(const DOMElement* e)
{
  saml::NDC ndc("shibmysql::ShibMySQLCCache");

  m_mysql = ThreadKey::create(&shib_mysql_destroy_handle);
  log = &(log4cpp::Category::getInstance("shibmysql::ShibMySQLCCache"));

  m_root=e;
  initialized = false;
  mysqlInit();
  thread_init();
  initialized = true;

  m_cache = dynamic_cast<ISessionCache*>(
      SAMLConfig::getConfig().m_plugMgr.newPlugin(
        "edu.internet2.middleware.shibboleth.target.provider.MemorySessionCache", e
        )
    );

  // Initialize the cleanup thread
  shutdown_wait = CondWait::create();
  shutdown = false;
  cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

ShibMySQLCCache::~ShibMySQLCCache()
{
  shutdown = true;
  shutdown_wait->signal();
  cleanup_thread->join(NULL);

  delete m_cache;
  delete m_mysql;

  // Shutdown MySQL
  mysql_server_end();
}

ISessionCacheEntry* ShibMySQLCCache::find(const char* key, const IApplication* application)
{
  saml::NDC ndc("mysql::find");
  ISessionCacheEntry* res = m_cache->find(key,application);
  if (!res) {

    log->debug("Looking in database...");

    // nothing cached; see if this exists in the database
    string q = string("SELECT application_id,addr,statement FROM state WHERE cookie='") + key + "' LIMIT 1";

    MYSQL_RES* rows;
    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str()))
      log->error("Error searching for %s: %s", key, mysql_error(mysql));

    rows = mysql_store_result(mysql);

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

    // Pull apart the row and process the results
    MYSQL_ROW row = mysql_fetch_row(rows);
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IApplication* application=conf->getApplication(row[0]);
    if (!application) {
        mysql_free_result(rows);
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"unable to locate application for session, deleted?");
    }
    else if (strcmp(row[0],application->getId())) {
        log->crit("An application (%s) attempted to access another application's (%s) session!", application->getId(), row[0]);
        mysql_free_result(rows);
        return NULL;
    }

    istringstream str(row[2]);
    SAMLAuthenticationStatement *s = NULL;

    // Try to parse the AuthStatement
    try {
      s = new SAMLAuthenticationStatement(str);
    } catch (...) {
      mysql_free_result(rows);
      throw;
    }

    // Insert it into the memory cache
    if (s)
      m_cache->insert(key, application, s, row[1]);

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
    saml::SAMLAuthenticationStatement *s,
    const char *client_addr,
    saml::SAMLResponse* r,
    const IRoleDescriptor* source)
{
  saml::NDC ndc("mysql::insert");
  ostringstream os;
  os << *s;

  string q = string("INSERT INTO state VALUES('") + key + "','" + application->getId() + "',NOW(),'" + client_addr + "','" + os.str() + "')";

  log->debug("Query: %s", q.c_str());

  // Add it to the memory cache
  m_cache->insert(key, application, s, client_addr, r, source);

  // then add it to the database
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.c_str()))
    log->error("Error inserting %s: %s", key, mysql_error(mysql));
}

void ShibMySQLCCache::remove(const char* key)
{
  saml::NDC ndc("mysql::remove");

  // Remove the cached version
  m_cache->remove(key);

  // Remove from the database
  string q = string("DELETE FROM state WHERE cookie='") + key + "'";
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.c_str()))
    log->info("Error deleting entry %s: %s", key, mysql_error(mysql));
}

void ShibMySQLCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("mysql::cleanup");

  thread_init();

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

    MYSQL_RES *rows;
    if (mysql_query(mysql, q.str().c_str()))
      log->error("Error searching for old items: %s", mysql_error(mysql));

    rows = mysql_store_result(mysql);
    if (!rows)
      continue;

    if (mysql_num_fields(rows) != 1) {
      log->error("Wrong number of rows, 1 != %d", mysql_num_fields(rows));
      mysql_free_result(rows);
      continue;
    }

    // For each row, remove the entry from the database.
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(rows)) != NULL)
      remove(row[0]);

    mysql_free_result(rows);
  }

  log->debug("cleanup thread exiting...");

  mutex->unlock();
  delete mutex;
  thread_end();
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

void ShibMySQLCCache::createDatabase(MYSQL* mysql, int major, int minor)
{
  log->info("Creating database.");

  MYSQL* ms = NULL;
  try {
    ms = mysql_init(NULL);
    if (!ms) {
      log->crit("mysql_init failed");
      throw ShibTargetException();
    }

    if (!mysql_real_connect(ms, NULL, NULL, NULL, NULL, 0, NULL, 0)) {
      log->crit("cannot open DB file to create DB: %s", mysql_error(ms));
      throw ShibTargetException();
    }

    if (mysql_query(ms, "CREATE DATABASE shar")) {
      log->crit("cannot create shar database: %s", mysql_error(ms));
      throw ShibTargetException();
    }

    if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shar", 0, NULL, 0)) {
      log->crit("cannot open SHAR database");
      throw ShibTargetException();
    }

    mysql_close(ms);
    
  } catch (ShibTargetException&) {
    if (ms)
      mysql_close(ms);
    mysql_close(mysql);
    throw runtime_error("mysql_real_connect");
  }

  // Now create the tables if they don't exist
  log->info("Creating database tables.");

  if (mysql_query(mysql, "CREATE TABLE version (major INT, minor INT)"))
    log->error ("Error creating version: %s", mysql_error(mysql));

  if (mysql_query(mysql,
		  "CREATE TABLE state (cookie VARCHAR(64) PRIMARY KEY, application_id VARCHAR(255),"
		  "atime DATETIME, addr VARCHAR(128), statement TEXT)"))
    log->error ("Error creating state: %s", mysql_error(mysql));

  ostringstream q;
  q << "INSERT INTO version VALUES(" << major << "," << minor << ")";
  if (mysql_query(mysql, q.str().c_str()))
    log->error ("Error setting version: %s", mysql_error(mysql));
}

void ShibMySQLCCache::upgradeDatabase(MYSQL* mysql)
{
    if (mysql_query(mysql, "DROP TABLE state")) {
        log->error("Error dropping old session state table: %s", mysql_error(mysql));
    }

    if (mysql_query(mysql,
        "CREATE TABLE state (cookie VARCHAR(64) PRIMARY KEY, application_id VARCHAR(255),"
       "atime DATETIME, addr VARCHAR(128), statement TEXT)")) {
        log->error ("Error creating state table: %s", mysql_error(mysql));
        throw runtime_error("error creating table");
    }

    ostringstream q;
    q << "UPDATE version SET major = " << PLUGIN_VER_MAJOR;
    if (mysql_query(mysql, q.str().c_str())) {
        log->error ("Error updating version: %s", mysql_error(mysql));
        throw runtime_error("error updating table");
    }
}

void ShibMySQLCCache::getVersion(MYSQL* mysql, int* major_p, int* minor_p)
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

      log->crit("Houston, we've got a problem with the database..");
      mysql_free_result (rows);
      throw runtime_error("Database version verification failed");
    }
  }
  log->crit("MySQL Read Failed in version verificatoin");
  throw runtime_error("MySQL Read Failed");
}

void ShibMySQLCCache::mysqlInit(void)
{
  log->info ("Opening MySQL Database");

  // Setup the argument array
  vector<string> arg_array;
  arg_array.push_back("shar");

  // grab any MySQL parameters from the config file
  const DOMElement* e=saml::XML::getFirstChildElement(m_root,ShibTargetConfig::SHIBTARGET_NS,Argument);
  while (e) {
      auto_ptr_char arg(e->getFirstChild()->getNodeValue());
      if (arg.get())
          arg_array.push_back(arg.get());
      e=saml::XML::getNextSiblingElement(e,ShibTargetConfig::SHIBTARGET_NS,Argument);
  }

  // Compute the argument array
  int arg_count = arg_array.size();
  const char** args=new const char*[arg_count];
  for (int i = 0; i < arg_count; i++)
    args[i] = arg_array[i].c_str();

  // Initialize MySQL with the arguments
  mysql_server_init(arg_count, (char **)args, NULL);

  delete[] args;
}  

/*************************************************************************
 * The CCacheEntry here is mostly a wrapper around the "memory"
 * cacheentry provided by shibboleth.  The only difference is that we
 * intercept the isSessionValid() so that we can "touch()" the
 * database if the session is still valid.
 */

ShibMySQLCCacheEntry::ShibMySQLCCacheEntry(const char* key, ISessionCacheEntry* entry, ShibMySQLCCache* cache)
{
  m_cacheEntry = entry;
  m_key = key;
  m_cache = cache;
}

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
    m_cache->log->info("Error updating timestamp on %s: %s",
			m_key.c_str(), mysql_error(mysql));
    return false;
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

#define PLUGINTYPE "edu.internet2.middleware.shibboleth.target.provider.MySQLSessionCache"

extern "C" int SHIBMYSQL_EXPORTS saml_extension_init(void*)
{
  // register this ccache type
  SAMLConfig::getConfig().m_plugMgr.regFactory(PLUGINTYPE, &new_mysql_ccache);
  return 0;
}

extern "C" void SHIBMYSQL_EXPORTS saml_extension_term()
{
  SAMLConfig::getConfig().m_plugMgr.unregFactory(PLUGINTYPE);
}

/*************************************************************************
 * Local Functions
 */

extern "C" void shib_mysql_destroy_handle(void* data)
{
  MYSQL* mysql = (MYSQL*) data;
  mysql_close(mysql);
}
