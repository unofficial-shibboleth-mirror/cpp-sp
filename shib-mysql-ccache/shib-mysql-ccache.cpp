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

#ifndef WIN32
# include <unistd.h>
#endif

#include <shib-target/shib-target.h>
#include <shib-target/ccache-utils.h>
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

class ShibMySQLCCache;
class ShibMySQLCCacheEntry : public CCacheEntry
{
public:
  ShibMySQLCCacheEntry(const char *, CCacheEntry*, ShibMySQLCCache*);
  ~ShibMySQLCCacheEntry() {}

  virtual Iterator<SAMLAssertion*> getAssertions(Resource& resource)
  	{ return m_cacheEntry->getAssertions(resource); }
  virtual void preFetch(Resource& resource, int prefetch_window)
  	{ m_cacheEntry->preFetch(resource, prefetch_window); }
  virtual bool isSessionValid(time_t lifetime, time_t timeout);
  virtual const char* getClientAddress()
  	{ return m_cacheEntry->getClientAddress(); }
  virtual const char* getSerializedStatement()
  	{ return m_cacheEntry->getSerializedStatement(); }
  virtual const SAMLAuthenticationStatement* getStatement()
	{ return m_cacheEntry->getStatement(); }
  virtual void release()
  	{ m_cacheEntry->release(); delete this; }

private:
  void touch();

  ShibMySQLCCache* m_cache;
  CCacheEntry *m_cacheEntry;
  string m_key;
};

class ShibMySQLCCache : public CCache
{
public:
  ShibMySQLCCache();
  virtual ~ShibMySQLCCache();

  virtual SAMLBinding* getBinding(const XMLCh* bindingProt)
  	{ return m_cache->getBinding(bindingProt); }
  virtual CCacheEntry* find(const char* key);
  virtual void insert(const char* key, SAMLAuthenticationStatement *s,
		      const char *client_addr);
  virtual void remove(const char* key);
  virtual void thread_init();

  void	cleanup();
  MYSQL* getMYSQL();

  log4cpp::Category* log;

private:
  CCache* m_cache;
  ThreadKey* m_mysql;

  static void*	cleanup_fcn(void*); // XXX Assumed an ShibMySQLCCache
  CondWait* shutdown_wait;
  bool shutdown;
  Thread* cleanup_thread;

  bool initialized;

  void createDatabase(MYSQL*, int major, int minor);
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

MYSQL* ShibMySQLCCache::getMYSQL()
{
  void* data = m_mysql->getData();
  return (MYSQL*)data;
}

void ShibMySQLCCache::thread_init()
{
  saml::NDC ndc("open_db");

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
      createDatabase(mysql, 0, 0);
    }
  }

  int major = -1, minor = -1;
  getVersion (mysql, &major, &minor);

  // Make sure we've got the right version
  if (major != 0 && minor != 0) {
    log->crit("Invalid database version: %d.%d", major, minor);
    throw runtime_error("Invalid Database version");
  }

  // We're all set.. Save off the handle for this thread.
  m_mysql->setData((void*)mysql);
}

ShibMySQLCCache::ShibMySQLCCache()
{
  saml::NDC ndc("shibmysql::ShibMySQLCCache");

  m_mysql = ThreadKey::create(&shib_mysql_destroy_handle);
  string ctx = "shibmysql::ShibMySQLCCache";
  log = &(log4cpp::Category::getInstance(ctx));

  initialized = false;
  mysqlInit();
  thread_init();
  initialized = true;

  m_cache = CCache::getInstance("memory");

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

CCacheEntry* ShibMySQLCCache::find(const char* key)
{
  saml::NDC ndc("mysql::find");
  CCacheEntry* res = m_cache->find(key);
  if (!res) {

    log->debug("Looking in database...");

    // nothing cached; see if this exists in the database
    ostringstream q;
    q << "SELECT addr,statement FROM state WHERE cookie='" << key << "' LIMIT 1";

    MYSQL_RES* rows;
    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.str().c_str()))
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
    istringstream str(row[1]);
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
      m_cache->insert(key, s, row[0]);

    // Free the results, and then re-run the 'find' query
    mysql_free_result(rows);
    res = m_cache->find(key);
    if (!res)
      return NULL;
  }

  return new ShibMySQLCCacheEntry(key, res, this);
}

void ShibMySQLCCache::insert(const char* key, SAMLAuthenticationStatement *s,
			    const char *client_addr)
{
  saml::NDC ndc("mysql::insert");
  ostringstream os;
  os << *s;

  ostringstream q;
  q << "INSERT INTO state VALUES('" << key << "', NOW(), '" << client_addr
    << "', '" << os.str() << "')";

  log->debug("Query: %s", q.str().c_str());

  // Add it to the memory cache
  m_cache->insert(key, s, client_addr);

  // then add it to the database
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.str().c_str()))
    log->error("Error inserting %s: %s", key, mysql_error(mysql));
}

void ShibMySQLCCache::remove(const char* key)
{
  saml::NDC ndc("mysql::remove");

  // Remove the cached version
  m_cache->remove(key);

  // Remove from the database
  ostringstream q;
  q << "DELETE FROM state WHERE cookie='" << key << "'";
  MYSQL* mysql = getMYSQL();
  if (mysql_query(mysql, q.str().c_str()))
    log->error("Error deleting entry %s: %s", key, mysql_error(mysql));
}

void ShibMySQLCCache::cleanup()
{
  Mutex* mutex = Mutex::create();
  saml::NDC ndc("mysql::cleanup()");

  thread_init();

  ShibTargetConfig& config = ShibTargetConfig::getConfig();
  ShibINI& ini = config.getINI();

  int rerun_timer = 0;
  int timeout_life = 0;

  string tag;
  if (ini.get_tag (SHIBTARGET_SHAR, SHIBTARGET_TAG_CACHECLEAN, true, &tag))
    rerun_timer = atoi(tag.c_str());

  // search for 'mysql-cache-timeout' and then the regular cache timeout
  if (ini.get_tag (SHIBTARGET_SHAR, "mysql-cache-timeout", true, &tag))
    timeout_life = atoi(tag.c_str());
  else if (ini.get_tag (SHIBTARGET_SHAR, SHIBTARGET_TAG_CACHETIMEOUT, true, &tag))
    timeout_life = atoi(tag.c_str());

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
      throw new ShibTargetException();
    }

    if (!mysql_real_connect(ms, NULL, NULL, NULL, NULL, 0, NULL, 0)) {
      log->crit("cannot open DB file to create DB: %s", mysql_error(ms));
      throw new ShibTargetException();
    }

    if (mysql_query(ms, "CREATE DATABASE shar")) {
      log->crit("cannot create shar database: %s", mysql_error(ms));
      throw new ShibTargetException();
    }

    if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shar", 0, NULL, 0)) {
      log->crit("cannot open SHAR database");
      throw new ShibTargetException();
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
		  "CREATE TABLE state (cookie VARCHAR(64) PRIMARY KEY, "
		  "atime DATETIME, addr VARCHAR(128), statement TEXT)"))
    log->error ("Error creating state: %s", mysql_error(mysql));

  ostringstream q;
  q << "INSERT INTO version VALUES(" << major << "," << minor << ")";
  if (mysql_query(mysql, q.str().c_str()))
    log->error ("Error setting version: %s", mysql_error(mysql));
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
  string tag;

  tag = SHIBTARGET_SHAR;
  arg_array.push_back(tag);

  // grab any MySQL parameters from the config file
  ShibTargetConfig& config = ShibTargetConfig::getConfig();
  ShibINI& ini = config.getINI();

  if (ini.exists("mysql")) {
    ShibINI::Iterator* iter = ini.tag_iterator("mysql");

    for (const string* str = iter->begin(); str; str = iter->next()) {
      string arg = ini.get("mysql", *str);
      arg_array.push_back(arg);
    }
    delete iter;
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

ShibMySQLCCacheEntry::ShibMySQLCCacheEntry(const char* key, CCacheEntry *entry,
					 ShibMySQLCCache* cache)
{
  m_cacheEntry = entry;
  m_key = key;
  m_cache = cache;
}

bool ShibMySQLCCacheEntry::isSessionValid(time_t lifetime, time_t timeout)
{
  bool res = m_cacheEntry->isSessionValid(lifetime, timeout);
  if (res == true)
    touch();
  return res;
}

void ShibMySQLCCacheEntry::touch()
{
  ostringstream q;
  q << "UPDATE state SET atime=NOW() WHERE cookie='" << m_key << "'";

  MYSQL* mysql = m_cache->getMYSQL();
  if (mysql_query(mysql, q.str().c_str()))
    m_cache->log->error("Error updating timestamp on %s: %s",
			m_key.c_str(), mysql_error(mysql));
}

/*************************************************************************
 * The registration functions here...
 */

extern "C" CCache* new_mysql_ccache(void)
{
  return new ShibMySQLCCache();
}

extern "C" int saml_extension_init(void* context)
{
  // register this ccache type
  CCache::registerFactory("mysql", &new_mysql_ccache);
  return 0;
}

/*************************************************************************
 * Local Functions
 */

extern "C" void shib_mysql_destroy_handle(void* data)
{
  MYSQL* mysql = (MYSQL*) data;
  mysql_close(mysql);
}
