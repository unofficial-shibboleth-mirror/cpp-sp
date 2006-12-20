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

#include <xmltooling/util/NDC.h>
#include <log4cpp/Category.hh>

#include <sstream>

#ifdef WIN32
# include <winsock.h>
#endif
#include <mysql.h>

// wanted to use MySQL codes for this, but can't seem to get back a 145
#define isCorrupt(s) strstr(s,"(errno: 145)")

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace shibtarget;
using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

#define PLUGIN_VER_MAJOR 3
#define PLUGIN_VER_MINOR 0

#define STATE_TABLE \
  "CREATE TABLE state (" \
  "cookie VARCHAR(64) PRIMARY KEY, " \
  "application_id VARCHAR(255)," \
  "ctime TIMESTAMP," \
  "atime TIMESTAMP," \
  "addr VARCHAR(128)," \
  "major INT," \
  "minor INT," \
  "provider VARCHAR(256)," \
  "subject TEXT," \
  "authn_context TEXT," \
  "tokens TEXT)"

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

static bool g_MySQLInitialized = false;

class MySQLBase : public virtual saml::IPlugIn
{
public:
  MySQLBase(const DOMElement* e);
  virtual ~MySQLBase();

  MYSQL* getMYSQL();
  bool repairTable(MYSQL*&, const char* table);

  log4cpp::Category* log;

protected:
    xmltooling::ThreadKey* m_mysql;
  const DOMElement* m_root; // can only use this during initialization

  bool initialized;
  bool handleShutdown;

  void createDatabase(MYSQL*, int major, int minor);
  void upgradeDatabase(MYSQL*);
  pair<int,int> getVersion(MYSQL*);
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
  xmltooling::NDC ndc("MySQLBase");
#endif
  log = &(Category::getInstance("shibtarget.SessionCache.MySQL"));

  m_mysql = xmltooling::ThreadKey::create(&shib_mysql_destroy_handle);

  initialized = false;
  mysqlInit(e,*log);
  getMYSQL();
  initialized = true;
}

MySQLBase::~MySQLBase()
{
  delete m_mysql;
}

MYSQL* MySQLBase::getMYSQL()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("getMYSQL");
#endif

    // Do we already have a handle?
    MYSQL* mysql=reinterpret_cast<MYSQL*>(m_mysql->getData());
    if (mysql)
        return mysql;

    // Connect to the database
    mysql = mysql_init(NULL);
    if (!mysql) {
        log->error("mysql_init failed");
        mysql_close(mysql);
        throw SAMLException("MySQLBase::getMYSQL(): mysql_init() failed");
    }

    if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shibd", 0, NULL, 0)) {
        if (initialized) {
            log->crit("mysql_real_connect failed: %s", mysql_error(mysql));
            mysql_close(mysql);
            throw SAMLException("MySQLBase::getMYSQL(): mysql_real_connect() failed");
        }
        else {
            log->info("mysql_real_connect failed: %s.  Trying to create", mysql_error(mysql));

            // This will throw an exception if it fails.
            createDatabase(mysql, PLUGIN_VER_MAJOR, PLUGIN_VER_MINOR);
        }
    }

    pair<int,int> v=getVersion (mysql);

    // Make sure we've got the right version
    if (v.first != PLUGIN_VER_MAJOR || v.second != PLUGIN_VER_MINOR) {
   
        // If we're capable, try upgrading on the fly...
        if (v.first == 0  || v.first == 1 || v.first == 2) {
            if (mysql_query(mysql, "DROP TABLE state")) {
                log->error("error dropping old session state table: %s", mysql_error(mysql));
            }
            if (v.first==2 && mysql_query(mysql, "DROP TABLE replay")) {
                log->error("error dropping old session state table: %s", mysql_error(mysql));
            }
            upgradeDatabase(mysql);
        }
        else {
            mysql_close(mysql);
            log->crit("Unknown database version: %d.%d", v.first, v.second);
            throw SAMLException("MySQLBase::getMYSQL(): Unknown database version");
        }
    }

    // We're all set.. Save off the handle for this thread.
    m_mysql->setData(mysql);
    return mysql;
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
    mysql=getMYSQL();
    return true;
}

void MySQLBase::createDatabase(MYSQL* mysql, int major, int minor)
{
  log->info("creating database");

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

    if (mysql_query(ms, "CREATE DATABASE shibd")) {
      log->crit("cannot create shibd database: %s", mysql_error(ms));
      throw SAMLException("ShibMySQLCCache::createDatabase(): create db cmd failed");
    }

    if (!mysql_real_connect(mysql, NULL, NULL, NULL, "shibd", 0, NULL, 0)) {
      log->crit("cannot open shibd database");
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
    log->error ("error creating version: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  if (mysql_query(mysql,STATE_TABLE)) {
    log->error ("error creating state table: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  if (mysql_query(mysql,REPLAY_TABLE)) {
    log->error ("error creating replay table: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): create table cmd failed");
  }

  ostringstream q;
  q << "INSERT INTO version VALUES(" << major << "," << minor << ")";
  if (mysql_query(mysql, q.str().c_str())) {
    log->error ("error setting version: %s", mysql_error(mysql));
    throw SAMLException("ShibMySQLCCache::createDatabase(): version insert failed");
  }
}

void MySQLBase::upgradeDatabase(MYSQL* mysql)
{
    if (mysql_query(mysql,STATE_TABLE)) {
        log->error ("error creating state table: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error creating state table");
    }

    if (mysql_query(mysql,REPLAY_TABLE)) {
        log->error ("error creating replay table: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error creating replay table");
    }

    ostringstream q;
    q << "UPDATE version SET major = " << PLUGIN_VER_MAJOR;
    if (mysql_query(mysql, q.str().c_str())) {
        log->error ("error updating version: %s", mysql_error(mysql));
        throw SAMLException("ShibMySQLCCache::upgradeDatabase(): error updating version");
    }
}

pair<int,int> MySQLBase::getVersion(MYSQL* mysql)
{
    // grab the version number from the database
    if (mysql_query(mysql, "SELECT * FROM version")) {
        log->error("error reading version: %s", mysql_error(mysql));
        throw SAMLException("MySQLBase::getVersion(): error reading version");
    }

    MYSQL_RES* rows = mysql_store_result(mysql);
    if (rows) {
        if (mysql_num_rows(rows) == 1 && mysql_num_fields(rows) == 2)  {
          MYSQL_ROW row = mysql_fetch_row(rows);
          int major = row[0] ? atoi(row[0]) : -1;
          int minor = row[1] ? atoi(row[1]) : -1;
          log->debug("opening database version %d.%d", major, minor);
          mysql_free_result(rows);
          return make_pair(major,minor);
        }
        else {
            // Wrong number of rows or wrong number of fields...
            log->crit("Houston, we've got a problem with the database...");
            mysql_free_result(rows);
            throw SAMLException("MySQLBase::getVersion(): version verification failed");
        }
    }
    log->crit("MySQL Read Failed in version verification");
    throw SAMLException("MySQLBase::getVersion(): error reading version");
}

static void mysqlInit(const DOMElement* e, Category& log)
{
    if (g_MySQLInitialized) {
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
    vector<string>::size_type arg_count = arg_array.size();
    const char** args=new const char*[arg_count];
    for (vector<string>::size_type i = 0; i < arg_count; i++)
        args[i] = arg_array[i].c_str();

    // Initialize MySQL with the arguments
    mysql_server_init(arg_count, (char **)args, NULL);

    delete[] args;
    g_MySQLInitialized = true;
}  

class ShibMySQLCCache : public MySQLBase, virtual public ISessionCache, virtual public ISessionCacheStore
{
public:
    ShibMySQLCCache(const DOMElement* e);
    virtual ~ShibMySQLCCache();

    // Delegate all the ISessionCache methods.
    string insert(
        const IApplication* application,
        const IEntityDescriptor* source,
        const char* client_addr,
        const SAMLSubject* subject,
        const char* authnContext,
        const SAMLResponse* tokens
        )
    { return m_cache->insert(application,source,client_addr,subject,authnContext,tokens); }
    ISessionCacheEntry* find(const char* key, const IApplication* application, const char* client_addr)
    { return m_cache->find(key,application,client_addr); }
    void remove(const char* key, const IApplication* application, const char* client_addr)
    { m_cache->remove(key,application,client_addr); }

    bool setBackingStore(ISessionCacheStore*) {return false;}

    // Store methods handle the database work
    HRESULT onCreate(
        const char* key,
        const IApplication* application,
        const ISessionCacheEntry* entry,
        int majorVersion,
        int minorVersion,
        time_t created
        );
    HRESULT onRead(
        const char* key,
        string& applicationId,
        string& clientAddress,
        string& providerId,
        string& subject,
        string& authnContext,
        string& tokens,
        int& majorVersion,
        int& minorVersion,
        time_t& created,
        time_t& accessed
        );
    HRESULT onRead(const char* key, time_t& accessed);
    HRESULT onRead(const char* key, string& tokens);
    HRESULT onUpdate(const char* key, const char* tokens=NULL, time_t accessed=0);
    HRESULT onDelete(const char* key);

    void cleanup();

private:
    bool m_storeAttributes;
    ISessionCache* m_cache;
    xmltooling::CondWait* shutdown_wait;
    bool shutdown;
    xmltooling::Thread* cleanup_thread;

    static void* cleanup_fcn(void*); // XXX Assumed an ShibMySQLCCache
};

ShibMySQLCCache::ShibMySQLCCache(const DOMElement* e) : MySQLBase(e), m_storeAttributes(false)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("ShibMySQLCCache");
#endif

    m_cache = dynamic_cast<ISessionCache*>(
        SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::MemorySessionCacheType, e)
    );
    if (!m_cache->setBackingStore(this)) {
        delete m_cache;
        throw SAMLException("Unable to register MySQL cache plugin as a cache store.");
    }
    
    shutdown_wait = xmltooling::CondWait::create();
    shutdown = false;

    // Load our configuration details...
    const XMLCh* tag=m_root->getAttributeNS(NULL,storeAttributes);
    if (tag && *tag && (*tag==chLatin_t || *tag==chDigit_1))
        m_storeAttributes=true;

    // Initialize the cleanup thread
    cleanup_thread = xmltooling::Thread::create(&cleanup_fcn, (void*)this);
}

ShibMySQLCCache::~ShibMySQLCCache()
{
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(NULL);
    delete m_cache;
}

HRESULT ShibMySQLCCache::onCreate(
    const char* key,
    const IApplication* application,
    const ISessionCacheEntry* entry,
    int majorVersion,
    int minorVersion,
    time_t created
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onCreate");
#endif

    // Get XML data from entry. Default is not to return SAML objects.
    const char* context=entry->getAuthnContext();
    pair<const char*,const SAMLSubject*> subject=entry->getSubject();
    pair<const char*,const SAMLResponse*> tokens=entry->getTokens();

    ostringstream q;
    q << "INSERT INTO state VALUES('" << key << "','" << application->getId() << "',";
    if (created==0)
        q << "NOW(),NOW(),'";
    else
        q << "FROM_UNIXTIME(" << created << "),NOW(),'";
    q << entry->getClientAddress() << "'," << majorVersion << "," << minorVersion << ",'" << entry->getProviderId() << "','"
        << subject.first << "','" << context << "',";

    if (m_storeAttributes && tokens.first)
        q << "'" << tokens.first << "')";
    else
        q << "null)";

    if (log->isDebugEnabled())
        log->debug("SQL insert: %s", q.str().c_str());

    // then add it to the database
    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.str().c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error inserting %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            // Try again...
            if (mysql_query(mysql, q.str().c_str())) {
                log->error("error inserting %s: %s", key, mysql_error(mysql));
                return E_FAIL;
            }
        }
        else
            throw E_FAIL;
    }

    return NOERROR;
}

HRESULT ShibMySQLCCache::onRead(
    const char* key,
    string& applicationId,
    string& clientAddress,
    string& providerId,
    string& subject,
    string& authnContext,
    string& tokens,
    int& majorVersion,
    int& minorVersion,
    time_t& created,
    time_t& accessed
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onRead");
#endif

    log->debug("searching MySQL database...");

    string q = string("SELECT application_id,UNIX_TIMESTAMP(ctime),UNIX_TIMESTAMP(atime),addr,major,minor,provider,subject,authn_context,tokens FROM state WHERE cookie='") + key + "' LIMIT 1";

    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error searching for %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            if (mysql_query(mysql, q.c_str()))
                log->error("error retrying search for %s: %s", key, mysql_error(mysql));
        }
    }

    MYSQL_RES* rows = mysql_store_result(mysql);

    // Nope, doesn't exist.
    if (!rows || mysql_num_rows(rows)==0) {
        log->debug("not found in database");
        if (rows)
            mysql_free_result(rows);
        return S_FALSE;
    }

    // Make sure we got 1 and only 1 row.
    if (mysql_num_rows(rows) > 1) {
        log->error("database select returned %d rows!", mysql_num_rows(rows));
        mysql_free_result(rows);
        return E_FAIL;
    }

    log->debug("session found, tranfering data back into memory");
    
    /* Columns in query:
        0: application_id
        1: ctime
        2: atime
        3: address
        4: major
        5: minor
        6: provider
        7: subject
        8: authncontext
        9: tokens
     */

    MYSQL_ROW row = mysql_fetch_row(rows);
    applicationId=row[0];
    created=atoi(row[1]);
    accessed=atoi(row[2]);
    clientAddress=row[3];
    majorVersion=atoi(row[4]);
    minorVersion=atoi(row[5]);
    providerId=row[6];
    subject=row[7];
    authnContext=row[8];
    if (row[9])
        tokens=row[9];

    // Free the results.
    mysql_free_result(rows);

    return NOERROR;
}

HRESULT ShibMySQLCCache::onRead(const char* key, time_t& accessed)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onRead");
#endif

    log->debug("reading last access time from MySQL database");

    string q = string("SELECT UNIX_TIMESTAMP(atime) FROM state WHERE cookie='") + key + "' LIMIT 1";

    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error searching for %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            if (mysql_query(mysql, q.c_str()))
                log->error("error retrying search for %s: %s", key, mysql_error(mysql));
        }
    }

    MYSQL_RES* rows = mysql_store_result(mysql);

    // Nope, doesn't exist.
    if (!rows || mysql_num_rows(rows)==0) {
        log->warn("session expected, but not found in database");
        if (rows)
            mysql_free_result(rows);
        return S_FALSE;
    }

    // Make sure we got 1 and only 1 row.
    if (mysql_num_rows(rows) != 1) {
        log->error("database select returned %d rows!", mysql_num_rows(rows));
        mysql_free_result(rows);
        return E_FAIL;
    }

    MYSQL_ROW row = mysql_fetch_row(rows);
    accessed=atoi(row[0]);

    // Free the results.
    mysql_free_result(rows);

    return NOERROR;
}

HRESULT ShibMySQLCCache::onRead(const char* key, string& tokens)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onRead");
#endif

    if (!m_storeAttributes)
        return S_FALSE;

    log->debug("reading cached tokens from MySQL database");

    string q = string("SELECT tokens FROM state WHERE cookie='") + key + "' LIMIT 1";

    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error searching for %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            if (mysql_query(mysql, q.c_str()))
                log->error("error retrying search for %s: %s", key, mysql_error(mysql));
        }
    }

    MYSQL_RES* rows = mysql_store_result(mysql);

    // Nope, doesn't exist.
    if (!rows || mysql_num_rows(rows)==0) {
        log->warn("session expected, but not found in database");
        if (rows)
            mysql_free_result(rows);
        return S_FALSE;
    }

    // Make sure we got 1 and only 1 row.
    if (mysql_num_rows(rows) != 1) {
        log->error("database select returned %d rows!", mysql_num_rows(rows));
        mysql_free_result(rows);
        return E_FAIL;
    }

    MYSQL_ROW row = mysql_fetch_row(rows);
    if (row[0])
        tokens=row[0];

    // Free the results.
    mysql_free_result(rows);

    return NOERROR;
}

HRESULT ShibMySQLCCache::onUpdate(const char* key, const char* tokens, time_t lastAccess)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onUpdate");
#endif

    ostringstream q;
    if (lastAccess>0)
        q << "UPDATE state SET atime=FROM_UNIXTIME(" << lastAccess << ")";
    else if (tokens) {
        if (!m_storeAttributes)
            return S_FALSE;
        q << "UPDATE state SET tokens=";
        if (*tokens)
            q << "'" << tokens << "'";
        else
            q << "null";
    }
    else {
        log->warn("onUpdate called with nothing to do!");
        return S_FALSE;
    }
 
    q << " WHERE cookie='" << key << "'";

    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.str().c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error updating %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            // Try again...
            if (mysql_query(mysql, q.str().c_str())) {
                log->error("error updating %s: %s", key, mysql_error(mysql));
                return E_FAIL;
            }
        }
        else
            return E_FAIL;
    }

    return NOERROR;
}

HRESULT ShibMySQLCCache::onDelete(const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("onDelete");
#endif

    // Remove from the database
    string q = string("DELETE FROM state WHERE cookie='") + key + "'";
    MYSQL* mysql = getMYSQL();
    if (mysql_query(mysql, q.c_str())) {
        const char* err=mysql_error(mysql);
        log->error("error deleting entry %s: %s", key, err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
            // Try again...
            if (mysql_query(mysql, q.c_str())) {
                log->error("error deleting entry %s: %s", key, mysql_error(mysql));
                return E_FAIL;
            }
        }
        else
            return E_FAIL;
    }

    return NOERROR;
}

void ShibMySQLCCache::cleanup()
{
#ifdef _DEBUG
  xmltooling::NDC ndc("cleanup");
#endif

  xmltooling::Mutex* mutex = xmltooling::Mutex::create();

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

  log->info("cleanup thread started...Run every %d secs; timeout after %d secs", rerun_timer, timeout_life);

  while (shutdown == false) {
    shutdown_wait->timedwait(mutex, rerun_timer);

    if (shutdown == true)
      break;

    // Find all the entries in the database that haven't been used
    // recently In particular, find all entries that have not been
    // accessed in 'timeout_life' seconds.
    ostringstream q;
    q << "DELETE FROM state WHERE " << "UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(atime) >= " << timeout_life;

    if (mysql_query(mysql, q.str().c_str())) {
      const char* err=mysql_error(mysql);
      log->error("error purging old records: %s", err);
        if (isCorrupt(err) && repairTable(mysql,"state")) {
          if (mysql_query(mysql, q.str().c_str()))
            log->error("error re-purging old records: %s", mysql_error(mysql));
        }
    }
  }

  log->info("cleanup thread exiting...");

  mutex->unlock();
  delete mutex;
  xmltooling::Thread::exit(NULL);
}

void* ShibMySQLCCache::cleanup_fcn(void* cache_p)
{
  ShibMySQLCCache* cache = (ShibMySQLCCache*)cache_p;

#ifndef WIN32
  // First, let's block all signals
  xmltooling::Thread::mask_all_signals();
#endif

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

class MySQLReplayCache : public MySQLBase, virtual public IReplayCache
{
public:
  MySQLReplayCache(const DOMElement* e);
  virtual ~MySQLReplayCache() {}

  bool check(const XMLCh* str, time_t expires) {auto_ptr_XMLCh temp(str); return check(temp.get(),expires);}
  bool check(const char* str, time_t expires);
};

MySQLReplayCache::MySQLReplayCache(const DOMElement* e) : MySQLBase(e) {}

bool MySQLReplayCache::check(const char* str, time_t expires)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("check");
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

extern "C" int SHIBMYSQL_EXPORTS saml_extension_init(void*)
{
    // register this ccache type
    SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::MySQLReplayCacheType, &new_mysql_replay);
    SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::MySQLSessionCacheType, &new_mysql_ccache);
    return 0;
}

extern "C" void SHIBMYSQL_EXPORTS saml_extension_term()
{
    // Shutdown MySQL
    if (g_MySQLInitialized)
        mysql_server_end();
    SAMLConfig::getConfig().getPlugMgr().unregFactory(shibtarget::XML::MySQLReplayCacheType);
    SAMLConfig::getConfig().getPlugMgr().unregFactory(shibtarget::XML::MySQLSessionCacheType);
}
