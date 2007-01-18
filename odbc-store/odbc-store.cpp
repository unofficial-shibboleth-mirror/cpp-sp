/*
 *  Copyright 2001-2007 Internet2
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
 * odbc-store.cpp - Storage service using ODBC
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
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define NOMINMAX
# define SHIBODBC_EXPORTS __declspec(dllexport)
#else
# define SHIBODBC_EXPORTS
#endif

#include <shib-target/shib-target.h>
#include <shibsp/exceptions.h>
#include <log4cpp/Category.hh>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>

#include <ctime>
#include <algorithm>
#include <sstream>

#include <sql.h>
#include <sqlext.h>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace shibsp;
using namespace shibtarget;
using namespace opensaml::saml2md;
using namespace saml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

#define PLUGIN_VER_MAJOR 3
#define PLUGIN_VER_MINOR 0

#define COLSIZE_KEY 64
#define COLSIZE_CONTEXT 256
#define COLSIZE_STRING_VALUE 256


/* tables definitions - not used here */

#define STRING_TABLE "STRING_STORE"

#define STRING_TABLE \
  "CREATE TABLE STRING_TABLE ( "\
  "context VARCHAR( COLSIZE_CONTEXT ), " \
  "key VARCHAR( COLSIZE_KEY ), " \
  "value VARCHAR( COLSIZE_STRING_VALUE ), " \
  "expires TIMESTAMP, "
  "PRIMARY KEY (context, key), "
  "INDEX (context))"


#define TEXT_TABLE "TEXT_STORE"

#define TEXT_TABLE \
  "CREATE TABLE TEXT_TABLE ( "\
  "context VARCHAR( COLSIZE_CONTEXT ), " \
  "key VARCHAR( COLSIZE_KEY ), " \
  "value LONG TEXT, " \
  "expires TIMESTAMP, "
  "PRIMARY KEY (context, key), "
  "INDEX (context))"




static const XMLCh ConnectionString[] =
{ chLatin_C, chLatin_o, chLatin_n, chLatin_n, chLatin_e, chLatin_c, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_S, chLatin_t, chLatin_r, chLatin_i, chLatin_n, chLatin_g, chNull
};
static const XMLCh cleanupInterval[] =
{ chLatin_c, chLatin_l, chLatin_e, chLatin_a, chLatin_n, chLatin_u, chLatin_p,
  chLatin_I, chLatin_n, chLatin_t, chLatin_e, chLatin_r, chLatin_v, chLatin_a, chLatin_l, chNull
};
static const XMLCh cacheTimeout[] =
{ chLatin_c, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull };
static const XMLCh odbcTimeout[] =
{ chLatin_o, chLatin_d, chLatin_b, chLatin_c, chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_o, chLatin_u, chLatin_t, chNull };
static const XMLCh storeAttributes[] =
{ chLatin_s, chLatin_t, chLatin_o, chLatin_r, chLatin_e, chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chLatin_s, chNull };

static const XMLCh cleanupInterval[] = UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);


// ODBC tools

struct ODBCConn {
    ODBCConn(SQLHDBC conn) : handle(conn) {}
    ~ODBCConn() {SQLFreeHandle(SQL_HANDLE_DBC,handle);}
    operator SQLHDBC() {return handle;}
    SQLHDBC handle;
};

class ODBCBase : public virtual saml::IPlugIn
{
public:
    ODBCBase(const DOMElement* e);
    virtual ~ODBCBase();

    SQLHDBC getHDBC();

    Category* log;

protected:
    const DOMElement* m_root; // can only use this during initialization
    string m_connstring;

    static SQLHENV m_henv;          // single handle for both plugins
    bool m_bInitializedODBC;        // tracks which class handled the process
    static const char* p_connstring;

    pair<int,int> getVersion(SQLHDBC);
    void log_error(SQLHANDLE handle, SQLSMALLINT htype);
};

SQLHENV ODBCBase::m_henv = SQL_NULL_HANDLE;
const char* ODBCBase::p_connstring = NULL;

ODBCBase::ODBCBase(const DOMElement* e) : m_root(e), m_bInitializedODBC(false)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("ODBCBase");
#endif
    log = &(Category::getInstance("shibtarget.ODBC"));

    if (m_henv == SQL_NULL_HANDLE) {
        // Enable connection pooling.
        SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0);

        // Allocate the environment.
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_henv)))
            throw ConfigurationException("ODBC failed to initialize.");

        // Specify ODBC 3.x
        SQLSetEnvAttr(m_henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);

        log->info("ODBC initialized");
        m_bInitializedODBC = true;
    }

    // Grab connection string from the configuration.
    e=XMLHelper::getFirstChildElement(e,ConnectionString);
    if (!e || !e->hasChildNodes()) {
        if (!p_connstring) {
            this->~ODBCBase();
            throw ConfigurationException("ODBC cache requires ConnectionString element in configuration.");
        }
        m_connstring=p_connstring;
    }
    else {
        xmltooling::auto_ptr_char arg(e->getFirstChild()->getNodeValue());
        m_connstring=arg.get();
        p_connstring=m_connstring.c_str();
    }

    // Connect and check version.
    SQLHDBC conn=getHDBC();
    pair<int,int> v=getVersion(conn);
    SQLFreeHandle(SQL_HANDLE_DBC,conn);

    // Make sure we've got the right version.
    if (v.first != PLUGIN_VER_MAJOR) {
        this->~ODBCBase();
        log->crit("unknown database version: %d.%d", v.first, v.second);
        throw SAMLException("Unknown cache database version.");
    }
}

ODBCBase::~ODBCBase()
{
    //delete m_mysql;
    if (m_bInitializedODBC)
        SQLFreeHandle(SQL_HANDLE_ENV,m_henv);
    m_bInitializedODBC=false;
    m_henv = SQL_NULL_HANDLE;
    p_connstring=NULL;
}

void ODBCBase::log_error(SQLHANDLE handle, SQLSMALLINT htype)
{
    SQLSMALLINT	 i = 0;
    SQLINTEGER	 native;
    SQLCHAR	 state[7];
    SQLCHAR	 text[256];
    SQLSMALLINT	 len;
    SQLRETURN	 ret;

    do {
        ret = SQLGetDiagRec(htype, handle, ++i, state, &native, text, sizeof(text), &len);
        if (SQL_SUCCEEDED(ret))
            log->error("ODBC Error: %s:%ld:%ld:%s", state, i, native, text);
    } while(SQL_SUCCEEDED(ret));
}

SQLHDBC ODBCBase::getHDBC()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("getMYSQL");
#endif

    // Get a handle.
    SQLHDBC handle;
    SQLRETURN sr=SQLAllocHandle(SQL_HANDLE_DBC, m_henv, &handle);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("failed to allocate connection handle");
        log_error(m_henv, SQL_HANDLE_ENV);
        throw SAMLException("ODBCBase::getHDBC failed to allocate connection handle");
    }

    sr=SQLDriverConnect(handle,NULL,(SQLCHAR*)m_connstring.c_str(),m_connstring.length(),NULL,0,NULL,SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("failed to connect to database");
        log_error(handle, SQL_HANDLE_DBC);
        throw SAMLException("ODBCBase::getHDBC failed to connect to database");
    }

    return handle;
}

pair<int,int> ODBCBase::getVersion(SQLHDBC conn)
{
    // Grab the version number from the database.
    SQLHSTMT hstmt;
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
    
    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)"SELECT major,minor FROM version", SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("failed to read version from database");
        log_error(hstmt, SQL_HANDLE_STMT);
        throw SAMLException("ODBCBase::getVersion failed to read version from database");
    }

    SQLINTEGER major;
    SQLINTEGER minor;
    SQLBindCol(hstmt,1,SQL_C_SLONG,&major,0,NULL);
    SQLBindCol(hstmt,2,SQL_C_SLONG,&minor,0,NULL);

    if ((sr=SQLFetch(hstmt)) != SQL_NO_DATA) {
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return pair<int,int>(major,minor);
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    log->error("no rows returned in version query");
    throw SAMLException("ODBCBase::getVersion failed to read version from database");
}


// ------------------------------------------------------------

// ODBC Storage Service class

class ODBCStorageService : public ODBCBase, public StorageService
{
    string stringTable = STRING_TABLE;
    string textTable = TEXT_TABLE;

public:
    ODBCStorageService(const DOMElement* e);
    virtual ~ODBCStorageService();

    void createString(const char* context, const char* key, const char* value, time_t expiration) {
        return createRow(string_table, context, key, value, expiration);
    }
    bool readString(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL) {
        return readRow(string_table, context, key, value, expiration, COLSIZE_STRING_VALUE);
    }
    bool updateString(const char* context, const char* key, const char* value=NULL, time_t expiration=0) {
        return updateRow(string_table, context, key, value, expiration);
    }
    bool deleteString(const char* context, const char* key) {
        return deleteRow(string_table, context, key, value, expiration);
    }

    void createText(const char* context, const char* key, const char* value, time_t expiration) {
        return createRow(text_table, context, key, value, expiration);
    }
    bool readText(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL) {
        return readRow(text_table, context, key, value, expiration, 0);
    }
    bool updateText(const char* context, const char* key, const char* value=NULL, time_t expiration=0) {
        return updateRow(text_table, context, key, value, expiration);
    }
    bool deleteText(const char* context, const char* key) {
        return deleteRow(text_table, context, key, value, expiration);
    }

    void reap(const char* context) {
        reap(string_table, context);
        reap(text_table, context);
    }
    void deleteContext(const char* context) {
        deleteCtx(string_table, context);
        deleteCtx(text_table, context);
    }
     

private:

    void createRow(const char *table, const char* context, const char* key, const char* value, time_t expiration);
    bool readRow(const char *table, const char* context, const char* key, string* pvalue, time_t* pexpiration, int maxsize);
    bool updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration);
    bool deleteRow(const char *table, const char* context, const char* key);

    void reapRows(const char* table, const char* context);
    void deleteCtx(const char* table, const char* context);

    xmltooling::CondWait* shutdown_wait;
    bool shutdown;
    xmltooling::Thread* cleanup_thread;

    static void* cleanup_fcn(void*); 
    void cleanup();

    CondWait* shutdown_wait;
    Thread* cleanup_thread;
    bool shutdown;
    int m_cleanupInterval;
    Category& log;

    StorageService* ODBCStorageServiceFactory(const DOMElement* const & e)
    {
        return new ODBCStorageService(e);
    }

    // convert SQL timestamp to time_t 
    time_t timeFromTimestamp(SQL_TIMESTAMP_STRUCT expires)
    {
        time_t ret;
        struct tm t;
        t.tm_sec=expires.second;
        t.tm_min=expires.minute;
        t.tm_hour=expires.hour;
        t.tm_mday=expires.day;
        t.tm_mon=expires.month-1;
        t.tm_year=expires.year-1900;
        t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
        ret = timegm(&t);
#else
        ret = mktime(&t) - timezone;
#endif
        return (ret);
    }

    // conver time_t to SQL string
    void timestampFromTime(time_t t, char &ret)
    {
#ifdef HAVE_GMTIME_R
        struct tm res;
        struct tm* ptime=gmtime_r(&created,&res);
#else
        struct tm* ptime=gmtime(&created);
#endif
        strftime(ret,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);
    }

    // make a string safe for SQL command
    // result to be free'd only if it isn't the input
    char *makeSafeSQL(const char *src)
    {
       int ns = 0;
       int nc = 0;
       char *s;
    
       // see if any conversion needed
       for (s=(char*)src; *s; nc++,s++) if (*s=='\''||*s=='\\') ns++;
       if (ns==0) return ((char*)src);
    
       char *safe = (char*) malloc(nc+2*ns+1);
       for (s=safe; *src; src++) {
           if (*src=='\''||*src=='\\') *s++ = '\\';
           *s++ = (char)*src;
       }
       *s = '\0';
       return (safe);
    }

    void freeSafeSQL(char *safe, const char *src)
    {
        if (safe!=src) free(safe);
    }

};

// class constructor

ODBCStorageService::ODBCStorageService(const DOMElement* e):
   ODBCBase(e),
   shutdown(false),
   m_cleanupInterval(0)

{
#ifdef _DEBUG
    xmltooling::NDC ndc("ODBCStorageService");
#endif
    log = &(Category::getInstance("shibtarget.StorageService.ODBC"));

    const XMLCh* tag=e ? e->getAttributeNS(NULL,cleanupInterval) : NULL;
    if (tag && *tag) {
        m_cleanupInterval = XMLString::parseInt(tag);
    }
    if (!m_cleanupInterval) m_cleanupInterval=300;

    contextLock = Mutex::create();
    shutdown_wait = CondWait::create();

    // Initialize the cleanup thread
    cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

ODBCStorageService::~ODBCStorageService()
{
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(NULL);

    delete shutdown_wait;
}


// create 

void ODBCStorageService::createRow(const char *table, const char* context, const char* key, const char* value, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("createRow");
#endif

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and exectute insert statement.
    char *scontext = makeSafeSQL(context);
    char *svalue = makeSafeSQL(value);
    string q  = string("INSERT ") + table + " VALUES ('" + scontext + "','" + key + "','" + svalue + "'," + timebuf + "')";
    freeSafeSQL(scontext, context)
    freeSafeSQL(svalue, value)
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("insert record failed (t=%s, c=%s, k=%s", table, context, key);
        log_error(hstmt, SQL_HANDLE_STMT);
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
}

// read

bool ODBCStorageService::readRow(const char *table, const char* context, const char* key, string& pvalue, time_t& pexpiration, int maxsize)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("readRow");
#endif

    SQLCHAR *tvalue = NULL;
    SQL_TIMESTAMP_STRUCT expires;
    time_t exp;

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and exectute select statement.
    char *scontext = makeSafeSQL(context);
    string q = string("SELECT expires,value FROM ") + table +
               " WHERE context='" + scontext + "' AND key='" + key + "'";
    freeSafeSQL(scontext, context)
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error searching for (t=%s, c=%s, k=%s)", table, context, key);
        log_error(hstmt, SQL_HANDLE_STMT);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return false;
    }

    // retrieve data 
    SQLBindCol(hstmt,1,SQL_C_TYPE_TIMESTAMP,&expires,0,NULL);

    if ((sr=SQLFetch(hstmt)) == SQL_NO_DATA) {
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return false;
    }

    // expire time from bound col
    exp = timeFromTimestamp(expires);
    if (time(NULL)>ezp) {
        log->debug(".. expired");
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return false;
    }
    if (pexpiration) pexpiration = exp;

    // value by getdata

    // see how much text there is
    if (maxsize==0) {
         SQLINTEGER nch;
         SQLCHAR tv[12];
         sr = SQLGetData(hstmt, 2, SQL_C_CHAR, tvp, BUFSIZE_TEXT_BLOCK, &nch);
         if (sr==SQL_SUCCESS || sr==SQL_SUCCESS_WITH_INFO) {
             maxsize = nch;
         }
    }

    tvalue = (SQLCHAR*) malloc(maxsize+1);
    sr = SQLGetData(hstmt, 2, SQL_C_CHAR, tvalue, maxsize, &nch);
        if (sr!=SQL_SUCCESS) {
            log->error("error retriving value for (t=%s, c=%s, k=%s)", table, context, key);
            log_error(hstmt, SQL_HANDLE_STMT);
            SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
            return false;
        }
    }
    pvalue = string(tvalue);
    free(tvalue);

    log->debug(".. value found");

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return true;
}


// update 

bool ODBCStorageService::updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("updateRow");
#endif

    bool ret = true;

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and exectute update statement.

    string expstr = "";
    if (expiration) expstr = string(",expires = '") + timebuf + "' ";

    char *scontext = makeSafeSQL(context);
    char *svalue = makeSafeSQL(value);
    string q  = string("UPDATE ") + table + " SET value='" + svalue + "'" + expstr + 
               " WHERE context='" + scontext + "' AND key='" + key + "' AND expires > NOW()";
    freeSafeSQL(scontext, context)
    freeSafeSQL(svalue, value)
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("update record failed (t=%s, c=%s, k=%s", table, context, key);
        log_error(hstmt, SQL_HANDLE_STMT);
        ret = false;
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return ret;
}


// delete

bool ODBCStorageService::deleteRow(const char *table, const char *context, const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteRow");
#endif

    bool ret = true;

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and execute delete statement.
    char *scontext = makeSafeSQL(context);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "' AND key='" + key + "'";
    freeSafeSQL(scontext, context)
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
 
    if (sr==SQL_NO_DATA) {
        ret = false;
    } else if (!SQL_SUCCEEDED(sr)) {
        log->error("error deleting record (t=%s, c=%s, k=%s)", table, context, key);
        log_error(hstmt, SQL_HANDLE_STMT);
        ret = false;
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return ret;
}


// cleanup - delete expired entries

void ODBCStorageService::cleanup()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("cleanup");
#endif

    Mutex* mutex = xmltooling::Mutex::create();

    int rerun_timer = 0;
    int timeout_life = 0;

    mutex->lock();

    log->info("cleanup thread started... running every %d secs", m_cleanupInterval);

    while (!shutdown) {
        shutdown_wait->timedwait(mutex, m_cleanupInterval);

        if (shutdown) break;

        reap(NULL);
    }

    log->info("cleanup thread exiting...");

    mutex->unlock();
    delete mutex;
    xmltooling::Thread::exit(NULL);
}

void* ODBCStorageService::cleanup_fcn(void* cache_p)
{
  ODBCStorageService* cache = (ODBCStorageService*)cache_p;

#ifndef WIN32
  // First, let's block all signals
  Thread::mask_all_signals();
#endif

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}


// remove expired entries for a context

void ODBCStorageService::reapRows(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("reapRows");
#endif

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and execute delete statement.
    string q;
    if (context) {
        char *scontext = makeSafeSQL(context);
        q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "' AND expires<NOW()";
        freeSafeSQL(scontext, context)
    } else {
        q = string("DELETE FROM ") + table + " WHERE expires<NOW()";
    }
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
 
    if ((sr!=SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        log->error("error expiring records (t=%s, c=%s)", table, context?context:"null");
        log_error(hstmt, SQL_HANDLE_STMT);
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
}



// remove all entries for a context

void ODBCStorageService::deleteCtx(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteCtx");
#endif

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare and execute delete statement.
    char *scontext = makeSafeSQL(context);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "'";
    freeSafeSQL(scontext, context)
    log->debug("SQL: %s", q.str());

    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
 
    if ((sr!=SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        log->error("error deleting context (t=%s, c=%s)", table, context);
        log_error(hstmt, SQL_HANDLE_STMT);
    }

    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
}
