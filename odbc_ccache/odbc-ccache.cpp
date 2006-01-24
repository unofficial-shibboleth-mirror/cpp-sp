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
 * odbc-ccache.cpp - Shibboleth Credential Cache using ODBC
 *
 * Scott Cantor <cantor.2@osu.edu>
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
# define SHIBODBC_EXPORTS __declspec(dllexport)
#else
# define SHIBODBC_EXPORTS
#endif

#include <shib/shib-threads.h>
#include <shib-target/shib-target.h>
#include <log4cpp/Category.hh>

#include <sstream>

#include <sql.h>
#include <sqlext.h>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

#define PLUGIN_VER_MAJOR 3
#define PLUGIN_VER_MINOR 0

#define COLSIZE_KEY 64
#define COLSIZE_APPLICATION_ID 256
#define COLSIZE_ADDRESS 128
#define COLSIZE_PROVIDER_ID 256
#define LONGDATA_BUFLEN 2048

/*
  CREATE TABLE state (
      cookie VARCHAR(64) PRIMARY KEY,
      application_id VARCHAR(256),
      ctime TIMESTAMP,
      atime TIMESTAMP,
      addr VARCHAR(128),
      major INT,
      minor INT,
      provider VARCHAR(256),
      subject TEXT,
      authn_context TEXT,
      tokens TEXT
      )
*/

#define REPLAY_TABLE \
  "CREATE TABLE replay (id VARCHAR(255) PRIMARY KEY, " \
  "expires TIMESTAMP, " \
  "INDEX (expires))"

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

    log4cpp::Category* log;

protected:
    //ThreadKey* m_mysql;
    const DOMElement* m_root; // can only use this during initialization
    string m_connstring;

    static SQLHENV m_henv;          // single handle for both plugins
    bool m_bInitializedODBC;        // tracks which class handled the process

    pair<int,int> getVersion(SQLHDBC);
    void log_error(SQLHANDLE handle, SQLSMALLINT htype);
};

SQLHENV ODBCBase::m_henv = SQL_NULL_HANDLE;

/*
extern "C" void shib_mysql_destroy_handle(void* data)
{
  MYSQL* mysql = (MYSQL*) data;
  if (mysql) mysql_close(mysql);
}
*/

ODBCBase::ODBCBase(const DOMElement* e) : m_root(e), m_bInitializedODBC(false)
{
#ifdef _DEBUG
    saml::NDC ndc("ODBCBase");
#endif
    log = &(Category::getInstance("shibtarget.SessionCache.ODBC"));
    //m_mysql = ThreadKey::create(&shib_mysql_destroy_handle);

    if (m_henv != SQL_NULL_HANDLE) {
        log->info("ODBC already initialized");
        return;
    }

    // Enable connection pooling.
    SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0);

    // Allocate the environment.
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_henv)))
        throw ConfigurationException("ODBC failed to initialize.");

    // Specify ODBC 3.x
    SQLSetEnvAttr(m_henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);

    log->info("ODBC initialized");
    m_bInitializedODBC = true;

    // Grab connection string from the configuration.
    e=saml::XML::getFirstChildElement(e,shibtarget::XML::SHIBTARGET_NS,ConnectionString);
    if (!e || !e->hasChildNodes()) {
        this->~ODBCBase();
        throw ConfigurationException("ODBC cache requires ConnectionString element in configuration.");
    }
    auto_ptr_char arg(e->getFirstChild()->getNodeValue());
    m_connstring=arg.get();

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
    m_henv = SQL_NULL_HANDLE;
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
    } while(ret==SQL_SUCCESS);
}

SQLHDBC ODBCBase::getHDBC()
{
#ifdef _DEBUG
    saml::NDC ndc("getMYSQL");
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
    SQLBindCol(hstmt,1,SQL_INTEGER,&major,0,NULL);
    SQLBindCol(hstmt,2,SQL_INTEGER,&minor,0,NULL);

    if ((sr=SQLFetch(hstmt)) != SQL_NO_DATA) {
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return pair<int,int>(major,minor);
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    log->error("no rows returned in version query");
    throw SAMLException("ODBCBase::getVersion failed to read version from database");
}

class ODBCCCache : public ODBCBase, virtual public ISessionCache, virtual public ISessionCacheStore
{
public:
    ODBCCCache(const DOMElement* e);
    virtual ~ODBCCCache();

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
    CondWait* shutdown_wait;
    bool shutdown;
    Thread* cleanup_thread;

    static void* cleanup_fcn(void*); // XXX Assumed an ODBCCCache
};

ODBCCCache::ODBCCCache(const DOMElement* e) : ODBCBase(e), m_storeAttributes(false)
{
#ifdef _DEBUG
    saml::NDC ndc("ODBCCCache");
#endif

    m_cache = dynamic_cast<ISessionCache*>(
        SAMLConfig::getConfig().getPlugMgr().newPlugin(shibtarget::XML::MemorySessionCacheType, e)
    );
    if (!m_cache->setBackingStore(this)) {
        delete m_cache;
        throw SAMLException("Unable to register ODBC cache plugin as a cache store.");
    }
    
    shutdown_wait = CondWait::create();
    shutdown = false;

    // Load our configuration details...
    const XMLCh* tag=m_root->getAttributeNS(NULL,storeAttributes);
    if (tag && *tag && (*tag==chLatin_t || *tag==chDigit_1))
        m_storeAttributes=true;

    // Initialize the cleanup thread
    cleanup_thread = Thread::create(&cleanup_fcn, (void*)this);
}

ODBCCCache::~ODBCCCache()
{
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(NULL);
    delete m_cache;
}

HRESULT ODBCCCache::onCreate(
    const char* key,
    const IApplication* application,
    const ISessionCacheEntry* entry,
    int majorVersion,
    int minorVersion,
    time_t created
    )
{
#ifdef _DEBUG
    saml::NDC ndc("onCreate");
#endif

    // Get XML data from entry. Default is not to return SAML objects.
    const char* context=entry->getAuthnContext();
    pair<const char*,const SAMLSubject*> subject=entry->getSubject();
    pair<const char*,const SAMLResponse*> tokens=entry->getTokens();

    // Stringify timestamp.
    if (created==0)
        created=time(NULL);
#ifndef HAVE_GMTIME_R
    struct tm* ptime=gmtime(&created);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&created,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);

    // Prepare insert statement.
    ostringstream q;
    q << "INSERT INTO state VALUES('" << key << "','" << application->getId() << "'," << timebuf << "," << timebuf
        << ",'" << entry->getClientAddress() << "'," << majorVersion << "," << minorVersion << ",'" << entry->getProviderId()
        << "',?,?,?)";

    if (m_storeAttributes && tokens.first)
        q << "'" << tokens.first << "')";
    else
        q << "null)";

    if (log->isDebugEnabled())
        log->debug("SQL insert: %s", q.str().c_str());

    // Get statement handle.
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    // Prepare it.
    SQLRETURN sr=SQLPrepare(hstmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("failed to prepare insert statement");
        log_error(hstmt, SQL_HANDLE_STMT);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return E_FAIL;
    }

    // Bind text parameters to statement.
    SQLINTEGER cbSubject,cbContext,cbTokens;
    SQLBindParameter(hstmt,1,SQL_PARAM_INPUT,SQL_C_CHAR,SQL_LONGVARCHAR,0,0,(SQLPOINTER)subject.first,0,&cbSubject);
    SQLBindParameter(hstmt,2,SQL_PARAM_INPUT,SQL_C_CHAR,SQL_LONGVARCHAR,0,0,(SQLPOINTER)context,0,&cbContext);
    SQLBindParameter(hstmt,3,SQL_PARAM_INPUT,SQL_C_CHAR,SQL_LONGVARCHAR,0,0,(SQLPOINTER)tokens.first,0,&cbTokens);
    cbSubject=SQL_LEN_DATA_AT_EXEC(strlen(subject.first));
    cbContext=SQL_LEN_DATA_AT_EXEC(strlen(context));
    if (!m_storeAttributes || !tokens.first)
        cbTokens=SQL_NULL_DATA;
    else
        cbTokens=SQL_LEN_DATA_AT_EXEC(strlen(tokens.first));

    // Execute statement.
    sr=SQLExecute(hstmt);
    if (sr==SQL_NEED_DATA) {
        // Loop to send text data into driver.
        // pData is set each round by the driver to the pointers we bound above.
        char* pData;
        sr=SQLParamData(hstmt,(SQLPOINTER*)&pData);
        while (sr==SQL_NEED_DATA) {
            size_t len=strlen(pData);
            while (len>0) {
                SQLPutData(hstmt, pData, min(LONGDATA_BUFLEN,len));
                pData += min(LONGDATA_BUFLEN,len);
                len = len - LONGDATA_BUFLEN;
            }
            sr=SQLParamData(hstmt,(SQLPOINTER*)&pData);
       }
    }

    HRESULT hr=NOERROR;
    if (!SQL_SUCCEEDED(sr)) {
        log->error("failed to insert record into database");
        log_error(hstmt, SQL_HANDLE_STMT);
        hr=E_FAIL;
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return hr;
}

HRESULT ODBCCCache::onRead(
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
    saml::NDC ndc("onRead");
#endif

    log->debug("searching MySQL database...");

    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

    string q = string("SELECT application_id,ctime,atime,addr,major,minor,provider,subject,authn_context,tokens FROM state WHERE cookie='") + key + "'";
    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error searching for (%s)",key);
        log_error(hstmt, SQL_HANDLE_STMT);
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return E_FAIL;
    }

    SQLINTEGER major,minor;
    SQL_TIMESTAMP_STRUCT atime,ctime;
    SQLCHAR application_id[COLSIZE_APPLICATION_ID+1];
    SQLCHAR addr[COLSIZE_ADDRESS+1];
    SQLCHAR provider_id[COLSIZE_PROVIDER_ID+1];

    // Bind simple output columns.
    SQLBindCol(hstmt,1,SQL_VARCHAR,application_id,sizeof(application_id),NULL);
    SQLBindCol(hstmt,2,SQL_TYPE_TIMESTAMP,&ctime,0,NULL);
    SQLBindCol(hstmt,3,SQL_TYPE_TIMESTAMP,&atime,0,NULL);
    SQLBindCol(hstmt,4,SQL_VARCHAR,addr,sizeof(addr),NULL);
    SQLBindCol(hstmt,5,SQL_INTEGER,&major,0,NULL);
    SQLBindCol(hstmt,6,SQL_INTEGER,&minor,0,NULL);
    SQLBindCol(hstmt,7,SQL_VARCHAR,provider_id,sizeof(provider_id),NULL);

    if ((sr=SQLFetch(hstmt)) == SQL_NO_DATA) {
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return S_FALSE;
    }

    log->debug("session found, tranfering data back into memory");

    // Copy back simple data.
    applicationId = (char*)application_id;
    clientAddress = (char*)addr;
    majorVersion = major;
    minorVersion = minor;
    providerId = (char*)provider_id;

    struct tm t;
    t.tm_sec=ctime.second;
    t.tm_min=ctime.minute;
    t.tm_hour=ctime.hour;
    t.tm_mday=ctime.day;
    t.tm_mon=ctime.month-1;
    t.tm_year=ctime.year-1900;
    t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
    created=timegm(&t);
#else
    // Windows, and hopefully most others...?
    created = mktime(&t) - timezone;
#endif
    t.tm_sec=atime.second;
    t.tm_min=atime.minute;
    t.tm_hour=atime.hour;
    t.tm_mday=atime.day;
    t.tm_mon=atime.month-1;
    t.tm_year=atime.year-1900;
    t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
    accessed=timegm(&t);
#else
    // Windows, and hopefully most others...?
    accessed = mktime(&t) - timezone;
#endif

    // Extract text data.
    string* ptrs[] = {&subject, &authnContext, &tokens};
    HRESULT hr=NOERROR;
    SQLINTEGER len;
    SQLCHAR buf[LONGDATA_BUFLEN];
    for (int i=0; i<3; i++) {
        while ((sr=SQLGetData(hstmt,i+8,SQL_C_CHAR,buf,sizeof(buf),&len)) != SQL_NO_DATA) {
            if (!SUCCEEDED(sr)) {
                log->error("error while reading text field from result set");
                log_error(hstmt, SQL_HANDLE_STMT);
                hr=E_FAIL;
                break;
            }
            ptrs[i]->append((char*)buf);
        }
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return hr;
}

HRESULT ODBCCCache::onRead(const char* key, time_t& accessed)
{
#ifdef _DEBUG
    saml::NDC ndc("onRead");
#endif

    log->debug("reading last access time from MySQL database");

    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
    
    string q = string("SELECT atime FROM state WHERE cookie='") + key + "'";
    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error searching for (%s)",key);
        log_error(hstmt, SQL_HANDLE_STMT);
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return E_FAIL;
    }

    SQL_TIMESTAMP_STRUCT atime;
    SQLBindCol(hstmt,1,SQL_TYPE_TIMESTAMP,&atime,0,NULL);

    if ((sr=SQLFetch(hstmt)) == SQL_NO_DATA) {
        log->warn("session expected, but not found in database");
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return S_FALSE;
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);

    struct tm t;
    t.tm_sec=atime.second;
    t.tm_min=atime.minute;
    t.tm_hour=atime.hour;
    t.tm_mday=atime.day;
    t.tm_mon=atime.month-1;
    t.tm_year=atime.year-1900;
    t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
    accessed=timegm(&t);
#else
    // Windows, and hopefully most others...?
    accessed = mktime(&t) - timezone;
#endif
    return NOERROR;
}

HRESULT ODBCCCache::onRead(const char* key, string& tokens)
{
#ifdef _DEBUG
    saml::NDC ndc("onRead");
#endif

    if (!m_storeAttributes)
        return S_FALSE;

    log->debug("reading cached tokens from MySQL database");

    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
    
    string q = string("SELECT tokens FROM state WHERE cookie='") + key + "'";
    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error searching for (%s)",key);
        log_error(hstmt, SQL_HANDLE_STMT);
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return E_FAIL;
    }

    if ((sr=SQLFetch(hstmt)) == SQL_NO_DATA) {
        log->warn("session expected, but not found in database");
        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
        return S_FALSE;
    }

    HRESULT hr=NOERROR;
    SQLINTEGER len;
    SQLCHAR buf[LONGDATA_BUFLEN];
    while ((sr=SQLGetData(hstmt,1,SQL_C_CHAR,buf,sizeof(buf),&len)) != SQL_NO_DATA) {
        if (!SUCCEEDED(sr)) {
            log->error("error while reading text field from result set");
            log_error(hstmt, SQL_HANDLE_STMT);
            hr=E_FAIL;
            break;
        }
        tokens += (char*)buf;
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return hr;
}

HRESULT ODBCCCache::onUpdate(const char* key, const char* tokens, time_t lastAccess)
{
#ifdef _DEBUG
    saml::NDC ndc("onUpdate");
#endif

    SQLRETURN sr;
    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());

    ostringstream q;
    if (lastAccess>0) {
#ifndef HAVE_GMTIME_R
        struct tm* ptime=gmtime(&lastAccess);
#else
        struct tm res;
        struct tm* ptime=gmtime_r(&lastAccess,&res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);
        q << "UPDATE state SET atime=" << timebuf << " WHERE cookie='" << key << "'";

        SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
        sr=SQLExecDirect(hstmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
    }
    else if (tokens) {
        if (!m_storeAttributes)
            return S_FALSE;
        q << "UPDATE state SET tokens=? WHERE cookie='" << key << "'";

        SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);

        // Prepare it.
        sr=SQLPrepare(hstmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
        if (!SQL_SUCCEEDED(sr)) {
            log->error("failed to prepare insert statement");
            log_error(hstmt, SQL_HANDLE_STMT);
            SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
            return E_FAIL;
        }

        // Bind text parameters to statement.
        SQLINTEGER cbTokens;
        SQLBindParameter(hstmt,1,SQL_PARAM_INPUT,SQL_C_CHAR,SQL_LONGVARCHAR,0,0,(SQLPOINTER)tokens,0,&cbTokens);
        if (tokens)
            cbTokens=SQL_LEN_DATA_AT_EXEC(strlen(tokens));
        else
            cbTokens=SQL_NULL_DATA;

        // Execute statement.
        sr=SQLExecute(hstmt);
        if (sr==SQL_NEED_DATA) {
            // Loop to send text data into driver.
            // pData is set each round by the driver to the pointers we bound above.
            char* pData;
            sr=SQLParamData(hstmt,(SQLPOINTER*)&pData);
            while (sr==SQL_NEED_DATA) {
                size_t len=strlen(pData);
                while (len>0) {
                    SQLPutData(hstmt, pData, min(LONGDATA_BUFLEN,len));
                    pData += min(LONGDATA_BUFLEN,len);
                    len = len - LONGDATA_BUFLEN;
                }
                sr=SQLParamData(hstmt,(SQLPOINTER*)&pData);
           }
        }
    }
    else {
        log->warn("onUpdate called with nothing to do!");
        return S_FALSE;
    }
 
    HRESULT hr=NOERROR;
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error updating record (key=%s)", key);
        log_error(hstmt, SQL_HANDLE_STMT);
        hr=E_FAIL;
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return hr;
}

HRESULT ODBCCCache::onDelete(const char* key)
{
#ifdef _DEBUG
    saml::NDC ndc("onDelete");
#endif

    SQLHSTMT hstmt;
    ODBCConn conn(getHDBC());
    SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
    string q = string("DELETE FROM state WHERE cookie='") + key + "'";
    SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
 
    HRESULT hr=NOERROR;
    if (!SQL_SUCCEEDED(sr)) {
        log->error("error deleting record (key=%s)", key);
        log_error(hstmt, SQL_HANDLE_STMT);
        hr=E_FAIL;
    }

    SQLCloseCursor(hstmt);
    SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
    return hr;
}

void ODBCCCache::cleanup()
{
#ifdef _DEBUG
    saml::NDC ndc("cleanup");
#endif

    Mutex* mutex = Mutex::create();

    int rerun_timer = 0;
    int timeout_life = 0;

    // Load our configuration details...
    const XMLCh* tag=m_root->getAttributeNS(NULL,cleanupInterval);
    if (tag && *tag)
        rerun_timer = XMLString::parseInt(tag);

    // search for 'mysql-cache-timeout' and then the regular cache timeout
    tag=m_root->getAttributeNS(NULL,odbcTimeout);
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

    log->info("cleanup thread started...Run every %d secs; timeout after %d secs", rerun_timer, timeout_life);

    while (shutdown == false) {
        shutdown_wait->timedwait(mutex, rerun_timer);

        if (shutdown == true)
            break;

        // Find all the entries in the database that haven't been used
        // recently In particular, find all entries that have not been
        // accessed in 'timeout_life' seconds.

        time_t stale=time(NULL)-timeout_life;
#ifndef HAVE_GMTIME_R
        struct tm* ptime=gmtime(&stale);
#else
        struct tm res;
        struct tm* ptime=gmtime_r(&stale,&res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);

        string q = string("DELETE FROM state WHERE atime < ") +  timebuf;

        SQLHSTMT hstmt;
        ODBCConn conn(getHDBC());
        SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
        SQLRETURN sr=SQLExecDirect(hstmt, (SQLCHAR*)q.c_str(), SQL_NTS);
        if (!SQL_SUCCEEDED(sr)) {
            log->error("error purging old records");
            log_error(hstmt, SQL_HANDLE_STMT);
        }

        SQLCloseCursor(hstmt);
        SQLFreeHandle(SQL_HANDLE_STMT,hstmt);
     }

    log->info("cleanup thread exiting...");

    mutex->unlock();
    delete mutex;
    Thread::exit(NULL);
}

void* ODBCCCache::cleanup_fcn(void* cache_p)
{
  ODBCCCache* cache = (ODBCCCache*)cache_p;

  // First, let's block all signals
  Thread::mask_all_signals();

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

/*
class MySQLReplayCache : public MySQLBase, virtual public IReplayCache
{
public:
  MySQLReplayCache(const DOMElement* e);
  virtual ~MySQLReplayCache() {}

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

IPlugIn* new_mysql_replay(const DOMElement* e)
{
    return new MySQLReplayCache(e);
}
*/

/*************************************************************************
 * The registration functions here...
 */

IPlugIn* new_mysql_ccache(const DOMElement* e)
{
    return new ODBCCCache(e);
}


extern "C" int SHIBODBC_EXPORTS saml_extension_init(void*)
{
    // register this ccache type
//    SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::MySQLReplayCacheType, &new_mysql_replay);
    SAMLConfig::getConfig().getPlugMgr().regFactory(shibtarget::XML::MySQLSessionCacheType, &new_mysql_ccache);
    return 0;
}

extern "C" void SHIBODBC_EXPORTS saml_extension_term()
{
    SAMLConfig::getConfig().getPlugMgr().unregFactory(shibtarget::XML::MySQLSessionCacheType);
//    SAMLConfig::getConfig().getPlugMgr().unregFactory(shibtarget::XML::MySQLReplayCacheType);
}
