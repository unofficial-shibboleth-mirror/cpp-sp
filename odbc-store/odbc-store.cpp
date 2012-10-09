/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * odbc-store.cpp
 *
 * Storage Service using ODBC.
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#ifdef WIN32
# define ODBCSTORE_EXPORTS __declspec(dllexport)
#else
# define ODBCSTORE_EXPORTS
#endif

#include <xmltooling/logging.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#include <sql.h>
#include <sqlext.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

#define PLUGIN_VER_MAJOR 1
#define PLUGIN_VER_MINOR 1

#define LONGDATA_BUFLEN 16384

#define COLSIZE_CONTEXT 255
#define COLSIZE_ID 255
#define COLSIZE_STRING_VALUE 255

#define STRING_TABLE "strings"
#define TEXT_TABLE "texts"

/* table definitions
CREATE TABLE version (
    major int NOT nullptr,
    minor int NOT nullptr
    )

CREATE TABLE strings (
    context varchar(255) not null,
    id varchar(255) not null,
    expires datetime not null,
    version int not null,
    value varchar(255) not null,
    PRIMARY KEY (context, id)
    )

CREATE TABLE texts (
    context varchar(255) not null,
    id varchar(255) not null,
    expires datetime not null,
    version int not null,
    value text not null,
    PRIMARY KEY (context, id)
    )
*/

namespace {
    static const XMLCh cleanupInterval[] =  UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
    static const XMLCh isolationLevel[] =   UNICODE_LITERAL_14(i,s,o,l,a,t,i,o,n,L,e,v,e,l);
    static const XMLCh ConnectionString[] = UNICODE_LITERAL_16(C,o,n,n,e,c,t,i,o,n,S,t,r,i,n,g);
    static const XMLCh RetryOnError[] =     UNICODE_LITERAL_12(R,e,t,r,y,O,n,E,r,r,o,r);
    static const XMLCh contextSize[] =      UNICODE_LITERAL_11(c,o,n,t,e,x,t,S,i,z,e);
    static const XMLCh keySize[] =          UNICODE_LITERAL_7(k,e,y,S,i,z,e);
    static const XMLCh stringSize[] =       UNICODE_LITERAL_10(s,t,r,i,n,g,S,i,z,e);

    // RAII for ODBC handles
    struct ODBCConn {
        ODBCConn(SQLHDBC conn) : handle(conn), autoCommit(true) {}
        ~ODBCConn() {
            if (handle != SQL_NULL_HDBC) {
                SQLRETURN sr = SQL_SUCCESS;
                if (!autoCommit)
                    sr = SQLSetConnectAttr(handle, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, 0);
                SQLDisconnect(handle);
                SQLFreeHandle(SQL_HANDLE_DBC, handle);
                if (!SQL_SUCCEEDED(sr))
                    throw IOException("Failed to commit connection and return to auto-commit mode.");
            }
        }
        operator SQLHDBC() {return handle;}
        SQLHDBC handle;
        bool autoCommit;
    };

    class ODBCStorageService : public StorageService
    {
    public:
        ODBCStorageService(const DOMElement* e);
        virtual ~ODBCStorageService();

        const Capabilities& getCapabilities() const {
            return m_caps;
        }

        bool createString(const char* context, const char* key, const char* value, time_t expiration) {
            return createRow(STRING_TABLE, context, key, value, expiration);
        }
        int readString(const char* context, const char* key, string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0) {
            return readRow(STRING_TABLE, context, key, pvalue, pexpiration, version);
        }
        int updateString(const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0) {
            return updateRow(STRING_TABLE, context, key, value, expiration, version);
        }
        bool deleteString(const char* context, const char* key) {
            return deleteRow(STRING_TABLE, context, key);
        }

        bool createText(const char* context, const char* key, const char* value, time_t expiration) {
            return createRow(TEXT_TABLE, context, key, value, expiration);
        }
        int readText(const char* context, const char* key, string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0) {
            return readRow(TEXT_TABLE, context, key, pvalue, pexpiration, version);
        }
        int updateText(const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0) {
            return updateRow(TEXT_TABLE, context, key, value, expiration, version);
        }
        bool deleteText(const char* context, const char* key) {
            return deleteRow(TEXT_TABLE, context, key);
        }

        void reap(const char* context) {
            reap(STRING_TABLE, context);
            reap(TEXT_TABLE, context);
        }

        void updateContext(const char* context, time_t expiration) {
            updateContext(STRING_TABLE, context, expiration);
            updateContext(TEXT_TABLE, context, expiration);
        }

        void deleteContext(const char* context) {
            deleteContext(STRING_TABLE, context);
            deleteContext(TEXT_TABLE, context);
        }
         

    private:
        bool createRow(const char *table, const char* context, const char* key, const char* value, time_t expiration);
        int readRow(const char *table, const char* context, const char* key, string* pvalue, time_t* pexpiration, int version);
        int updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration, int version);
        bool deleteRow(const char *table, const char* context, const char* key);

        void reap(const char* table, const char* context);
        void updateContext(const char* table, const char* context, time_t expiration);
        void deleteContext(const char* table, const char* context);

        SQLHDBC getHDBC();
        SQLHSTMT getHSTMT(SQLHDBC);
        pair<SQLINTEGER,SQLINTEGER> getVersion(SQLHDBC);
        pair<bool,bool> log_error(SQLHANDLE handle, SQLSMALLINT htype, const char* checkfor=nullptr);

        static void* cleanup_fn(void*); 
        void cleanup();

        Category& m_log;
        Capabilities m_caps;
        int m_cleanupInterval;
        scoped_ptr<CondWait> shutdown_wait;
        Thread* cleanup_thread;
        bool shutdown;

        SQLHENV m_henv;
        string m_connstring;
        long m_isolation;
        bool m_wideVersion;
        vector<SQLINTEGER> m_retries;
    };

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
    void timestampFromTime(time_t t, char* ret)
    {
#ifdef HAVE_GMTIME_R
        struct tm res;
        struct tm* ptime=gmtime_r(&t,&res);
#else
        struct tm* ptime=gmtime(&t);
#endif
        strftime(ret,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);
    }

    class SQLString {
        const char* m_src;
        string m_copy;
    public:
        SQLString(const char* src) : m_src(src) {
            if (strchr(src, '\'')) {
                m_copy = src;
                replace_all(m_copy, "'", "''");
            }
        }

        operator const char*() const {
            return tostr();
        }

        const char* tostr() const {
            return m_copy.empty() ? m_src : m_copy.c_str();
        }
    };
};

ODBCStorageService::ODBCStorageService(const DOMElement* e) : m_log(Category::getInstance("XMLTooling.StorageService")),
    m_caps(XMLHelper::getAttrInt(e, 255, contextSize), XMLHelper::getAttrInt(e, 255, keySize), XMLHelper::getAttrInt(e, 255, stringSize)),
    m_cleanupInterval(XMLHelper::getAttrInt(e, 900, cleanupInterval)),
    cleanup_thread(nullptr), shutdown(false), m_henv(SQL_NULL_HENV), m_isolation(SQL_TXN_SERIALIZABLE), m_wideVersion(false)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("ODBCStorageService");
#endif
    string iso(XMLHelper::getAttrString(e, "SERIALIZABLE", isolationLevel));
    if (iso == "SERIALIZABLE")
        m_isolation = SQL_TXN_SERIALIZABLE;
    else if (iso == "REPEATABLE_READ")
        m_isolation = SQL_TXN_REPEATABLE_READ;
    else if (iso == "READ_COMMITTED")
        m_isolation = SQL_TXN_READ_COMMITTED;
    else if (iso == "READ_UNCOMMITTED")
        m_isolation = SQL_TXN_READ_UNCOMMITTED;
    else
        throw XMLToolingException("Unknown transaction isolationLevel property.");

    if (m_henv == SQL_NULL_HENV) {
        // Enable connection pooling.
        SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0);

        // Allocate the environment.
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_henv)))
            throw XMLToolingException("ODBC failed to initialize.");

        // Specify ODBC 3.x
        SQLSetEnvAttr(m_henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);

        m_log.info("ODBC initialized");
    }

    // Grab connection string from the configuration.
    e = e ? XMLHelper::getFirstChildElement(e, ConnectionString) : nullptr;
    auto_ptr_char arg(e ? e->getTextContent() : nullptr);
    if (!arg.get() || !*arg.get()) {
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
        throw XMLToolingException("ODBC StorageService requires ConnectionString element in configuration.");
    }
    m_connstring = arg.get();

    // Connect and check version.
    ODBCConn conn(getHDBC());
    pair<SQLINTEGER,SQLINTEGER> v = getVersion(conn);

    // Make sure we've got the right version.
    if (v.first != PLUGIN_VER_MAJOR) {
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
        m_log.crit("unknown database version: %d.%d", v.first, v.second);
        throw XMLToolingException("Unknown database version for ODBC StorageService.");
    }
    
    if (v.first > 1 || v.second > 0) {
        m_log.info("using 32-bit int type for version fields in tables");
        m_wideVersion = true;
    }

    // Load any retry errors to check.
    e = XMLHelper::getNextSiblingElement(e, RetryOnError);
    while (e) {
        if (e->hasChildNodes()) {
            m_retries.push_back(XMLString::parseInt(e->getTextContent()));
            m_log.info("will retry operations when native ODBC error (%ld) is returned", m_retries.back());
        }
        e = XMLHelper::getNextSiblingElement(e, RetryOnError);
    }

    // Initialize the cleanup thread
    shutdown_wait.reset(CondWait::create());
    cleanup_thread = Thread::create(&cleanup_fn, (void*)this);
}

ODBCStorageService::~ODBCStorageService()
{
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(nullptr);
    if (m_henv != SQL_NULL_HANDLE)
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
}

pair<bool,bool> ODBCStorageService::log_error(SQLHANDLE handle, SQLSMALLINT htype, const char* checkfor)
{
    SQLSMALLINT	 i = 0;
    SQLINTEGER	 native;
    SQLCHAR	 state[7];
    SQLCHAR	 text[256];
    SQLSMALLINT	 len;
    SQLRETURN	 ret;

    pair<bool,bool> res = make_pair(false,false);
    do {
        ret = SQLGetDiagRec(htype, handle, ++i, state, &native, text, sizeof(text), &len);
        if (SQL_SUCCEEDED(ret)) {
            m_log.error("ODBC Error: %s:%ld:%ld:%s", state, i, native, text);
            for (vector<SQLINTEGER>::const_iterator n = m_retries.begin(); !res.first && n != m_retries.end(); ++n)
                res.first = (*n == native);
            if (checkfor && !strcmp(checkfor, (const char*)state))
                res.second = true;
        }
    } while(SQL_SUCCEEDED(ret));
    return res;
}

SQLHDBC ODBCStorageService::getHDBC()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("getHDBC");
#endif

    // Get a handle.
    SQLHDBC handle = SQL_NULL_HDBC;
    SQLRETURN sr = SQLAllocHandle(SQL_HANDLE_DBC, m_henv, &handle);
    if (!SQL_SUCCEEDED(sr) || handle == SQL_NULL_HDBC) {
        m_log.error("failed to allocate connection handle");
        log_error(m_henv, SQL_HANDLE_ENV);
        throw IOException("ODBC StorageService failed to allocate a connection handle.");
    }

    sr = SQLDriverConnect(handle,nullptr,(SQLCHAR*)m_connstring.c_str(),m_connstring.length(),nullptr,0,nullptr,SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to connect to database");
        log_error(handle, SQL_HANDLE_DBC);
        SQLFreeHandle(SQL_HANDLE_DBC, handle);
        throw IOException("ODBC StorageService failed to connect to database.");
    }

    sr = SQLSetConnectAttr(handle, SQL_ATTR_TXN_ISOLATION, (SQLPOINTER)m_isolation, 0);
    if (!SQL_SUCCEEDED(sr)) {
        SQLDisconnect(handle);
        SQLFreeHandle(SQL_HANDLE_DBC, handle);
        throw IOException("ODBC StorageService failed to set transaction isolation level.");
    }

    return handle;
}

SQLHSTMT ODBCStorageService::getHSTMT(SQLHDBC conn)
{
    SQLHSTMT hstmt = SQL_NULL_HSTMT;
    SQLRETURN sr = SQLAllocHandle(SQL_HANDLE_STMT, conn, &hstmt);
    if (!SQL_SUCCEEDED(sr) || hstmt == SQL_NULL_HSTMT) {
        m_log.error("failed to allocate statement handle");
        log_error(conn, SQL_HANDLE_DBC);
        throw IOException("ODBC StorageService failed to allocate a statement handle.");
    }
    return hstmt;
}

pair<SQLINTEGER,SQLINTEGER> ODBCStorageService::getVersion(SQLHDBC conn)
{
    // Grab the version number from the database.
    SQLHSTMT stmt = getHSTMT(conn);
    
    SQLRETURN sr = SQLExecDirect(stmt, (SQLCHAR*)"SELECT major,minor FROM version", SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to read version from database");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to read version from database.");
    }

    SQLINTEGER major;
    SQLINTEGER minor;
    SQLBindCol(stmt, 1, SQL_C_SLONG, &major, 0, nullptr);
    SQLBindCol(stmt, 2, SQL_C_SLONG, &minor, 0, nullptr);

    if ((sr = SQLFetch(stmt)) != SQL_NO_DATA)
        return make_pair(major,minor);

    m_log.error("no rows returned in version query");
    throw IOException("ODBC StorageService failed to read version from database.");
}

bool ODBCStorageService::createRow(const char* table, const char* context, const char* key, const char* value, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("createRow");
#endif

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    string q  = string("INSERT INTO ") + table + " VALUES (?,?," + timebuf + ",1,?)";

    SQLRETURN sr = SQLPrepare(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLPrepare failed (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLPrepare succeeded. SQL: %s", q.c_str());

    SQLLEN b_ind = SQL_NTS;
    sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(context), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (context = %s)", context);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (context = %s)", context);

    sr = SQLBindParam(stmt, 2, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(key), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (key = %s)", key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (key = %s)", key);

    if (strcmp(table, TEXT_TABLE)==0)
        sr = SQLBindParam(stmt, 3, SQL_C_CHAR, SQL_LONGVARCHAR, strlen(value), 0, const_cast<char*>(value), &b_ind);
    else
        sr = SQLBindParam(stmt, 3, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(value), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (value = %s)", value);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (value = %s)", value);
    
    int attempts = 3;
    pair<bool,bool> logres;
    do {
        logres = make_pair(false,false);
        attempts--;
        sr = SQLExecute(stmt);
        if (SQL_SUCCEEDED(sr)) {
            m_log.debug("SQLExecute of insert succeeded");
            return true;
        }
        m_log.error("insert record failed (t=%s, c=%s, k=%s)", table, context, key);
        logres = log_error(stmt, SQL_HANDLE_STMT, "23000");
        if (logres.second)
            return false;   // supposedly integrity violation?
    } while (attempts && logres.first);

    throw IOException("ODBC StorageService failed to insert record.");
}

int ODBCStorageService::readRow(const char *table, const char* context, const char* key, string* pvalue, time_t* pexpiration, int version)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("readRow");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and exectute select statement.
    char timebuf[32];
    timestampFromTime(time(nullptr), timebuf);
    SQLString scontext(context);
    SQLString skey(key);
    string q("SELECT version");
    if (pexpiration)
        q += ",expires";
    if (pvalue) {
        pvalue->erase();
        q = q + ",CASE version WHEN " + lexical_cast<string>(version) + " THEN null ELSE value END";
    }
    q = q + " FROM " + table + " WHERE context='" + scontext.tostr() + "' AND id='" + skey.tostr() + "' AND expires > " + timebuf;
    if (m_log.isDebugEnabled())
        m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("error searching for (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService search failed.");
    }

    SQLSMALLINT ver;
    SQLINTEGER widever;
    SQL_TIMESTAMP_STRUCT expiration;

    if (m_wideVersion)
        SQLBindCol(stmt, 1, SQL_C_SLONG, &widever, 0, nullptr);
    else
        SQLBindCol(stmt, 1, SQL_C_SSHORT, &ver, 0, nullptr);
    if (pexpiration)
        SQLBindCol(stmt, 2, SQL_C_TYPE_TIMESTAMP, &expiration, 0, nullptr);

    if ((sr = SQLFetch(stmt)) == SQL_NO_DATA) {
        if (m_log.isDebugEnabled())
            m_log.debug("search returned no data (t=%s, c=%s, k=%s)", table, context, key);
        return 0;
    }

    if (pexpiration)
        *pexpiration = timeFromTimestamp(expiration);

    if (version == (m_wideVersion ? widever : ver)) {
        if (m_log.isDebugEnabled())
            m_log.debug("versioned search detected no change (t=%s, c=%s, k=%s)", table, context, key);
        return version; // nothing's changed, so just echo back the version
    }

    if (pvalue) {
        SQLLEN len;
        SQLCHAR buf[LONGDATA_BUFLEN];
        while ((sr = SQLGetData(stmt, (pexpiration ? 3 : 2), SQL_C_CHAR, buf, sizeof(buf), &len)) != SQL_NO_DATA) {
            if (!SQL_SUCCEEDED(sr)) {
                m_log.error("error while reading text field from result set");
                log_error(stmt, SQL_HANDLE_STMT);
                throw IOException("ODBC StorageService search failed to read data from result set.");
            }
            pvalue->append((char*)buf);
        }
    }
    
    return (m_wideVersion ? widever : ver);
}

int ODBCStorageService::updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration, int version)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("updateRow");
#endif

    if (!value && !expiration)
        throw IOException("ODBC StorageService given invalid update instructions.");

    // Get statement handle. Disable auto-commit mode to wrap select + update.
    ODBCConn conn(getHDBC());
    SQLRETURN sr = SQLSetConnectAttr(conn, SQL_ATTR_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF, 0);
    if (!SQL_SUCCEEDED(sr))
        throw IOException("ODBC StorageService failed to disable auto-commit mode.");
    conn.autoCommit = false;
    SQLHSTMT stmt = getHSTMT(conn);

    // First, fetch the current version for later, which also ensures the record still exists.
    char timebuf[32];
    timestampFromTime(time(nullptr), timebuf);
    SQLString scontext(context);
    SQLString skey(key);
    string q("SELECT version FROM ");
    q = q + table + " WHERE context='" + scontext.tostr() + "' AND id='" + skey.tostr() + "' AND expires > " + timebuf;

    m_log.debug("SQL: %s", q.c_str());

    sr = SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("error searching for (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService search failed.");
    }

    SQLSMALLINT ver;
    SQLINTEGER widever;
    if (m_wideVersion)
        SQLBindCol(stmt, 1, SQL_C_SLONG, &widever, 0, nullptr);
    else
        SQLBindCol(stmt, 1, SQL_C_SSHORT, &ver, 0, nullptr);
    if ((sr = SQLFetch(stmt)) == SQL_NO_DATA) {
        return 0;
    }

    // Check version?
    if (version > 0 && version != (m_wideVersion ? widever : ver)) {
        return -1;
    }
    else if ((m_wideVersion && widever == INT_MAX) || (!m_wideVersion && ver == 32767)) {
        m_log.error("record version overflow (t=%s, c=%s, k=%s)", table, context, key);
        throw IOException("Version overflow, record in ODBC StorageService could not be updated.");
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    stmt = getHSTMT(conn);

    // Prepare and exectute update statement.
    q = string("UPDATE ") + table + " SET ";

    if (value)
        q = q + "value=?, version=version+1";

    if (expiration) {
        timestampFromTime(expiration, timebuf);
        if (value)
            q += ',';
        q = q + "expires = " + timebuf;
    }

    q = q + " WHERE context='" + scontext.tostr() + "' AND id='" + skey.tostr() + "'";

    sr = SQLPrepare(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("update of record failed (t=%s, c=%s, k=%s", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to update record.");
    }
    m_log.debug("SQLPrepare succeeded. SQL: %s", q.c_str());

    SQLLEN b_ind = SQL_NTS;
    if (value) {
        if (strcmp(table, TEXT_TABLE)==0)
            sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_LONGVARCHAR, strlen(value), 0, const_cast<char*>(value), &b_ind);
        else
            sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(value), &b_ind);
        if (!SQL_SUCCEEDED(sr)) {
            m_log.error("SQLBindParam failed (value = %s)", value);
            log_error(stmt, SQL_HANDLE_STMT);
            throw IOException("ODBC StorageService failed to update record.");
        }
        m_log.debug("SQLBindParam succeeded (value = %s)", value);
    }

    int attempts = 3;
    pair<bool,bool> logres;
    do {
        logres = make_pair(false,false);
        attempts--;
        sr = SQLExecute(stmt);
        if (sr == SQL_NO_DATA)
            return 0;   // went missing?
        else if (SQL_SUCCEEDED(sr)) {
            m_log.debug("SQLExecute of update succeeded");
            return (m_wideVersion ? widever : ver) + 1;
        }

        m_log.error("update of record failed (t=%s, c=%s, k=%s)", table, context, key);
        logres = log_error(stmt, SQL_HANDLE_STMT);
    } while (attempts && logres.first);

    throw IOException("ODBC StorageService failed to update record.");
}

bool ODBCStorageService::deleteRow(const char *table, const char *context, const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteRow");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    SQLString scontext(context);
    SQLString skey(key);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext.tostr() + "' AND id='" + skey.tostr() + "'";
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr = SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
     if (sr == SQL_NO_DATA)
        return false;
    else if (!SQL_SUCCEEDED(sr)) {
        m_log.error("error deleting record (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to delete record.");
    }

    return true;
}


void ODBCStorageService::cleanup()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("cleanup");
#endif

    scoped_ptr<Mutex> mutex(Mutex::create());

    mutex->lock();

    m_log.info("cleanup thread started... running every %d secs", m_cleanupInterval);

    while (!shutdown) {
        shutdown_wait->timedwait(mutex.get(), m_cleanupInterval);
        if (shutdown)
            break;
        try {
            reap(nullptr);
        }
        catch (std::exception& ex) {
            m_log.error("cleanup thread swallowed exception: %s", ex.what());
        }
    }

    m_log.info("cleanup thread exiting...");

    mutex->unlock();
    Thread::exit(nullptr);
}

void* ODBCStorageService::cleanup_fn(void* cache_p)
{
  ODBCStorageService* cache = (ODBCStorageService*)cache_p;

#ifndef WIN32
  // First, let's block all signals
  Thread::mask_all_signals();
#endif

  // Now run the cleanup process.
  cache->cleanup();
  return nullptr;
}

void ODBCStorageService::updateContext(const char *table, const char* context, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("updateContext");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    char nowbuf[32];
    timestampFromTime(time(nullptr), nowbuf);

    SQLString scontext(context);
    string q = string("UPDATE ") + table + " SET expires = " + timebuf + " WHERE context='" + scontext.tostr() + "' AND expires > " + nowbuf;

    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr = SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr != SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error updating records (t=%s, c=%s)", table, context ? context : "all");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to update context expiration.");
    }
}

void ODBCStorageService::reap(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("reap");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    char nowbuf[32];
    timestampFromTime(time(nullptr), nowbuf);
    string q;
    if (context) {
        SQLString scontext(context);
        q = string("DELETE FROM ") + table + " WHERE context='" + scontext.tostr() + "' AND expires <= " + nowbuf;
    }
    else {
        q = string("DELETE FROM ") + table + " WHERE expires <= " + nowbuf;
    }
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr = SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr != SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error expiring records (t=%s, c=%s)", table, context ? context : "all");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to purge expired records.");
    }
}

void ODBCStorageService::deleteContext(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteContext");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    SQLString scontext(context);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext.tostr() + "'";
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr = SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr != SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error deleting context (t=%s, c=%s)", table, context);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to delete context.");
    }
}

extern "C" int ODBCSTORE_EXPORTS xmltooling_extension_init(void*)
{
    // Register this SS type
    XMLToolingConfig::getConfig().StorageServiceManager.registerFactory("ODBC", ODBCStorageServiceFactory);
    return 0;
}

extern "C" void ODBCSTORE_EXPORTS xmltooling_extension_term()
{
    XMLToolingConfig::getConfig().StorageServiceManager.deregisterFactory("ODBC");
}
