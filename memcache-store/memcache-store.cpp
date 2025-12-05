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
 * memcache-store.cpp
 *
 * Storage Service using memcache (pre memcache tags).
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
# define MCEXT_EXPORTS __declspec(dllexport)
#else
# define MCEXT_EXPORTS
#endif

#include <xmltooling/base.h>

#include <list>
#include <iostream> 
#include <libmemcached/memcached.h>
#include <xercesc/util/XMLUniDefs.hpp>

#include <xmltooling/logging.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/range/algorithm_ext.hpp>

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

namespace {
    static const XMLCh Hosts[] = UNICODE_LITERAL_5(H,o,s,t,s);
    static const XMLCh prefix[] = UNICODE_LITERAL_6(p,r,e,f,i,x);
    static const XMLCh buildMap[] = UNICODE_LITERAL_8(b,u,i,l,d,M,a,p);
    static const XMLCh sendTimeout[] = UNICODE_LITERAL_11(s,e,n,d,T,i,m,e,o,u,t);
    static const XMLCh recvTimeout[] = UNICODE_LITERAL_11(r,e,c,v,T,i,m,e,o,u,t);
    static const XMLCh pollTimeout[] = UNICODE_LITERAL_11(p,o,l,l,T,i,m,e,o,u,t);
    static const XMLCh failLimit[] = UNICODE_LITERAL_9(f,a,i,l,L,i,m,i,t);
    static const XMLCh retryTimeout[] = UNICODE_LITERAL_12(r,e,t,r,y,T,i,m,e,o,u,t);
    static const XMLCh nonBlocking[] = UNICODE_LITERAL_11(n,o,n,B,l,o,c,k,i,n,g);
  
    class mc_record {
    public:
        string value;
        time_t expiration;
        mc_record() {};
        mc_record(string _v, time_t _e) : value(_v), expiration(_e) {}
    };

    class MemcacheBase {
    public:
        MemcacheBase(const DOMElement* e);
        ~MemcacheBase();
        
        bool addMemcache(const char* key, string &value, time_t timeout, uint32_t flags, bool use_prefix = true);
        bool setMemcache(const char* key, string &value, time_t timeout, uint32_t flags, bool use_prefix = true);
        bool replaceMemcache(const char* key, string &value, time_t timeout, uint32_t flags, bool use_prefix = true);
        bool getMemcache(const char* key, string &dest, uint32_t *flags, bool use_prefix = true);
        bool deleteMemcache(const char* key, time_t timeout, bool use_prefix = true);

        void serialize(mc_record &source, string &dest);
        void serialize(list<string> &source, string &dest);
        void deserialize(string &source, mc_record &dest);
        void deserialize(string &source, list<string> &dest);

        bool addLock(string what, bool use_prefix = true);
        void deleteLock(string what, bool use_prefix = true);

    protected:
        Category& m_log;
        memcached_st* memc;
        string m_prefix;
        scoped_ptr<Mutex> m_lock;

    private:
        bool handleError(const char*, memcached_return) const;
    };
  
    class MemcacheStorageService : public StorageService, public MemcacheBase {

    public:
        MemcacheStorageService(const DOMElement* e);
        ~MemcacheStorageService() {}
    
        const Capabilities& getCapabilities() const {
            return m_caps;
        }

        bool createString(const char* context, const char* key, const char* value, time_t expiration);
        int readString(const char* context, const char* key, string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0);
        int updateString(const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0);
        bool deleteString(const char* context, const char* key);
    
        bool createText(const char* context, const char* key, const char* value, time_t expiration) {
            return createString(context, key, value, expiration);
        }
        int readText(const char* context, const char* key, string* pvalue=nullptr, time_t* pexpiration=nullptr, int version=0) {
            return readString(context, key, pvalue, pexpiration, version);
        }
        int updateText(const char* context, const char* key, const char* value=nullptr, time_t expiration=0, int version=0) {
            return updateString(context, key, value, expiration, version);
        }
        bool deleteText(const char* context, const char* key) {
            return deleteString(context, key);
        }
    
        void reap(const char*) {}

        void updateContext(const char* context, time_t expiration);
        void deleteContext(const char* context);

    private:
        string sanitizeKey(const char* key);

        Capabilities m_caps;
        bool m_buildMap;
    };

    StorageService* MemcacheStorageServiceFactory(const DOMElement* const & e, bool) {
        return new MemcacheStorageService(e);
    }
};

MemcacheBase::MemcacheBase(const DOMElement* e)
    : m_log(Category::getInstance("XMLTooling.StorageService.MEMCACHE")), memc(nullptr),
        m_prefix(XMLHelper::getAttrString(e, nullptr, prefix)), m_lock(Mutex::create())
{
    memc = memcached_create(nullptr);
    if (!memc)
        throw XMLToolingException("MemcacheBase::Memcache(): memcached_create() failed");
    m_log.debug("Memcache created");

    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_HASH, MEMCACHED_HASH_CRC);
    m_log.debug("CRC hash set");

    int prop = XMLHelper::getAttrInt(e, 999999, sendTimeout);
    m_log.debug("MEMCACHED_BEHAVIOR_SND_TIMEOUT will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_SND_TIMEOUT, prop);

    prop = XMLHelper::getAttrInt(e, 999999, recvTimeout);
    m_log.debug("MEMCACHED_BEHAVIOR_RCV_TIMEOUT will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_RCV_TIMEOUT, prop);

    prop = XMLHelper::getAttrInt(e, 1000, pollTimeout);
    m_log.debug("MEMCACHED_BEHAVIOR_POLL_TIMEOUT will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_POLL_TIMEOUT, prop);

    prop = XMLHelper::getAttrInt(e, 5, failLimit);
    m_log.debug("MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_SERVER_FAILURE_LIMIT, prop);

    prop = XMLHelper::getAttrInt(e, 30, retryTimeout);
    m_log.debug("MEMCACHED_BEHAVIOR_RETRY_TIMEOUT will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_RETRY_TIMEOUT, prop);

    prop = XMLHelper::getAttrInt(e, 1, nonBlocking);
    m_log.debug("MEMCACHED_BEHAVIOR_NO_BLOCK will be set to %d", prop);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, prop);

    // Grab hosts from the configuration.
    e = e ? XMLHelper::getFirstChildElement(e, Hosts) : nullptr;
    if (!e || !e->hasChildNodes()) {
        memcached_free(memc);
        throw XMLToolingException("Memcache StorageService requires Hosts element in configuration.");
    }
    auto_ptr_char h(XMLHelper::getTextContent(e));
    m_log.debug("INIT: GOT Hosts: %s", h.get());
    memcached_server_st* servers;
    servers = memcached_servers_parse(const_cast<char*>(h.get()));
    m_log.debug("Got %u hosts.",  memcached_server_list_count(servers));
    if (memcached_server_push(memc, servers) != MEMCACHED_SUCCESS) {
        memcached_server_list_free(servers);
        memcached_free(memc);
        throw IOException("MemcacheBase: memcached_server_push() failed");
    }
    memcached_server_list_free(servers);

    m_log.debug("Memcache object initialized");
}

MemcacheBase::~MemcacheBase()
{
    memcached_free(memc);
    m_log.debug("Base object destroyed");
}


bool MemcacheBase::handleError(const char* fn, memcached_return rv) const
{
#ifdef HAVE_MEMCACHED_LAST_ERROR_MESSAGE
    string error = string("Memcache::") + fn + ": " + memcached_last_error_message(memc);
#else
    string error;
    if (rv == MEMCACHED_ERRNO) {
        // System error
        error = string("Memcache::") + fn + "SYSTEM ERROR: " + strerror(memc->cached_errno);
    }
    else {
        error = string("Memcache::") + fn + " Problems: " + memcached_strerror(memc, rv);
    }
#endif
    m_log.error(error);
    throw IOException(error);
}

bool MemcacheBase::addLock(string what, bool use_prefix)
{
    string lock_name = what + ":LOCK";
    string set_val = "1";
    unsigned tries = 5;
    while (!addMemcache(lock_name.c_str(), set_val, 5, 0, use_prefix)) {
        if (tries-- == 0) {
            m_log.debug("Unable to get lock %s... FAILED.", lock_name.c_str());
            return false;
        }
        m_log.debug("Unable to get lock %s... Retrying.", lock_name.c_str());
    
        // sleep 100ms
#ifdef WIN32
        Sleep(100);
#else
        struct timeval tv = { 0, 100000 };
        select(0, 0, 0, 0, &tv);
#endif
    }
    return true;
}

void MemcacheBase::deleteLock(string what, bool use_prefix)
{
    string lock_name = what + ":LOCK";
    deleteMemcache(lock_name.c_str(), 0, use_prefix);
    return;

}  

void MemcacheBase::deserialize(string& source, mc_record& dest)
{
    istringstream is(source, stringstream::in | stringstream::out);
    is >> dest.expiration;
    is.ignore(1); // ignore delimiter
    dest.value = is.str().c_str() + is.tellg();
}

void MemcacheBase::deserialize(string& source, list<string>& dest)
{
    istringstream is(source, stringstream::in | stringstream::out);
    while (!is.eof()) {
        string s;
        is >> s;
        dest.push_back(s);
    }
}

void MemcacheBase::serialize(mc_record& source, string& dest)
{
    ostringstream os(stringstream::in | stringstream::out);
    os << source.expiration;
    os << "-"; // delimiter
    os << source.value;
    dest = os.str();
}

void MemcacheBase::serialize(list<string>& source, string& dest)
{
    ostringstream os(stringstream::in | stringstream::out);
    for(list<string>::iterator iter = source.begin(); iter != source.end(); iter++) {
        if (iter != source.begin()) {
            os << endl;
        }
        os << *iter;
    }
    dest = os.str();
}

bool MemcacheBase::deleteMemcache(const char* key, time_t timeout, bool use_prefix)
{
    string final_key;
    if (use_prefix)
        final_key = m_prefix + key;
    else
        final_key = key;

    Lock lock(m_lock);
    memcached_return rv = memcached_delete(memc, const_cast<char*>(final_key.c_str()), final_key.length(), timeout);

    switch (rv) {
        case MEMCACHED_SUCCESS:
            return true;
        case MEMCACHED_NOTFOUND:
            // Key wasn't there... No biggie.
            return false;
        default:
            return handleError("deleteMemcache", rv);
    }
}

bool MemcacheBase::getMemcache(const char* key, string& dest, uint32_t* flags, bool use_prefix)
{
    string final_key;
    if (use_prefix)
        final_key = m_prefix + key;
    else
        final_key = key;

    Lock lock(m_lock);
    size_t len;
    memcached_return rv;
    char* result = memcached_get(memc, const_cast<char*>(final_key.c_str()), final_key.length(), &len, flags, &rv);

    switch (rv) {
        case MEMCACHED_SUCCESS:
            dest = result;
            free(result);
            return true;
        case MEMCACHED_NOTFOUND:
            m_log.debug("Key %s not found in memcache...", key);
            return false;
        default:
            return handleError("getMemcache", rv);
    }
}

bool MemcacheBase::addMemcache(const char* key, string& value, time_t timeout, uint32_t flags, bool use_prefix)
{
    string final_key;
    if (use_prefix)
        final_key = m_prefix + key;
    else
        final_key = key;

    Lock lock(m_lock);
    memcached_return rv = memcached_add(
        memc, const_cast<char*>(final_key.c_str()), final_key.length(), const_cast<char*>(value.c_str()), value.length(), timeout, flags
        );

    switch (rv) {
        case MEMCACHED_SUCCESS:
            return true;
        case MEMCACHED_NOTSTORED:
            return false;
        default:
            return handleError("addMemcache", rv);
    }
}

bool MemcacheBase::setMemcache(const char* key, string& value, time_t timeout, uint32_t flags, bool use_prefix)
{
    string final_key;
    if (use_prefix)
        final_key = m_prefix + key;
    else
        final_key = key;

    Lock lock(m_lock);
    memcached_return rv = memcached_set(
        memc, const_cast<char*>(final_key.c_str()), final_key.length(), const_cast<char*>(value.c_str()), value.length(), timeout, flags
        );

    if (rv == MEMCACHED_SUCCESS)
        return true;
    return handleError("setMemcache", rv);
}

bool MemcacheBase::replaceMemcache(const char* key, string& value, time_t timeout, uint32_t flags, bool use_prefix)
{
  
    string final_key;
    if (use_prefix)
        final_key = m_prefix + key;
    else
        final_key = key;

    Lock lock(m_lock);
    memcached_return rv = memcached_replace(
        memc, const_cast<char*>(final_key.c_str()), final_key.length(), const_cast<char*>(value.c_str()), value.length(), timeout, flags
        );

    switch (rv) {
        case MEMCACHED_SUCCESS:
            return true;
        case MEMCACHED_NOTSTORED:
            // not there
            return false;
        default:
            return handleError("replaceMemcache", rv);
    }
}


MemcacheStorageService::MemcacheStorageService(const DOMElement* e)
    : MemcacheBase(e), m_caps(80, 250 - m_prefix.length() - 1 - 80, 255),
        m_buildMap(XMLHelper::getAttrBool(e, false, buildMap))
{
    if (m_buildMap)
        m_log.debug("Cache built with buildMap ON");
}

string MemcacheStorageService::sanitizeKey(const char* key)
{
    string s_key = key;
    remove_erase_if(s_key, is_space());
    return s_key;
}

bool MemcacheStorageService::createString(const char* context, const char* key, const char* value, time_t expiration)
{
    m_log.debug("createString ctx: %s - key: %s", context, key);

    string final_key = string(context) + ':' + sanitizeKey(key);

    mc_record rec(value, expiration);
    string final_value;
    serialize(rec, final_value);

    bool result = addMemcache(final_key.c_str(), final_value, expiration, 1); // the flag will be the version

    if (result && m_buildMap) {
        m_log.debug("Got result, updating map");

        string map_name = context;
        // we need to update the context map
        if (!addLock(map_name)) {
            m_log.error("Unable to get lock for context %s!", context);
            deleteMemcache(final_key.c_str(), 0);
            return false;
        }

        string ser_arr;
        uint32_t flags;
        bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
    
        list<string> contents;
        if (result) {
            m_log.debug("Match found. Parsing...");
            deserialize(ser_arr, contents);
            if (m_log.isDebugEnabled()) {
                m_log.debug("Iterating retrieved session map...");
                for(list<string>::const_iterator iter = contents.begin(); iter != contents.end(); ++iter)
                    m_log.debug("value = %s", iter->c_str());
            }
        }
        else {
            m_log.debug("New context: %s", map_name.c_str());
        }

        contents.push_back(sanitizeKey(key));
        serialize(contents, ser_arr);
        setMemcache(map_name.c_str(), ser_arr, expiration, 0);
        deleteLock(map_name);
    }
    return result;
}

int MemcacheStorageService::readString(const char* context, const char* key, string* pvalue, time_t* pexpiration, int version)
{
    m_log.debug("readString ctx: %s - key: %s", context, key);

    string final_key = string(context) + ":" + sanitizeKey(key);
    uint32_t rec_version;
    string value;

    if (m_buildMap) {
        m_log.debug("Checking context");
        string map_name = context;
        string ser_arr;
        uint32_t flags;
        bool ctx_found = getMemcache(map_name.c_str(), ser_arr, &flags);
        if (!ctx_found)
            return 0;
    }

    bool found = getMemcache(final_key.c_str(), value, &rec_version);
    if (!found)
        return 0;

    mc_record rec;
    if (pexpiration || pvalue)
        deserialize(value, rec);
    
    if (pexpiration)
        *pexpiration = rec.expiration;

    if (version && rec_version <= (uint32_t)version)
        return version;

    if (pvalue)
        *pvalue = rec.value;

    return rec_version;
}

int MemcacheStorageService::updateString(const char* context, const char* key, const char* value, time_t expiration, int version)
{
    m_log.debug("updateString ctx: %s - key: %s", context, key);

    time_t final_exp = expiration;
    time_t* want_expiration = nullptr;
    if (!final_exp)
        want_expiration = &final_exp;

    int read_res = readString(context, sanitizeKey(key).c_str(), nullptr, want_expiration, version);

    if (!read_res) {
        // not found
        return read_res;
    }

    if (version && version != read_res) {
        // version incorrect
        return -1;
    }

    // Proceding with update
    string final_key = string(context) + ':' + sanitizeKey(key);
    mc_record rec(value, final_exp);
    string final_value;
    serialize(rec, final_value);

    replaceMemcache(final_key.c_str(), final_value, final_exp, ++version);
    return version;
}

bool MemcacheStorageService::deleteString(const char* context, const char* key)
{
    m_log.debug("deleteString ctx: %s - key: %s", context, key);
  
    string final_key = string(context) + ':' + sanitizeKey(key);

    // Not updating context map, if there is one. There is no need.
    return deleteMemcache(final_key.c_str(), 0);
}

void MemcacheStorageService::updateContext(const char* context, time_t expiration)
{

    m_log.debug("updateContext ctx: %s", context);

    if (!m_buildMap) {
        m_log.error("updateContext invoked on a Storage with no context map built!");
        return;
    }

    string map_name = context;
    string ser_arr;
    uint32_t flags;
    bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
  
    list<string> contents;
    if (result) {
        m_log.debug("Match found. Parsing...");
        deserialize(ser_arr, contents);
    
        m_log.debug("Iterating retrieved session map...");
        for(list<string>::const_iterator iter = contents.begin(); iter != contents.end(); ++iter) {
            // Update expiration times
            string value;
            int read_res = readString(context, iter->c_str(), &value, nullptr, 0);
            if (!read_res) {
                // not found
                continue;
            }

            updateString(context, iter->c_str(), value.c_str(), expiration, read_res);
        }
        replaceMemcache(map_name.c_str(), ser_arr, expiration, flags);
    }
}

void MemcacheStorageService::deleteContext(const char* context)
{

    m_log.debug("deleteContext ctx: %s", context);

    if (!m_buildMap) {
        m_log.error("deleteContext invoked on a Storage with no context map built!");
        return;
    }

    string map_name = context;
    string ser_arr;
    uint32_t flags;
    bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
  
    list<string> contents;
    if (result) {
        m_log.debug("Match found. Parsing...");
        deserialize(ser_arr, contents);
    
        m_log.debug("Iterating retrieved session map...");
        for (list<string>::const_iterator iter = contents.begin(); iter != contents.end(); ++iter) {
            string final_key = map_name + ':' + *iter;
            deleteString(context, iter->c_str());
        }
    
        deleteMemcache(map_name.c_str(), 0);
    }
}

extern "C" int MCEXT_EXPORTS xmltooling_extension_init(void*) {
    // Register this SS type
    XMLToolingConfig::getConfig().StorageServiceManager.registerFactory("MEMCACHE", MemcacheStorageServiceFactory);
    return 0;
}

extern "C" void MCEXT_EXPORTS xmltooling_extension_term() {
    XMLToolingConfig::getConfig().StorageServiceManager.deregisterFactory("MEMCACHE");
}
