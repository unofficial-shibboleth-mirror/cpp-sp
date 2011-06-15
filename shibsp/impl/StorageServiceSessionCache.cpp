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
 * StorageServiceSessionCache.cpp
 *
 * StorageService-based SessionCache implementation.
 *
 * Instead of optimizing this plugin with a buffering scheme that keeps objects around
 * and avoids extra parsing steps, I'm assuming that systems that require such can
 * layer their own cache plugin on top of this version either by delegating to it
 * or using the remoting support. So this version will load sessions directly
 * from the StorageService, instantiate enough to expose the Session API,
 * and then delete everything when they're unlocked. All data in memory is always
 * kept in sync with the StorageService (no lazy updates).
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SessionCacheEx.h"
#include "TransactionLog.h"
#include "attribute/Attribute.h"
#include "handler/RemotedHandler.h"
#include "remoting/ListenerService.h"
#include "util/SPConstants.h"

#include <algorithm>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/util/StorageService.h>
using namespace opensaml::saml2md;
#else
# include <ctime>
# include <xmltooling/util/DateTime.h>
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class StoredSession;
    class SSCache : public SessionCacheEx
#ifndef SHIBSP_LITE
        ,public virtual Remoted
#endif
    {
    public:
        SSCache(const DOMElement* e);
        ~SSCache();

#ifndef SHIBSP_LITE
        void receive(DDF& in, ostream& out);

        void insert(
            const Application& app,
            const HTTPRequest& httpRequest,
            HTTPResponse& httpResponse,
            time_t expires,
            const saml2md::EntityDescriptor* issuer=nullptr,
            const XMLCh* protocol=nullptr,
            const saml2::NameID* nameid=nullptr,
            const XMLCh* authn_instant=nullptr,
            const XMLCh* session_index=nullptr,
            const XMLCh* authncontext_class=nullptr,
            const XMLCh* authncontext_decl=nullptr,
            const vector<const Assertion*>* tokens=nullptr,
            const vector<Attribute*>* attributes=nullptr
            );
        vector<string>::size_type logout(
            const Application& app,
            const saml2md::EntityDescriptor* issuer,
            const saml2::NameID& nameid,
            const set<string>* indexes,
            time_t expires,
            vector<string>& sessions
            );
        bool matches(
            const Application& app,
            const HTTPRequest& request,
            const saml2md::EntityDescriptor* issuer,
            const saml2::NameID& nameid,
            const set<string>* indexes
            );
#endif
        Session* find(const Application& app, const char* key, const char* client_addr=nullptr, time_t* timeout=nullptr);
        void remove(const Application& app, const char* key);
        void test();

        string active(const Application& app, const HTTPRequest& request) {
            if (!m_inboundHeader.empty()) {
                string session_id = request.getHeader(m_inboundHeader.c_str());
                if (!session_id.empty())
                    return session_id;
            }
            pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");
            const char* session_id = request.getCookie(shib_cookie.first.c_str());
            return (session_id ? session_id : "");
        }

        Session* find(const Application& app, const HTTPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr) {
            string id = active(app, request);
            if (!id.empty())
                return find(app, id.c_str(), client_addr, timeout);
            return nullptr;
        }

        Session* find(const Application& app, HTTPRequest& request, const char* client_addr=nullptr, time_t* timeout=nullptr);
        void remove(const Application& app, const HTTPRequest& request, HTTPResponse* response=nullptr);

        unsigned long getCacheTimeout(const Application& app) {
            // Computes offset for adjusting expiration of sessions.
            // This can either be static, or dynamic based on the per-app session timeout.
            if (m_cacheTimeout)
                return m_cacheTimeout;
            pair<bool,unsigned int> timeout = pair<bool,unsigned int>(false, 3600);
            const PropertySet* props = app.getPropertySet("Sessions");
            if (props) {
                timeout = props->getUnsignedInt("timeout");
                if (!timeout.first)
                    timeout.second = 3600;
            }
            return timeout.second + m_cacheAllowance;
        }

        Category& m_log;
        bool inproc;
#ifndef SHIBSP_LITE
        StorageService* m_storage;
        StorageService* m_storage_lite;
#endif

    private:
#ifndef SHIBSP_LITE
        // maintain back-mappings of NameID/SessionIndex -> session key
        void insert(const char* key, time_t expires, const char* name, const char* index);
        bool stronglyMatches(const XMLCh* idp, const XMLCh* sp, const saml2::NameID& n1, const saml2::NameID& n2) const;

        bool m_cacheAssertions;
#endif
        const DOMElement* m_root;         // Only valid during initialization
        unsigned long m_inprocTimeout,m_cacheTimeout,m_cacheAllowance;
        string m_inboundHeader,m_outboundHeader;

        // inproc means we buffer sessions in memory
        RWLock* m_lock;
        map<string,StoredSession*> m_hashtable;

        // management of buffered sessions
       void dormant(const char* key);
       static void* cleanup_fn(void*);

        bool shutdown;
        CondWait* shutdown_wait;
        Thread* cleanup_thread;
    };

    class StoredSession : public virtual Session
    {
    public:
        StoredSession(SSCache* cache, DDF& obj) : m_obj(obj),
#ifndef SHIBSP_LITE
                m_nameid(nullptr),
#endif
                m_cache(cache), m_expires(0), m_lastAccess(time(nullptr)), m_lock(nullptr) {
            auto_ptr_XMLCh exp(m_obj["expires"].string());
            if (exp.get()) {
                DateTime iso(exp.get());
                iso.parseDateTime();
                m_expires = iso.getEpoch();
            }

#ifndef SHIBSP_LITE
            const char* nameid = obj["nameid"].string();
            if (nameid) {
                // Parse and bind the document into an XMLObject.
                istringstream instr(nameid);
                DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr);
                XercesJanitor<DOMDocument> janitor(doc);
                auto_ptr<saml2::NameID> n(saml2::NameIDBuilder::buildNameID());
                n->unmarshall(doc->getDocumentElement(), true);
                janitor.release();
                m_nameid = n.release();
            }
#endif
            if (cache->inproc)
                m_lock = Mutex::create();
        }

        ~StoredSession() {
            delete m_lock;
            m_obj.destroy();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
#ifndef SHIBSP_LITE
            delete m_nameid;
            for_each(m_tokens.begin(), m_tokens.end(), cleanup_pair<string,Assertion>());
#endif
        }

        Lockable* lock() {
            if (m_lock)
                m_lock->lock();
            return this;
        }
        void unlock() {
            if (m_lock)
                m_lock->unlock();
            else
                delete this;
        }

        const char* getID() const {
            return m_obj.name();
        }
        const char* getApplicationID() const {
            return m_obj["application_id"].string();
        }
        const char* getClientAddress() const {
            return m_obj["client_addr"].string();
        }
        const char* getEntityID() const {
            return m_obj["entity_id"].string();
        }
        const char* getProtocol() const {
            return m_obj["protocol"].string();
        }
        const char* getAuthnInstant() const {
            return m_obj["authn_instant"].string();
        }
#ifndef SHIBSP_LITE
        const saml2::NameID* getNameID() const {
            return m_nameid;
        }
#endif
        const char* getSessionIndex() const {
            return m_obj["session_index"].string();
        }
        const char* getAuthnContextClassRef() const {
            return m_obj["authncontext_class"].string();
        }
        const char* getAuthnContextDeclRef() const {
            return m_obj["authncontext_decl"].string();
        }
        const vector<Attribute*>& getAttributes() const {
            if (m_attributes.empty())
                unmarshallAttributes();
            return m_attributes;
        }
        const multimap<string,const Attribute*>& getIndexedAttributes() const {
            if (m_attributeIndex.empty()) {
                if (m_attributes.empty())
                    unmarshallAttributes();
                for (vector<Attribute*>::const_iterator a = m_attributes.begin(); a != m_attributes.end(); ++a) {
                    const vector<string>& aliases = (*a)->getAliases();
                    for (vector<string>::const_iterator alias = aliases.begin(); alias != aliases.end(); ++alias)
                        m_attributeIndex.insert(multimap<string,const Attribute*>::value_type(*alias, *a));
                }
            }
            return m_attributeIndex;
        }
        const vector<const char*>& getAssertionIDs() const {
            if (m_ids.empty()) {
                DDF ids = m_obj["assertions"];
                DDF id = ids.first();
                while (id.isstring()) {
                    m_ids.push_back(id.string());
                    id = ids.next();
                }
            }
            return m_ids;
        }

        void validate(const Application& application, const char* client_addr, time_t* timeout);

#ifndef SHIBSP_LITE
        void addAttributes(const vector<Attribute*>& attributes);
        const Assertion* getAssertion(const char* id) const;
        void addAssertion(Assertion* assertion);
#endif

        time_t getExpiration() const { return m_expires; }
        time_t getLastAccess() const { return m_lastAccess; }

    private:
        void unmarshallAttributes() const;

        DDF m_obj;
#ifndef SHIBSP_LITE
        saml2::NameID* m_nameid;
        mutable map<string,Assertion*> m_tokens;
#endif
        mutable vector<Attribute*> m_attributes;
        mutable multimap<string,const Attribute*> m_attributeIndex;
        mutable vector<const char*> m_ids;

        SSCache* m_cache;
        time_t m_expires,m_lastAccess;
        Mutex* m_lock;
    };

    SessionCache* SHIBSP_DLLLOCAL StorageServiceCacheFactory(const DOMElement* const & e)
    {
        return new SSCache(e);
    }
}

Session* SessionCache::find(const Application& application, HTTPRequest& request, const char* client_addr, time_t* timeout)
{
    return find(application, const_cast<const HTTPRequest&>(request), client_addr, timeout);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
    SPConfig::getConfig().SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceCacheFactory);
}

Session::Session()
{
}

Session::~Session()
{
}

void StoredSession::unmarshallAttributes() const
{
    Attribute* attribute;
    DDF attrs = m_obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        try {
            attribute = Attribute::unmarshall(attr);
            m_attributes.push_back(attribute);
            if (m_cache->m_log.isDebugEnabled())
                m_cache->m_log.debug("unmarshalled attribute (ID: %s) with %d value%s",
                    attribute->getId(), attr.first().integer(), attr.first().integer()!=1 ? "s" : "");
        }
        catch (AttributeException& ex) {
            const char* id = attr.first().name();
            m_cache->m_log.error("error unmarshalling attribute (ID: %s): %s", id ? id : "none", ex.what());
        }
        attr = attrs.next();
    }
}

void StoredSession::validate(const Application& app, const char* client_addr, time_t* timeout)
{
    time_t now = time(nullptr);

    // Basic expiration?
    if (m_expires > 0) {
        if (now > m_expires) {
            m_cache->m_log.info("session expired (ID: %s)", getID());
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }
    }

    // Address check?
    if (client_addr) {
        if (m_cache->m_log.isDebugEnabled())
            m_cache->m_log.debug("comparing client address %s against %s", client_addr, getClientAddress());
        if (!XMLString::equals(getClientAddress(),client_addr)) {
            m_cache->m_log.warn("client address mismatch");
            throw RetryableProfileException(
                "Your IP address ($1) does not match the address recorded at the time the session was established.",
                params(1,client_addr)
                );
        }
    }

    if (!timeout)
        return;

    if (!SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        DDF in("touch::"STORAGESERVICE_SESSION_CACHE"::SessionCache"), out;
        DDFJanitor jin(in);
        in.structure();
        in.addmember("key").string(getID());
        in.addmember("version").integer(m_obj["version"].integer());
        in.addmember("application_id").string(app.getId());
        if (*timeout) {
            // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
            struct tm* ptime=gmtime(timeout);
#else
            struct tm res;
            struct tm* ptime=gmtime_r(timeout,&res);
#endif
            char timebuf[32];
            strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
            in.addmember("timeout").string(timebuf);
        }

        try {
            out=app.getServiceProvider().getListenerService()->send(in);
        }
        catch (...) {
            out.destroy();
            throw;
        }

        if (out.isstruct()) {
            // We got an updated record back.
            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_attributeIndex.clear();
            m_obj.destroy();
            m_obj = out;
        }
    }
    else {
#ifndef SHIBSP_LITE
        if (!m_cache->m_storage)
            throw ConfigurationException("Session touch requires a StorageService.");

        // Do a versioned read.
        string record;
        time_t lastAccess;
        int curver = m_obj["version"].integer();
        int ver = m_cache->m_storage->readText(getID(), "session", &record, &lastAccess, curver);
        if (ver == 0) {
            m_cache->m_log.warn("unsuccessful versioned read of session (ID: %s), cache out of sync?", getID());
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }

        // Adjust for expiration to recover last access time and check timeout.
        unsigned long cacheTimeout = m_cache->getCacheTimeout(app);
        lastAccess -= cacheTimeout;
        if (*timeout > 0 && now - lastAccess >= *timeout) {
            m_cache->m_log.info("session timed out (ID: %s)", getID());
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }

        // Update storage expiration, if possible.
        try {
            m_cache->m_storage->updateContext(getID(), now + cacheTimeout);
        }
        catch (exception& ex) {
            m_cache->m_log.error("failed to update session expiration: %s", ex.what());
        }

        if (ver > curver) {
            // We got an updated record back.
            DDF newobj;
            istringstream in(record);
            in >> newobj;
            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_attributeIndex.clear();
            m_obj.destroy();
            m_obj = newobj;
        }
#else
        throw ConfigurationException("Session touch requires a StorageService.");
#endif
    }

    m_lastAccess = now;
}

#ifndef SHIBSP_LITE

void StoredSession::addAttributes(const vector<Attribute*>& attributes)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("addAttributes");
#endif

    if (!m_cache->m_storage)
        throw ConfigurationException("Session modification requires a StorageService.");

    m_cache->m_log.debug("adding attributes to session (%s)", getID());

    int ver;
    do {
        DDF attr;
        DDF attrs = m_obj["attributes"];
        if (!attrs.islist())
            attrs = m_obj.addmember("attributes").list();
        for (vector<Attribute*>::const_iterator a=attributes.begin(); a!=attributes.end(); ++a) {
            attr = (*a)->marshall();
            attrs.add(attr);
        }

        // Tentatively increment the version.
        m_obj["version"].integer(m_obj["version"].integer()+1);

        ostringstream str;
        str << m_obj;
        string record(str.str());

        try {
            ver = m_cache->m_storage->updateText(getID(), "session", record.c_str(), 0, m_obj["version"].integer()-1);
        }
        catch (exception&) {
            // Roll back modification to record.
            m_obj["version"].integer(m_obj["version"].integer()-1);
            vector<Attribute*>::size_type count = attributes.size();
            while (count--)
                attrs.last().destroy();
            throw;
        }

        if (ver <= 0) {
            // Roll back modification to record.
            m_obj["version"].integer(m_obj["version"].integer()-1);
            vector<Attribute*>::size_type count = attributes.size();
            while (count--)
                attrs.last().destroy();
        }
        if (!ver) {
            // Fatal problem with update.
            throw IOException("Unable to update stored session.");
        }
        else if (ver < 0) {
            // Out of sync.
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(getID(), "session", &record, nullptr);
            if (!ver) {
                m_cache->m_log.error("readText failed on StorageService for session (%s)", getID());
                throw IOException("Unable to read back stored session.");
            }

            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_attributeIndex.clear();
            newobj["version"].integer(ver);
            m_obj.destroy();
            m_obj = newobj;

            ver = -1;
        }
    } while (ver < 0);  // negative indicates a sync issue so we retry

    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.infoStream() <<
        "Added the following attributes to session (ID: " <<
            getID() <<
        ") for (applicationId: " <<
            m_obj["application_id"].string() <<
        ") {";
    for (vector<Attribute*>::const_iterator a=attributes.begin(); a!=attributes.end(); ++a)
        xlog->log.infoStream() << "\t" << (*a)->getId() << " (" << (*a)->valueCount() << " values)";
    xlog->log.info("}");

    // We own them now, so clean them up.
    for_each(attributes.begin(), attributes.end(), xmltooling::cleanup<Attribute>());
}

const Assertion* StoredSession::getAssertion(const char* id) const
{
    if (!m_cache->m_storage)
        throw ConfigurationException("Assertion retrieval requires a StorageService.");

    map<string,Assertion*>::const_iterator i = m_tokens.find(id);
    if (i!=m_tokens.end())
        return i->second;

    string tokenstr;
    if (!m_cache->m_storage->readText(getID(), id, &tokenstr, nullptr))
        throw FatalProfileException("Assertion not found in cache.");

    // Parse and bind the document into an XMLObject.
    istringstream instr(tokenstr);
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr);
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();

    Assertion* token = dynamic_cast<Assertion*>(xmlObject.get());
    if (!token)
        throw FatalProfileException("Request for cached assertion returned an unknown object type.");

    // Transfer ownership to us.
    xmlObject.release();
    m_tokens[id]=token;
    return token;
}

void StoredSession::addAssertion(Assertion* assertion)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("addAssertion");
#endif

    if (!m_cache->m_storage)
        throw ConfigurationException("Session modification requires a StorageService.");

    if (!assertion)
        throw FatalProfileException("Unknown object type passed to session for storage.");

    auto_ptr_char id(assertion->getID());

    m_cache->m_log.debug("adding assertion (%s) to session (%s)", id.get(), getID());

    time_t exp;
    if (!m_cache->m_storage->readText(getID(), "session", nullptr, &exp))
        throw IOException("Unable to load expiration time for stored session.");

    ostringstream tokenstr;
    tokenstr << *assertion;
    if (!m_cache->m_storage->createText(getID(), id.get(), tokenstr.str().c_str(), exp))
        throw IOException("Attempted to insert duplicate assertion ID into session.");

    int ver;
    do {
        DDF token = DDF(nullptr).string(id.get());
        m_obj["assertions"].add(token);

        // Tentatively increment the version.
        m_obj["version"].integer(m_obj["version"].integer()+1);

        ostringstream str;
        str << m_obj;
        string record(str.str());

        try {
            ver = m_cache->m_storage->updateText(getID(), "session", record.c_str(), 0, m_obj["version"].integer()-1);
        }
        catch (exception&) {
            token.destroy();
            m_obj["version"].integer(m_obj["version"].integer()-1);
            m_cache->m_storage->deleteText(getID(), id.get());
            throw;
        }

        if (ver <= 0) {
            token.destroy();
            m_obj["version"].integer(m_obj["version"].integer()-1);
        }
        if (!ver) {
            // Fatal problem with update.
            m_cache->m_log.error("updateText failed on StorageService for session (%s)", getID());
            m_cache->m_storage->deleteText(getID(), id.get());
            throw IOException("Unable to update stored session.");
        }
        else if (ver < 0) {
            // Out of sync.
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(getID(), "session", &record, nullptr);
            if (!ver) {
                m_cache->m_log.error("readText failed on StorageService for session (%s)", getID());
                m_cache->m_storage->deleteText(getID(), id.get());
                throw IOException("Unable to read back stored session.");
            }

            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_attributeIndex.clear();
            newobj["version"].integer(ver);
            m_obj.destroy();
            m_obj = newobj;

            ver = -1;
        }
    } while (ver < 0); // negative indicates a sync issue so we retry

    m_ids.clear();
    delete assertion;

    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.info(
        "Added assertion (ID: %s) to session for (applicationId: %s) with (ID: %s)",
        id.get(), m_obj["application_id"].string(), getID()
        );
}

#endif

SessionCache::SessionCache()
{
}

SessionCache::~SessionCache()
{
}

SessionCacheEx::SessionCacheEx()
{
}

SessionCacheEx::~SessionCacheEx()
{
}

SSCache::SSCache(const DOMElement* e)
    : m_log(Category::getInstance(SHIBSP_LOGCAT".SessionCache")), inproc(true),
#ifndef SHIBSP_LITE
      m_storage(nullptr), m_storage_lite(nullptr), m_cacheAssertions(true),
#endif
      m_root(e), m_inprocTimeout(900), m_cacheTimeout(0), m_cacheAllowance(0),
      m_lock(nullptr), shutdown(false), shutdown_wait(nullptr), cleanup_thread(nullptr)
{
    SPConfig& conf = SPConfig::getConfig();
    inproc = conf.isEnabled(SPConfig::InProcess);

    static const XMLCh cacheAllowance[] =   UNICODE_LITERAL_14(c,a,c,h,e,A,l,l,o,w,a,n,c,e);
    static const XMLCh cacheAssertions[] =  UNICODE_LITERAL_15(c,a,c,h,e,A,s,s,e,r,t,i,o,n,s);
    static const XMLCh cacheTimeout[] =     UNICODE_LITERAL_12(c,a,c,h,e,T,i,m,e,o,u,t);
    static const XMLCh inprocTimeout[] =    UNICODE_LITERAL_13(i,n,p,r,o,c,T,i,m,e,o,u,t);
    static const XMLCh inboundHeader[] =    UNICODE_LITERAL_13(i,n,b,o,u,n,d,H,e,a,d,e,r);
    static const XMLCh outboundHeader[] =   UNICODE_LITERAL_14(o,u,t,b,o,u,n,d,H,e,a,d,e,r);
    static const XMLCh _StorageService[] =  UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh _StorageServiceLite[] = UNICODE_LITERAL_18(S,t,o,r,a,g,e,S,e,r,v,i,c,e,L,i,t,e);

    m_cacheTimeout = XMLHelper::getAttrInt(e, 0, cacheTimeout);
    m_cacheAllowance = XMLHelper::getAttrInt(e, 0, cacheAllowance);
    if (inproc)
        m_inprocTimeout = XMLHelper::getAttrInt(e, 900, inprocTimeout);
    m_inboundHeader = XMLHelper::getAttrString(e, nullptr, inboundHeader);
    if (!m_inboundHeader.empty())
        RemotedHandler::addRemotedHeader(m_inboundHeader.c_str());
    m_outboundHeader = XMLHelper::getAttrString(e, nullptr, outboundHeader);

#ifndef SHIBSP_LITE
    if (conf.isEnabled(SPConfig::OutOfProcess)) {
        string ssid(XMLHelper::getAttrString(e, nullptr, _StorageService));
        if (!ssid.empty()) {
            m_storage = conf.getServiceProvider()->getStorageService(ssid.c_str());
            if (m_storage)
                m_log.info("bound to StorageService (%s)", ssid.c_str());
            else
                m_log.warn("specified StorageService (%s) not found", ssid.c_str());
        }
        if (!m_storage) {
            m_storage = conf.getServiceProvider()->getStorageService(nullptr);
            if (m_storage)
                m_log.info("bound to arbitrary StorageService");
            else
                throw ConfigurationException("SessionCache unable to locate StorageService, check configuration.");
        }

        ssid = XMLHelper::getAttrString(e, nullptr, _StorageServiceLite);
        if (!ssid.empty()) {
            m_storage_lite = conf.getServiceProvider()->getStorageService(ssid.c_str());
            if (m_storage_lite)
                m_log.info("bound to 'lite' StorageService (%s)", ssid.c_str());
            else
                m_log.warn("specified 'lite' StorageService (%s) not found", ssid.c_str());
        }
        if (!m_storage_lite) {
            m_log.info("StorageService for 'lite' use not set, using standard StorageService");
            m_storage_lite = m_storage;
        }

        m_cacheAssertions = XMLHelper::getAttrBool(e, true, cacheAssertions);
    }
#endif

    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (inproc) {
        if (!conf.isEnabled(SPConfig::OutOfProcess) && !listener)
            throw ConfigurationException("SessionCache requires a ListenerService, but none available.");
        m_lock = RWLock::create();
        shutdown_wait = CondWait::create();
        cleanup_thread = Thread::create(&cleanup_fn, this);
    }
#ifndef SHIBSP_LITE
    else {
        if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
            listener->regListener("find::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
            listener->regListener("remove::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
            listener->regListener("touch::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
        }
        else {
            m_log.info("no ListenerService available, cache remoting disabled");
        }
    }
#endif
}

SSCache::~SSCache()
{
    if (inproc) {
        // Shut down the cleanup thread and let it know...
        shutdown = true;
        shutdown_wait->signal();
        cleanup_thread->join(nullptr);

        for_each(m_hashtable.begin(),m_hashtable.end(),cleanup_pair<string,StoredSession>());
        delete m_lock;

        delete cleanup_thread;
        delete shutdown_wait;
    }
#ifndef SHIBSP_LITE
    else {
        SPConfig& conf = SPConfig::getConfig();
        ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
        if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
            listener->unregListener("find::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
            listener->unregListener("remove::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
            listener->unregListener("touch::"STORAGESERVICE_SESSION_CACHE"::SessionCache",this);
        }
    }
#endif
}

#ifndef SHIBSP_LITE

void SSCache::test()
{
    auto_ptr_char temp(SAMLConfig::getConfig().generateIdentifier());
    m_storage->createString("SessionCacheTest", temp.get(), "Test", time(nullptr) + 60);
    m_storage->deleteString("SessionCacheTest", temp.get());
}

void SSCache::insert(const char* key, time_t expires, const char* name, const char* index)
{
    string dup;
    if (strlen(name) > 255) {
        dup = string(name).substr(0,255);
        name = dup.c_str();
    }

    DDF obj;
    DDFJanitor jobj(obj);

    // Since we can't guarantee uniqueness, check for an existing record.
    string record;
    time_t recordexp;
    int ver = m_storage_lite->readText("NameID", name, &record, &recordexp);
    if (ver > 0) {
        // Existing record, so we need to unmarshall it.
        istringstream in(record);
        in >> obj;
    }
    else {
        // New record.
        obj = DDF(nullptr).structure();
    }

    if (!index || !*index)
        index = "_shibnull";
    DDF sessions = obj.addmember(index);
    if (!sessions.islist())
        sessions.list();
    DDF session = DDF(nullptr).string(key);
    sessions.add(session);

    // Remarshall the record.
    ostringstream out;
    out << obj;

    // Try and store it back...
    if (ver > 0) {
        ver = m_storage_lite->updateText("NameID", name, out.str().c_str(), max(expires, recordexp), ver);
        if (ver <= 0) {
            // Out of sync, or went missing, so retry.
            return insert(key, expires, name, index);
        }
    }
    else if (!m_storage_lite->createText("NameID", name, out.str().c_str(), expires)) {
        // Hit a dup, so just retry, hopefully hitting the other branch.
        return insert(key, expires, name, index);
    }
}

void SSCache::insert(
    const Application& app,
    const HTTPRequest& httpRequest,
    HTTPResponse& httpResponse,
    time_t expires,
    const saml2md::EntityDescriptor* issuer,
    const XMLCh* protocol,
    const saml2::NameID* nameid,
    const XMLCh* authn_instant,
    const XMLCh* session_index,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
    const vector<const Assertion*>* tokens,
    const vector<Attribute*>* attributes
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("insert");
#endif
    if (!m_storage)
        throw ConfigurationException("SessionCache insertion requires a StorageService.");

    m_log.debug("creating new session");

    time_t now = time(nullptr);
    auto_ptr_char index(session_index);
    auto_ptr_char entity_id(issuer ? issuer->getEntityID() : nullptr);
    auto_ptr_char name(nameid ? nameid->getName() : nullptr);

    if (nameid) {
        // Check for a pending logout.
        char namebuf[256];
        strncpy(namebuf, name.get(), 255);
        namebuf[255] = 0;
        string pending;
        int ver = m_storage_lite->readText("Logout", namebuf, &pending);
        if (ver > 0) {
            DDF pendobj;
            DDFJanitor jpend(pendobj);
            istringstream pstr(pending);
            pstr >> pendobj;
            // IdP.SP.index contains logout expiration, if any.
            DDF deadmenwalking = pendobj[issuer ? entity_id.get() : "_shibnull"][app.getRelyingParty(issuer)->getString("entityID").second];
            const char* logexpstr = deadmenwalking[session_index ? index.get() : "_shibnull"].string();
            if (!logexpstr && session_index)    // we tried an exact session match, now try for nullptr
                logexpstr = deadmenwalking["_shibnull"].string();
            if (logexpstr) {
                auto_ptr_XMLCh dt(logexpstr);
                DateTime dtobj(dt.get());
                dtobj.parseDateTime();
                time_t logexp = dtobj.getEpoch();
                if (now - XMLToolingConfig::getConfig().clock_skew_secs < logexp)
                    throw FatalProfileException("A logout message from your identity provider has blocked your login attempt.");
            }
        }
    }

    auto_ptr_char key(SAMLConfig::getConfig().generateIdentifier());

    // Store session properties in DDF.
    DDF obj = DDF(key.get()).structure();
    DDFJanitor entryobj(obj);
    obj.addmember("version").integer(1);
    obj.addmember("application_id").string(app.getId());

    // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
    struct tm* ptime=gmtime(&expires);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&expires,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
    obj.addmember("expires").string(timebuf);

    obj.addmember("client_addr").string(httpRequest.getRemoteAddr().c_str());
    if (issuer)
        obj.addmember("entity_id").string(entity_id.get());
    if (protocol) {
        auto_ptr_char prot(protocol);
        obj.addmember("protocol").string(prot.get());
    }
    if (authn_instant) {
        auto_ptr_char instant(authn_instant);
        obj.addmember("authn_instant").string(instant.get());
    }
    if (session_index)
        obj.addmember("session_index").string(index.get());
    if (authncontext_class) {
        auto_ptr_char ac(authncontext_class);
        obj.addmember("authncontext_class").string(ac.get());
    }
    if (authncontext_decl) {
        auto_ptr_char ad(authncontext_decl);
        obj.addmember("authncontext_decl").string(ad.get());
    }

    if (nameid) {
        ostringstream namestr;
        namestr << *nameid;
        obj.addmember("nameid").string(namestr.str().c_str());
    }

    if (tokens && m_cacheAssertions) {
        obj.addmember("assertions").list();
        for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
            auto_ptr_char tokenid((*t)->getID());
            DDF tokid = DDF(nullptr).string(tokenid.get());
            obj["assertions"].add(tokid);
        }
    }

    if (attributes) {
        DDF attr;
        DDF attrlist = obj.addmember("attributes").list();
        for (vector<Attribute*>::const_iterator a=attributes->begin(); a!=attributes->end(); ++a) {
            attr = (*a)->marshall();
            attrlist.add(attr);
        }
    }

    ostringstream record;
    record << obj;

    m_log.debug("storing new session...");
    unsigned long cacheTimeout = getCacheTimeout(app);
    if (!m_storage->createText(key.get(), "session", record.str().c_str(), now + cacheTimeout))
        throw FatalProfileException("Attempted to create a session with a duplicate key.");

    // Store the reverse mapping for logout.
    try {
        if (nameid)
            insert(key.get(), expires, name.get(), index.get());
    }
    catch (exception& ex) {
        m_log.error("error storing back mapping of NameID for logout: %s", ex.what());
    }

    if (tokens && m_cacheAssertions) {
        try {
            for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                ostringstream tokenstr;
                tokenstr << *(*t);
                auto_ptr_char tokenid((*t)->getID());
                if (!m_storage->createText(key.get(), tokenid.get(), tokenstr.str().c_str(), now + cacheTimeout))
                    throw IOException("duplicate assertion ID ($1)", params(1, tokenid.get()));
            }
        }
        catch (exception& ex) {
            m_log.error("error storing assertion along with session: %s", ex.what());
        }
    }

    const char* pid = obj["entity_id"].string();
    const char* prot = obj["protocol"].string();
    m_log.info("new session created: ID (%s) IdP (%s) Protocol(%s) Address (%s)",
        key.get(), pid ? pid : "none", prot ? prot : "none", httpRequest.getRemoteAddr().c_str());

    // Transaction Logging
    string primaryAssertionID("none");
    if (m_cacheAssertions) {
        if (tokens)
            primaryAssertionID = obj["assertions"].first().string();
    }
    else if (tokens) {
        auto_ptr_char tokenid(tokens->front()->getID());
        primaryAssertionID = tokenid.get();
    }
    TransactionLog* xlog = app.getServiceProvider().getTransactionLog();
    Locker locker(xlog);
    xlog->log.infoStream() <<
        "New session (ID: " <<
            key.get() <<
        ") with (applicationId: " <<
            app.getId() <<
        ") for principal from (IdP: " <<
            (pid ? pid : "none") <<
        ") at (ClientAddress: " <<
            httpRequest.getRemoteAddr() <<
        ") with (NameIdentifier: " <<
            (nameid ? name.get() : "none") <<
        ") using (Protocol: " <<
            (prot ? prot : "none") <<
        ") from (AssertionID: " <<
            primaryAssertionID <<
        ")";

    if (attributes) {
        xlog->log.infoStream() <<
            "Cached the following attributes with session (ID: " <<
                key.get() <<
            ") for (applicationId: " <<
                app.getId() <<
            ") {";
        for (vector<Attribute*>::const_iterator a=attributes->begin(); a!=attributes->end(); ++a)
            xlog->log.infoStream() << "\t" << (*a)->getId() << " (" << (*a)->valueCount() << " values)";
        xlog->log.info("}");
    }

    if (!m_outboundHeader.empty())
        httpResponse.setResponseHeader(m_outboundHeader.c_str(), key.get());

    time_t cookieLifetime = 0;
    pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_", &cookieLifetime);
    string k(key.get());
    k += shib_cookie.second;

    if (cookieLifetime > 0) {
        cookieLifetime += now;
#ifndef HAVE_GMTIME_R
        ptime=gmtime(&cookieLifetime);
#else
        ptime=gmtime_r(&cookieLifetime,&res);
#endif
        char cookietimebuf[64];
        strftime(cookietimebuf,64,"; expires=%a, %d %b %Y %H:%M:%S GMT",ptime);
        k += cookietimebuf;
    }

    httpResponse.setCookie(shib_cookie.first.c_str(), k.c_str());
}

bool SSCache::matches(
    const Application& app,
    const xmltooling::HTTPRequest& request,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const set<string>* indexes
    )
{
    auto_ptr_char entityID(issuer ? issuer->getEntityID() : nullptr);
    try {
        Session* session = find(app, request);
        if (session) {
            Locker locker(session, false);
            if (XMLString::equals(session->getEntityID(), entityID.get()) && session->getNameID() &&
                    stronglyMatches(issuer->getEntityID(), app.getRelyingParty(issuer)->getXMLString("entityID").second, nameid, *session->getNameID())) {
                return (!indexes || indexes->empty() || (session->getSessionIndex() ? (indexes->count(session->getSessionIndex())>0) : false));
            }
        }
    }
    catch (exception& ex) {
        m_log.error("error while matching session: %s", ex.what());
    }
    return false;
}

vector<string>::size_type SSCache::logout(
    const Application& app,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const set<string>* indexes,
    time_t expires,
    vector<string>& sessionsKilled
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("logout");
#endif

    if (!m_storage)
        throw ConfigurationException("SessionCache insertion requires a StorageService.");

    auto_ptr_char entityID(issuer ? issuer->getEntityID() : nullptr);
    auto_ptr_char name(nameid.getName());

    m_log.info("request to logout sessions from (%s) for (%s)", entityID.get() ? entityID.get() : "unknown", name.get());

    if (strlen(name.get()) > 255)
        const_cast<char*>(name.get())[255] = 0;

    DDF obj;
    DDFJanitor jobj(obj);
    string record;
    int ver;

    if (expires) {
        // Record the logout to prevent post-delivered assertions.
        // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
        struct tm* ptime=gmtime(&expires);
#else
        struct tm res;
        struct tm* ptime=gmtime_r(&expires,&res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);

        time_t oldexp = 0;
        ver = m_storage_lite->readText("Logout", name.get(), &record, &oldexp);
        if (ver > 0) {
            istringstream lin(record);
            lin >> obj;
        }
        else {
            obj = DDF(nullptr).structure();
        }

        // Structure is keyed by the IdP and SP, with a member per session index containing the expiration.
        DDF root = obj.addmember(issuer ? entityID.get() : "_shibnull").addmember(app.getRelyingParty(issuer)->getString("entityID").second);
        if (indexes) {
            for (set<string>::const_iterator x = indexes->begin(); x!=indexes->end(); ++x)
                root.addmember(x->c_str()).string(timebuf);
        }
        else {
            root.addmember("_shibnull").string(timebuf);
        }

        // Write it back.
        ostringstream lout;
        lout << obj;

        if (ver > 0) {
            ver = m_storage_lite->updateText("Logout", name.get(), lout.str().c_str(), max(expires, oldexp), ver);
            if (ver <= 0) {
                // Out of sync, or went missing, so retry.
                return logout(app, issuer, nameid, indexes, expires, sessionsKilled);
            }
        }
        else if (!m_storage_lite->createText("Logout", name.get(), lout.str().c_str(), expires)) {
            // Hit a dup, so just retry, hopefully hitting the other branch.
            return logout(app, issuer, nameid, indexes, expires, sessionsKilled);
        }

        obj.destroy();
        record.erase();
    }

    // Read in potentially matching sessions.
    ver = m_storage_lite->readText("NameID", name.get(), &record);
    if (ver == 0) {
        m_log.debug("no active sessions to logout for supplied issuer and subject");
        return 0;
    }

    istringstream in(record);
    in >> obj;

    // The record contains child lists for each known session index.
    DDF key;
    DDF sessions = obj.first();
    while (sessions.islist()) {
        if (!indexes || indexes->empty() || indexes->count(sessions.name())) {
            key = sessions.first();
            while (key.isstring()) {
                // Fetch the session for comparison.
                Session* session = nullptr;
                try {
                    session = find(app, key.string());
                }
                catch (exception& ex) {
                    m_log.error("error locating session (%s): %s", key.string(), ex.what());
                }

                if (session) {
                    Locker locker(session, false);
                    // Same issuer?
                    if (XMLString::equals(session->getEntityID(), entityID.get())) {
                        // Same NameID?
                        if (stronglyMatches(issuer->getEntityID(), app.getRelyingParty(issuer)->getXMLString("entityID").second, nameid, *session->getNameID())) {
                            sessionsKilled.push_back(key.string());
                            key.destroy();
                        }
                        else {
                            m_log.debug("session (%s) contained a non-matching NameID, leaving it alone", key.string());
                        }
                    }
                    else {
                        m_log.debug("session (%s) established by different IdP, leaving it alone", key.string());
                    }
                }
                else {
                    // Session's gone, so...
                    sessionsKilled.push_back(key.string());
                    key.destroy();
                }
                key = sessions.next();
            }

            // No sessions left for this index?
            if (sessions.first().isnull())
                sessions.destroy();
        }
        sessions = obj.next();
    }

    if (obj.first().isnull())
        obj.destroy();

    // If possible, write back the mapping record (this isn't crucial).
    try {
        if (obj.isnull()) {
            m_storage_lite->deleteText("NameID", name.get());
        }
        else if (!sessionsKilled.empty()) {
            ostringstream out;
            out << obj;
            if (m_storage_lite->updateText("NameID", name.get(), out.str().c_str(), 0, ver) <= 0)
                m_log.warn("logout mapping record changed behind us, leaving it alone");
        }
    }
    catch (exception& ex) {
        m_log.error("error updating logout mapping record: %s", ex.what());
    }

    return sessionsKilled.size();
}

bool SSCache::stronglyMatches(const XMLCh* idp, const XMLCh* sp, const saml2::NameID& n1, const saml2::NameID& n2) const
{
    if (!XMLString::equals(n1.getName(), n2.getName()))
        return false;

    const XMLCh* s1 = n1.getFormat();
    const XMLCh* s2 = n2.getFormat();
    if (!s1 || !*s1)
        s1 = saml2::NameID::UNSPECIFIED;
    if (!s2 || !*s2)
        s2 = saml2::NameID::UNSPECIFIED;
    if (!XMLString::equals(s1,s2))
        return false;

    s1 = n1.getNameQualifier();
    s2 = n2.getNameQualifier();
    if (!s1 || !*s1)
        s1 = idp;
    if (!s2 || !*s2)
        s2 = idp;
    if (!XMLString::equals(s1,s2))
        return false;

    s1 = n1.getSPNameQualifier();
    s2 = n2.getSPNameQualifier();
    if (!s1 || !*s1)
        s1 = sp;
    if (!s2 || !*s2)
        s2 = sp;
    if (!XMLString::equals(s1,s2))
        return false;

    return true;
}

#endif

Session* SSCache::find(const Application& app, const char* key, const char* client_addr, time_t* timeout)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("find");
#endif
    StoredSession* session=nullptr;

    if (inproc) {
        m_log.debug("searching local cache for session (%s)", key);
        m_lock->rdlock();
        map<string,StoredSession*>::const_iterator i=m_hashtable.find(key);
        if (i!=m_hashtable.end()) {
            // Save off and lock the session.
            session = i->second;
            session->lock();
            m_lock->unlock();
            m_log.debug("session found locally, validating it for use");
        }
        else {
            m_lock->unlock();
        }
    }

    if (!session) {
        if (!SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            m_log.debug("session not found locally, remoting the search");
            // Remote the request.
            DDF in("find::"STORAGESERVICE_SESSION_CACHE"::SessionCache"), out;
            DDFJanitor jin(in);
            in.structure();
            in.addmember("key").string(key);
            in.addmember("application_id").string(app.getId());
            if (timeout && *timeout) {
                // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
                struct tm* ptime=gmtime(timeout);
#else
                struct tm res;
                struct tm* ptime=gmtime_r(timeout,&res);
#endif
                char timebuf[32];
                strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
                in.addmember("timeout").string(timebuf);
            }

            try {
                out=app.getServiceProvider().getListenerService()->send(in);
                if (!out.isstruct()) {
                    out.destroy();
                    m_log.debug("session not found in remote cache");
                    return nullptr;
                }

                // Wrap the results in a local entry and save it.
                session = new StoredSession(this, out);
                // The remote end has handled timeout issues, we handle address and expiration checks.
                timeout = nullptr;
            }
            catch (...) {
                out.destroy();
                throw;
            }
        }
        else {
            // We're out of process, so we can search the storage service directly.
#ifndef SHIBSP_LITE
            if (!m_storage)
                throw ConfigurationException("SessionCache lookup requires a StorageService.");

            m_log.debug("searching for session (%s)", key);

            DDF obj;
            time_t lastAccess;
            string record;
            int ver = m_storage->readText(key, "session", &record, &lastAccess);
            if (!ver)
                return nullptr;

            m_log.debug("reconstituting session and checking validity");

            istringstream in(record);
            in >> obj;

            unsigned long cacheTimeout = getCacheTimeout(app);
            lastAccess -= cacheTimeout;   // adjusts it back to the last time the record's timestamp was touched
            time_t now=time(nullptr);

            if (timeout && *timeout > 0 && now - lastAccess >= *timeout) {
                m_log.info("session timed out (ID: %s)", key);
                remove(app, key);
                const char* eid = obj["entity_id"].string();
                if (!eid) {
                    obj.destroy();
                    throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
                }
                string eid2(eid);
                obj.destroy();
                throw RetryableProfileException("Your session has expired, and you must re-authenticate.", namedparams(1, "entityID", eid2.c_str()));
            }

            if (timeout) {
                // Update storage expiration, if possible.
                try {
                    m_storage->updateContext(key, now + cacheTimeout);
                }
                catch (exception& ex) {
                    m_log.error("failed to update session expiration: %s", ex.what());
                }
            }

            // Wrap the results in a local entry and save it.
            session = new StoredSession(this, obj);
            // We handled timeout issues, still need to handle address and expiration checks.
            timeout = nullptr;
#else
            throw ConfigurationException("SessionCache search requires a StorageService.");
#endif
        }

        if (inproc) {
            // Lock for writing and repeat the search to avoid duplication.
            m_lock->wrlock();
            SharedLock shared(m_lock, false);
            if (m_hashtable.count(key)) {
                // We're using an existing session entry.
                delete session;
                session = m_hashtable[key];
                session->lock();
            }
            else {
                m_hashtable[key]=session;
                session->lock();
            }
        }
    }

    if (!XMLString::equals(session->getApplicationID(), app.getId())) {
        m_log.error("an application (%s) tried to access another application's session", app.getId());
        session->unlock();
        return nullptr;
    }

    // Verify currency and update the timestamp if indicated by caller.
    try {
        session->validate(app, client_addr, timeout);
    }
    catch (...) {
        session->unlock();
        remove(app, key);
        throw;
    }

    return session;
}

Session* SSCache::find(const Application& app, HTTPRequest& request, const char* client_addr, time_t* timeout)
{
    string id = active(app, request);
    if (id.empty())
        return nullptr;
    try {
        Session* session = find(app, id.c_str(), client_addr, timeout);
        if (session)
            return session;
        HTTPResponse* response = dynamic_cast<HTTPResponse*>(&request);
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");
            string exp(shib_cookie.second);
            exp += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
            response->setCookie(shib_cookie.first.c_str(), exp.c_str());
        }
    }
    catch (exception&) {
        HTTPResponse* response = dynamic_cast<HTTPResponse*>(&request);
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");
            string exp(shib_cookie.second);
            exp += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
            response->setCookie(shib_cookie.first.c_str(), exp.c_str());
        }
        throw;
    }
    return nullptr;
}

void SSCache::remove(const Application& app, const HTTPRequest& request, HTTPResponse* response)
{
    string session_id;
    pair<string,const char*> shib_cookie = app.getCookieNameProps("_shibsession_");

    if (!m_inboundHeader.empty())
        session_id = request.getHeader(m_inboundHeader.c_str());
    if (session_id.empty()) {
        const char* c = request.getCookie(shib_cookie.first.c_str());
        if (c && *c)
            session_id = c;
    }

    if (!session_id.empty()) {
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            string exp(shib_cookie.second);
            exp += "; expires=Mon, 01 Jan 2001 00:00:00 GMT";
            response->setCookie(shib_cookie.first.c_str(), exp.c_str());
        }
        remove(app, session_id.c_str());
    }
}

void SSCache::remove(const Application& app, const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("remove");
#endif
    // Take care of local copy.
    if (inproc)
        dormant(key);

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        // Remove the session from storage directly.
#ifndef SHIBSP_LITE
        m_storage->deleteContext(key);
        m_log.info("removed session (%s)", key);

        TransactionLog* xlog = app.getServiceProvider().getTransactionLog();
        Locker locker(xlog);
        xlog->log.info("Destroyed session (applicationId: %s) (ID: %s)", app.getId(), key);
#else
        throw ConfigurationException("SessionCache removal requires a StorageService.");
#endif
    }
    else {
        // Remote the request.
        DDF in("remove::"STORAGESERVICE_SESSION_CACHE"::SessionCache");
        DDFJanitor jin(in);
        in.structure();
        in.addmember("key").string(key);
        in.addmember("application_id").string(app.getId());

        DDF out = app.getServiceProvider().getListenerService()->send(in);
        out.destroy();
    }
}

void SSCache::dormant(const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("dormant");
#endif

    m_log.debug("deleting local copy of session (%s)", key);

    // lock the cache for writing, which means we know nobody is sitting in find()
    m_lock->wrlock();

    // grab the entry from the table
    map<string,StoredSession*>::const_iterator i=m_hashtable.find(key);
    if (i==m_hashtable.end()) {
        m_lock->unlock();
        return;
    }

    // ok, remove the entry and lock it
    StoredSession* entry=i->second;
    m_hashtable.erase(key);
    entry->lock();

    // unlock the cache
    m_lock->unlock();

    // we can release the cache entry lock because we know we're not in the cache anymore
    entry->unlock();

    delete entry;
}

void* SSCache::cleanup_fn(void* p)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("cleanup");
#endif

    SSCache* pcache = reinterpret_cast<SSCache*>(p);

#ifndef WIN32
    // First, let's block all signals
    Thread::mask_all_signals();
#endif

    auto_ptr<Mutex> mutex(Mutex::create());

    // Load our configuration details...
    static const XMLCh cleanupInterval[] = UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
    const XMLCh* tag=pcache->m_root ? pcache->m_root->getAttributeNS(nullptr, cleanupInterval) : nullptr;
    int rerun_timer = 900;
    if (tag && *tag) {
        rerun_timer = XMLString::parseInt(tag);
        if (rerun_timer <= 0)
            rerun_timer = 900;
    }

    mutex->lock();

    pcache->m_log.info("cleanup thread started...run every %d secs; timeout after %d secs", rerun_timer, pcache->m_inprocTimeout);

    while (!pcache->shutdown) {
        pcache->shutdown_wait->timedwait(mutex.get(), rerun_timer);
        if (pcache->shutdown)
            break;

        // Ok, let's run through the cleanup process and clean out
        // really old sessions.  This is a two-pass process.  The
        // first pass is done holding a read-lock while we iterate over
        // the cache.  The second pass doesn't need a lock because
        // the 'deletes' will lock the cache.

        // Pass 1: iterate over the map and find all entries that have not been
        // used in the allotted timeout.
        vector<string> stale_keys;
        time_t stale = time(nullptr) - pcache->m_inprocTimeout;

        pcache->m_log.debug("cleanup thread running");

        pcache->m_lock->rdlock();
        for (map<string,StoredSession*>::const_iterator i=pcache->m_hashtable.begin(); i!=pcache->m_hashtable.end(); ++i) {
            // If the last access was BEFORE the stale timeout...
            i->second->lock();
            time_t last=i->second->getLastAccess();
            i->second->unlock();
            if (last < stale)
                stale_keys.push_back(i->first);
        }
        pcache->m_lock->unlock();

        if (!stale_keys.empty()) {
            pcache->m_log.info("purging %d old sessions", stale_keys.size());

            // Pass 2: walk through the list of stale entries and remove them from the cache
            for (vector<string>::const_iterator j = stale_keys.begin(); j != stale_keys.end(); ++j)
                pcache->dormant(j->c_str());
        }

        pcache->m_log.debug("cleanup thread completed");
    }

    pcache->m_log.info("cleanup thread exiting");

    mutex->unlock();
    return nullptr;
}

#ifndef SHIBSP_LITE

void SSCache::receive(DDF& in, ostream& out)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("receive");
#endif
    const Application* app = SPConfig::getConfig().getServiceProvider()->getApplication(in["application_id"].string());
    if (!app)
        throw ListenerException("Application not found, check configuration?");

    if (!strcmp(in.name(),"find::"STORAGESERVICE_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session lookup.");

        // Do an unversioned read.
        string record;
        time_t lastAccess;
        if (!m_storage->readText(key, "session", &record, &lastAccess)) {
            DDF ret(nullptr);
            DDFJanitor jan(ret);
            out << ret;
            return;
        }

        // Adjust for expiration to recover last access time and check timeout.
        unsigned long cacheTimeout = getCacheTimeout(*app);
        lastAccess -= cacheTimeout;
        time_t now=time(nullptr);

        // See if we need to check for a timeout.
        if (in["timeout"].string()) {
            time_t timeout = 0;
            auto_ptr_XMLCh dt(in["timeout"].string());
            DateTime dtobj(dt.get());
            dtobj.parseDateTime();
            timeout = dtobj.getEpoch();

            if (timeout > 0 && now - lastAccess >= timeout) {
                m_log.info("session timed out (ID: %s)", key);
                remove(*app, key);
                throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
            }

            // Update storage expiration, if possible.
            try {
                m_storage->updateContext(key, now + cacheTimeout);
            }
            catch (exception& ex) {
                m_log.error("failed to update session expiration: %s", ex.what());
            }
        }

        // Send the record back.
        out << record;
    }
    else if (!strcmp(in.name(),"touch::"STORAGESERVICE_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session check.");

        // Do a versioned read.
        string record;
        time_t lastAccess;
        int curver = in["version"].integer();
        int ver = m_storage->readText(key, "session", &record, &lastAccess, curver);
        if (ver == 0) {
            m_log.warn("unsuccessful versioned read of session (ID: %s), caches out of sync?", key);
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }

        // Adjust for expiration to recover last access time and check timeout.
        unsigned long cacheTimeout = getCacheTimeout(*app);
        lastAccess -= cacheTimeout;
        time_t now=time(nullptr);

        // See if we need to check for a timeout.
        time_t timeout = 0;
        auto_ptr_XMLCh dt(in["timeout"].string());
        if (dt.get()) {
            DateTime dtobj(dt.get());
            dtobj.parseDateTime();
            timeout = dtobj.getEpoch();
        }

        if (timeout > 0 && now - lastAccess >= timeout) {
            m_log.info("session timed out (ID: %s)", key);
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }

        // Update storage expiration, if possible.
        try {
            m_storage->updateContext(key, now + cacheTimeout);
        }
        catch (exception& ex) {
            m_log.error("failed to update session expiration: %s", ex.what());
        }

        if (ver > curver) {
            // Send the record back.
            out << record;
        }
        else {
            DDF ret(nullptr);
            DDFJanitor jan(ret);
            out << ret;
        }
    }
    else if (!strcmp(in.name(),"remove::"STORAGESERVICE_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameter missing for session removal.");

        remove(*app, key);
        DDF ret(nullptr);
        DDFJanitor jan(ret);
        out << ret;
    }
}

#endif
