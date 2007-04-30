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
#include "SessionCache.h"
#include "TransactionLog.h"
#include "attribute/Attribute.h"
#include "remoting/ListenerService.h"
#include "util/SPConstants.h"

#include <log4cpp/Category.hh>
#include <saml/SAMLConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace shibsp {

    class SSCache;
    class StoredSession : public virtual Session
    {
    public:
        StoredSession(SSCache* cache, DDF& obj) : m_obj(obj), m_nameid(NULL), m_cache(cache) {
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
        }
        
        ~StoredSession();
        
        Lockable* lock() {
            return this;
        }
        void unlock() {
            delete this;
        }
        
        const char* getClientAddress() const {
            return m_obj["client_addr"].string();
        }
        const char* getEntityID() const {
            return m_obj["entity_id"].string();
        }
        const char* getAuthnInstant() const {
            return m_obj["authn_instant"].string();
        }
        const opensaml::saml2::NameID* getNameID() const {
            return m_nameid;
        }
        const char* getSessionIndex() const {
            return m_obj["session_index"].string();
        }
        const char* getAuthnContextClassRef() const {
            return m_obj["authncontext_class"].string();
        }
        const char* getAuthnContextDeclRef() const {
            return m_obj["authncontext_decl"].string();
        }
        const multimap<string,Attribute*>& getAttributes() const {
            if (m_attributes.empty())
                unmarshallAttributes();
            return m_attributes;
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
        
        void addAttributes(const vector<Attribute*>& attributes);
        const Assertion* getAssertion(const char* id) const;
        void addAssertion(Assertion* assertion);

    private:
        void unmarshallAttributes() const;

        DDF m_obj;
        saml2::NameID* m_nameid;
        mutable multimap<string,Attribute*> m_attributes;
        mutable vector<const char*> m_ids;
        mutable map<string,Assertion*> m_tokens;
        SSCache* m_cache;
    };
    
    class SSCache : public SessionCache, public virtual Remoted
    {
    public:
        SSCache(const DOMElement* e);
        ~SSCache();
    
        void receive(DDF& in, ostream& out);
        
        string insert(
            time_t expires,
            const Application& application,
            const char* client_addr=NULL,
            const saml2md::EntityDescriptor* issuer=NULL,
            const saml2::NameID* nameid=NULL,
            const char* authn_instant=NULL,
            const char* session_index=NULL,
            const char* authncontext_class=NULL,
            const char* authncontext_decl=NULL,
            const vector<const Assertion*>* tokens=NULL,
            const multimap<string,Attribute*>* attributes=NULL
            );
        Session* find(const char* key, const Application& application, const char* client_addr=NULL, time_t timeout=0);
        void remove(const char* key, const Application& application, const char* client_addr);

        Category& m_log;
        StorageService* m_storage;
    };

    SessionCache* SHIBSP_DLLLOCAL StorageServiceCacheFactory(const DOMElement* const & e)
    {
        return new SSCache(e);
    }

    static const XMLCh _StorageService[] =   UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
}

StoredSession::~StoredSession()
{
    m_obj.destroy();
    delete m_nameid;
    for_each(m_attributes.begin(), m_attributes.end(), cleanup_pair<string,Attribute>());
    for_each(m_tokens.begin(), m_tokens.end(), cleanup_pair<string,Assertion>());
}

void StoredSession::unmarshallAttributes() const
{
    Attribute* attribute;
    DDF attrs = m_obj["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        try {
            attribute = Attribute::unmarshall(attr);
            m_attributes.insert(make_pair(attribute->getId(), attribute));
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

void StoredSession::addAttributes(const vector<Attribute*>& attributes)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("addAttributes");
#endif

    m_cache->m_log.debug("adding attributes to session (%s)", m_obj.name());
    
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
            ver = m_cache->m_storage->updateText(m_obj.name(), "session", record.c_str(), 0, m_obj["version"].integer()-1);
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
            ver = m_cache->m_storage->readText(m_obj.name(), "session", &record, NULL);
            if (!ver) {
                m_cache->m_log.error("readText failed on StorageService for session (%s)", m_obj.name());
                throw IOException("Unable to read back stored session.");
            }
            
            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), cleanup_const_pair<string,Attribute>());
            m_attributes.clear();
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
            m_obj.name() <<
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
    map<string,Assertion*>::const_iterator i = m_tokens.find(id);
    if (i!=m_tokens.end())
        return i->second;
    
    string tokenstr;
    if (!m_cache->m_storage->readText(m_obj.name(), id, &tokenstr, NULL))
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
    
    if (!assertion)
        throw FatalProfileException("Unknown object type passed to session for storage.");

    auto_ptr_char id(assertion->getID());

    m_cache->m_log.debug("adding assertion (%s) to session (%s)", id.get(), m_obj.name());

    time_t exp;
    if (!m_cache->m_storage->readText(m_obj.name(), "session", NULL, &exp))
        throw IOException("Unable to load expiration time for stored session.");

    ostringstream tokenstr;
    tokenstr << *assertion;
    m_cache->m_storage->createText(m_obj.name(), id.get(), tokenstr.str().c_str(), exp);
    
    int ver;
    do {
        DDF token = DDF(NULL).string(id.get());
        m_obj["assertions"].add(token);

        // Tentatively increment the version.
        m_obj["version"].integer(m_obj["version"].integer()+1);
    
        ostringstream str;
        str << m_obj;
        string record(str.str()); 

        try {
            ver = m_cache->m_storage->updateText(m_obj.name(), "session", record.c_str(), 0, m_obj["version"].integer()-1);
        }
        catch (exception&) {
            token.destroy();
            m_obj["version"].integer(m_obj["version"].integer()-1);
            m_cache->m_storage->deleteText(m_obj.name(), id.get());
            throw;
        }

        if (ver <= 0) {
            token.destroy();
            m_obj["version"].integer(m_obj["version"].integer()-1);
        }            
        if (!ver) {
            // Fatal problem with update.
            m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
            m_cache->m_storage->deleteText(m_obj.name(), id.get());
            throw IOException("Unable to update stored session.");
        }
        else if (ver < 0) {
            // Out of sync.
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(m_obj.name(), "session", &record, NULL);
            if (!ver) {
                m_cache->m_log.error("readText failed on StorageService for session (%s)", m_obj.name());
                m_cache->m_storage->deleteText(m_obj.name(), id.get());
                throw IOException("Unable to read back stored session.");
            }
            
            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), cleanup_const_pair<string,Attribute>());
            m_attributes.clear();
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
        id.get(), m_obj["application_id"].string(), m_obj.name()
        );
}

SSCache::SSCache(const DOMElement* e)
    : SessionCache(e), m_log(Category::getInstance(SHIBSP_LOGCAT".SessionCache")), m_storage(NULL)
{
    SPConfig& conf = SPConfig::getConfig();
    const XMLCh* tag = e ? e->getAttributeNS(NULL,_StorageService) : NULL;
    if (tag && *tag) {
        auto_ptr_char ssid(tag);
        m_storage = conf.getServiceProvider()->getStorageService(ssid.get());
        if (m_storage)
            m_log.info("bound to StorageService (%s)", ssid.get());
        else
            throw ConfigurationException("SessionCache unable to locate StorageService, check configuration.");
    }

    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
        listener->regListener("insert::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->regListener("find::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->regListener("remove::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->regListener("touch::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->regListener("getAssertion::"REMOTED_SESSION_CACHE"::SessionCache",this);
    }
    else {
        m_log.info("no ListenerService available, cache remoting disabled");
    }
}

SSCache::~SSCache()
{
    SPConfig& conf = SPConfig::getConfig();
    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
        listener->unregListener("insert::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("find::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("remove::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("touch::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("getAssertion::"REMOTED_SESSION_CACHE"::SessionCache",this);
    }
}

string SSCache::insert(
    time_t expires,
    const Application& application,
    const char* client_addr,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID* nameid,
    const char* authn_instant,
    const char* session_index,
    const char* authncontext_class,
    const char* authncontext_decl,
    const vector<const Assertion*>* tokens,
    const multimap<string,Attribute*>* attributes
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("insert");
#endif

    m_log.debug("creating new session");

    auto_ptr_char key(SAMLConfig::getConfig().generateIdentifier());

    // Store session properties in DDF.
    DDF obj = DDF(key.get()).structure();
    obj.addmember("version").integer(1);
    obj.addmember("application_id").string(application.getId());
    if (expires > 0) {
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
    }
    if (client_addr)
        obj.addmember("client_addr").string(client_addr);
    if (issuer) {
        auto_ptr_char entity_id(issuer->getEntityID());
        obj.addmember("entity_id").string(entity_id.get());
    }
    if (authn_instant)
        obj.addmember("authn_instant").string(authn_instant);
    if (session_index)
        obj.addmember("session_index").string(session_index);
    if (authncontext_class)
        obj.addmember("authncontext_class").string(authncontext_class);
    if (authncontext_decl)
        obj.addmember("authncontext_decl").string(authncontext_decl);

    if (nameid) {
        ostringstream namestr;
        namestr << *nameid;
        obj.addmember("nameid").string(namestr.str().c_str());
    }

    if (tokens) {
        obj.addmember("assertions").list();
        for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
            auto_ptr_char tokenid((*t)->getID());
            DDF tokid = DDF(NULL).string(tokenid.get());
            obj["assertions"].add(tokid);
        }
    }
    
    if (attributes) {
        DDF attr;
        DDF attrlist = obj.addmember("attributes").list();
        for (multimap<string,Attribute*>::const_iterator a=attributes->begin(); a!=attributes->end(); ++a) {
            attr = a->second->marshall();
            attrlist.add(attr);
        }
    }
    
    ostringstream record;
    record << obj;
    
    m_log.debug("storing new session...");
    time_t now = time(NULL);
    m_storage->createText(key.get(), "session", record.str().c_str(), now + m_cacheTimeout);
    if (tokens) {
        try {
            for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                ostringstream tokenstr;
                tokenstr << *(*t);
                auto_ptr_char tokenid((*t)->getID());
                m_storage->createText(key.get(), tokenid.get(), tokenstr.str().c_str(), now + m_cacheTimeout);
            }
        }
        catch (exception& ex) {
            m_log.error("error storing assertion along with session: %s", ex.what());
        }
    }

    const char* pid = obj["entity_id"].string();
    m_log.debug("new session created: SessionID (%s) IdP (%s) Address (%s)", key.get(), pid ? pid : "none", client_addr);

    // Transaction Logging
    auto_ptr_char name(nameid ? nameid->getName() : NULL);
    TransactionLog* xlog = application.getServiceProvider().getTransactionLog();
    Locker locker(xlog);
    xlog->log.infoStream() <<
        "New session (ID: " <<
            key.get() <<
        ") with (applicationId: " <<
            application.getId() <<
        ") for principal from (IdP: " <<
            (pid ? pid : "none") <<
        ") at (ClientAddress: " <<
            (client_addr ? client_addr : "none") <<
        ") with (NameIdentifier: " <<
            (name.get() ? name.get() : "none") <<
        ")";
    
    if (attributes) {
        xlog->log.infoStream() <<
            "Cached the following attributes with session (ID: " <<
                key.get() <<
            ") for (applicationId: " <<
                application.getId() <<
            ") {";
        for (multimap<string,Attribute*>::const_iterator a=attributes->begin(); a!=attributes->end(); ++a)
            xlog->log.infoStream() << "\t" << a->second->getId() << " (" << a->second->valueCount() << " values)";
        xlog->log.info("}");
        for_each(attributes->begin(), attributes->end(), cleanup_pair<string,Attribute>());
    }

    return key.get();
}

Session* SSCache::find(const char* key, const Application& application, const char* client_addr, time_t timeout)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("find");
#endif

    m_log.debug("searching for session (%s)", key);
    
    time_t lastAccess;
    string record;
    int ver = m_storage->readText(key, "session", &record, &lastAccess);
    if (!ver)
        return NULL;
    
    m_log.debug("reconstituting session and checking validity");
    
    DDF obj;
    istringstream in(record);
    in >> obj;
    
    if (!XMLString::equals(obj["application_id"].string(), application.getId())) {
        m_log.error("an application (%s) tried to access another application's session", application.getId());
        obj.destroy();
        return NULL;
    }

    if (client_addr) {
        if (m_log.isDebugEnabled())
            m_log.debug("comparing client address %s against %s", client_addr, obj["client_addr"].string());
        if (strcmp(obj["client_addr"].string(),client_addr)) {
            m_log.warn("client address mismatch");
            remove(key, application, client_addr);
            RetryableProfileException ex(
                "Your IP address ($1) does not match the address recorded at the time the session was established.",
                params(1,client_addr)
                );
            string eid(obj["entity_id"].string());
            obj.destroy();
            if (eid.empty())
                throw ex;
            MetadataProvider* m=application.getMetadataProvider();
            Locker locker(m);
            annotateException(&ex,m->getEntityDescriptor(eid.c_str(),false)); // throws it
        }
    }

    lastAccess -= m_cacheTimeout;   // adjusts it back to the last time the record's timestamp was touched
    time_t now=time(NULL);
    
    if (timeout > 0 && now - lastAccess >= timeout) {
        m_log.info("session timed out (ID: %s)", key);
        remove(key, application, client_addr);
        RetryableProfileException ex("Your session has expired, and you must re-authenticate.");
        string eid(obj["entity_id"].string());
        obj.destroy();
        if (eid.empty())
            throw ex;
        MetadataProvider* m=application.getMetadataProvider();
        Locker locker(m);
        annotateException(&ex,m->getEntityDescriptor(eid.c_str(),false)); // throws it
    }
    
    auto_ptr_XMLCh exp(obj["expires"].string());
    if (exp.get()) {
        DateTime iso(exp.get());
        iso.parseDateTime();
        if (now > iso.getEpoch()) {
            m_log.info("session expired (ID: %s)", key);
            remove(key, application, client_addr);
            RetryableProfileException ex("Your session has expired, and you must re-authenticate.");
            string eid(obj["entity_id"].string());
            obj.destroy();
            if (eid.empty())
                throw ex;
            MetadataProvider* m=application.getMetadataProvider();
            Locker locker(m);
            annotateException(&ex,m->getEntityDescriptor(eid.c_str(),false)); // throws it
        }
    }
    
    // Update storage expiration, if possible.
    try {
        m_storage->updateContext(key, now + m_cacheTimeout);
    }
    catch (exception& ex) {
        m_log.error("failed to update session expiration: %s", ex.what());
    }

    // Finally build the Session object.
    try {
        return new StoredSession(this, obj);
    }
    catch (exception&) {
        obj.destroy();
        throw;
    }
}

void SSCache::remove(const char* key, const Application& application, const char* client_addr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("remove");
#endif

    m_log.debug("removing session (%s)", key);

    m_storage->deleteContext(key);

    TransactionLog* xlog = application.getServiceProvider().getTransactionLog();
    Locker locker(xlog);
    xlog->log.info("Destroyed session (applicationId: %s) (ID: %s)", application.getId(), key);
}

void SSCache::receive(DDF& in, ostream& out)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("receive");
#endif

    if (!strcmp(in.name(),"insert::"REMOTED_SESSION_CACHE"::SessionCache")) {
        auto_ptr_char key(SAMLConfig::getConfig().generateIdentifier());
        in.name(key.get());

        DDF tokens = in["tokens"].remove();
        DDFJanitor tjan(tokens);
        
        m_log.debug("storing new session...");
        ostringstream record;
        record << in;
        time_t now = time(NULL);
        m_storage->createText(key.get(), "session", record.str().c_str(), now + m_cacheTimeout);
        if (tokens.islist()) {
            try {
                DDF token = tokens.first();
                while (token.isstring()) {
                    m_storage->createText(key.get(), token.name(), token.string(), now + m_cacheTimeout);
                    token = tokens.next();
                }
            }
            catch (IOException& ex) {
                m_log.error("error storing assertion along with session: %s", ex.what());
            }
        }
        const char* pid = in["entity_id"].string();
        m_log.debug("new session created: SessionID (%s) IdP (%s) Address (%s)", key.get(), pid ? pid : "none", in["client_addr"].string());
    
        DDF ret = DDF(NULL).structure();
        DDFJanitor jan(ret);
        ret.addmember("key").string(key.get());
        out << ret;
    }
    else if (!strcmp(in.name(),"find::"REMOTED_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session removal.");

        // Do an unversioned read.
        string record;
        time_t lastAccess;
        if (!m_storage->readText(key, "session", &record, &lastAccess)) {
            DDF ret(NULL);
            DDFJanitor jan(ret);
            out << ret;
            return;
        }

        // Adjust for expiration to recover last access time and check timeout.
        lastAccess -= m_cacheTimeout;
        time_t now=time(NULL);

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
            remove(key,*(SPConfig::getConfig().getServiceProvider()->getApplication("default")),NULL);
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        } 

        // Update storage expiration, if possible.
        try {
            m_storage->updateContext(key, now + m_cacheTimeout);
        }
        catch (exception& ex) {
            m_log.error("failed to update session expiration: %s", ex.what());
        }
            
        // Send the record back.
        out << record;
    }
    else if (!strcmp(in.name(),"touch::"REMOTED_SESSION_CACHE"::SessionCache")) {
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
        lastAccess -= m_cacheTimeout;
        time_t now=time(NULL);

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
            m_storage->updateContext(key, now + m_cacheTimeout);
        }
        catch (exception& ex) {
            m_log.error("failed to update session expiration: %s", ex.what());
        }
            
        if (ver > curver) {
            // Send the record back.
            out << record;
        }
        else {
            DDF ret(NULL);
            DDFJanitor jan(ret);
            out << ret;
        }
    }
    else if (!strcmp(in.name(),"remove::"REMOTED_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameter missing for session removal.");
        
        remove(key,*(SPConfig::getConfig().getServiceProvider()->getApplication("default")),NULL);
        DDF ret(NULL);
        DDFJanitor jan(ret);
        out << ret;
    }
    else if (!strcmp(in.name(),"getAssertion::"REMOTED_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        const char* id=in["id"].string();
        if (!key || !id)
            throw ListenerException("Required parameters missing for assertion retrieval.");
        string token;
        if (!m_storage->readText(key, id, &token, NULL))
            throw FatalProfileException("Assertion not found in cache.");
        out << token;
    }
}
