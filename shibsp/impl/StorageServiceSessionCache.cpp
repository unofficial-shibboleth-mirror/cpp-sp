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
        
        const char* getID() const {
            return m_obj.name();
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
            const XMLCh* protocol=NULL,
            const saml2::NameID* nameid=NULL,
            const XMLCh* authn_instant=NULL,
            const XMLCh* session_index=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const Assertion*>* tokens=NULL,
            const multimap<string,Attribute*>* attributes=NULL
            );
        Session* find(const char* key, const Application& application, const char* client_addr=NULL, time_t* timeout=NULL);
        void remove(const char* key, const Application& application);
        void remove(
            const saml2md::EntityDescriptor* issuer,
            const saml2::NameID& nameid,
            const char* index,
            const Application& application,
            vector<string>& sessions
            );

        Category& m_log;
        StorageService* m_storage;

    private:
        // maintain back-mappings of NameID/SessionIndex -> session key
        void insert(const char* key, time_t expires, const char* name, const char* index);

        bool stronglyMatches(const XMLCh* idp, const XMLCh* sp, const saml2::NameID& n1, const saml2::NameID& n2) const;
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
            ver = m_cache->m_storage->readText(getID(), "session", &record, NULL);
            if (!ver) {
                m_cache->m_log.error("readText failed on StorageService for session (%s)", getID());
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
    map<string,Assertion*>::const_iterator i = m_tokens.find(id);
    if (i!=m_tokens.end())
        return i->second;
    
    string tokenstr;
    if (!m_cache->m_storage->readText(getID(), id, &tokenstr, NULL))
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

    m_cache->m_log.debug("adding assertion (%s) to session (%s)", id.get(), getID());

    time_t exp;
    if (!m_cache->m_storage->readText(getID(), "session", NULL, &exp))
        throw IOException("Unable to load expiration time for stored session.");

    ostringstream tokenstr;
    tokenstr << *assertion;
    if (!m_cache->m_storage->createText(getID(), id.get(), tokenstr.str().c_str(), exp))
        throw IOException("Attempted to insert duplicate assertion ID into session.");
    
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
            ver = m_cache->m_storage->readText(getID(), "session", &record, NULL);
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
        id.get(), m_obj["application_id"].string(), getID()
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
        listener->unregListener("find::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("remove::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("touch::"REMOTED_SESSION_CACHE"::SessionCache",this);
        listener->unregListener("getAssertion::"REMOTED_SESSION_CACHE"::SessionCache",this);
    }
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
    int ver = m_storage->readText("NameID", name, &record, &recordexp);
    if (ver > 0) {
        // Existing record, so we need to unmarshall it.
        istringstream in(record);
        in >> obj;
    }
    else {
        // New record.
        obj.structure();
    }

    if (!index || !*index)
        index = "_shibnull";
    DDF sessions = obj.addmember(index);
    if (!sessions.islist())
        sessions.list();
    DDF session = DDF(NULL).string(key);
    sessions.add(session);

    // Remarshall the record.
    ostringstream out;
    out << obj;

    // Try and store it back...
    if (ver > 0) {
        ver = m_storage->updateText("NameID", name, out.str().c_str(), max(expires, recordexp), ver);
        if (ver <= 0) {
            // Out of sync, or went missing, so retry.
            return insert(key, expires, name, index);
        }
    }
    else if (!m_storage->createText("NameID", name, out.str().c_str(), expires)) {
        // Hit a dup, so just retry, hopefully hitting the other branch.
        return insert(key, expires, name, index);
    }
}

string SSCache::insert(
    time_t expires,
    const Application& application,
    const char* client_addr,
    const saml2md::EntityDescriptor* issuer,
    const XMLCh* protocol,
    const saml2::NameID* nameid,
    const XMLCh* authn_instant,
    const XMLCh* session_index,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl,
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

    if (client_addr)
        obj.addmember("client_addr").string(client_addr);
    if (issuer) {
        auto_ptr_char entity_id(issuer->getEntityID());
        obj.addmember("entity_id").string(entity_id.get());
    }
    if (protocol) {
        auto_ptr_char prot(protocol);
        obj.addmember("protocol").string(prot.get());
    }
    if (authn_instant) {
        auto_ptr_char instant(authn_instant);
        obj.addmember("authn_instant").string(instant.get());
    }
    auto_ptr_char index(session_index);
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
    if (!m_storage->createText(key.get(), "session", record.str().c_str(), now + m_cacheTimeout))
        throw FatalProfileException("Attempted to create a session with a duplicate key.");
    
    // Store the reverse mapping for logout.
    auto_ptr_char name(nameid ? nameid->getName() : NULL);
    try {
        if (name.get())
            insert(key.get(), expires, name.get(), index.get());
    }
    catch (exception& ex) {
        m_log.error("error storing back mapping of NameID for logout: %s", ex.what());
    }

    if (tokens) {
        try {
            for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                ostringstream tokenstr;
                tokenstr << *(*t);
                auto_ptr_char tokenid((*t)->getID());
                if (!m_storage->createText(key.get(), tokenid.get(), tokenstr.str().c_str(), now + m_cacheTimeout))
                    throw IOException("duplicate assertion ID ($1)", params(1, tokenid.get()));
            }
        }
        catch (exception& ex) {
            m_log.error("error storing assertion along with session: %s", ex.what());
        }
    }

    const char* pid = obj["entity_id"].string();
    m_log.info("new session created: SessionID (%s) IdP (%s) Address (%s)", key.get(), pid ? pid : "none", client_addr);

    // Transaction Logging
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
    }

    return key.get();
}

Session* SSCache::find(const char* key, const Application& application, const char* client_addr, time_t* timeout)
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
            remove(key, application);
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
    
    if (timeout && *timeout > 0 && now - lastAccess >= *timeout) {
        m_log.info("session timed out (ID: %s)", key);
        remove(key, application);
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
            remove(key, application);
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
    
    if (timeout) {
        // Update storage expiration, if possible.
        try {
            m_storage->updateContext(key, now + m_cacheTimeout);
        }
        catch (exception& ex) {
            m_log.error("failed to update session expiration: %s", ex.what());
        }
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

void SSCache::remove(const char* key, const Application& application)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("remove");
#endif

    m_storage->deleteContext(key);
    m_log.info("removed session (%s)", key);

    TransactionLog* xlog = application.getServiceProvider().getTransactionLog();
    Locker locker(xlog);
    xlog->log.info("Destroyed session (applicationId: %s) (ID: %s)", application.getId(), key);
}

void SSCache::remove(
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const char* index,
    const Application& application,
    vector<string>& sessionsKilled
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("remove");
#endif

    auto_ptr_char entityID(issuer ? issuer->getEntityID() : NULL);
    auto_ptr_char name(nameid.getName());

    m_log.info(
        "request to logout sessions from (%s) for (%s) for session index (%s)",
        entityID.get() ? entityID.get() : "unknown", name.get(), index ? index : "all"
        );

    if (strlen(name.get()) > 255)
        const_cast<char*>(name.get())[255] = 0;

    // Read in potentially matching sessions.
    string record;
    int ver = m_storage->readText("NameID", name.get(), &record);
    if (ver == 0) {
        m_log.debug("no active sessions to remove for supplied issuer and name identifier");
        return;
    }

    DDF obj;
    DDFJanitor jobj(obj);
    istringstream in(record);
    in >> obj;

    // The record contains child lists for each known session index.
    DDF key;
    DDF sessions = obj.first();
    while (sessions.islist()) {
        if (!index || !strcmp(sessions.name(), index)) {
            key = sessions.first();
            while (key.isstring()) {
                // Fetch the session for comparison and possible removal.
                Session* session = find(key.string(), application);
                Locker locker(session);
                if (session) {
                    // Same issuer?
                    if (XMLString::equals(session->getEntityID(), entityID.get())) {
                        // Same NameID?
                        if (stronglyMatches(issuer->getEntityID(), application.getXMLString("entityID").second, nameid, *session->getNameID())) {
                            sessionsKilled.push_back(key.string());
                            remove(key.string(), application);  // let this throw to detect errors in case the full logout fails?
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
            m_storage->deleteText("NameID", name.get());
        }
        else if (!sessionsKilled.empty()) {
            ostringstream out;
            out << obj;
            if (m_storage->updateText("NameID", name.get(), out.str().c_str(), 0, ver) <= 0)
                m_log.warn("logout mapping record changed behind us, leaving it alone");
        }
    }
    catch (exception& ex) {
        m_log.error("error updating logout mapping record: %s", ex.what());
    }
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

void SSCache::receive(DDF& in, ostream& out)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("receive");
#endif

    if (!strcmp(in.name(),"find::"REMOTED_SESSION_CACHE"::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session removal.");

        const Application* app = SPConfig::getConfig().getServiceProvider()->getApplication(in["application_id"].string());
        if (!app)
            throw ListenerException("Application not found, check configuration?");

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
        if (in["timeout"].string()) {
            time_t timeout = 0;
            auto_ptr_XMLCh dt(in["timeout"].string());
            DateTime dtobj(dt.get());
            dtobj.parseDateTime();
            timeout = dtobj.getEpoch();
                    
            if (timeout > 0 && now - lastAccess >= timeout) {
                m_log.info("session timed out (ID: %s)", key);
                remove(key,*app);
                throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
            } 

            // Update storage expiration, if possible.
            try {
                m_storage->updateContext(key, now + m_cacheTimeout);
            }
            catch (exception& ex) {
                m_log.error("failed to update session expiration: %s", ex.what());
            }
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

        const Application* app = SPConfig::getConfig().getServiceProvider()->getApplication(in["application_id"].string());
        if (!app)
            throw ListenerException("Application not found, check configuration?");

        remove(key,*app);
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
