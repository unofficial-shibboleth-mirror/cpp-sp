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

/** StorageServiceSessionCache.cpp
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
        StoredSession(SSCache* cache, const Application& app, DDF& obj, int version)
                : m_appId(app.getId()), m_version(version), m_obj(obj), m_cache(cache) {
            const char* nameid = obj["nameid"].string();
            if (!nameid)
                throw FatalProfileException("NameID missing from cached session.");
            
            // Parse and bind the document into an XMLObject.
            istringstream instr(nameid);
            DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr); 
            XercesJanitor<DOMDocument> janitor(doc);
            auto_ptr<saml2::NameID> n(saml2::NameIDBuilder::buildNameID());
            n->unmarshall(doc->getDocumentElement(), true);
            janitor.release();
            
            // TODO: Process attributes...

            m_nameid = n.release();
        }
        
        ~StoredSession();
        
        Lockable* lock() {
            return this;
        }
        void unlock() {
            delete this;
        }
        
        const char* getClientAddress() const {
            return m_obj["client_address"].string();
        }
        const char* getEntityID() const {
            return m_obj["entity_id"].string();
        }
        const char* getAuthnInstant() const {
            return m_obj["authn_instant"].string();
        }
        const opensaml::saml2::NameID& getNameID() const {
            return *m_nameid;
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
        const vector<const Attribute*>& getAttributes() const {
            return m_attributes;
        }
        const vector<const char*>& getAssertionIDs() const {
            if (m_ids.empty()) {
                DDF id = m_obj["assertions"].first();
                while (id.isstring()) {
                    m_ids.push_back(id.name());
                    id = id.next();
                }
            }
            return m_ids;
        }
        
        void addAttributes(const vector<Attribute*>& attributes);
        const RootObject* getAssertion(const char* id) const;
        void addAssertion(RootObject* assertion);

    private:
        string m_appId;
        int m_version;
        DDF m_obj;
        saml2::NameID* m_nameid;
        vector<const Attribute*> m_attributes;
        mutable vector<const char*> m_ids;
        mutable map<string,RootObject*> m_tokens;
        SSCache* m_cache;
    };
    
    class SSCache : public SessionCache, public virtual Remoted
    {
    public:
        SSCache(const DOMElement* e);
        ~SSCache() {}
    
        void receive(const DDF& in, ostream& out);
        
        string insert(
            time_t expires,
            const Application& application,
            const char* client_addr,
            const saml2md::EntityDescriptor* issuer,
            const saml2::NameID& nameid,
            const char* authn_instant=NULL,
            const char* session_index=NULL,
            const char* authncontext_class=NULL,
            const char* authncontext_decl=NULL,
            const RootObject* ssoToken=NULL,
            const vector<Attribute*>* attributes=NULL
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
    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
    for_each(m_tokens.begin(), m_tokens.end(), xmltooling::cleanup_pair<string,RootObject>());
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
        
        ostringstream str;
        str << m_obj;
        string record(str.str()); 

        ver = m_cache->m_storage->updateText(m_appId.c_str(), m_obj.name(), record.c_str(), 0, m_version);
        if (ver <= 0) {
            // Roll back modification to record.
            vector<Attribute*>::size_type count = attributes.size();
            while (count--)
                attrs.last().destroy();            
        }
        if (!ver) {
            // Fatal problem with update.
            m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
            throw IOException("Unable to update stored session.");
        }
        else if (ver < 0) {
            // Out of sync.
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(m_appId.c_str(), m_obj.name(), &record, NULL);
            if (!ver) {
                m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
                throw IOException("Unable to update stored session.");
            }
            
            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_obj.destroy();
            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_version = ver;
            m_obj = newobj;
            // TODO: handle attributes
            
            ver = -1;
        }
        else {
            // Update with new version.
            m_version = ver;
        }
    } while (ver < 0);  // negative indicates a sync issue so we retry

    // Transfer ownership to us.
    m_attributes.insert(m_attributes.end(), attributes.begin(), attributes.end());

    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.infoStream() <<
        "Added the following attributes to session (ID: " <<
            m_obj.name() <<
        ") for (applicationId: " <<
            m_appId.c_str() <<
        ") {";
    for (vector<Attribute*>::const_iterator a=attributes.begin(); a!=attributes.end(); ++a)
        xlog->log.infoStream() << "\t" << (*a)->getId() << " (" << (*a)->valueCount() << " values)";
    xlog->log.info("}");
}

const RootObject* StoredSession::getAssertion(const char* id) const
{
    map<string,RootObject*>::const_iterator i = m_tokens.find(id);
    if (i!=m_tokens.end())
        return i->second;
    
    // Parse and bind the document into an XMLObject.
    const char* tokenstr = m_obj["assertions"][id].string();
    if (!tokenstr)
        throw FatalProfileException("Assertion not found in cache.");
    istringstream instr(tokenstr);
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();
    
    RootObject* token = dynamic_cast<RootObject*>(xmlObject.get());
    if (!token || !token->isAssertion())
        throw FatalProfileException("Request for cached assertion returned an unknown object type.");

    // Transfer ownership to us.
    xmlObject.release();
    m_tokens[id]=token;
    return token;
}

void StoredSession::addAssertion(RootObject* assertion)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("addAssertion");
#endif
    
    if (!assertion || !assertion->isAssertion())
        throw FatalProfileException("Unknown object type passed to session for storage.");

    auto_ptr_char id(assertion->getID());

    m_cache->m_log.debug("adding assertion (%s) to session (%s)", id.get(), m_obj.name());

    ostringstream os;
    os << *assertion;
    
    int ver;
    do {
        DDF token = m_obj["assertions"];
        if (!token.isstruct())
            token = m_obj.addmember("assertions").structure();
        token = token.addmember(id.get()).string(os.str().c_str());
    
        ostringstream str;
        str << m_obj;
        string record(str.str()); 

        ver = m_cache->m_storage->updateText(m_appId.c_str(), m_obj.name(), record.c_str(), 0, m_version);
        if (ver <= 0)
            token.destroy();            
        if (!ver) {
            // Fatal problem with update.
            m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
            throw IOException("Unable to update stored session.");
        }
        else if (ver < 0) {
            // Out of sync.
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(m_appId.c_str(), m_obj.name(), &record, NULL);
            if (!ver) {
                m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
                throw IOException("Unable to update stored session.");
            }
            
            // Reset object.
            DDF newobj;
            istringstream in(record);
            in >> newobj;

            m_obj.destroy();
            m_ids.clear();
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            m_attributes.clear();
            m_version = ver;
            m_obj = newobj;
            // TODO: handle attributes
            
            ver = -1;
        }
        else {
            // Update with new version.
            m_version = ver;
        }
    } while (ver < 0); // negative indicates a sync issue so we retry

    delete assertion;

    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.info(
        "Added assertion (ID: %s) to session for (applicationId: %s) with (ID: %s)",
        id.get(), m_appId.c_str(), m_obj.name()
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
        listener->regListener("insert::"REMOTED_SESSION_CACHE,this);
        listener->regListener("find::"REMOTED_SESSION_CACHE,this);
        listener->regListener("remove::"REMOTED_SESSION_CACHE,this);
    }
    else {
        m_log.info("no ListenerService available, cache remoting is disabled");
    }
}

string SSCache::insert(
    time_t expires,
    const Application& application,
    const char* client_addr,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const char* authn_instant,
    const char* session_index,
    const char* authncontext_class,
    const char* authncontext_decl,
    const RootObject* ssoToken,
    const vector<Attribute*>* attributes
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("insert");
#endif

    m_log.debug("creating new session");

    auto_ptr_char key(SAMLConfig::getConfig().generateIdentifier());

    // Store session properties in DDF.
    DDF obj = DDF(key.get()).structure();
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
    obj.addmember("client_address").string(client_addr);
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

    ostringstream namestr;
    namestr << nameid;
    obj.addmember("nameid").string(namestr.str().c_str());
    
    if (ssoToken) {
        ostringstream tokenstr;
        tokenstr << *ssoToken;
        auto_ptr_char tokenid(ssoToken->getID());
        obj.addmember("assertions").structure().addmember(tokenid.get()).string(tokenstr.str().c_str());
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
    m_storage->createText(application.getId(), key.get(), record.str().c_str(), time(NULL) + m_cacheTimeout);
    const char* pid = obj["entity_id"].string();
    m_log.debug("new session created: SessionID (%s) IdP (%s) Address (%s)", key.get(), pid ? pid : "none", client_addr);

    // Transaction Logging
    auto_ptr_char name(nameid.getName());
    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.infoStream() <<
        "New session (ID: " <<
            key.get() <<
        ") with (applicationId: " <<
            application.getId() <<
        ") for principal from (IdP: " <<
            (pid ? pid : "none") <<
        ") at (ClientAddress: " <<
            client_addr <<
        ") with (NameIdentifier: " <<
            name.get() <<
        ")";
    
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
    int ver = m_storage->readText(application.getId(), key, &record, &lastAccess);
    if (!ver)
        return NULL;
    
    m_log.debug("reconstituting session and checking for validity");
    
    DDF obj;
    istringstream in(record);
    in >> obj;
    
    lastAccess -= m_cacheTimeout;   // adjusts it back to the last time the record's timestamp was touched
 
    if (client_addr) {
        if (m_log.isDebugEnabled())
            m_log.debug("comparing client address %s against %s", client_addr, obj["client_address"].string());
        if (strcmp(obj["client_address"].string(),client_addr)) {
            m_log.info("client address mismatch");
            RetryableProfileException ex(
                "Your IP address ($1) does not match the address recorded at the time the session was established.",
                params(1,client_addr)
                );
            string eid(obj["entity_id"].string());
            obj.destroy();
            MetadataProvider* m=application.getMetadataProvider();
            Locker locker(m);
            annotateException(&ex,m->getEntityDescriptor(eid.c_str(),false)); // throws it
        }
    }

    time_t now=time(NULL);
    
    if (timeout > 0 && now - lastAccess >= timeout) {
        m_log.info("session timed out (ID: %s)", key);
        RetryableProfileException ex("Your session has expired, and you must re-authenticate.");
        string eid(obj["entity_id"].string());
        obj.destroy();
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
            RetryableProfileException ex("Your session has expired, and you must re-authenticate.");
            string eid(obj["entity_id"].string());
            obj.destroy();
            MetadataProvider* m=application.getMetadataProvider();
            Locker locker(m);
            annotateException(&ex,m->getEntityDescriptor(eid.c_str(),false)); // throws it
        }
    }
    
    // Update storage expiration, if possible.
    ver = m_storage->updateText(application.getId(), key, NULL, now + m_cacheTimeout); 
    if (!ver)
        m_log.error("failed to update record expiration");

    // Finally build the Session object.
    try {
        return new StoredSession(this, application, obj, ver);
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

    m_storage->deleteText(application.getId(), key);

    TransactionLog* xlog = SPConfig::getConfig().getServiceProvider()->getTransactionLog();
    Locker locker(xlog);
    xlog->log.info("Destroyed session (applicationId: %s) (ID: %s)", application.getId(), key);
}

void SSCache::receive(const DDF& in, ostream& out)
{
}
