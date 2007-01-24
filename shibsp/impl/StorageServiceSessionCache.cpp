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
 * StorageService-based SessionCache implementation
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
        StoredSession(SSCache* cache, DDF& obj) : m_cache(cache), m_obj(obj) {}
        
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
                DDF id = m_obj["assertion_ids"].first();
                while (id.isstring()) {
                    m_ids.push_back(id.string());
                    id = id.next();
                }
            }
            return m_ids;
        }
        
        void addAttributes(const vector<Attribute*>& attributes);
        const RootObject* getAssertion(const char* id) const;
        void addAssertion(RootObject* assertion);

    private:
        DDF m_obj;
        saml2::NameID* m_nameid;
        vector<const Attribute*> m_attributes;
        mutable vector<const char*> m_ids;
        mutable map<string,RootObject*> m_tokens;
        time_t m_sessionCreated,m_lastAccess;
        SSCache* m_cache;
    };
    
    class SSCache : public SessionCache
    {
    public:
        SSCache(const DOMElement* e);
        ~SSCache() {}
    
        DDF receive(const DDF& in);
        
        string insert(
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
        Session* find(const char* key, const Application& application, const char* client_addr);
        void remove(const char* key, const Application& application, const char* client_addr);

        Category& m_log;
        StorageService* m_storage;
    };

    SessionCache* SHIBSP_DLLLOCAL StorageServiceCacheFactory(const DOMElement* const & e)
    {
        return new SSCache(e);
    }

    static const XMLCh storageService[] =   UNICODE_LITERAL_14(s,t,o,r,a,g,e,S,e,r,v,i,c,e);
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

    DDF attr;
    DDF attrs = m_obj["attributes"];
    if (!attrs.islist())
        attrs = m_obj.addmember("attributes").list();
    for (vector<Attribute*>::const_iterator a=attributes.begin(); a!=attributes.end(); ++a) {
        attr = (*a)->marshall();
        attrs.add(attr);
    }
    
    ostringstream record;
    record << m_obj;
    
    if (!m_cache->m_storage->updateText(m_obj["application_id"].string(), m_obj.name(), record.str().c_str())) {
        // Roll back modification to record.
        vector<Attribute*>::size_type count = attributes.size();
        while (count--)
            attrs.last().destroy();            
        m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
        throw IOException("Unable to update stored session.");
    }

    // Transfer ownership to us.
    m_attributes.insert(m_attributes.end(), attributes.begin(), attributes.end());

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
    
    DDF tokens = m_obj["assertions"];
    if (!tokens.isstruct())
        tokens = m_obj.addmember("assertions").structure();
    tokens = tokens.addmember(id.get()).string(os.str().c_str());

    ostringstream record;
    record << m_obj;
    
    if (!m_cache->m_storage->updateText(m_obj["application_id"].string(), m_obj.name(), record.str().c_str())) {
        // Roll back modification to record.
        tokens.destroy();
        m_cache->m_log.error("updateText failed on StorageService for session (%s)", m_obj.name());
        throw IOException("Unable to update stored session.");
    }

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
    // TODO: assign storage service
}

string SSCache::insert(
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

    time_t created = time(NULL);
#ifndef HAVE_GMTIME_R
    struct tm* ptime=gmtime(&created);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&created,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);

    // Store session properties in DDF.
    DDF obj = DDF(key.get()).structure();
    obj.addmember("created").string(timebuf);
    obj.addmember("client_address").string(client_addr);
    obj.addmember("application_id").string(application.getId());
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
    m_storage->createText(application.getId(), key.get(), record.str().c_str(), created + m_cacheTimeout);
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

Session* SSCache::find(const char* key, const Application& application, const char* client_addr)
{
    return NULL;
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
