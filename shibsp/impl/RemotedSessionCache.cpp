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

/**
 * RemotedSessionCache.cpp
 * 
 * SessionCache implementation that delegates to a remoted version.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "attribute/Attribute.h"
#include "remoting/ListenerService.h"
#include "util/SPConstants.h"

#include <sstream>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class RemotedSession : public virtual Session
    {
    public:
        RemotedSession(const char* key, DDF& obj) : m_key(key), m_obj(obj), m_nameid(NULL) {
            const char* nameid = obj["nameid"].string();
            if (!nameid)
                throw FatalProfileException("NameID missing from remotely cached session.");
            
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
        
        ~RemotedSession() {
            m_obj.destroy();
            delete m_nameid;
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
            for_each(m_tokens.begin(), m_tokens.end(), xmltooling::cleanup_pair<string,RootObject>());
        }
        
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
        string m_key;
        mutable DDF m_obj;
        saml2::NameID* m_nameid;
        vector<const Attribute*> m_attributes;
        mutable vector<const char*> m_ids;
        mutable map<string,RootObject*> m_tokens;
    };
    
    class RemotedCache : public SessionCache
    {
    public:
        RemotedCache(const DOMElement* e);
        ~RemotedCache() {}
    
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
    };

    SessionCache* SHIBSP_DLLLOCAL RemotedCacheFactory(const DOMElement* const & e)
    {
        return new RemotedCache(e);
    }
}

void RemotedSession::addAttributes(const vector<Attribute*>& attributes)
{
    DDF in("addAttributes::"REMOTED_SESSION_CACHE);
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(m_key.c_str());

    DDF attr;
    DDF attrs = in.addmember("attributes").list();
    for (vector<Attribute*>::const_iterator a=attributes.begin(); a!=attributes.end(); ++a) {
        attr = (*a)->marshall();
        attrs.add(attr);
    }

    attr=SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
    DDFJanitor jout(attr);
    
    // Transfer ownership to us.
    m_attributes.insert(m_attributes.end(), attributes.begin(), attributes.end());
}

const RootObject* RemotedSession::getAssertion(const char* id) const
{
    map<string,RootObject*>::const_iterator i = m_tokens.find(id);
    if (i!=m_tokens.end())
        return i->second;
    
    DDF in("getAssertion::"REMOTED_SESSION_CACHE);
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(m_key.c_str());
    in.addmember("assertion_id").string(id);

    DDF out = SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
    DDFJanitor jout(out);
    
    const char* tokenstr = out["assertion"].string();
    if (!tokenstr)
        return NULL;
    
    // Parse and bind the document into an XMLObject.
    istringstream instr(tokenstr);
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr); 
    XercesJanitor<DOMDocument> janitor(doc);
    auto_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();
    
    RootObject* token = dynamic_cast<RootObject*>(xmlObject.get());
    if (!token || !token->isAssertion())
        throw FatalProfileException("Remoted call for cached assertion returned an unknown object type.");

    // Transfer ownership to us.
    xmlObject.release();
    m_tokens[id]=token;
    return token;
}

void RemotedSession::addAssertion(RootObject* assertion)
{
    if (!assertion || !assertion->isAssertion())
        throw FatalProfileException("Unknown object type passed to session cache for storage.");

    DDF in("addAssertion::"REMOTED_SESSION_CACHE);
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(m_key.c_str());
    
    ostringstream os;
    os << *assertion;
    in.addmember("assertion").string(os.str().c_str());

    DDF out = SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
    out.destroy();
    delete assertion;
}

RemotedCache::RemotedCache(const DOMElement* e) : SessionCache(e)
{
    if (!SPConfig::getConfig().getServiceProvider()->getListenerService())
        throw ConfigurationException("RemotedCacheService requires a ListenerService, but none available.");
}

string RemotedCache::insert(
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
    DDF in("insert::"REMOTED_SESSION_CACHE);
    DDFJanitor jin(in);
    in.structure();
    in.addmember("application_id").string(application.getId());
    in.addmember("client_address").string(client_addr);
    if (issuer) {
        auto_ptr_char provid(issuer->getEntityID());
        in.addmember("entity_id").string(provid.get());
    }
    if (authn_instant)
        in.addmember("authn_instant").string(authn_instant);
    if (session_index)
        in.addmember("session_index").string(session_index);
    if (authncontext_class)
        in.addmember("authncontext_class").string(authncontext_class);
    if (authncontext_decl)
        in.addmember("authncontext_decl").string(authncontext_decl);
    
    ostringstream namestr;
    namestr << nameid;
    in.addmember("nameid").string(namestr.str().c_str());

    if (ssoToken) {
        ostringstream tokenstr;
        tokenstr << *ssoToken;
        auto_ptr_char tokenid(ssoToken->getID());
        in.addmember("assertion_ids").list().add(DDF(NULL).string(tokenid.get()));
        in.addmember("assertions").list().add(DDF(NULL).string(tokenstr.str().c_str()));
    }
    
    if (attributes) {
        DDF attr;
        DDF attrs = in.addmember("attributes").list();
        for (vector<Attribute*>::const_iterator a=attributes->begin(); a!=attributes->end(); ++a) {
            attr = (*a)->marshall();
            attrs.add(attr);
        }
    }

    DDF out=SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
    DDFJanitor jout(out);
    if (out["key"].isstring()) {
        for_each(attributes->begin(), attributes->end(), xmltooling::cleanup<Attribute>());
        return out["key"].string();
    }
    throw RetryableProfileException("A remoted cache insertion operation did not return a usable session key.");
}

Session* RemotedCache::find(const char* key, const Application& application, const char* client_addr)
{
    DDF in("find::"REMOTED_SESSION_CACHE), out;
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(key);
    in.addmember("application_id").string(application.getId());
    in.addmember("client_address").string(client_addr);
    
    try {
        out=SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
        if (!out.isstruct()) {
            out.destroy();
            return NULL;
        }
        
        // Wrap the results in a stub entry and return it to the caller.
        return new RemotedSession(key, out);
    }
    catch (...) {
        out.destroy();
        throw;
    }
}

void RemotedCache::remove(const char* key, const Application& application, const char* client_addr)
{
    DDF in("remove::"REMOTED_SESSION_CACHE);
    DDFJanitor jin(in);
    in.structure();
    in.addmember("key").string(key);
    in.addmember("application_id").string(application.getId());
    in.addmember("client_address").string(client_addr);
    
    DDF out = SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
    out.destroy();
}
