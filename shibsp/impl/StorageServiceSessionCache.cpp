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
#include "TransactionLog.h"
#include "attribute/Attribute.h"
#include "handler/RemotedHandler.h"
#include "impl/StoredSession.h"
#include "impl/StorageServiceSessionCache.h"
#include "util/IPRange.h"
#include "util/SPConstants.h"

#include <algorithm>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/bind.hpp>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/io/HTTPResponse.h>
#include <xmltooling/security/DataSealer.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
# include <saml/SAMLConfig.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/metadata/Metadata.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/util/ParserPool.h>
# include <xmltooling/util/StorageService.h>
using namespace opensaml::saml2md;
#else
# include <xercesc/util/XMLDateTime.hpp>
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

SessionCache* SHIBSP_DLLLOCAL StorageServiceCacheFactory(const DOMElement* const & e, bool deprecationSupport)
{
    return new SSCache(e, deprecationSupport);
}

void SHIBSP_API shibsp::registerSessionCaches()
{
    SPConfig::getConfig().SessionCacheManager.registerFactory(STORAGESERVICE_SESSION_CACHE, StorageServiceCacheFactory);
}

SessionCache::SessionCache()
{
}

SessionCache::~SessionCache()
{
}

SSCache::SSCache(const DOMElement* e, bool deprecationSupport)
    :
#ifndef SHIBSP_LITE
      m_storage(nullptr), m_storage_lite(nullptr), m_cacheAssertions(true), m_reverseIndex(true), m_softRevocation(true), m_reverseIndexMaxSize(0),
#endif
      m_root(e), m_inprocTimeout(900), m_cacheTimeout(0), m_cacheAllowance(0),
      m_log(Category::getInstance(SHIBSP_LOGCAT ".SessionCache")), inproc(true), shutdown(false)
{
    SPConfig& conf = SPConfig::getConfig();
    inproc = conf.isEnabled(SPConfig::InProcess);

    static const XMLCh cacheAllowance[] =       UNICODE_LITERAL_14(c,a,c,h,e,A,l,l,o,w,a,n,c,e);
    static const XMLCh cacheAssertions[] =      UNICODE_LITERAL_15(c,a,c,h,e,A,s,s,e,r,t,i,o,n,s);
    static const XMLCh cacheTimeout[] =         UNICODE_LITERAL_12(c,a,c,h,e,T,i,m,e,o,u,t);
    static const XMLCh excludeReverseIndex[] =  UNICODE_LITERAL_19(e,x,c,l,u,d,e,R,e,v,e,r,s,e,I,n,d,e,x);
    static const XMLCh persistedAttributes[] =  UNICODE_LITERAL_19(p,e,r,s,i,s,t,e,d,A,t,t,r,i,b,u,t,e,s);
    static const XMLCh inprocTimeout[] =        UNICODE_LITERAL_13(i,n,p,r,o,c,T,i,m,e,o,u,t);
    static const XMLCh inboundHeader[] =        UNICODE_LITERAL_13(i,n,b,o,u,n,d,H,e,a,d,e,r);
    static const XMLCh maintainReverseIndex[] = UNICODE_LITERAL_20(m,a,i,n,t,a,i,n,R,e,v,e,r,s,e,I,n,d,e,x);
    static const XMLCh reverseIndexMaxSize[] =  UNICODE_LITERAL_19(r,e,v,e,r,s,e,I,n,d,e,x,M,a,x,S,i,z,e);
    static const XMLCh softRevocation[] =       UNICODE_LITERAL_14(s,o,f,t,R,e,v,o,c,a,t,i,o,n);
    static const XMLCh outboundHeader[] =       UNICODE_LITERAL_14(o,u,t,b,o,u,n,d,H,e,a,d,e,r);
    static const XMLCh _StorageService[] =      UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh _StorageServiceLite[] =  UNICODE_LITERAL_18(S,t,o,r,a,g,e,S,e,r,v,i,c,e,L,i,t,e);
    static const XMLCh _unreliableNetworks[] =  UNICODE_LITERAL_18(u,n,r,e,l,i,a,b,l,e,N,e,t,w,o,r,k,s);

    if (e && e->hasAttributeNS(nullptr, cacheTimeout)) {
        m_log.warn("DEPRECATED: cacheTimeout property is replaced by cacheAllowance (see documentation)");
        m_cacheTimeout = XMLHelper::getAttrInt(e, 0, cacheTimeout);
    }
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
                throw ConfigurationException("SessionCache unable to locate StorageService ($1), check configuration.", params(1, ssid.c_str()));
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
                throw ConfigurationException("SessionCache unable to locate 'lite' StorageService ($1), check configuration.", params(1, ssid.c_str()));
        }
        if (!m_storage_lite) {
            m_log.info("StorageService for 'lite' use not set, using standard StorageService");
            m_storage_lite = m_storage;
        }

        m_softRevocation = XMLHelper::getAttrBool(e, true, softRevocation);
        m_cacheAssertions = XMLHelper::getAttrBool(e, deprecationSupport, cacheAssertions);
        m_reverseIndex = XMLHelper::getAttrBool(e, true, maintainReverseIndex);
        m_reverseIndexMaxSize = XMLHelper::getAttrInt(e, 0, reverseIndexMaxSize);
        const XMLCh* excludedNames = e ? e->getAttributeNS(nullptr, excludeReverseIndex) : nullptr;
        if (excludedNames && *excludedNames) {
            XMLStringTokenizer toks(excludedNames);
            while (toks.hasMoreTokens())
                m_excludedNames.insert(toks.nextToken());
        }

        const XMLCh* persistedAttributeIds = e ? e->getAttributeNS(nullptr, persistedAttributes) : nullptr;
        if (persistedAttributeIds && *persistedAttributeIds) {
            XMLStringTokenizer toks(persistedAttributeIds);
            while (toks.hasMoreTokens()) {
                auto_ptr_char tok(toks.nextToken());
                m_persistedAttributeIds.insert(tok.get());
            }
        }

        if (!m_persistedAttributeIds.empty()) {
			if (XMLToolingConfig::getConfig().getDataSealer() == nullptr)
				throw ConfigurationException("Persisting sessions across nodes requires DataSealer component, check configuration");
			XMLToolingConfig::getConfig().getDataSealer()->wrap("testing", time(nullptr)); // should throw if no key is installed
        }
    }
#endif

    const XMLCh* unreliableNetworks = e ? e->getAttributeNS(nullptr, _unreliableNetworks) : nullptr;
    if (unreliableNetworks && *unreliableNetworks) {
        XMLStringTokenizer toks(unreliableNetworks);
        while (toks.hasMoreTokens()) {
            auto_ptr_char tok(toks.nextToken());
            m_unreliableNetworks.push_back(IPRange::parseCIDRBlock(tok.get()));
        }
    }

    ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
    if (inproc) {
        if (!conf.isEnabled(SPConfig::OutOfProcess) && !listener)
            throw ConfigurationException("SessionCache requires a ListenerService, but none available.");
        m_lock.reset(RWLock::create());
        shutdown_wait.reset(CondWait::create());
        cleanup_thread.reset(Thread::create(&cleanup_fn, this));
    }
#ifndef SHIBSP_LITE
    else {
        if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
            listener->regListener("find::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
            listener->regListener("recover::" STORAGESERVICE_SESSION_CACHE "::SessionCache", this);
            listener->regListener("remove::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
            listener->regListener("touch::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
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
        if (shutdown_wait.get())
            shutdown_wait->signal();
        if (cleanup_thread.get())
            cleanup_thread->join(nullptr);

        for_each(m_hashtable.begin(),m_hashtable.end(),cleanup_pair<string,StoredSession>());
    }
#ifndef SHIBSP_LITE
    else {
        SPConfig& conf = SPConfig::getConfig();
        ListenerService* listener=conf.getServiceProvider()->getListenerService(false);
        if (listener && conf.isEnabled(SPConfig::OutOfProcess)) {
            listener->unregListener("find::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
            listener->unregListener("recover::" STORAGESERVICE_SESSION_CACHE "::SessionCache", this);
            listener->unregListener("remove::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
            listener->unregListener("touch::" STORAGESERVICE_SESSION_CACHE "::SessionCache",this);
        }
    }
#endif
}

unsigned long SSCache::getCacheTimeout(const Application& app) const
{
    // Computes offset for adjusting expiration of sessions.
    // This can either be static, or dynamic based on the per-app session timeout or lifetime.
    if (m_cacheTimeout)
        return m_cacheTimeout;
    pair<bool, unsigned int> timeout = pair<bool, unsigned int>(false, 3600);
    const PropertySet* props = app.getPropertySet("Sessions");
    if (props) {
        timeout = props->getUnsignedInt("timeout");
        if (!timeout.first)
            timeout.second = 3600;
    }
    // As long as one of the two factors is set, add them together.
    if (timeout.second > 0 || m_cacheAllowance > 0)
        return timeout.second + m_cacheAllowance;

    // If timeouts are off, and there's no cache slop set, then use the lifetime.
    timeout = pair<bool, unsigned int>(false, 28800);
    if (props) {
        timeout = props->getUnsignedInt("lifetime");
        if (!timeout.first || timeout.second == 0)
            timeout.second = 28800;
    }
    return timeout.second;
}

string SSCache::active(const Application& app, const HTTPRequest& request)
{
    if (!m_inboundHeader.empty()) {
        string session_id = request.getHeader(m_inboundHeader.c_str());
        if (!session_id.empty())
            return session_id;
    }

    const char* session_id = request.getCookie(app.getCookieName("_shibsession_").c_str());
    return (session_id ? session_id : "");
}

bool SSCache::compareAddresses(const char* client_addr, const char* session_addr) const
{
    if (XMLString::equals(client_addr, session_addr)) {
        return true;
    }

    for (vector<IPRange>::const_iterator i = m_unreliableNetworks.begin(); i != m_unreliableNetworks.end(); ++i) {
        if (i->contains(client_addr) && i->contains(session_addr)) {
            return true;
        }
    }

    return false;
}

#ifndef SHIBSP_LITE

void SSCache::test()
{
    XMLCh* wide = SAMLConfig::getConfig().generateIdentifier();
    auto_ptr_char temp(wide);
    XMLString::release(&wide);
    m_storage->createString("SessionCacheTest", temp.get(), "Test", time(nullptr) + 60);
    m_storage->deleteString("SessionCacheTest", temp.get());
}

void SSCache::insert(const char* key, time_t expires, const char* name, const char* index, short attempts)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("insert");
#endif
    if (attempts > 10) {
        throw IOException("Exceeded retry limit.");
    }

    if (!name || !*name) {
        m_log.warn("NameID value was empty or null, ignoring request to store for logout");
        return;
    }

    string dup;
    unsigned int storageLimit = m_storage_lite->getCapabilities().getKeySize();
    if (strlen(name) > storageLimit) {
        dup = string(name).substr(0, storageLimit);
        name = dup.c_str();
    }

    DDF obj;
    DDFJanitor jobj(obj);

    // Since we can't guarantee uniqueness, check for an existing record.
    string record;
    time_t recordexp = 0;
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
    if (!sessions.isstruct())
        sessions.structure();
    else if (sessions.integer() == m_reverseIndexMaxSize)
        sessions.first().destroy();
    sessions.addmember(key);

    // Remarshall the record.
    ostringstream out;
    out << obj;

    // Try and store it back...
    if (ver > 0) {
        ver = m_storage_lite->updateText("NameID", name, out.str().c_str(), max(expires, recordexp), ver);
        if (ver <= 0) {
            // Out of sync, or went missing, so retry.
            return insert(key, expires, name, index, attempts + 1);
        }
    }
    else if (!m_storage_lite->createText("NameID", name, out.str().c_str(), expires)) {
        // Hit a dup, so just retry, hopefully hitting the other branch.
        return insert(key, expires, name, index, attempts + 1);
    }
}

void SSCache::insert(
    string& sessionID,
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

    if (name.get() && *name.get()) {
        // Check for a pending logout.
        unsigned int storageLimit = m_storage_lite->getCapabilities().getKeySize();
        string namebuf = name.get();
        if (namebuf.length() > storageLimit)
            namebuf = namebuf.substr(0, storageLimit);
        string pending;
        int ver = m_storage_lite->readText("Logout", namebuf.c_str(), &pending);
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
                XMLDateTime dtobj(dt.get());
                dtobj.parseDateTime();
                time_t logexp = dtobj.getEpoch();
                if (now - XMLToolingConfig::getConfig().clock_skew_secs < logexp)
                    throw FatalProfileException("A logout message from your identity provider has blocked your login attempt.");
            }
        }
    }

    XMLCh* widekey = SAMLConfig::getConfig().generateIdentifier();
    auto_ptr_char key(widekey);
    XMLString::release(&widekey);

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

    string caddr(httpRequest.getRemoteAddr());
    if (!caddr.empty()) {
        DDF addrobj = obj.addmember("client_addr").structure();
        addrobj.addmember(StoredSession::getAddressFamily(caddr.c_str())).string(caddr.c_str());
    }

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
    if (name.get() && *name.get() && m_reverseIndex
            && (m_excludedNames.size() == 0 || m_excludedNames.count(nameid->getName()) == 0)) {
        try {
            insert(key.get(), expires, name.get(), index.get());
        }
        catch (const std::exception& ex) {
            m_log.error("error storing back mapping of NameID for logout: %s", ex.what());
        }
    }

    if (tokens && m_cacheAssertions) {
        try {
            for (vector<const Assertion*>::const_iterator t = tokens->begin(); t!=tokens->end(); ++t) {
                ostringstream tokenstr;
                tokenstr << *(*t);
                auto_ptr_char tokenid((*t)->getID());
                if (!tokenid.get() || !*tokenid.get() || strlen(tokenid.get()) > m_storage->getCapabilities().getKeySize())
                    throw IOException("Assertion ID is missing or exceeds key size of storage service.");
                else if (!m_storage->createText(key.get(), tokenid.get(), tokenstr.str().c_str(), now + cacheTimeout))
                    throw IOException("Duplicate assertion ID ($1)", params(1, tokenid.get()));
            }
        }
        catch (const std::exception& ex) {
            m_log.error("error storing assertion along with session: %s", ex.what());
        }
    }

    const char* pid = obj["entity_id"].string();
    const char* prot = obj["protocol"].string();
    m_log.info("new session created: ID (%s) IdP (%s) Protocol(%s) Address (%s)",
        key.get(), pid ? pid : "none", prot ? prot : "none", httpRequest.getRemoteAddr().c_str());

    if (!m_outboundHeader.empty())
        httpResponse.setResponseHeader(m_outboundHeader.c_str(), key.get());

    time_t cookieLifetime = 0;
    string shib_cookie = app.getCookieName("_shibsession_", &cookieLifetime);
    HTTPResponse::samesite_t sameSitePolicy = getSameSitePolicy(app);
    httpResponse.setCookie(shib_cookie.c_str(), key.get(), cookieLifetime, sameSitePolicy);
    sessionID = key.get();

    // See if we need to persist the session data itself to a cookie for cross-node recovery.
    if (!m_persistedAttributeIds.empty()) {
        persist(app, httpResponse, obj, expires, sameSitePolicy);
    }
}

void SSCache::persist(
    const Application& app,
    HTTPResponse& httpResponse,
    DDF& session,
    time_t expires,
    HTTPResponse::samesite_t sameSitePolicy
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("persist");
#endif

    m_log.debug("checking if session (%s) should be persisted to cookie", session.name());

    // We don't save assertions...
    session["assertions"].destroy();

    // Check each attribute.
    DDF attrs = session["attributes"];
    DDF attr = attrs.first();
    while (!attr.isnull()) {
        const char* aname = attr.first().name();
        if (m_persistedAttributeIds.count(aname) == 0) {
            m_log.debug("not persisting attribute for session recovery: %s", aname);
            attr.destroy();
        }
        else {
            m_log.debug("persisting attribute for session recovery: %s", aname);
        }
        attr = attrs.next();
    }

    if (attrs.integer() == 0) {
        m_log.info("session (%s) contained no attributes requiring persistence, will not be recoverable", session.name());
        return;
    }

    ostringstream persisted;
    persisted << session;

    try {
        string sealed = XMLToolingConfig::getConfig().getDataSealer()->wrap(persisted.str().c_str(), expires);
        sealed = XMLToolingConfig::getConfig().getURLEncoder()->encode(sealed.c_str());

        time_t cookieLifetime;
        string shib_cookie = app.getCookieName("_shibsealed_", &cookieLifetime);
        httpResponse.setCookie(shib_cookie.c_str(), sealed.c_str(), cookieLifetime, sameSitePolicy);
    }
    catch (const std::exception& e) {
        m_log.error("failed to wrap session (%s) with DataSealer: %s", session.name(), e.what());
    }
}

bool SSCache::matches(
    const Application& app,
    xmltooling::HTTPRequest& request,
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
    catch (const std::exception& ex) {
        m_log.error("error while matching session: %s", ex.what());
    }
    return false;
}

vector<string>::size_type SSCache::_logout(
    const Application& app,
    const saml2md::EntityDescriptor* issuer,
    const saml2::NameID& nameid,
    const set<string>* indexes,
    time_t expires,
    vector<string>& sessionsKilled,
    short attempts
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("logout");
#endif

    if (!m_storage)
        throw ConfigurationException("SessionCache logout requires a StorageService.");
    else if (attempts > 10)
        throw IOException("Exceeded retry limit.");

    auto_ptr_char entityID(issuer ? issuer->getEntityID() : nullptr);
    auto_ptr_char name(nameid.getName());

    m_log.info("request to logout sessions from (%s) for (%s)", entityID.get() ? entityID.get() : "unknown", name.get());

    unsigned int storageLimit = m_storage_lite->getCapabilities().getKeySize();
    if (strlen(name.get()) > storageLimit)
        const_cast<char*>(name.get())[storageLimit] = 0;

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
                return _logout(app, issuer, nameid, indexes, expires, sessionsKilled, attempts + 1);
            }
        }
        else if (!m_storage_lite->createText("Logout", name.get(), lout.str().c_str(), expires)) {
            // Hit a dup, so just retry, hopefully hitting the other branch.
            return _logout(app, issuer, nameid, indexes, expires, sessionsKilled, attempts + 1);
        }

        obj.destroy();
        record.erase();
    }

    if (!m_reverseIndex) {
        m_log.error("cannot support logout because maintainReverseIndex property is turned off");
        throw ConfigurationException("Logout is unsupported by the session cache configuration.");
    }

    // Read in potentially matching sessions.
    ver = m_storage_lite->readText("NameID", name.get(), &record);
    if (ver == 0) {
        m_log.debug("no active sessions to logout for supplied issuer and subject");
        return 0;
    }

    istringstream in(record);
    in >> obj;

    // The record contains child structs for each known session index.
    DDF key;
    DDF sessions = obj.first();
    while (sessions.isstruct()) {
        if (!indexes || indexes->empty() || indexes->count(sessions.name())) {
            key = sessions.first();
            while (!key.isnull()) {
                // Fetch the session for comparison.
                Session* session = nullptr;
                try {
                    session = find(app, key.name());
                }
                catch (const std::exception& ex) {
                    m_log.error("error locating session (%s): %s", key.name(), ex.what());
                }

                if (session) {
                    Locker locker(session, false);
                    // Same issuer?
                    if (XMLString::equals(session->getEntityID(), entityID.get())) {
                        // Same NameID?
                        if (stronglyMatches(issuer->getEntityID(), app.getRelyingParty(issuer)->getXMLString("entityID").second, nameid, *session->getNameID())) {
                            sessionsKilled.push_back(key.name());
                            key.destroy();
                        }
                        else {
                            m_log.debug("session (%s) contained a non-matching NameID, leaving it alone", key.name());
                        }
                    }
                    else {
                        m_log.debug("session (%s) established by different IdP, leaving it alone", key.name());
                    }
                }
                else {
                    // Session may already be gone, or it may be associated with a different application.
                    // To be conservative, we'll leave it alone. This isn't really increasing our security
                    // risk, because if we can't lookup the session, it's unlikely the calling logout code
                    // can either, so there's no chance of removing the session anyway.
                    m_log.warn("session (%s) not accessible for logout, may be gone, or associated with a different application", key.name());
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
    catch (const std::exception& ex) {
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

LogoutEvent* SSCache::newLogoutEvent(const Application& app) const
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::Logging))
        return nullptr;
    try {
        auto_ptr<TransactionLog::Event> event(SPConfig::getConfig().EventManager.newPlugin(LOGOUT_EVENT, nullptr, false));
        LogoutEvent* logout_event = dynamic_cast<LogoutEvent*>(event.get());
        if (logout_event) {
            logout_event->m_app = &app;
            event.release();
            return logout_event;
        }
        else {
            m_log.warn("unable to audit event, log event object was of an incorrect type");
        }
    }
    catch (const std::exception& ex) {
        m_log.warn("exception auditing event: %s", ex.what());
    }
    return nullptr;
}

#endif

HTTPResponse::samesite_t SSCache::getSameSitePolicy(const Application& app) const
{
    const PropertySet* props = app.getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> sameSiteSession = props->getString("sameSiteSession");
        if (sameSiteSession.first) {
            if (!strcmp(sameSiteSession.second, "None")) {
                return HTTPResponse::SAMESITE_NONE;
            }
            else if (!strcmp(sameSiteSession.second, "Lax")) {
                return HTTPResponse::SAMESITE_LAX;
            }
            else if (!strcmp(sameSiteSession.second, "Strict")) {
                return HTTPResponse::SAMESITE_STRICT;
            }
        }
    }
    return HTTPResponse::SAMESITE_ABSENT;
}

Session* SSCache::_find(const Application& app, const char* key, const char* recovery, const char* client_addr, time_t* timeout)
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
            DDF in("find::" STORAGESERVICE_SESSION_CACHE "::SessionCache"), out;
            DDFJanitor jin(in);
            in.structure();
            in.addmember("key").string(key);
            in.addmember("sealed").string(recovery);
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
            time_t lastAccess = 0;
            string record;
            int ver = m_storage->readText(key, "session", &record, &lastAccess);
            if (!ver) {
                if (recovery && *recovery && recover(app, key, recovery)) {
                    // Retry the read.
                    ver = m_storage->readText(key, "session", &record, &lastAccess);
                    if (!ver)
                        m_log.warn("recovered session (%s) is missing from storage service", key);
                }
                if (!ver)
                    return nullptr;
            }

            if (0 == lastAccess) {
                m_log.error("session (ID: %s) did not report time of last access", key);
                throw RetryableProfileException("Your session's last access time was missing, and you must re-authenticate.");
            }

            m_log.debug("reconstituting session and checking validity");

            istringstream in(record);
            in >> obj;

            unsigned long cacheTimeout = getCacheTimeout(app);
            lastAccess -= cacheTimeout;   // adjusts it back to the last time the record's timestamp was touched
            time_t now=time(nullptr);

            if (timeout && *timeout > 0 && now - lastAccess >= *timeout) {
                m_log.info("session timed out (ID: %s)", key);
                scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(app));
                if (logout_event.get()) {
                    logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_INVALID;
                    logout_event->m_sessions.push_back(key);
                    app.getServiceProvider().getTransactionLog()->write(*logout_event);
                }
                remove(app, key);
                const char* eid = obj["entity_id"].string();
                if (!eid) {
                    obj.destroy();
                    throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
                }
                string eid2(eid);
                obj.destroy();
                throw RetryableProfileException("Your session has timed out due to inactivity, and you must re-authenticate.",
                    namedparams(1, "entityID", eid2.c_str()));
            }

            if (timeout) {
                // Update storage expiration, if possible.
                try {
                    m_storage->updateContext(key, now + cacheTimeout);
                }
                catch (const std::exception& ex) {
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
        m_log.warn("an application (%s) tried to access another application's session", app.getId());
        session->unlock();
        return nullptr;
    }

    // Verify currency and update the timestamp if indicated by caller.
    try {
        session->validate(app, client_addr, timeout);
    }
    catch (...) {
#ifndef SHIBSP_LITE
        scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(app));
        if (logout_event.get()) {
            logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_INVALID;
            logout_event->m_session = session;
            logout_event->m_sessions.push_back(session->getID());
            app.getServiceProvider().getTransactionLog()->write(*logout_event);
        }
#endif
        session->unlock();
        remove(app, key);
        throw;
    }

    return session;
}

Session* SSCache::find(const Application& app, HTTPRequest& request, const char* client_addr, time_t* timeout)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("find");
#endif
    string id = active(app, request);
    if (id.empty())
        return nullptr;

    HTTPResponse::samesite_t sameSitePolicy = getSameSitePolicy(app);
    const char* c = request.getCookie(app.getCookieName("_shibsealed_").c_str());

    try {
        Session* session = _find(app, id.c_str(), c, client_addr, timeout);
        if (session)
            return session;

        HTTPResponse* response = dynamic_cast<HTTPResponse*>(&request);
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            response->setCookie(app.getCookieName("_shibsession_").c_str(), nullptr, 0, sameSitePolicy);
            response->setCookie(app.getCookieName("_shibsealed_").c_str(), nullptr, 0, sameSitePolicy);
        }
    }
    catch (const std::exception&) {
        HTTPResponse* response = dynamic_cast<HTTPResponse*>(&request);
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            response->setCookie(app.getCookieName("_shibsession_").c_str(), nullptr, 0, sameSitePolicy);
            response->setCookie(app.getCookieName("_shibsealed_").c_str(), nullptr, 0, sameSitePolicy);
        }
        throw;
    }
    return nullptr;
}

bool SSCache::recover(const Application& app, const char* key, const char* data)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("recover");
#endif

    if (!SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        m_log.debug("remoting recovery of session from sealed cookie");
        // Remote the request.
        DDF in("recover::" STORAGESERVICE_SESSION_CACHE "::SessionCache"), out;
        DDFJanitor jin(in);
        in.structure();
        in.addmember("key").string(key);
        in.addmember("application_id").string(app.getId());
        in.addmember("sealed").string(data);

        out = app.getServiceProvider().getListenerService()->send(in);
        if (!out.isint() || out.integer() != 1) {
            out.destroy();
            m_log.debug("recovery of session (%s) failed", key);
            return false;
        }

        out.destroy();
        m_log.debug("session (%s) recovered from sealed cookie", key);
    }
    else {
        // We're out of process, so we can recover the session.
#ifndef SHIBSP_LITE
        m_log.debug("checking for revocation of session (%s)", key);
        try {
            if (m_storage_lite->readString("Revoked", key) > 0) {
                m_log.warn("blocked recovery of revoked session (%s)", key);
                return false;
            }
        }
        catch (const std::exception& ex) {
            if (m_softRevocation)
                m_log.warn("ignoring failed check for revocation of session (%s): %s", ex.what());
            else {
                m_log.warn("check for revocation of session (%s) failed, treating as revoked: %s", ex.what());
                return false;
            }
        }

        m_log.debug("attempting recovery of session (%s)", key);

        DDF obj;
        DDFJanitor jobj(obj);
        string unwrapped;

        char* dup = nullptr;
        try {
            dup = strdup(data);
            XMLToolingConfig::getConfig().getURLEncoder()->decode(dup);
            unwrapped = XMLToolingConfig::getConfig().getDataSealer()->unwrap(dup);
            free(dup);

            stringstream str(unwrapped);
            str >> obj;
        }
        catch (const std::exception& e) {
            if (dup)
                free(dup);
            m_log.error("failed to unwrap sealed session data with DataSealer: %s", e.what());
            return false;
        }

        if (!obj.isstruct() || !obj.name() || strcmp(obj.name(), key)) {
            m_log.info("recovered session data was invalid for session (%s)", key);
            return false;
        }

        scoped_ptr<saml2::NameID> nameidObject;
        const char* nameid = obj["nameid"].string();
        if (nameid) {
            // Parse and bind the document into an XMLObject.
            istringstream instr(nameid);
            DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr);
            XercesJanitor<DOMDocument> janitor(doc);
            nameidObject.reset(saml2::NameIDBuilder::buildNameID());
            nameidObject->unmarshall(doc->getDocumentElement(), true);
            janitor.release();
        }

        m_log.debug("storing recovered session (%s)...", key);
        time_t now = time(nullptr);
        if (!m_storage->createText(key, "session", unwrapped.c_str(), now + getCacheTimeout(app))) {
            m_log.debug("recovered session (%s) matched existing record, likely a race condition");
            return true;
        }

        // Store the reverse mapping for logout.
        auto_ptr_char name(nameidObject ? nameidObject->getName() : nullptr);
        if (name.get() && *name.get() && m_reverseIndex
            && (m_excludedNames.size() == 0 || m_excludedNames.count(nameidObject->getName()) == 0)) {
            try {
                auto_ptr_XMLCh exp(obj["expires"].string());
                if (exp.get()) {
                    XMLDateTime iso(exp.get());
                    iso.parseDateTime();
                    insert(key, iso.getEpoch(), name.get(), obj["session_index"].string());
                }
            }
            catch (const std::exception& ex) {
                m_log.error("error storing back mapping of NameID for logout: %s", ex.what());
            }
        }

        const char* pid = obj["entity_id"].string();
        const char* prot = obj["protocol"].string();
        m_log.info("session recovered: ID (%s) IdP (%s) Protocol(%s)",
            key, pid ? pid : "none", prot ? prot : "none");
#else
        throw ConfigurationException("SessionCache recovery requires a DataSealer.");
#endif
    }

    return true;
}

void SSCache::remove(const Application& app, const HTTPRequest& request, HTTPResponse* response, time_t revocationExp)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("remove");
#endif
    string session_id;
    string shib_cookie = app.getCookieName("_shibsession_");

    if (!m_inboundHeader.empty())
        session_id = request.getHeader(m_inboundHeader.c_str());
    if (session_id.empty()) {
        const char* c = request.getCookie(shib_cookie.c_str());
        if (c && *c)
            session_id = c;
    }

    if (!session_id.empty()) {
        if (response) {
            if (!m_outboundHeader.empty())
                response->setResponseHeader(m_outboundHeader.c_str(), nullptr);
            HTTPResponse::samesite_t sameSitePolicy = getSameSitePolicy(app);
            response->setCookie(shib_cookie.c_str(), nullptr, 0, sameSitePolicy);
            response->setCookie(app.getCookieName("_shibsealed_").c_str(), nullptr, 0, sameSitePolicy);
        }
        remove(app, session_id.c_str(), revocationExp);
    }
}

void SSCache::remove(const Application& app, const char* key, time_t revocationExp)
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

        if (!m_persistedAttributeIds.empty()) {
            if (!revocationExp) {
                const PropertySet* props = app.getPropertySet("Sessions");
                if (props)
                    revocationExp = props->getUnsignedInt("lifetime").second;
                if (!revocationExp)
                    revocationExp = 28800;
                revocationExp += time(nullptr);
            }
            try {
                if (!m_storage_lite->createString("Revoked", key, "1", revocationExp))
                    m_log.warn("duplicate insertion of revocation for session (%s)", key);
            }
            catch (const std::exception& ex) {
                m_log.warn("error recording revocation of session (%s): %s", key, ex.what());
            }
        }
#else
        throw ConfigurationException("SessionCache removal requires a StorageService.");
#endif
    }
    else {
        // Remote the request.
        DDF in("remove::" STORAGESERVICE_SESSION_CACHE "::SessionCache");
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

    scoped_ptr<Mutex> mutex(Mutex::create());

    // Load our configuration details...
    static const XMLCh cleanupInterval[] = UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
    const XMLCh* tag = pcache->m_root ? pcache->m_root->getAttributeNS(nullptr, cleanupInterval) : nullptr;
    int rerun_timer = 900;
    if (tag && *tag) {
        try {
            rerun_timer = XMLString::parseInt(tag);
        }
        catch (XMLException&) {
            pcache->m_log.error("cleanupInterval setting was not a numeric value");
            rerun_timer = 0;
        }
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
        for (map<string,StoredSession*>::const_iterator i = pcache->m_hashtable.begin(); i != pcache->m_hashtable.end(); ++i) {
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
            for (vector<string>::const_iterator i = stale_keys.begin(); i != stale_keys.end(); ++i) {
                pcache->dormant(i->c_str());
            }
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

    if (!strcmp(in.name(),"find::" STORAGESERVICE_SESSION_CACHE "::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session lookup.");

        // Do an unversioned read.
        string record;
        time_t lastAccess = 0;
        int ver = m_storage->readText(key, "session", &record, &lastAccess);
        if (!ver) {
            const char* recovery = in["sealed"].string();
            if (recovery && *recovery && recover(*app, key, recovery)) {
                // Retry the read.
                ver = m_storage->readText(key, "session", &record, &lastAccess);
                if (!ver)
                    m_log.warn("recovered session (%s) is missing from storage service", key);
            }

            if (!ver) {
                DDF ret(nullptr);
                DDFJanitor jan(ret);
                out << ret;
                return;
            }
        }
        
        if (lastAccess == 0) {
            m_log.error("session (ID: %s) did not report time of last access", key);
            throw RetryableProfileException("Your session's last access time was missing, and you must re-authenticate.");
        }

        // Adjust for expiration to recover last access time and check timeout.
        unsigned long cacheTimeout = getCacheTimeout(*app);
        lastAccess -= cacheTimeout;
        time_t now=time(nullptr);

        // See if we need to check for a timeout.
        if (in["timeout"].string()) {
            time_t timeout = 0;
            auto_ptr_XMLCh dt(in["timeout"].string());
            XMLDateTime dtobj(dt.get());
            dtobj.parseDateTime();
            timeout = dtobj.getEpoch();

            if (timeout > 0 && now - lastAccess >= timeout) {
                m_log.info("session timed out (ID: %s)", key);
                scoped_ptr<LogoutEvent> logout_event(newLogoutEvent(*app));
                if (logout_event.get()) {
                    logout_event->m_logoutType = LogoutEvent::LOGOUT_EVENT_INVALID;
                    logout_event->m_sessions.push_back(key);
                    app->getServiceProvider().getTransactionLog()->write(*logout_event);
                }
                remove(*app, key);
                throw RetryableProfileException("Your session has timed out due to inactivity, and you must re-authenticate.");
            }

            // Update storage expiration, if possible.
            try {
                m_storage->updateContext(key, now + cacheTimeout);
            }
            catch (const std::exception& ex) {
                m_log.error("failed to update session expiration: %s", ex.what());
            }
        }

        // Send the record back.
        out << record;
    }
    else if (!strcmp(in.name(),"touch::" STORAGESERVICE_SESSION_CACHE "::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameters missing for session check.");
        const char* client_addr = in["client_addr"].string();

        // Do a read. May be unversioned if we need to bind a new client address.
        string record;
        time_t lastAccess = 0;
        int curver = in["version"].integer();
        int ver = m_storage->readText(key, "session", &record, &lastAccess, client_addr ? 0 : curver);
        if (ver == 0) {
            m_log.info("session (ID: %s) no longer in storage", key);
            throw RetryableProfileException("Your session is not available in the session store, and you must re-authenticate.");
        }
        else if (lastAccess == 0) {
            m_log.error("session (ID: %s) did not report time of last access", key);
            throw RetryableProfileException("Your session's last access time was missing, and you must re-authenticate.");
        }

        // Adjust for expiration to recover last access time and check timeout.
        unsigned long cacheTimeout = getCacheTimeout(*app);
        lastAccess -= cacheTimeout;
        time_t now=time(nullptr);

        // See if we need to check for a timeout.
        time_t timeout = 0;
        auto_ptr_XMLCh dt(in["timeout"].string());
        if (dt.get()) {
            XMLDateTime dtobj(dt.get());
            dtobj.parseDateTime();
            timeout = dtobj.getEpoch();
        }

        if (timeout > 0 && now - lastAccess >= timeout) {
            m_log.info("session timed out (ID: %s)", key);
            throw RetryableProfileException("Your session has timed out due to inactivity, and you must re-authenticate.");
        }

        // Update storage expiration, if possible.
        try {
            m_storage->updateContext(key, now + cacheTimeout);
        }
        catch (const std::exception& ex) {
            m_log.error("failed to update session expiration: %s", ex.what());
        }

        // We may need to write back a new address into the session using a versioned update loop.
        if (client_addr) {
            short attempts = 0;
            m_log.info("binding session (%s) to new client address (%s)", key, client_addr);
            do {
                // We have to reconstitute the session object ourselves.
                DDF sessionobj;
                DDFJanitor sessionjan(sessionobj);
                istringstream src(record);
                src >> sessionobj;
                ver = sessionobj["version"].integer();
                const char* saddr = sessionobj["client_addr"][StoredSession::getAddressFamily(client_addr)].string();
                if (saddr) {
                    // Something snuck in and bound the session to this address type, so it better match what we have.
                    if (!XMLString::equals(saddr, client_addr)) {
                        m_log.warn("client address mismatch, client (%s), session (%s)", client_addr, saddr);
                        throw RetryableProfileException(
                            "Your IP address ($1) does not match the address recorded at the time the session was established.",
                            params(1, client_addr)
                            );
                    }
                    break;  // No need to update.
                }
                else {
                    // Bind it into the session.
                    sessionobj["client_addr"].addmember(StoredSession::getAddressFamily(client_addr)).string(client_addr);
                }

                // Tentatively increment the version.
                sessionobj["version"].integer(sessionobj["version"].integer() + 1);

                ostringstream str;
                str << sessionobj;
                record = str.str();

                ver = m_storage->updateText(key, "session", record.c_str(), 0, ver);
                if (!ver) {
                    // Fatal problem with update.
                    m_log.error("updateText failed on StorageService for session (%s)", key);
                    throw IOException("Unable to update stored session.");
                }
                if (ver < 0) {
                    // Out of sync.
                    if (++attempts > 10) {
                        m_log.error("failed to bind client address, update attempts exceeded limit");
                        throw IOException("Unable to update stored session, exceeded retry limit.");
                    }
                    m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
                    sessionobj["version"].integer(sessionobj["version"].integer() - 1);
                    ver = m_storage->readText(key, "session", &record);
                    if (!ver) {
                        m_log.error("readText failed on StorageService for session (%s)", key);
                        throw IOException("Unable to read back stored session.");
                    }
                    ver = -1;
                }
            } while (ver < 0); // negative indicates a sync issue so we retry
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
    else if (!strcmp(in.name(),"remove::" STORAGESERVICE_SESSION_CACHE "::SessionCache")) {
        const char* key=in["key"].string();
        if (!key)
            throw ListenerException("Required parameter missing for session removal.");
        time_t revocationExp = 0;
        auto_ptr_XMLCh dt(in["revocationExp"].string());
        if (dt.get()) {
            XMLDateTime dtobj(dt.get());
            dtobj.parseDateTime();
            revocationExp = dtobj.getEpoch();
        }

        remove(*app, key, revocationExp);
        DDF ret(nullptr);
        DDFJanitor jan(ret);
        out << ret;
    }
    else if (!strcmp(in.name(), "recover::" STORAGESERVICE_SESSION_CACHE "::SessionCache")) {
        const char* key = in["key"].string();
        const char* cookie = in["sealed"].string();
        if (!key || !cookie)
            throw ListenerException("Required parameter missing for session recovery.");

        DDF ret(nullptr);
        DDFJanitor jan(ret);
        if (recover(*app, key, cookie))
            ret.integer(1L);
        else
            ret.integer(0L);
        out << ret;
    }
}

#endif
