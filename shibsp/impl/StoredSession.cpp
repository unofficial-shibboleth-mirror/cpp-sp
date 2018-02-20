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
 * StoredSession.cpp
 *
 * Implementation of Session subclass used by StorageService-backed SessionCache.
 */

#include "internal.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "impl/StoredSession.h"
#include "impl/StorageServiceSessionCache.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>

#ifndef SHIBSP_LITE
# include <saml/exceptions.h>
# include <saml/saml2/core/Assertions.h>
# include <xmltooling/XMLToolingConfig.h>
# include <xmltooling/util/ParserPool.h>
# include <xmltooling/util/StorageService.h>
# include <xercesc/util/XMLStringTokenizer.hpp>
using namespace opensaml::saml2md;
#else
# include <xercesc/util/XMLDateTime.hpp>
#endif

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

Session::Session()
{
}

Session::~Session()
{
}

const char* StoredSession::getAddressFamily(const char* addr) {
    if (strchr(addr, ':'))
        return "6";
    else
        return "4";
}

StoredSession::StoredSession(SSCache* cache, DDF& obj)
    : m_obj(obj), m_cache(cache), m_expires(0), m_lastAccess(time(nullptr))
{
    // Check for old address format.
    if (m_obj["client_addr"].isstring()) {
        const char* saddr = m_obj["client_addr"].string();
        DDF addrobj = m_obj["client_addr"].structure();
        if (saddr && *saddr) {
            addrobj.addmember(getAddressFamily(saddr)).string(saddr);
        }
    }

    auto_ptr_XMLCh exp(m_obj["expires"].string());
    if (exp.get()) {
        XMLDateTime iso(exp.get());
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
        m_nameid.reset(saml2::NameIDBuilder::buildNameID());
        m_nameid->unmarshall(doc->getDocumentElement(), true);
        janitor.release();
    }
#endif
    if (cache->inproc)
        m_lock.reset(Mutex::create());
}

StoredSession::~StoredSession()
{
    m_obj.destroy();
    for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
}

Lockable* StoredSession::lock()
{
    if (m_lock.get())
        m_lock->lock();
    return this;
}
void StoredSession::unlock()
{
    if (m_lock.get())
        m_lock->unlock();
    else
        delete this;
}

const multimap<string, const Attribute*>& StoredSession::getIndexedAttributes() const
{
    if (m_attributeIndex.empty()) {
        if (m_attributes.empty())
            unmarshallAttributes();
        for (vector<Attribute*>::const_iterator a = m_attributes.begin(); a != m_attributes.end(); ++a) {
            const vector<string>& aliases = (*a)->getAliases();
            for (vector<string>::const_iterator alias = aliases.begin(); alias != aliases.end(); ++alias)
                m_attributeIndex.insert(multimap<string, const Attribute*>::value_type(*alias, *a));
        }
    }
    return m_attributeIndex;
}

const vector<const char*>& StoredSession::getAssertionIDs() const
{
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
        const char* saddr = getClientAddress(getAddressFamily(client_addr));
        if (saddr && *saddr) {
            if (!XMLString::equals(saddr, client_addr)) {
                m_cache->m_log.warn("client address mismatch, client (%s), session (%s)", client_addr, saddr);
                throw RetryableProfileException(
                    "Your IP address ($1) does not match the address recorded at the time the session was established.",
                    params(1, client_addr)
                    );
            }
            client_addr = nullptr;  // clear out parameter as signal that session need not be updated below
        }
        else {
            m_cache->m_log.info("session (%s) not yet bound to client address type, binding it to (%s)", getID(), client_addr);
        }
    }

    if (!timeout && !client_addr)
        return;

    if (!SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
        DDF in("touch::" STORAGESERVICE_SESSION_CACHE "::SessionCache"), out;
        DDFJanitor jin(in);
        in.structure();
        in.addmember("key").string(getID());
        in.addmember("version").integer(m_obj["version"].integer());
        in.addmember("application_id").string(app.getId());
        if (client_addr)    // signals we need to bind an additional address to the session
            in.addmember("client_addr").string(client_addr);
        if (timeout && *timeout) {
            // On 64-bit Windows, time_t doesn't fit in a long, so I'm using ISO timestamps.
#ifndef HAVE_GMTIME_R
            struct tm* ptime = gmtime(timeout);
#else
            struct tm res;
            struct tm* ptime = gmtime_r(timeout,&res);
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
            m_cache->m_log.debug("session updated, reconstituting it");
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

        // Versioned read, since we already have the data in hand if it's current.
        string record;
        time_t lastAccess = 0;
        int curver = m_obj["version"].integer();
        int ver = m_cache->m_storage->readText(getID(), "session", &record, &lastAccess, curver);
        if (ver == 0) {
            m_cache->m_log.info("session (ID: %s) no longer in storage", getID());
            throw RetryableProfileException("Your session has expired, and you must re-authenticate.");
        }

        if (timeout) {
            if (lastAccess == 0) {
                m_cache->m_log.error("session (ID: %s) did not report time of last access", getID());
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
            catch (std::exception& ex) {
                m_cache->m_log.error("failed to update session expiration: %s", ex.what());
            }
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

        // We may need to write back a new address into the session using a versioned update loop.
        if (client_addr) {
            short attempts = 0;
            do {
                const char* saddr = getClientAddress(getAddressFamily(client_addr));
                if (saddr) {
                    // Something snuck in and bound the session to this address type, so it better match what we have.
                    if (!XMLString::equals(saddr, client_addr)) {
                        m_cache->m_log.warn("client address mismatch, client (%s), session (%s)", client_addr, saddr);
                        throw RetryableProfileException(
                            "Your IP address ($1) does not match the address recorded at the time the session was established.",
                            params(1, client_addr)
                            );
                    }
                    break;  // No need to update.
                }
                else {
                    // Bind it into the session.
                    setClientAddress(client_addr);
                }

                // Tentatively increment the version.
                m_obj["version"].integer(m_obj["version"].integer() + 1);

                ostringstream str;
                str << m_obj;
                record = str.str();

                try {
                    ver = m_cache->m_storage->updateText(getID(), "session", record.c_str(), 0, m_obj["version"].integer() - 1);
                }
                catch (std::exception&) {
                    m_obj["version"].integer(m_obj["version"].integer() - 1);
                    throw;
                }

                if (ver <= 0) {
                    m_obj["version"].integer(m_obj["version"].integer() - 1);
                }

                if (!ver) {
                    // Fatal problem with update.
                    m_cache->m_log.error("updateText failed on StorageService for session (%s)", getID());
                    throw IOException("Unable to update stored session.");
                }
                else if (ver < 0) {
                    // Out of sync.
                    if (++attempts > 10) {
                        m_cache->m_log.error("failed to bind client address, update attempts exceeded limit");
                        throw IOException("Unable to update stored session, exceeded retry limit.");
                    }
                    m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
                    ver = m_cache->m_storage->readText(getID(), "session", &record);
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
            } while (ver < 0); // negative indicates a sync issue so we retry
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
    short attempts = 0;
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
        catch (std::exception&) {
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
            if (++attempts > 10) {
                m_cache->m_log.error("failed to update stored session, update attempts exceeded limit");
                throw IOException("Unable to update stored session, exceeded retry limit.");
            }
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(getID(), "session", &record);
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

    // We own them now, so clean them up.
    for_each(attributes.begin(), attributes.end(), xmltooling::cleanup<Attribute>());
}

const Assertion* StoredSession::getAssertion(const char* id) const
{
    if (!m_cache->m_storage)
        throw ConfigurationException("Assertion retrieval requires a StorageService.");

    map< string,boost::shared_ptr<Assertion> >::const_iterator i = m_tokens.find(id);
    if (i != m_tokens.end())
        return i->second.get();

    string tokenstr;
    if (!m_cache->m_storage->readText(getID(), id, &tokenstr))
        throw FatalProfileException("Assertion not found in cache.");

    // Parse and bind the document into an XMLObject.
    istringstream instr(tokenstr);
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(instr);
    XercesJanitor<DOMDocument> janitor(doc);
    boost::shared_ptr<XMLObject> xmlObject(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
    janitor.release();
    
    boost::shared_ptr<Assertion> token = dynamic_pointer_cast<Assertion,XMLObject>(xmlObject);
    if (!token)
        throw FatalProfileException("Request for cached assertion returned an unknown object type.");

    m_tokens[id] = token;
    return token.get();
}

void StoredSession::addAssertion(Assertion* assertion)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("addAssertion");
#endif

    if (!m_cache->m_storage)
        throw ConfigurationException("Session modification requires a StorageService.");
    else if (!assertion)
        throw FatalProfileException("Unknown object type passed to session for storage.");

    auto_ptr_char id(assertion->getID());
    if (!id.get() || !*id.get())
        throw IOException("Assertion did not carry an ID.");
    else if (strlen(id.get()) > m_cache->m_storage->getCapabilities().getKeySize())
        throw IOException("Assertion ID ($1) exceeds allowable storage key size.", params(1, id.get()));

    m_cache->m_log.debug("adding assertion (%s) to session (%s)", id.get(), getID());

    time_t exp = 0;
    if (!m_cache->m_storage->readText(getID(), "session", nullptr, &exp) || exp == 0)
        throw IOException("Unable to load expiration time for stored session.");

    ostringstream tokenstr;
    tokenstr << *assertion;
    if (!m_cache->m_storage->createText(getID(), id.get(), tokenstr.str().c_str(), exp))
        throw IOException("Attempted to insert duplicate assertion ID into session.");

    int ver;
    short attempts = 0;
    do {
        DDF token = DDF(nullptr).string(id.get());
        m_obj["assertions"].add(token);

        // Tentatively increment the version.
        m_obj["version"].integer(m_obj["version"].integer() + 1);

        ostringstream str;
        str << m_obj;
        string record(str.str());

        try {
            ver = m_cache->m_storage->updateText(getID(), "session", record.c_str(), 0, m_obj["version"].integer()-1);
        }
        catch (std::exception&) {
            token.destroy();
            m_obj["version"].integer(m_obj["version"].integer() - 1);
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
            if (++attempts > 10) {
                m_cache->m_log.error("failed to update stored session, update attempts exceeded limit");
                throw IOException("Unable to update stored session, exceeded retry limit.");
            }
            m_cache->m_log.warn("storage service indicates the record is out of sync, updating with a fresh copy...");
            ver = m_cache->m_storage->readText(getID(), "session", &record);
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
}

#endif

