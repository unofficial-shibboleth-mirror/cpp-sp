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
 * DynamicMetadataProvider.cpp
 *
 * Advanced implementation of a dynamic caching MetadataProvider.
 */
#include <fstream>


#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "metadata/MetadataProviderCriteria.h"
#include <boost/algorithm/string.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>
#include <xsec/framework/XSECDefs.hpp>

#include <saml/version.h>
#include <saml/binding/SAMLArtifact.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/AbstractDynamicMetadataProvider.h>
#include <saml/saml2/metadata/MetadataFilter.h>

#include <xmltooling/util/Threads.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialCriteria.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/SecurityHelper.h>
#include <xmltooling/security/X509TrustEngine.h>
#include <xmltooling/soap/HTTPSOAPTransport.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>

#ifndef WIN32
# if defined(HAVE_SYS_TYPES_H) && defined(HAVE_DIRENT_H)
#  include <dirent.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <errno.h>
# else
#  error Unsupported directory library headers.
# endif
#endif

using namespace shibsp;
using namespace opensaml;
using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    class SHIBSP_DLLLOCAL DynamicMetadataProvider : public AbstractDynamicMetadataProvider
    {
    public:
        DynamicMetadataProvider(const xercesc::DOMElement* e=nullptr);

        virtual ~DynamicMetadataProvider() { delete m_init_thread; }

        virtual void indexEntity(EntityDescriptor* site, time_t& validUntil, bool replace=false) const;

        virtual void unindex(const XMLCh* entityID, bool freeSites=false) const;

        void init();

    protected:
        EntityDescriptor* resolve(const MetadataProvider::Criteria& criteria) const;

    private:
        bool m_verifyHost, m_ignoreTransport, m_encoded, m_backgroundInit;
        const bool m_isMDQ;
        static bool s_artifactWarned;
        string m_subst, m_match, m_regex, m_hashed, m_cacheDir;
        boost::scoped_ptr<X509TrustEngine> m_trust;
        boost::scoped_ptr<CredentialResolver> m_dummyCR;
        Thread* m_init_thread;
        Category & m_log;
        static void* init_fn(void*);

    };

    MetadataProvider* SHIBSP_DLLLOCAL DynamicMetadataProviderFactory(const DOMElement* const & e)
    {
        return new DynamicMetadataProvider(e);
    }

    static const XMLCh encoded[] =          UNICODE_LITERAL_7(e,n,c,o,d,e,d);
    static const XMLCh hashed[] =           UNICODE_LITERAL_6(h,a,s,h,e,d);
    static const XMLCh ignoreTransport[] =  UNICODE_LITERAL_15(i,g,n,o,r,e,T,r,a,n,s,p,o,r,t);
    static const XMLCh match[] =            UNICODE_LITERAL_5(m,a,t,c,h);
    static const XMLCh Regex[] =            UNICODE_LITERAL_5(R,e,g,e,x);
    static const XMLCh Subst[] =            UNICODE_LITERAL_5(S,u,b,s,t);
    static const XMLCh _TrustEngine[] =     UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh verifyHost[] =       UNICODE_LITERAL_10(v,e,r,i,f,y,H,o,s,t);
    static const XMLCh cacheDirectory[] =   UNICODE_LITERAL_14(c,a,c,h,e,D,i,r,e,c,t,o,r,y);
    static const XMLCh backgroundInit[] =   UNICODE_LITERAL_20(b,a,c,k,g,r,o,u,n,d,I,n,i,t,i,a,l,i,z,e);
    static const XMLCh baseUrl[] =          UNICODE_LITERAL_7(b,a,s,e,U,r,l);
};

bool DynamicMetadataProvider::s_artifactWarned(false);

DynamicMetadataProvider::DynamicMetadataProvider(const DOMElement* e)
    : MetadataProvider(e), AbstractDynamicMetadataProvider(true, e),
        m_verifyHost(XMLHelper::getAttrBool(e, true, verifyHost)),
        m_log( Category::getInstance(SHIBSP_LOGCAT ".MetadataProvider.Dynamic")),
        m_cacheDir(XMLHelper::getAttrString(e, "", cacheDirectory)),
        m_ignoreTransport(XMLHelper::getAttrBool(e, false, ignoreTransport)),
        m_encoded(true), m_trust(nullptr), m_init_thread(nullptr), m_isMDQ(XMLHelper::getAttrString(e, "Dyanamic", _type) == "MDQ")
{
    const DOMElement* child = XMLHelper::getFirstChildElement(e, Subst);
    if (child && child->hasChildNodes()) {
        auto_ptr_char s(child->getFirstChild()->getNodeValue());
        if (s.get() && *s.get()) {
            m_subst = s.get();
            m_encoded = XMLHelper::getAttrBool(child, true, encoded);
            m_hashed = XMLHelper::getAttrString(child, nullptr, hashed);
            if (!m_subst.empty() &&
                XMLString::startsWithI(m_subst.c_str(), "file://")) {
                throw ConfigurationException("Dynamic MetadataProvider: <Subst> cannot be a file:// URL");
            }
            if (m_isMDQ)
                throw ConfigurationException("Dynamic MetadataProvider: <Subst> is incompatible with type=\"MDQ\"");
        }
    }

    if (m_subst.empty()) {
        child = XMLHelper::getFirstChildElement(e, Regex);
        if (child && child->hasChildNodes() && child->hasAttributeNS(nullptr, match)) {
            m_match = XMLHelper::getAttrString(child, nullptr, match);
            auto_ptr_char repl(child->getFirstChild()->getNodeValue());
            if (repl.get() && *repl.get()) {
                m_regex = repl.get();
                if (!m_regex.empty() &&
                    XMLString::startsWithI(m_regex.c_str(), "file://")) {
                    throw ConfigurationException("Dynamic MetadataProvider: <Regex> cannot be a file:// URL");
                }
                if (m_isMDQ)
                    throw ConfigurationException("Dynamic MetadataProvider: <Regex> is incompatible with type=\"MDQ\"");
            }
        }
    }

    if (m_isMDQ) {
        string theBaseUrl(XMLHelper::getAttrString(e, nullptr, baseUrl));
        if (theBaseUrl.empty())
            throw ConfigurationException("Dynamic MetadataProvider: type=\"MDQ\" must also contain baseUrl=\"whatever\"");
        m_subst = theBaseUrl + (boost::algorithm::ends_with(theBaseUrl, "/") ? "entities/$entityID" : "/entities/$entityID");
        m_hashed = "";
    }

    if (!m_ignoreTransport) {
        child = XMLHelper::getFirstChildElement(e, _TrustEngine);
        string t = XMLHelper::getAttrString(child, nullptr, _type);
        if (!t.empty()) {
            TrustEngine* trust = XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t.c_str(), child);
            if (!dynamic_cast<X509TrustEngine*>(trust)) {
                delete trust;
                throw ConfigurationException("Dynamic MetadataProvider requires X509TrustEngine plugin.");
            }
            m_trust.reset(dynamic_cast<X509TrustEngine*>(trust));
            m_dummyCR.reset(XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(DUMMY_CREDENTIAL_RESOLVER, nullptr));
        }

        if (!m_trust.get() || !m_dummyCR.get())
            throw ConfigurationException("Dynamic MetadataProvider requires X509TrustEngine plugin unless ignoreTransport is set.");
    }

    if (!m_cacheDir.empty()) {
        XMLToolingConfig::getConfig().getPathResolver()->resolve(m_cacheDir, PathResolver::XMLTOOLING_CACHE_FILE);
        m_backgroundInit = XMLHelper::getAttrBool(e, true, backgroundInit);
    }
}

void DynamicMetadataProvider::init()
{
    if (m_cacheDir.empty())
        return;

#ifdef WIN32
    if (!CreateDirectoryA(m_cacheDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        m_log.warn("Could not create cache directory %s (%d)", m_cacheDir.c_str(), GetLastError());
#else
    if (mkdir(m_cacheDir.c_str(), S_IRWXU))
        m_log.warn("Could not create cache directory %s (%d)", m_cacheDir.c_str(), errno);
#endif
    if (m_backgroundInit) {
        m_init_thread = Thread::create(&init_fn, this);
        m_init_thread->detach();
    }
    else
        init_fn(this);
}


EntityDescriptor* DynamicMetadataProvider::resolve(const MetadataProvider::Criteria& criteria) const
{
#ifdef _DEBUG
    xmltooling::NDC("resolve");
#endif

    string name;
    if (criteria.entityID_ascii) {
        name = criteria.entityID_ascii;
    }
    else if (criteria.entityID_unicode) {
        auto_ptr_char temp(criteria.entityID_unicode);
        name = temp.get();
    }
    else if (criteria.artifact) {
        if (m_subst.empty() && (m_regex.empty() || m_match.empty()))
            throw MetadataException("Unable to resolve metadata dynamically from an artifact.");
        name = "{sha1}" + criteria.artifact->getSource();
    }

    // Possibly transform the input into a different URL to use.
    if (!m_subst.empty()) {
        string name2(name);
        if (!m_hashed.empty()) {
            name2 = SecurityHelper::doHash(m_hashed.c_str(), name.c_str(), name.length());
        }
        name2 = boost::replace_first_copy(m_subst, "$entityID",
            m_encoded ? XMLToolingConfig::getConfig().getURLEncoder()->encode(name2.c_str()) : name2);
        m_log.info("transformed location from (%s) to (%s)", name.c_str(), name2.c_str());
        name = name2;
    }
    else if (!m_match.empty() && !m_regex.empty()) {
        try {
            RegularExpression exp(m_match.c_str());
            XMLCh* temp = exp.replace(name.c_str(), m_regex.c_str());
            if (temp) {
                auto_ptr_char narrow(temp);
                XMLString::release(&temp);

                // For some reason it returns the match string if it doesn't match the expression.
                if (name != narrow.get()) {
                    m_log.info("transformed location from (%s) to (%s)", name.c_str(), narrow.get());
                    name = narrow.get();
                }
            }
        }
        catch (XMLException& ex) {
            auto_ptr_char msg(ex.getMessage());
            m_log.error("caught error applying regular expression: %s", msg.get());
        }
    }

    if (XMLString::startsWithI(name.c_str(), "file://")) {
        throw MetadataException("Dynamic MetadataProvider: Resolved name cannot start with a file:// ");
    }

    // Establish networking properties based on calling application.
    const MetadataProviderCriteria* mpc = dynamic_cast<const MetadataProviderCriteria*>(&criteria);
    if (!mpc)
        throw MetadataException("Dynamic MetadataProvider requires Shibboleth-aware lookup criteria, check calling code.");
    const PropertySet* relyingParty;
    if (criteria.artifact)
        relyingParty = mpc->application.getRelyingParty((XMLCh*)nullptr);
    else if (criteria.entityID_unicode)
        relyingParty = mpc->application.getRelyingParty(criteria.entityID_unicode);
    else {
        auto_ptr_XMLCh temp2(name.c_str());
        relyingParty = mpc->application.getRelyingParty(temp2.get());
    }

    // Prepare a transport object addressed appropriately.
    SOAPTransport::Address addr(relyingParty->getString("entityID").second, name.c_str(), name.c_str());
    const char* pch = strchr(addr.m_endpoint,':');
    if (!pch)
        throw IOException("location was not a URL.");
    string scheme(addr.m_endpoint, pch-addr.m_endpoint);
    boost::scoped_ptr<SOAPTransport> transport;
    try {
        transport.reset(XMLToolingConfig::getConfig().SOAPTransportManager.newPlugin(scheme.c_str(), addr));
    }
    catch (exception& ex) {
        m_log.error("exception while building transport object to resolve URL: %s", ex.what());
        throw IOException("Unable to resolve entityID with a known transport protocol.");
    }

    // Apply properties as directed.
    transport->setVerifyHost(m_verifyHost);
    HTTPSOAPTransport *httpTransport = dynamic_cast<HTTPSOAPTransport*>(transport.get());
    if (httpTransport) {
        httpTransport->setAcceptEncoding("");
    }
    if (m_trust.get() && m_dummyCR.get() && !transport->setTrustEngine(m_trust.get(), m_dummyCR.get()))
        throw IOException("Unable to install X509TrustEngine into transport object.");

    Locker credlocker(nullptr, false);
    CredentialResolver* credResolver = nullptr;
    pair<bool,const char*> authType=relyingParty->getString("authType");
    if (!authType.first || !strcmp(authType.second,"TLS")) {
        credResolver = mpc->application.getCredentialResolver();
        if (credResolver)
            credlocker.assign(credResolver);
        if (credResolver) {
            CredentialCriteria cc;
            cc.setUsage(Credential::TLS_CREDENTIAL);
            authType = relyingParty->getString("keyName");
            if (authType.first)
                cc.getKeyNames().insert(authType.second);
            const Credential* cred = credResolver->resolve(&cc);
            cc.getKeyNames().clear();
            if (cred) {
                if (!transport->setCredential(cred))
                    m_log.error("failed to load Credential into metadata resolver");
            }
            else {
                m_log.error("no TLS credential supplied");
            }
        }
        else {
            m_log.error("no CredentialResolver available for TLS");
        }
    }
    else {
        SOAPTransport::transport_auth_t type=SOAPTransport::transport_auth_none;
        pair<bool,const char*> username=relyingParty->getString("authUsername");
        pair<bool,const char*> password=relyingParty->getString("authPassword");
        if (!username.first || !password.first)
            m_log.error("transport authType (%s) specified but authUsername or authPassword was missing", authType.second);
        else if (!strcmp(authType.second,"basic"))
            type = SOAPTransport::transport_auth_basic;
        else if (!strcmp(authType.second,"digest"))
            type = SOAPTransport::transport_auth_digest;
        else if (!strcmp(authType.second,"ntlm"))
            type = SOAPTransport::transport_auth_ntlm;
        else if (!strcmp(authType.second,"gss"))
            type = SOAPTransport::transport_auth_gss;
        else if (strcmp(authType.second,"none"))
            m_log.error("unknown authType (%s) specified for RelyingParty", authType.second);
        if (type > SOAPTransport::transport_auth_none) {
            if (transport->setAuth(type,username.second,password.second))
                m_log.debug("configured for transport authentication (method=%s, username=%s)", authType.second, username.second);
            else
                m_log.error("failed to configure transport authentication (method=%s)", authType.second);
        }
    }

    pair<bool,unsigned int> timeout = relyingParty->getUnsignedInt("connectTimeout");
    transport->setConnectTimeout(timeout.first ? timeout.second : 10);
    timeout = relyingParty->getUnsignedInt("timeout");
    transport->setTimeout(timeout.first ? timeout.second : 20);
    mpc->application.getServiceProvider().setTransportOptions(*transport);

    HTTPSOAPTransport* http = dynamic_cast<HTTPSOAPTransport*>(transport.get());
    if (http) {
        pair<bool,bool> flag = relyingParty->getBool("chunkedEncoding");
        http->useChunkedEncoding(flag.first && flag.second);
        http->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
        http->setRequestHeader("XML-Security-C", XSEC_FULLVERSIONDOT);
        http->setRequestHeader("OpenSAML-C", gOpenSAMLDotVersionStr);
        http->setRequestHeader(PACKAGE_NAME, PACKAGE_VERSION);
    }

    try {
        // Use a nullptr stream to trigger a body-less "GET" operation.
        transport->send();
        istream& msg = transport->receive();

        EntityDescriptor* entity = entityFromStream(msg);

        if (nullptr != entity && !m_isMDQ && criteria.artifact && !s_artifactWarned) {
            m_log.warn("Successful resolution of an artifact by a non-MDQ dynamic server is not guaranteed to work");
            s_artifactWarned = true;
        }

        return entity;
    }
    catch (XMLException& e) {
        auto_ptr_char msg(e.getMessage());
        m_log.error("Xerces error while resolving location (%s): %s", name.c_str(), msg.get());
        throw MetadataException(msg.get());
    }
}

void DynamicMetadataProvider::unindex(const XMLCh* entityID, bool freeSites) const
{
    AbstractDynamicMetadataProvider::unindex(entityID, freeSites);
    if (m_cacheDir.empty())
        return;

    auto_ptr_char id(entityID);

    const string backingFile(m_cacheDir + "/" + SecurityHelper::doHash("SHA1", id.get(), strlen(id.get())) + ".xml");
    m_log.debug("Removing %s", backingFile.c_str());
    remove(backingFile.c_str());
}

void DynamicMetadataProvider::indexEntity(EntityDescriptor* site, time_t& validUntil, bool replace) const
{
    AbstractDynamicMetadataProvider::indexEntity(site, validUntil, replace);

    if (m_cacheDir.empty())
        return;

    const auto_ptr_char temp(site->getEntityID());
    const string hashed(SecurityHelper::doHash("SHA1", temp.get(), strlen(temp.get()), true));
    const string backingFile(m_cacheDir.empty() ? "" : m_cacheDir + "/" + hashed + ".xml");

    if (!replace) {
        struct stat buffer;
        if (stat(backingFile.c_str(), &buffer) == 0)
            return;
    }

    ofstream out(backingFile.c_str());

    XMLHelper::serialize(site->marshall(), out, false);
}

void *DynamicMetadataProvider::init_fn(void* pv)
{
    DynamicMetadataProvider * me = reinterpret_cast<DynamicMetadataProvider*>(pv);

#ifndef WIN32
    // First, let's block all signals
    Thread::mask_all_signals();
#endif

    if (me->m_cacheDir.empty())
       return nullptr;

    string fullname;
#ifdef WIN32
    WIN32_FIND_DATA entry;
    HANDLE dirHandle = FindFirstFile((me->m_cacheDir + "/*").c_str(), &entry);

    if (dirHandle == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND)
            throw MetadataException("Dynamic MetadataProvider unable to open directory ($1)", params(1, me->m_cacheDir.c_str()));
        me->m_log.debug("no files found in cache (%s)", me->m_cacheDir.c_str());
        return nullptr;
    }

    do {
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(entry.cFileName, ".") && strcmp(entry.cFileName, ".."))
                me->m_log.warn("Invalid directory format, skipping (%s)", entry.cFileName);
            continue;
        }
        fullname = me->m_cacheDir + '/' + entry.cFileName;
#else
    DIR* d = opendir(me->m_cacheDir.c_str());
    if (!d) {
        throw MetadataException("Dynamic MetadataProvider unable to open directory ($1)", params(1, me->m_cacheDir.c_str()));
    }
    char dir_buf[sizeof(struct dirent) + PATH_MAX];
    struct dirent* ent = (struct dirent*)dir_buf;
    struct dirent* entptr = nullptr;
    while (readdir_r(d, ent, &entptr) == 0 && entptr) {
        if (!strcmp(entptr->d_name, ".") || !strcmp(entptr->d_name, ".."))
            continue;
        fullname = me->m_cacheDir + '/' + entptr->d_name;
        struct stat stat_buf;
        if (stat(fullname.c_str(), &stat_buf) != 0) {
            me->m_log.warn("unable to access (%s)", entptr->d_name);
            continue;
        }
        else if (S_ISDIR(stat_buf.st_mode)) {
            me->m_log.warn("Invalid directory format, skipping (%s)", entptr->d_name);
            continue;
        }
#endif
        try {
            me->m_log.info("Reload from %s", fullname.c_str());
            ifstream thisFileEntry(fullname.c_str());
            if (thisFileEntry) {
                auto_ptr<EntityDescriptor> entity (me->entityFromStream(thisFileEntry));
                thisFileEntry.close();
                if (entity.get()) {
                    const BatchLoadMetadataFilterContext bc(true);
                    me->doFilters(&bc, *entity);
                    me->cacheEntity(entity.get());
                    entity.release();
                }
            }
        }
        catch (XMLException& e) {
            auto_ptr_char msg(e.getMessage());
            me->m_log.error("Xerces error while reloading from cache (%s): %s ", fullname.c_str(), msg.get());
            remove(fullname.c_str());
        }
        catch (MetadataException& e) {
            auto_ptr_char msg(e.getMessage());
            me->m_log.error("Filter error while reloading from cache (%s): %s", fullname.c_str(), msg.get());
            remove(fullname.c_str());
        }
        catch (exception& e) {
            me->m_log.error("Other error while reloading from cache (%s): %s", fullname.c_str(), e.what());
            remove(fullname.c_str());
        }

#ifdef WIN32
    } while (FindNextFile(dirHandle, &entry));
    if (ERROR_NO_MORE_FILES != GetLastError())
        me->m_log.error("Error enumerating directory '%s' (%d)", me->m_cacheDir, GetLastError());
    FindClose(dirHandle);
#else
}
    closedir(d);
#endif

    return nullptr;
}

