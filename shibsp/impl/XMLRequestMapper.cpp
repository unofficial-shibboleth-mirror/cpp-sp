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

/** XMLRequestMapper.cpp
 *
 * XML-based RequestMapper implementation.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "RequestMapper.h"
#include "SPRequest.h"
#include "util/CGIParser.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <algorithm>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/algorithm/string.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

using shibspconstants::SHIB2SPCONFIG_NS;
using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    // Blocks access when an ACL plugin fails to load.
    class AccessControlDummy : public AccessControl
    {
    public:
        Lockable* lock() {
            return this;
        }

        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const {
            return shib_acl_false;
        }
    };

    class Override : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        Override(bool unicodeAware=false) : m_unicodeAware(unicodeAware) {}
        Override(bool unicodeAware, const DOMElement* e, Category& log, const Override* base=nullptr);
        ~Override() {}

        // Provides filter to exclude special config elements.
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }

        const Override* locate(const HTTPRequest& request) const;
        AccessControl* getAC() const { return (m_acl ? m_acl.get() : (getParent() ? dynamic_cast<const Override*>(getParent())->getAC() : nullptr)); }

    protected:
        void loadACL(const DOMElement* e, Category& log);

        bool m_unicodeAware;
        map< string,boost::shared_ptr<Override> > m_map;
        vector< pair< boost::shared_ptr<RegularExpression>,boost::shared_ptr<Override> > > m_regexps;
        vector< tuple< string,boost::shared_ptr<RegularExpression>,boost::shared_ptr<Override> > > m_queries;

    private:
        scoped_ptr<AccessControl> m_acl;
    };

    class XMLRequestMapperImpl : public Override
    {
    public:
        XMLRequestMapperImpl(const DOMElement* e, Category& log);

        ~XMLRequestMapperImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        const Override* findOverride(const char* vhost, const HTTPRequest& request) const;

    private:
        DOMDocument* m_document;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLRequestMapper : public RequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(const DOMElement* e) : ReloadableXMLFile(e,Category::getInstance(SHIBSP_LOGCAT".RequestMapper")) {
            background_load();
        }

        ~XMLRequestMapper() {
            shutdown();
        }

        Settings getSettings(const HTTPRequest& request) const;

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        scoped_ptr<XMLRequestMapperImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    RequestMapper* SHIBSP_DLLLOCAL XMLRequestMapperFactory(const DOMElement* const & e)
    {
        return new XMLRequestMapper(e);
    }

    static const XMLCh _AccessControl[] =           UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh AccessControlProvider[] =    UNICODE_LITERAL_21(A,c,c,e,s,s,C,o,n,t,r,o,l,P,r,o,v,i,d,e,r);
    static const XMLCh Host[] =                     UNICODE_LITERAL_4(H,o,s,t);
    static const XMLCh HostRegex[] =                UNICODE_LITERAL_9(H,o,s,t,R,e,g,e,x);
    static const XMLCh htaccess[] =                 UNICODE_LITERAL_8(h,t,a,c,c,e,s,s);
    static const XMLCh ignoreCase[] =               UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh ignoreOption[] =             UNICODE_LITERAL_1(i);
    static const XMLCh Path[] =                     UNICODE_LITERAL_4(P,a,t,h);
    static const XMLCh PathRegex[] =                UNICODE_LITERAL_9(P,a,t,h,R,e,g,e,x);
    static const XMLCh Query[] =                    UNICODE_LITERAL_5(Q,u,e,r,y);
    static const XMLCh name[] =                     UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh regex[] =                    UNICODE_LITERAL_5(r,e,g,e,x);
    static const XMLCh _type[] =                    UNICODE_LITERAL_4(t,y,p,e);
}

void SHIBSP_API shibsp::registerRequestMappers()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.RequestMapperManager.registerFactory(XML_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, XMLRequestMapperFactory);
}

RequestMapper::RequestMapper()
{
}

RequestMapper::~RequestMapper()
{
}

void Override::loadACL(const DOMElement* e, Category& log)
{
    try {
        const DOMElement* acl = XMLHelper::getFirstChildElement(e,htaccess);
        if (acl) {
            log.info("building Apache htaccess AccessControl provider...");
            m_acl.reset(SPConfig::getConfig().AccessControlManager.newPlugin(HT_ACCESS_CONTROL,acl));
        }
        else {
            acl = XMLHelper::getFirstChildElement(e,_AccessControl);
            if (acl) {
                log.info("building XML-based AccessControl provider...");
                m_acl.reset(SPConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL,acl));
            }
            else {
                acl = XMLHelper::getFirstChildElement(e,AccessControlProvider);
                if (acl) {
                    string t(XMLHelper::getAttrString(acl, nullptr, _type));
                    if (!t.empty()) {
                        log.info("building AccessControl provider of type %s...", t.c_str());
                        m_acl.reset(SPConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), acl));
                    }
                    else {
                        throw ConfigurationException("<AccessControlProvider> missing type attribute.");
                    }
                }
            }
        }
    }
    catch (std::exception& ex) {
        log.crit("exception building AccessControl provider: %s", ex.what());
        m_acl.reset(new AccessControlDummy());
    }
}

Override::Override(bool unicodeAware, const DOMElement* e, Category& log, const Override* base)
    : m_unicodeAware(unicodeAware)
{
    // Load the property set.
    load(e, nullptr, this);
    setParent(base);

    // Load any AccessControl provider.
    loadACL(e, log);

    // Handle nested Paths.
    DOMElement* path = XMLHelper::getFirstChildElement(e, Path);
    for (int i = 1; path; ++i, path = XMLHelper::getNextSiblingElement(path, Path)) {
        const XMLCh* n = path->getAttributeNS(nullptr,name);

        // Skip any leading slashes.
        while (n && *n == chForwardSlash)
            n++;

        // Check for empty name.
        if (!n || !*n) {
            log.warn("skipping Path element (%d) with empty name attribute", i);
            continue;
        }

        // Check for an embedded slash.
        int slash = XMLString::indexOf(n, chForwardSlash);
        if (slash > 0) {
            // Copy the first path segment.
            xstring namebuf;
            for (int pos = 0; pos < slash; ++pos)
                namebuf += n[pos];

            // Move past the slash in the original pathname.
            n = n + slash + 1;

            // Skip any leading slashes again.
            while (*n == chForwardSlash)
                ++n;

            if (*n) {
                // Create a placeholder Path element for the first path segment and replant under it.
                DOMElement* newpath = path->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, Path);
                newpath->setAttributeNS(nullptr, name, namebuf.c_str());
                path->setAttributeNS(nullptr, name, n);
                path->getParentNode()->replaceChild(newpath, path);
                newpath->appendChild(path);

                // Repoint our locals at the new parent.
                path = newpath;
                n = path->getAttributeNS(nullptr, name);
            }
            else {
                // All we had was a pathname with trailing slash(es), so just reset it without them.
                path->setAttributeNS(nullptr, name, namebuf.c_str());
                n = path->getAttributeNS(nullptr, name);
            }
        }

        char* dup = nullptr;
        try {
            boost::shared_ptr<Override> o(new Override(m_unicodeAware, path, log, this));
            if (m_unicodeAware) {
                dup = toUTF8(o->getXMLString("name").second, true /* use malloc */);
            }
            else {
                dup = strdup(o->getString("name").second);
                for (char* pch = dup; *pch; ++pch)
                    *pch = tolower(*pch);
            }
            if (m_map.count(dup)) {
                log.warn("skipping duplicate Path element (%s)", dup);
            }
            else {
                m_map[dup] = o;
                log.debug("added Path mapping (%s)", dup);
            }
            free(dup);
        }
        catch (std::exception&) {
            free(dup);
            throw;
        }
    }

    if (!XMLString::equals(e->getLocalName(), PathRegex)) {
        // Handle nested PathRegexs.
        path = XMLHelper::getFirstChildElement(e, PathRegex);
        for (int i = 1; path; ++i, path = XMLHelper::getNextSiblingElement(path, PathRegex)) {
            const XMLCh* n = path->getAttributeNS(nullptr, regex);
            if (!n || !*n) {
                log.warn("skipping PathRegex element (%d) with empty regex attribute",i);
                continue;
            }

            boost::shared_ptr<Override> o(new Override(m_unicodeAware, path, log, this));

            bool flag = XMLHelper::getAttrBool(path, true, ignoreCase);
            try {
                boost::shared_ptr<RegularExpression> re(new RegularExpression(n, flag ? &chNull : ignoreOption));
                m_regexps.push_back(make_pair(re, o));
            }
            catch (XMLException& ex) {
                auto_ptr_char tmp(ex.getMessage());
                log.error("caught exception while parsing PathRegex regular expression (%d): %s", i, tmp.get());
                throw ConfigurationException("Invalid regular expression in PathRegex element.");
            }

            if (log.isDebugEnabled())
                log.debug("added <PathRegex> mapping (%s)", o->getString("regex").second);
        }
    }

    // Handle nested Querys.
    path = XMLHelper::getFirstChildElement(e, Query);
    for (int i = 1; path; ++i, path = XMLHelper::getNextSiblingElement(path, Query)) {
        const XMLCh* n = path->getAttributeNS(nullptr, name);
        if (!n || !*n) {
            log.warn("skipping Query element (%d) with empty name attribute",i);
            continue;
        }
        auto_ptr_char ntemp(n);
        const XMLCh* v = path->getAttributeNS(nullptr, regex);

        try {
            boost::shared_ptr<Override> o(new Override(m_unicodeAware, path, log, this));
            boost::shared_ptr<RegularExpression> re((v && *v) ? new RegularExpression(v) : nullptr);
            m_queries.push_back(make_tuple(string(ntemp.get()), re, o));
        }
        catch (XMLException& ex) {
            auto_ptr_char tmp(ex.getMessage());
            log.error("caught exception while parsing Query regular expression (%d): %s", i, tmp.get());
            throw ConfigurationException("Invalid regular expression in Query element.");
        }

        log.debug("added <Query> mapping (%s)", ntemp.get());
    }
}

const Override* Override::locate(const HTTPRequest& request) const
{
    // This function is confusing because it's *not* recursive.
    // The whole path is tokenized and mapped in a loop, so the
    // path parameter starts with the entire request path and
    // we can skip the leading slash as irrelevant.
    const char* path = request.getRequestURI();
    if (*path == '/')
        path++;

    // Now we copy the path, chop the query string, and possibly lower case it.
    string dup(path);
    string::size_type sep = dup.find('?');
    if (sep != string::npos)
        dup = dup.substr(0, sep);
    if (!m_unicodeAware) {
        to_lower(dup);
    }

    // Default is for the current object to provide settings.
    const Override* o = this;

    // Tokenize the path by segment and try and map each segment.
    tokenizer< char_separator<char> > tokens(dup, char_separator<char>("/"));
    for (tokenizer< char_separator<char> >::iterator token = tokens.begin(); token != tokens.end(); ++token) {
        map< string,boost::shared_ptr<Override> >::const_iterator i = o->m_map.find(*token);
        if (i == o->m_map.end())
            break;  // Once there's no match, we've consumed as much of the path as possible here.
        // We found a match, so reset the settings pointer.
        o = i->second.get();

        // We descended a step down the path, so we need to advance the original
        // parameter for the regex step later.
        path += token->length();
        if (*path == '/')
            path++;
    }

    // If there's anything left, we try for a regex match on the rest of the path minus the query string.
    if (*path) {
        string path2(path);
        sep = path2.find('?');
        if (sep != string::npos)
            path2 = path2.substr(0, sep);

        for (vector< pair< boost::shared_ptr<RegularExpression>,boost::shared_ptr<Override> > >::const_iterator re = o->m_regexps.begin(); re != o->m_regexps.end(); ++re) {
            if (re->first->matches(path2.c_str())) {
                o = re->second.get();
                break;
            }
        }
    }

    // Finally, check for query string matches. This is another "unrolled" recursive descent in a loop.
    // To avoid consuming any POST data, we use a dedicated CGIParser.
    if (!o->m_queries.empty()) {
        bool descended;
        CGIParser cgi(request, true);
        do {
            descended = false;
            for (vector< tuple< string,boost::shared_ptr<RegularExpression>,boost::shared_ptr<Override> > >::const_iterator q = o->m_queries.begin(); !descended && q != o->m_queries.end(); ++q) {
                pair<CGIParser::walker,CGIParser::walker> vals = cgi.getParameters(q->get<0>().c_str());
                if (vals.first != vals.second) {
                    if (q->get<1>()) {
                        // We have to match one of the values.
                        while (vals.first != vals.second) {
                            if (q->get<1>()->matches(vals.first->second)) {
                                o = q->get<2>().get();
                                descended = true;
                                break;
                            }
                            ++vals.first;
                        }
                    }
                    else {
                        // The simple presence of the parameter is sufficient to match.
                        o = q->get<2>().get();
                        descended = true;
                    }
                }
            }
        } while (descended);
    }

    return o;
}

XMLRequestMapperImpl::XMLRequestMapperImpl(const DOMElement* e, Category& log) : m_document(nullptr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLRequestMapperImpl");
#endif
    static const XMLCh _RequestMap[] =  UNICODE_LITERAL_10(R,e,q,u,e,s,t,M,a,p);

    if (e && !XMLHelper::isNodeNamed(e, SHIB2SPCONFIG_NS, _RequestMap))
        throw ConfigurationException("XML RequestMapper requires conf:RequestMap at root of configuration.");

    // Load the property set.
    load(e, nullptr, this);

    // Inject "default" app ID if not explicit.
    if (!getString("applicationId").first)
        setProperty("applicationId", "default");

    // Load any AccessControl provider.
    loadACL(e, log);

    pair<bool,bool> unicodeAware = getBool("unicodeAware");
    m_unicodeAware = (unicodeAware.first && unicodeAware.second);

    // Loop over the HostRegex elements.
    const DOMElement* host = XMLHelper::getFirstChildElement(e, HostRegex);
    for (int i = 1; host; ++i, host = XMLHelper::getNextSiblingElement(host, HostRegex)) {
        const XMLCh* n = host->getAttributeNS(nullptr,regex);
        if (!n || !*n) {
            log.warn("Skipping HostRegex element (%d) with empty regex attribute", i);
            continue;
        }

        boost::shared_ptr<Override> o(new Override(m_unicodeAware, host, log, this));

        const XMLCh* flag = host->getAttributeNS(nullptr,ignoreCase);
        try {
            boost::shared_ptr<RegularExpression> re(
                new RegularExpression(n, (flag && (*flag==chLatin_f || *flag==chDigit_0)) ? &chNull : ignoreOption)
                );
            m_regexps.push_back(make_pair(re, o));
        }
        catch (XMLException& ex) {
            auto_ptr_char tmp(ex.getMessage());
            log.error("caught exception while parsing HostRegex regular expression (%d): %s", i, tmp.get());
        }

        log.debug("Added <HostRegex> mapping for %s", m_regexps.back().second->getString("regex").second);
    }

    // Loop over the Host elements.
    host = XMLHelper::getFirstChildElement(e, Host);
    for (int i = 1; host; ++i, host = XMLHelper::getNextSiblingElement(host, Host)) {
        const XMLCh* n=host->getAttributeNS(nullptr,name);
        if (!n || !*n) {
            log.warn("Skipping Host element (%d) with empty name attribute", i);
            continue;
        }

        boost::shared_ptr<Override> o(new Override(m_unicodeAware, host, log, this));
        pair<bool,const char*> name=o->getString("name");
        pair<bool,const char*> scheme=o->getString("scheme");
        pair<bool,const char*> port=o->getString("port");

        string dup(name.first ? name.second : "");
        to_lower(dup);

        if (!scheme.first && port.first) {
            // No scheme, but a port, so assume http.
            scheme = pair<bool,const char*>(true,"http");
        }
        else if (scheme.first && !port.first) {
            // Scheme, no port, so default it.
            // XXX Use getservbyname instead?
            port.first = true;
            if (!strcmp(scheme.second,"http"))
                port.second = "80";
            else if (!strcmp(scheme.second,"https"))
                port.second = "443";
            else if (!strcmp(scheme.second,"ftp"))
                port.second = "21";
            else if (!strcmp(scheme.second,"ldap"))
                port.second = "389";
            else if (!strcmp(scheme.second,"ldaps"))
                port.second = "636";
        }

        if (scheme.first) {
            string url(scheme.second);
            url=url + "://" + dup;

            // Is this the default port?
            if ((!strcmp(scheme.second,"http") && !strcmp(port.second,"80")) ||
                (!strcmp(scheme.second,"https") && !strcmp(port.second,"443")) ||
                (!strcmp(scheme.second,"ftp") && !strcmp(port.second,"21")) ||
                (!strcmp(scheme.second,"ldap") && !strcmp(port.second,"389")) ||
                (!strcmp(scheme.second,"ldaps") && !strcmp(port.second,"636"))) {
                // First store a port-less version.
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s",url.c_str());

                // Now append the port. The shared_ptr should refcount the Override to avoid double deletes.
                url=url + ':' + port.second;
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
            else {
                url=url + ':' + port.second;
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
        }
        else {
            // No scheme or port, so we enter dual hosts on http:80 and https:443
            string url("http://");
            url += dup;
            if (m_map.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_map[url] = o;
            log.debug("Added <Host> mapping for %s",url.c_str());

            url += ":80";
            if (m_map.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_map[url] = o;
            log.debug("Added <Host> mapping for %s",url.c_str());

            url = "https://" + dup;
            if (m_map.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_map[url] = o;
            log.debug("Added <Host> mapping for %s",url.c_str());

            url += ":443";
            if (m_map.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_map[url] = o;
            log.debug("Added <Host> mapping for %s",url.c_str());
        }
    }
}

const Override* XMLRequestMapperImpl::findOverride(const char* vhost, const HTTPRequest& request) const
{
    const Override* o = nullptr;
    map< string,boost::shared_ptr<Override> >::const_iterator i = m_map.find(vhost);
    if (i != m_map.end())
        o = i->second.get();
    else {
        for (vector< pair< boost::shared_ptr<RegularExpression>,boost::shared_ptr<Override> > >::const_iterator re = m_regexps.begin(); !o && re != m_regexps.end(); ++re) {
            if (re->first->matches(vhost))
                o=re->second.get();
        }
    }

    return o ? o->locate(request) : this;
}

pair<bool,DOMElement*> XMLRequestMapper::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<XMLRequestMapperImpl> impl(new XMLRequestMapperImpl(raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}

RequestMapper::Settings XMLRequestMapper::getSettings(const HTTPRequest& request) const
{
    try {
        string normalizedhost(request.getHostname());
        to_lower(normalizedhost);
        string vhost = string(request.getScheme()) + "://" + normalizedhost + ':' + lexical_cast<string>(request.getPort());
        const Override* o = m_impl->findOverride(vhost.c_str(), request);
        return Settings(o, o->getAC());
    }
    catch (XMLException& ex) {
        auto_ptr_char tmp(ex.getMessage());
        m_log.error("caught exception while locating content settings: %s", tmp.get());
        throw ConfigurationException("XML-based RequestMapper failed to retrieve content settings.");
    }
}
