/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** XMLRequestMapper.cpp
 *
 * XML-based RequestMapper implementation.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "SPRequest.h"
#include "io/HTTPRequest.h"
#include "logging/Category.h"
#include "util/CGIParser.h"
#include "util/BoostPropertySet.h"
#include "util/Misc.h"
#include "util/ReloadableXMLFile.h"
#include "util/SPConstants.h"

#include <algorithm>
#include <memory>
#include <regex>
#include <tuple>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {

    // Blocks access when an ACL plugin fails to load.
    class AccessControlDummy : public AccessControl, public NoOpSharedLockable
    {
    public:
        aclresult_t authorized(const SPRequest& request, const Session* session) const {
            return shib_acl_false;
        }
    };

    class Override : public BoostPropertySet
    {
    public:
        Override(bool unicodeAware=false) : m_unicodeAware(unicodeAware) {}
        Override(bool unicodeAware, ptree& pt, Category& log, const Override* base=nullptr);
        ~Override() {}

        const Override* locate(const HTTPRequest& request) const;
        AccessControl* getAC() const {
            return (m_acl ? m_acl.get() : (getParent() ? dynamic_cast<const Override*>(getParent())->getAC() : nullptr));
        }

    protected:
        void loadACL(const ptree& pt, Category& log);

        bool m_unicodeAware;
        // This uses shared_ptr to support multiple mappings for a given Override for Host.
        // For Path, it's just overhead.
        map< string,shared_ptr<Override> > m_map;
        vector< pair< regex,unique_ptr<Override> > > m_regexps;
        vector< tuple< string,boost::optional<regex>,unique_ptr<Override> > > m_queries;

    private:
        unique_ptr<AccessControl> m_acl;
    };

    class XMLRequestMapperImpl : public Override
    {
    public:
        XMLRequestMapperImpl(ptree& pt, Category& log);
        ~XMLRequestMapperImpl() {}

        const Override* findOverride(const char* vhost, const HTTPRequest& request) const;

        void setTree(ptree* pt) {
            m_tree.reset(pt);
        }

    private:
        unique_ptr<ptree> m_tree;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    static const char REQUEST_MAP_PROP_PATH[] = "RequestMap";

    class XMLRequestMapper : public RequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(const ptree& pt)
            : ReloadableXMLFile(REQUEST_MAP_PROP_PATH, pt, Category::getInstance(SHIBSP_LOGCAT ".RequestMapper")) {
            load(); // guarantees an exception or the map is loaded
        }

        ~XMLRequestMapper() {}

        Settings getSettings(const HTTPRequest& request) const;

    protected:
        pair<bool,ptree*> load() noexcept;

    private:
        unique_ptr<XMLRequestMapperImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    RequestMapper* SHIBSP_DLLLOCAL XMLRequestMapperFactory(const ptree& pt, bool deprecationSupport)
    {
        return new XMLRequestMapper(pt);
    }
}

void SHIBSP_API shibsp::registerRequestMappers()
{
    AgentConfig& conf=AgentConfig::getConfig();
    conf.RequestMapperManager.registerFactory(XML_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, XMLRequestMapperFactory);
}

RequestMapper::RequestMapper()
{
}

RequestMapper::~RequestMapper()
{
}

void Override::loadACL(const ptree& pt, Category& log)
{
    // This method looks for a supported child element to use as the basis
    // of constructing an AccessControl plugin.

    static const char ACCESS_CONTROL_PROP_PATH[] = "AccessControl";
    static const char ACCESS_CONTROL_PROVIDER_PROP_PATH[] = "AccessControlProvider";
    static const char HTACCESS_PROP_PATH[] = "htaccess";
    static const char TYPE_PROP_PATH[] = "<xmlattr>.type";

    try {
        boost::optional<const ptree&> acl = pt.get_child_optional(HTACCESS_PROP_PATH);
        if (acl) {
            log.info("building Apache htaccess AccessControl provider...");
            m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(HT_ACCESS_CONTROL, acl.get(), false));
        }
        else {
            acl = pt.get_child_optional(ACCESS_CONTROL_PROP_PATH);
            if (acl) {
                log.info("building XML-based AccessControl provider...");
                // TODO: this is tenative, but it seems like we need to pass in the parent tree to allow it to
                // walk down to the "expected" element, but TBD.
                m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL, pt, false));
            }
            else {
                acl = pt.get_child_optional(ACCESS_CONTROL_PROVIDER_PROP_PATH);
                if (acl) {
                    string t(pt.get(TYPE_PROP_PATH, ""));
                    if (!t.empty()) {
                        log.info("building AccessControl provider of type %s...", t.c_str());
                        m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), acl.get(), false));
                    }
                    else {
                        throw ConfigurationException("<AccessControlProvider> missing type attribute.");
                    }
                }
            }
        }
    }
    catch (const exception& ex) {
        log.crit("exception building AccessControl provider: %s", ex.what());
        m_acl.reset(new AccessControlDummy());
    }
}

Override::Override(bool unicodeAware, ptree& pt, Category& log, const Override* base)
    : m_unicodeAware(unicodeAware)
{
    // Load the <xmlattr> tree as a property set.
    const boost::optional<ptree&> xmlattrs = pt.get_child_optional("<xmlattr>");
    if (xmlattrs) {
        load(xmlattrs.get(), "unset");
    }
    setParent(base);

    // Load any AccessControl provider.
    loadACL(pt, log);

    static const char PATH_PROP_PATH[] = "Path";
    static const char PATH_REGEX_PROP_PATH[] = "PathRegex";
    static const char QUERY_PROP_PATH[] = "Query";
    static const char NAME_PROP_PATH[] = "<xmlattr>.name";
    static const char REGEX_PROP_PATH[] = "<xmlattr>.regex";

    // Process the various child types.

    for (auto& child : pt) {
        if (child.first == PATH_PROP_PATH) {
            const string nameprop(getString("name", ""));
            const char* n = nameprop.c_str();

            // Skip any leading slashes.
            while (n && *n == '/')
                n++;

            // Check for empty name.
            if (!n || !*n) {
                log.warn("skipping Path element with empty name attribute");
                continue;
            }

            // Check for an embedded slash.
            const char* slash = strchr(n, '/');
            if (slash) {
                // Copy the first path segment.
                string namebuf;
                for (const char* pos = n; pos < slash; ++pos) {
                    namebuf += *pos;
                }

                // Move past the slash in the original pathname.
                n = slash + 1;

                // Skip any leading slashes again.
                while (*n == '/')
                    ++n;

                if (*n) {
                    // TODO: Seriously doubt any of this will work, but fixing it will
                    // require substantial redesign.

                    // namebuf has the segment to process at "this" level
                    // The "new" injected Path Oevrride containing it would have no other
                    // attributes since the settings in the slash-containing Path would
                    // apply only to the final "leaf" of the Path's directory tree.

                    // The currently iterated pair's second member is the original Path
                    // tree with the multi-part pathname and all the settings under <xmlattr>.
                    // We would have to make the iterated pair's second member be a tree
                    // containing the namebuf path segment under <xmlattr>.name and containing
                    // the original tree with a modified <xmlattr>.name set to *n under a child named Path.

                    // Copy the old child tree into a local variable and adjust its name.
                    ptree old_child(child.second);
                    old_child.put(NAME_PROP_PATH, n);

                    // Create a new tree with just the namebuf prefix and the new child under it.
                    ptree new_child;
                    new_child.put(NAME_PROP_PATH, namebuf);
                    new_child.add_child(PATH_PROP_PATH, old_child);

                    // Replace the original child iterated with the "new" child.
                    child.second = new_child;
                    
                    // Repoint our locals at the new parent.
                    n = namebuf.c_str();    // seems like this shouldn't be needed
                }
                else {
                    // All we had was a pathname with trailing slash(es), so just reset it without them.
                    child.second.put(NAME_PROP_PATH, namebuf);
                    n = namebuf.c_str();    // seems like this shouldn't be needed
                }
            }

            shared_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));
            string mutable_path = o->getString("name", "");
            if (mutable_path.empty()) {
                throw new ConfigurationException("Path element did not contain a name attribute.");
            }

            // The thinking here is that the Unicode flag tells it to treat the
            // Path name as UTF-8, and thus can't be safely case-folded.
            if (!m_unicodeAware) {
                boost::algorithm::to_lower(mutable_path);
            }

            if (m_map.count(mutable_path)) {
                log.warn("skipping duplicate Path element (%s)", mutable_path.c_str());
            }
            else {
                m_map[mutable_path] = o;
                log.debug("added Path mapping (%s)", mutable_path.c_str());
            }
        }
        else if (child.first == PATH_REGEX_PROP_PATH) {
            const string regexpprop(child.second.get(REGEX_PROP_PATH, ""));
            if (regexpprop.empty()) {
                log.warn("skipping PathRegex element with empty regex attribute");
                continue;
            }

            unique_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));

            try {
                // TODO: more flag options, particular for dialect.
                regex::flag_type flags = regex_constants::optimize;
                if (!getBool("caseSensitive", false)) {
                    flags |= regex_constants::icase;
                }
                regex exp(regexpprop, flags);
                m_regexps.push_back(make_pair(exp, std::move(o)));
                log.debug("added <PathRegex> mapping (%s)", regexpprop.c_str());
            }
            catch (const regex_error& e) {
                log.error("error parsing PathRegex regular expression: %s", e.what());
                throw ConfigurationException("Invalid regular expression in PathRegex element.");
            }
        }
        else if (child.first == QUERY_PROP_PATH) {
            string nameprop(getString("name", ""));
            if (nameprop.empty()) {
                log.warn("skipping Query element with empty name attribute");
                continue;
            }

            unique_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));

            string regexpprop(getString("regex", ""));

            if (regexpprop.empty()) {
                m_queries.push_back(make_tuple(nameprop, boost::optional<regex>(), std::move(o)));
            }
            else {
                try {
                    // TODO: more flag options, particular for dialect.
                    regex::flag_type flags = regex_constants::optimize;
                    if (!getBool("caseSensitive", false)) {
                        flags |= regex_constants::icase;
                    }
                    regex exp(regexpprop, flags);

                    m_queries.push_back(make_tuple(nameprop, boost::optional<regex>(exp), std::move(o)));
                    log.debug("added <Query> mapping (%s)", nameprop.c_str());
                }
                catch (const regex_error& e) {
                    log.error("caught exception while parsing Query regular expression: %s", e.what());
                    throw ConfigurationException("Invalid regular expression in Query element.");
                }
            }
        }
    }
}

const Override* Override::locate(const HTTPRequest& request) const
{
    // This function is confusing because it's *not* recursive.
    // The whole path is tokenized and mapped in a loop, so the
    // path parameter starts with the entire request path and
    // we can skip the leading slash as irrelevant.
    const char* path = request.getRequestURI();
    if (path && *path == '/')
        path++;

    // Fix for bug 574, secadv 20061002
    // Unescape URI up to query string delimiter by looking for %XX escapes.
    // Adapted from Apache's util.c, ap_unescape_url function.
    string dup;
    if (path) {
        while (*path) {
            if (*path == '?') {
                dup += path;
                break;
            }
            else if (*path != '%') {
                dup += *path;
            }
            else {
                ++path;
                if (!isxdigit(*path) || !isxdigit(*(path+1)))
                    throw ConfigurationException("Bad request URI, contained unsupported encoded characters.");
                dup += x2c(path);
                ++path;
            }
            ++path;
        }
    }

    // Now we copy the path, chop the query string, and possibly lower case it.
    string::size_type sep = dup.find('?');
    if (sep != string::npos) {
        dup = dup.substr(0, sep);
    }

    // Default is for the current object to provide settings.
    const Override* o = this;

    // Reset the path pointer to the beginning of the decoded copy.
    path = dup.c_str();

    // Tokenize the path by segment and try and map each segment.
    boost::tokenizer< boost::char_separator<char> > tokens(dup, boost::char_separator<char>("/"));
    for (const string& token : tokens) {

        string tokendup(token);
        if (!m_unicodeAware) {
            boost::algorithm::to_lower(tokendup);
        }

        const auto& i = o->m_map.find(tokendup);
        if (i == o->m_map.end())
            break;  // Once there's no match, we've consumed as much of the path as possible here.
        // We found a match, so reset the settings pointer.
        o = i->second.get();

        // We descended a step down the path, so we need to advance the original
        // parameter for the regex step later.
        path += tokendup.length();
        if (*path == '/')
            path++;
    }

    // If there's anything left, we try for a regex match on the rest of the path minus the query string.
    if (*path) {
        for (const auto& re : m_regexps) {
            if (regex_match(path, re.first)) {
                o = re.second.get();
                break;
            }
        }
    }

    // Finally, check for query string matches. This is another "unrolled" recursive descent in a loop.
    // To avoid consuming any POST data, we use a dedicated CGIParser that only consumes the query string.
    if (!o->m_queries.empty()) {
        bool descended;
        CGIParser cgi(request, true);
        do {
            descended = false;
            for (auto q = o->m_queries.begin(); !descended && q != o->m_queries.end(); ++q) {
                pair<CGIParser::walker,CGIParser::walker> vals = cgi.getParameters(get<0>(*q).c_str());
                if (vals.first != vals.second) {
                    if (get<1>(*q)) {
                        // We have to match one of the values.
                        while (vals.first != vals.second) {
                            if (regex_match(vals.first->second, get<1>(*q).get())) {
                                o = get<2>(*q).get();
                                descended = true;
                                break;
                            }
                            ++vals.first;
                        }
                    }
                    else {
                        // The simple presence of the parameter is sufficient to match.
                        o = get<2>(*q).get();
                        descended = true;
                    }
                }
            }
        } while (descended);
    }

    return o;
}

XMLRequestMapperImpl::XMLRequestMapperImpl(ptree& pt, Category& log)
{
    // Load the property set.
    load(pt, "unset");

    // This probably will go away at some point but for now just leaving it.
    // Inject "default" app ID if not explicit.
    if (!getString("applicationId")) {
        pt.put("applicationId", "default");
    }

    // Load any AccessControl provider.
    loadACL(pt, log);

    m_unicodeAware = getBool("unicodeAware", false);

    static const char HOST_PROP_PATH[] = "Host";
    static const char HOST_REGEX_PROP_PATH[] = "HostRegex";

    // Loop over the HostRegex elements.
    for (auto& child : pt) {
        if (child.first == HOST_REGEX_PROP_PATH) {
            string regexprop(getString("regex", ""));
            if (regexprop.empty()) {
                log.warn("Skipping HostRegex element with empty regex attribute");
                continue;
            }

            unique_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));

            try {
                regex::flag_type flags = regex_constants::optimize;
                if (!getBool("caseSensitive", false)) {
                    flags |= regex_constants::icase;
                }
                regex exp(regexprop, flags);
                m_regexps.push_back(make_pair(exp, std::move(o)));
            }
            catch (const regex_error& e) {
                log.error("caught exception while parsing HostRegex regular expression: %s", e.what());
            }

            log.debug("Added <HostRegex> mapping for %s", regexprop.c_str());
        }
        else if (child.first == HOST_PROP_PATH) {
            string name(getString("name", ""));
            if (name.empty()) {
                log.warn("Skipping Host element with empty name attribute");
                continue;
            }

            shared_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));
            const char* scheme = o->getString("scheme");
            const char* port = o->getString("port");

            boost::algorithm::to_lower(name);

            if (!scheme && port) {
                // No scheme, but a port, so assume http.
                scheme = "http";
            }
            else if (scheme && !port) {
                // Scheme, no port, so default it.
                // XXX Use getservbyname instead?
                if (!strcmp(scheme,"http"))
                    port = "80";
                else if (!strcmp(scheme,"https"))
                    port = "443";
                else if (!strcmp(scheme,"ftp"))
                    port = "21";
                else if (!strcmp(scheme,"ldap"))
                    port = "389";
                else if (!strcmp(scheme,"ldaps"))
                    port = "636";
            }

            if (scheme) {
                string url(scheme);
                url = url + "://" + name;

                // Is this the default port?
                if ((!strcmp(scheme,"http") && !strcmp(port,"80")) ||
                    (!strcmp(scheme,"https") && !strcmp(port,"443")) ||
                    (!strcmp(scheme,"ftp") && !strcmp(port,"21")) ||
                    (!strcmp(scheme,"ldap") && !strcmp(port,"389")) ||
                    (!strcmp(scheme,"ldaps") && !strcmp(port,"636"))) {
                    // First store a port-less version.
                    if (m_map.count(url)) {
                        log.warn("Skipping duplicate Host element (%s)", url.c_str());
                        continue;
                    }
                    m_map[url] = o;
                    log.debug("Added <Host> mapping for %s", url.c_str());

                    // Now append the port. The shared_ptr should refcount the Override to avoid double deletes.
                    url=url + ':' + port;
                    m_map[url] = o;
                    log.debug("Added <Host> mapping for %s", url.c_str());
                }
                else {
                    url=url + ':' + port;
                    if (m_map.count(url)) {
                        log.warn("Skipping duplicate Host element (%s)", url.c_str());
                        continue;
                    }
                    m_map[url] = o;
                    log.debug("Added <Host> mapping for %s", url.c_str());
                }
            }
            else {
                // No scheme or port, so we enter dual hosts on http:80 and https:443
                string url("http://");
                url += name;
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s", url.c_str());

                url += ":80";
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s", url.c_str());

                url = "https://" + name;
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s", url.c_str());

                url += ":443";
                if (m_map.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("Added <Host> mapping for %s", url.c_str());
            }
        }
    }
}

const Override* XMLRequestMapperImpl::findOverride(const char* vhost, const HTTPRequest& request) const
{
    const Override* o = nullptr;
    const auto& i = m_map.find(vhost);
    if (i != m_map.end())
        o = i->second.get();
    else {
        for (const auto& re : m_regexps) {
            if (regex_match(vhost, re.first)) {
                o = re.second.get();
            }
        }
    }

    return o ? o->locate(request) : this;
}

pair<bool,ptree*> XMLRequestMapper::load() noexcept
{
    // Load from source using base class.
    pair<bool,ptree*> raw = ReloadableXMLFile::load();
    if (!raw.second) {
        return raw;
    }

    // If we own it, wrap it.
    unique_ptr<ptree> treejanitor(raw.first ? raw.second : nullptr);

    unique_ptr<XMLRequestMapperImpl> impl(new XMLRequestMapperImpl(*raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setTree(treejanitor.release());

    // Perform the swap inside a lock.
#ifdef HAVE_CXX14
    unique_lock<ReloadableXMLFile> locker(*this);
#endif
    m_impl.swap(impl);

    return make_pair(false,raw.second);
}

RequestMapper::Settings XMLRequestMapper::getSettings(const HTTPRequest& request) const
{
    string normalizedhost(request.getHostname());
    boost::algorithm::to_lower(normalizedhost);
    string vhost = string(request.getScheme()) + "://" + normalizedhost + ':' + boost::lexical_cast<string>(request.getPort());
    
    const Override* o = m_impl->findOverride(vhost.c_str(), request);

    return Settings(o, o->getAC());
}
