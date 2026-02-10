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

/** impl/XMLRequestMapper.cpp
 *
 * XML-based RequestMapper implementation.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "Agent.h"
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
#include <tuple>
#include <utility>
#include <boost/property_tree/ptree.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex.hpp>
namespace regexp = boost;
#else
# include <regex>
namespace regexp = std;
#endif

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
        void loadACL(ptree& pt, Category& log);

        bool m_unicodeAware;
        // This uses shared_ptr to support multiple mappings for a given Override for Host.
        // For Path, it's just overhead.
        map< string,shared_ptr<Override> > m_map;
        vector< pair< regexp::regex,unique_ptr<Override> > > m_regexps;
        vector< tuple< string,boost::optional<regexp::regex>,unique_ptr<Override> > > m_queries;

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
    static const char NAME_PROP_PATH[] = "<xmlattr>.name";
    static const char REGEX_PROP_PATH[] = "<xmlattr>.regex";

    class XMLRequestMapper : public RequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(ptree& pt)
            : ReloadableXMLFile(REQUEST_MAP_PROP_PATH, pt, Category::getInstance(SHIBSP_LOGCAT ".RequestMapper")) {
            if (!load().second) {
                throw ConfigurationException("Initial RequestMapper configuration was invalid.");
            }
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

    RequestMapper* SHIBSP_DLLLOCAL XMLRequestMapperFactory(ptree& pt, bool deprecationSupport)
    {
        return new XMLRequestMapper(pt);
    }

    static bool doRegex(const regexp::regex& exp, const char* input) {
        static regexp::regex_constants::match_flag_type match_flags =
            regexp::regex_constants::match_any | regexp::regex_constants::match_not_null;

        bool partial = AgentConfig::getConfig().getAgent().getBool(
            Agent::PARTIAL_REGEX_MATCHING_PROP_NAME, Agent::PARTIAL_REGEX_MATCHING_PROP_DEFAULT);
        if (partial) {
            return regexp::regex_search(input, exp, match_flags);
        }
        else {
            return regexp::regex_match(input, exp, match_flags);
        }
    }
}

void SHIBSP_API shibsp::registerRequestMappers()
{
    AgentConfig& conf=AgentConfig::getConfig();
    conf.RequestMapperManager.registerFactory(XML_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, XMLRequestMapperFactory);
}

const char RequestMapper::APPLICATION_ID_PROP_NAME[] =      "applicationId";
const char RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME[] = "attributeConfigId";
const char RequestMapper::ATTRIBUTE_VALUE_DELIMITER_PROP_NAME[] = "attributeValueDelimiter";
const char RequestMapper::AUTH_TYPE_PROP_NAME[] =           "authType";
const char RequestMapper::CONSISTENT_ADDRESS_PROP_NAME[] =  "consistentAddress";
const char RequestMapper::COOKIE_MAXAGE_PROP_NAME[] =       "cookieMaxAge";
const char RequestMapper::HANDLER_CONFIG_ID_PROP_NAME[] =   "handlerConfigId";
const char RequestMapper::HANDLER_SSL_PROP_NAME[] =         "handlerSSL";
const char RequestMapper::HANDLER_URL_PROP_NAME[] =         "handlerURL";
const char RequestMapper::HOME_URL_PROP_NAME[] =            "homeURL";
const char RequestMapper::EXPIRE_REDIRECTS_PROP_NAME[] =    "expireRedirects";
const char RequestMapper::LIFETIME_PROP_NAME[] =            "lifetime";
const char RequestMapper::LOGOUT_NOTIFY_PROP_NAME[] =       "logoutNotify";
const char RequestMapper::LOGOUT_URL_PROP_NAME[] =          "logoutURL";
const char RequestMapper::PRESERVE_POST_DATA_PROP_NAME[] =  "preservePostData";
const char RequestMapper::POST_LIMIT_PROP_NAME[] =          "postLimit";
const char RequestMapper::REDIRECT_ALLOW_PROP_NAME[] =      "redirectAllow";
const char RequestMapper::REDIRECT_ERRORS_PROP_NAME[] =     "redirectErrors";
const char RequestMapper::REDIRECT_LIMIT_PROP_NAME[] =      "redirectLimit";
const char RequestMapper::REDIRECT_TO_SSL_PROP_NAME[] =     "redirectToSSL";
const char RequestMapper::REMOTE_ADDR_PROP_NAME[] =         "REMOTE_ADDR";
const char RequestMapper::REMOTE_USER_PROP_NAME[] =         "REMOTE_USER";
const char RequestMapper::REQUIRE_LOGOUT_WITH_PROP_NAME[] = "requireLogoutWith";
const char RequestMapper::REQUIRE_SESSION_PROP_NAME[] =     "requireSession";
const char RequestMapper::SESSION_COOKIE_NAME_PROP_NAME[] = "sessionCookieName";
const char RequestMapper::SESSION_HOOK_PROP_NAME[] =        "sessionHook";
const char RequestMapper::TARGET_PROP_NAME[] =              "target";
const char RequestMapper::TIMEOUT_PROP_NAME[] =             "timeout";
const char RequestMapper::USE_HEADERS_PROP_NAME[] =         "useHeaders";
const char RequestMapper::USE_VARIABLES_PROP_NAME[] =       "useVariables";

const char RequestMapper::APPLICATION_ID_PROP_DEFAULT[] =   "default";
const char RequestMapper::ATTRIBUTE_VALUE_DELIMITER_PROP_DEFAULT[] = ";";
bool RequestMapper::CONSISTENT_ADDRESS_PROP_DEFAULT =       true;
bool RequestMapper::EXPIRE_REDIRECTS_PROP_DEFAULT =         true;
bool RequestMapper::HANDLER_SSL_PROP_DEFAULT =              true;
const char RequestMapper::HANDLER_URL_PROP_DEFAULT[] =      "/Shibboleth.sso";
const char RequestMapper::HOME_URL_PROP_DEFAULT[] =         "/";
unsigned int RequestMapper::LIFETIME_PROP_DEFAULT =         3600 * 8;
bool RequestMapper::PRESERVE_POST_DATA_PROP_DEFAULT =       false;
unsigned int RequestMapper::POST_LIMIT_PROP_DEFAULT =       1024 * 1024;
const char RequestMapper::REDIRECT_LIMIT_PROP_DEFAULT[] =   "exact";
bool RequestMapper::REQUIRE_SESSION_PROP_DEFAULT =          false;
unsigned int RequestMapper::TIMEOUT_PROP_DEFAULT =          3600;
bool RequestMapper::USE_HEADERS_PROP_DEFAULT =              false;
bool RequestMapper::USE_VARIABLES_PROP_DEFAULT =            true;

RequestMapper::RequestMapper()
{
}

RequestMapper::~RequestMapper()
{
}

void Override::loadACL(ptree& pt, Category& log)
{
    // This method looks for a supported child element to use as the basis
    // of constructing an AccessControl plugin.

    static const char ACCESS_CONTROL_PROP_PATH[] = "AccessControl";
    static const char ACCESS_CONTROL_PROVIDER_PROP_PATH[] = "AccessControlProvider";
    static const char TYPE_PROP_PATH[] = "<xmlattr>.type";

    try {
        boost::optional<ptree&> acl = pt.get_child_optional(ACCESS_CONTROL_PROP_PATH);
        if (acl) {
            log.info("building inline XML-based AccessControl provider...");
            m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL, acl.get(), false));
        }
        else {
            acl = pt.get_child_optional(ACCESS_CONTROL_PROVIDER_PROP_PATH);
            if (acl) {
                string t(acl->get(TYPE_PROP_PATH, "XML"));
                log.info("building AccessControl provider of type %s...", t.c_str());
                m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), acl.get(), false));
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
    // Load the property set and point it at our parent.
    load(pt, "unset");
    setParent(base);

    // Load any AccessControl provider.
    loadACL(pt, log);

    static const char PATH_PROP_PATH[] = "Path";
    static const char PATH_REGEX_PROP_PATH[] = "PathRegex";
    static const char QUERY_PROP_PATH[] = "Query";

    // Process the various child types.

    for (auto& child : pt) {
        if (child.first == PATH_PROP_PATH) {
            const string nameprop(child.second.get(NAME_PROP_PATH, ""));
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
                    // TODO: Tests suggest this is working, but that's extremely hard to
                    // fully believe yet.

                    // namebuf has the segment to process at "this" level
                    // The "new" injected Path Oevrride containing it should have no other
                    // attributes since the settings in the slash-containing Path apply
                    // only to the final "leaf" of the Path's directory tree.

                    // The currently iterated pair's second member is the original Path
                    // tree with the multi-part pathname and all the settings under <xmlattr>.
                    // We have to make the iterated pair's second member be a tree
                    // containing the namebuf path segment under <xmlattr>.name and containing
                    // the original tree with a modified <xmlattr>.name set to *n under a child
                    // named Path.

                    // Copy the old child tree into a local variable and adjust its name.
                    ptree old_child(child.second);
                    old_child.put(NAME_PROP_PATH, n);

                    // Create a new tree with just the namebuf prefix and the old child under it.
                    ptree new_child;
                    new_child.put(NAME_PROP_PATH, namebuf);
                    new_child.add_child(PATH_PROP_PATH, old_child);

                    // Replace the original child iterated with the "new" child.
                    child.second = new_child;
                }
                else {
                    // All we had was a pathname with trailing slash(es), so just reset it without them.
                    child.second.put(NAME_PROP_PATH, namebuf);
                }
            }

            shared_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));
            string mutable_path = o->getString("name", "");
            if (mutable_path.empty()) {
                throw ConfigurationException("Path element did not contain a name attribute.");
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
                regexp::regex::flag_type flags = regexp::regex_constants::extended | regexp::regex_constants::optimize;
                if (!o->getBool("caseSensitive", false)) {
                    flags |= regexp::regex_constants::icase;
                }
                regexp::regex exp(regexpprop, flags);
                m_regexps.push_back(make_pair(exp, std::move(o)));
                log.debug("added <PathRegex> mapping (%s)", regexpprop.c_str());
            }
            catch (const regexp::regex_error& e) {
                log.error("error parsing PathRegex regular expression: %s", e.what());
                throw ConfigurationException("Invalid regular expression in PathRegex element.");
            }
        }
        else if (child.first == QUERY_PROP_PATH) {
            string nameprop(child.second.get(NAME_PROP_PATH, ""));
            if (nameprop.empty()) {
                log.warn("skipping Query element with empty name attribute");
                continue;
            }

            unique_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));

            string regexpprop(o->getString("regex", ""));

            if (regexpprop.empty()) {
                m_queries.push_back(make_tuple(nameprop, boost::optional<regexp::regex>(), std::move(o)));
            }
            else {
                try {
                    // TODO: more flag options, particular for dialect.
                    regexp::regex::flag_type flags = regexp::regex_constants::extended | regexp::regex_constants::optimize;
                    if (!o->getBool("caseSensitive", false)) {
                        flags |= regexp::regex_constants::icase;
                    }
                    regexp::regex expr(regexpprop, flags);

                    m_queries.push_back(make_tuple(nameprop, boost::optional<regexp::regex>(expr), std::move(o)));
                    log.debug("added <Query> mapping (%s)", nameprop.c_str());
                }
                catch (const regexp::regex_error& e) {
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
            if (doRegex(re.first, path)) {
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
                            if (doRegex(get<1>(*q).get(), vals.first->second)) {
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

    static const char HOST_PROP_PATH[] = "Host";
    static const char HOST_REGEX_PROP_PATH[] = "HostRegex";
    static const char APPLICATION_ID_PROP_PATH[] = "<xmlattr>.applicationId";

    // This probably will go away at some point but for now just leaving it.
    // Inject "default" app ID if not explicit.
    const boost::optional<string> appId = pt.get_optional<string>(APPLICATION_ID_PROP_PATH);
    if (!appId) {
        pt.put(APPLICATION_ID_PROP_PATH, RequestMapper::APPLICATION_ID_PROP_DEFAULT);
    }

    // Load the property set.
    load(pt, "unset");

    // Load any AccessControl provider.
    loadACL(pt, log);

    m_unicodeAware = getBool("unicodeAware", false);

    // Loop over the HostRegex elements.
    for (auto& child : pt) {
        if (child.first == HOST_REGEX_PROP_PATH) {
            string regexprop(child.second.get(REGEX_PROP_PATH, ""));
            if (regexprop.empty()) {
                log.warn("skipping HostRegex element with empty regex attribute");
                continue;
            }

            unique_ptr<Override> o(new Override(m_unicodeAware, child.second, log, this));

            try {
                regexp::regex::flag_type flags = regexp::regex_constants::extended | regexp::regex_constants::optimize;
                if (!o->getBool("caseSensitive", false)) {
                    flags |= regexp::regex_constants::icase;
                }
                regexp::regex expr(regexprop, flags);
                m_regexps.push_back(make_pair(expr, std::move(o)));
            }
            catch (const regexp::regex_error& e) {
                log.error("caught exception while parsing HostRegex regular expression: %s", e.what());
            }

            log.debug("added <HostRegex> mapping for %s", regexprop.c_str());
        }
        else if (child.first == HOST_PROP_PATH) {
            string name(child.second.get(NAME_PROP_PATH, ""));
            if (name.empty()) {
                log.warn("skipping Host element with empty name attribute");
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
                        log.warn("skipping duplicate Host element (%s)", url.c_str());
                        continue;
                    }
                    m_map[url] = o;
                    log.debug("added <Host> mapping for %s", url.c_str());

                    // Now append the port. The shared_ptr should refcount the Override to avoid double deletes.
                    url=url + ':' + port;
                    m_map[url] = o;
                    log.debug("added <Host> mapping for %s", url.c_str());
                }
                else {
                    url=url + ':' + port;
                    if (m_map.count(url)) {
                        log.warn("skipping duplicate Host element (%s)", url.c_str());
                        continue;
                    }
                    m_map[url] = o;
                    log.debug("added <Host> mapping for %s", url.c_str());
                }
            }
            else {
                // No scheme or port, so we enter dual hosts on http:80 and https:443
                string url("http://");
                url += name;
                if (m_map.count(url)) {
                    log.warn("skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("added <Host> mapping for %s", url.c_str());

                url += ":80";
                if (m_map.count(url)) {
                    log.warn("skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("added <Host> mapping for %s", url.c_str());

                url = "https://" + name;
                if (m_map.count(url)) {
                    log.warn("skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("added <Host> mapping for %s", url.c_str());

                url += ":443";
                if (m_map.count(url)) {
                    log.warn("skipping duplicate Host element (%s)", url.c_str());
                    continue;
                }
                m_map[url] = o;
                log.debug("added <Host> mapping for %s", url.c_str());
            }
        }
    }
}

const Override* XMLRequestMapperImpl::findOverride(const char* vhost, const HTTPRequest& request) const
{
    const Override* o = nullptr;
    const auto& i = m_map.find(vhost);
    if (i != m_map.end()) {
        o = i->second.get();
    }
    else {
        for (const auto& re : m_regexps) {
            if (doRegex(re.first, vhost)) {
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

    try {
        // If we own it, wrap it.
        unique_ptr<ptree> treejanitor(raw.first ? raw.second : nullptr);

        // We need to navigate down to the properly named child that should have been checked
        // by the base class.
        unique_ptr<XMLRequestMapperImpl> impl(
            new XMLRequestMapperImpl(raw.second->get_child(REQUEST_MAP_PROP_PATH), m_log));

        // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
        impl->setTree(treejanitor.release());

        // Perform the swap inside a lock.
        unique_lock<ReloadableXMLFile> locker(*this);
        m_impl.swap(impl);
        updateModificationTime();

        return make_pair(false, raw.second);
    }
    catch (const exception& e) {
        m_log.error("exception loading RequestMapper: %s", e.what());
    }

    return make_pair(false, nullptr);
}

RequestMapper::Settings XMLRequestMapper::getSettings(const HTTPRequest& request) const
{
    string normalizedhost(request.getHostname());
    boost::algorithm::to_lower(normalizedhost);
    string vhost = string(request.getScheme()) + "://" + normalizedhost + ':' + boost::lexical_cast<string>(request.getPort());
    
    const Override* o = m_impl->findOverride(vhost.c_str(), request);

    return Settings(o, o->getAC());
}
