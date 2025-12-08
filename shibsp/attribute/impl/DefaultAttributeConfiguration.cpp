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

/**
 * attribute/impl/DefaultAttributeConfiguration.cpp
 * 
 * Default ptree-based AttributeConfiguration implementation.
 */

#include "internal.h"

#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "RequestMapper.h"
#include "SPRequest.h"
#include "attribute/AttributeConfiguration.h"
#include "logging/Category.h"
#include "remoting/ddf.h"
#include "session/SessionCache.h"
#include "util/BoostPropertySet.h"
#include "util/Misc.h"
#include "util/URLEncoder.h"

#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <map>
#include <set>
#include <string>
#include <stdexcept>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex.hpp>
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

namespace {

    class DefaultAttributeConfiguration : public virtual AttributeConfiguration, public virtual BoostPropertySet {
    public:
        DefaultAttributeConfiguration(const char* pathname);
        DefaultAttributeConfiguration(const ptree& pt);
        ~DefaultAttributeConfiguration() {}

        bool processAttributes(DDF& attributes) const;
        bool isCaseSensitive(const char* attributeID) const;
        void clearHeaders(SPRequest& request) const;
        void exportAttributes(SPRequest& request, const Session& session) const;
        bool hasMatchingValue(const Session& session, const char* attributeId, const char* value) const;
        bool hasMatchingValue(const Session& session, const char* attributeId, const set<string>& values) const;
        bool hasMatchingValue(const Session& session, const char* attributeId, const regexp::regex& expression) const;

    private:
        void init(const ptree& pt);
        const char* getFirstValue(const Session& session, const char* attributeId) const;

        Category& m_log;
        // Unused ptree if we configure via inline.
        ptree m_pt;
        string m_scopeDelimiter;
        bool m_urlEncoding,m_exportDuplicates,m_partialRegexMatching;
        map<string,string> m_mappings;
        set<string> m_caseInsensitiveIds;
    };

};

const char AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_NAME[] = "legacyClassRefAttribute";
const char AttributeConfiguration::LEGACY_AUTHTIME_ATTRIBUTE_PROP_NAME[] = "legacyAuthnTimeAttribute";

const char AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT[] = "Shib-AuthnContext-Class";
const char AttributeConfiguration::LEGACY_AUTHTIME_ATTRIBUTE_PROP_DEFAULT[] = "Shib-Authentication-Instant";


AttributeConfiguration::AttributeConfiguration() {}

AttributeConfiguration::~AttributeConfiguration() {}

DefaultAttributeConfiguration::DefaultAttributeConfiguration(const ptree& pt)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".AttributeConfiguration"))
{
    init(pt);
}

DefaultAttributeConfiguration::DefaultAttributeConfiguration(const char* pathname)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".AttributeConfiguration"))
{

    if (!pathname) {
        throw ConfigurationException("No pathname supplied for creating AttrbuteConfiguration.");
    }

    ini_parser::read_ini(pathname, m_pt);
    init(m_pt);
}

void DefaultAttributeConfiguration::init(const ptree& pt)
{
    static const char SETTINGS_PROP_SECTION_NAME[] = "attribute-settings";
    static const char MAPPINGS_PROP_SECTION_NAME[] = "attribute-mappings";

    static const char CASE_INSENSITIVE_ATTRS_PROP_NAME[] = "caseInsensitiveAttributes";
    static const char ENCODING_PROP_NAME[] = "encoding";
    static const char EXPORT_DUP_VALUES_PROP_NAME[] = "exportDuplicateValues";
    const char SCOPE_DELIMITER_PROP_NAME[] = "scopeDelimiter";

    static bool EXPORT_DUP_VALUES_PROP_DEFAULT = true;
    // Not the default, but the only defined option.
    static const char URL_ENCODING_PROP_VALUE[] = "URL";
    const char SCOPE_DELIMITER_PROP_DEFAULT[] = "@";

    m_urlEncoding = false;
    m_exportDuplicates = true;

    // Populate "built-in" mappings.
    for (const string& name : {"Shib-Application-ID", "Shib-Session-ID", "Shib-Session-Expires", "Shib-Session-Inactivity", "REMOTE_USER"}) {
        m_mappings[name] = name;
    }

    boost::optional<ptree&> settings = m_pt.get_child_optional(SETTINGS_PROP_SECTION_NAME);
    if (settings) {
        // The load is a convenience, but all the settings are captured here in the c'tor.
        load(settings.get());
        split_to_container(m_caseInsensitiveIds, getString(CASE_INSENSITIVE_ATTRS_PROP_NAME, ""));

        m_scopeDelimiter = getString(SCOPE_DELIMITER_PROP_NAME, SCOPE_DELIMITER_PROP_DEFAULT);
        m_urlEncoding = !strcmp(getString(ENCODING_PROP_NAME, ""), URL_ENCODING_PROP_VALUE);
        m_exportDuplicates = getBool(EXPORT_DUP_VALUES_PROP_NAME, EXPORT_DUP_VALUES_PROP_DEFAULT);

        m_partialRegexMatching = AgentConfig::getConfig().getAgent().getBool(
            Agent::PARTIAL_REGEX_MATCHING_PROP_NAME, Agent::PARTIAL_REGEX_MATCHING_PROP_DEFAULT);
    }
    else {
        // Default settings
        m_scopeDelimiter = SCOPE_DELIMITER_PROP_DEFAULT;
        m_urlEncoding = false;
        m_exportDuplicates = EXPORT_DUP_VALUES_PROP_DEFAULT;
        m_partialRegexMatching = Agent::PARTIAL_REGEX_MATCHING_PROP_DEFAULT;
    }

    boost::optional<ptree&> mappings = m_pt.get_child_optional(MAPPINGS_PROP_SECTION_NAME);
    if (!mappings) {
        return;
    }

    for (auto& child : *mappings) {
        if (!child.first.empty()) {
            string alias(child.second.get_value(""));
            if (alias.empty()) {
                continue;
            }

            m_mappings[child.first] = alias;
        }
    }
}

unique_ptr<AttributeConfiguration> AttributeConfiguration::newAttributeConfiguration(const ptree& pt)
{
    return unique_ptr<AttributeConfiguration>(new DefaultAttributeConfiguration(pt));
}

unique_ptr<AttributeConfiguration> AttributeConfiguration::newAttributeConfiguration(const char* pathname)
{
    return unique_ptr<AttributeConfiguration>(new DefaultAttributeConfiguration(pathname));
}

bool DefaultAttributeConfiguration::processAttributes(DDF& attributes) const
{
    if (!attributes.islist()) {
        m_log.warn("invalid data supplied for session attributes");
        return false;
    }

    DDF attr = attributes.first();
    while (!attr.isnull()) {
        if (!attr.name() || !isalnum(*(attr.name()))) {
            m_log.warn("invalid unnamed attribute in session data");
            attr.destroy();
        }
        else if (!attr.islist()) {
            m_log.warn("invalid attribute in session data, '%s' was not a list", attr.name());
            attr.destroy();
        }
        else {
            DDF value = attr.first();
            while (!value.isnull()) {
                if (value.isstring()) {
                    if (!value.string() || !(*(value.string()))) {
                        m_log.warn("removing null or empty string value from attribute '%s'", attr.name());
                        value.destroy();
                    }
                }
                else if (value.isstruct()) {
                    const char* lhs = value.getmember("value").string();
                    const char* scope = value.getmember("scope").string();
                    if (lhs && scope && *lhs && *scope) {
                        string s = string(lhs) + m_scopeDelimiter + scope;
                        value.string(s.c_str());
                    } else {
                        value.destroy();
                        m_log.warn("attribute '%s' scoped value had a null or empty value or scope", attr.name());
                    }
                }
                else if (value.isint()) {
                    try {
                        string s(boost::lexical_cast<string>(attr.integer()));
                        value.string(s.c_str());
                    } catch (const boost::bad_lexical_cast&) {
                        value.destroy();
                        m_log.warn("attribute '%s' value could not be converted from int to string", attr.name());
                    }
                }
                else if (value.islong()) {
                    try {
                        string s(boost::lexical_cast<string>(attr.longinteger()));
                        value.string(s.c_str());
                    } catch (const boost::bad_lexical_cast&) {
                        value.destroy();
                        m_log.warn("attribute '%s' value could not be converted from int to string", attr.name());
                    }
                }
                else {
                    value.destroy();
                    m_log.warn("attribute '%s' value was not a supported type", attr.name());
                }

                value = attr.next();
            }

            if (attr.integer() == 0) {
                m_log.info("no values remain in attribute (%s) after processing", attr.name());
                attr.destroy();
            }
        }

        attr = attributes.next();
    }

    if (attributes.first().isnull()) {
        m_log.warn("no valid attributes remain in session after processing");
    }
    return true;
}

bool DefaultAttributeConfiguration::isCaseSensitive(const char* attributeID) const
{
    if (!attributeID) {
        return true;
    }
    return m_caseInsensitiveIds.count(attributeID) == 0;
}

void DefaultAttributeConfiguration::clearHeaders(SPRequest& request) const
{
    if (request.isUseHeaders()) {
        for (const auto& names : m_mappings) {
            request.clearHeader(names.second.c_str());
        }
    }
}

void DefaultAttributeConfiguration::exportAttributes(SPRequest& request, const Session& session) const
{
    RequestMapper::Settings settings = request.getRequestSettings();
    const URLEncoder& encoder = AgentConfig::getConfig().getURLEncoder();

    const char* delim = settings.first->getString(RequestMapper::ATTRIBUTE_VALUE_DELIMITER_PROP_NAME,
        RequestMapper::ATTRIBUTE_VALUE_DELIMITER_PROP_DEFAULT);
    size_t delim_len = strlen(delim);

    // Default export strategy will include duplicates.
    if (m_exportDuplicates) {
        for (const auto& a : session.getAttributes()) {

            const string* headerNameToUse = &(a.first);
            const auto& headerMapping = m_mappings.find(a.first);
            if (headerMapping == m_mappings.end()) {
                if (request.isUseHeaders()) {
                    // No mapping, so cannot be supplied as a header.
                    continue;
                }
            } else {
                headerNameToUse = &(headerMapping->second);
            }

            string header(request.getSecureHeader(headerNameToUse->c_str()));

            DDF vals = a.second; // cheap copy drops const qualifier
            DDF v = vals.first();
            while (!v.isnull()) {
                if (!header.empty()) {
                    header += delim;
                }

                if (m_urlEncoding) {
                    // If URL-encoding, any semicolons will get escaped anyway.
                    header += encoder.encode(v.string());
                }
                else {
                    string serialized(v.string());
                    string::size_type pos = serialized.find(delim, string::size_type(0));
                    if (pos != string::npos) {
                        for (; pos != string::npos; pos = serialized.find(delim, pos)) {
                            serialized.insert(pos, "\\");
                            pos += delim_len + 1;
                        }
                    }
                    header += serialized;
                }

                v = vals.next();
            }
            request.setHeader(headerNameToUse->c_str(), header.c_str());
        }
    }
    else {
        // Capture values in a map of sets to check for duplicates on the fly.
        map<string,set<string>> valueMap;
        for (const auto& a : session.getAttributes()) {

            const string* headerNameToUse = &(a.first);
            const auto& headerMapping = m_mappings.find(a.first);
            if (headerMapping == m_mappings.end()) {
                if (request.isUseHeaders()) {
                    // No mapping, so cannot be supplied as a header.
                    continue;
                }
            } else {
                headerNameToUse = &(headerMapping->second);
            }

            DDF vals = a.second; // cheap copy drops const qualifier
            DDF v = vals.first();
            set<string>& targetSet = valueMap[*headerNameToUse];
            while (vals.isnull()) {
                targetSet.insert(v.string());
                v = vals.next();
            }
        }

        // Export the mapped sets to the headers.
        for (const auto& deduped : valueMap) {
            string header;
            for (const string& v : deduped.second) {
                if (!header.empty())
                    header += delim;
                if (m_urlEncoding) {
                    // If URL-encoding, any semicolons will get escaped anyway.
                    header += encoder.encode(v.c_str());
                }
                else {
                    string::size_type pos = v.find(delim, string::size_type(0));
                    if (pos != string::npos) {
                        string value(v);
                        for (; pos != string::npos; pos = value.find(delim, pos)) {
                            value.insert(pos, "\\");
                            pos += delim_len + 1;
                        }
                        header += value;
                    }
                    else {
                        header += v;
                    }
                }
            }
            request.setHeader(deduped.first.c_str(), header.c_str());
        }
    }

    // Check for REMOTE_USER.
    vector<string> rmids;
    split_to_container(rmids, settings.first->getString(RequestMapper::REMOTE_USER_PROP_NAME, ""));
    for (const string& rmid : rmids) {
        const char* firstVal = getFirstValue(session, rmid.c_str());
        if (firstVal && *firstVal) {
            if (m_urlEncoding)
                request.setRemoteUser(encoder.encode(firstVal).c_str());
            else
                request.setRemoteUser(firstVal);
            break;
        }
    }
}

bool DefaultAttributeConfiguration::hasMatchingValue(
    const Session& session, const char* attributeId, const set<string>& values
    ) const
{
    const auto& attr = session.getAttributes().find(attributeId);
    if (attr == session.getAttributes().end()) {
        return false;
    }

    bool caseSensitive = isCaseSensitive(attributeId);

    DDF val = const_cast<DDF&>(attr->second).first();
    while (!val.isnull()) {
        if (caseSensitive) {
            // Can just search the set.
            if (values.find(val.string()) != values.end()) {
                return true;
            }
        } else {
            // Have to loop over each set member for a case-insensitive comparison.
            for (const string& candidate : values) {
                if (!strcasecmp(val.string(), candidate.c_str())) {
                    return true;
                }
            }
        }

        val = const_cast<DDF&>(attr->second).next();
    }

    return false;
}

bool DefaultAttributeConfiguration::hasMatchingValue(
    const Session& session, const char* attributeId, const char* value
    ) const
{
    const auto& attr = session.getAttributes().find(attributeId);
    if (attr == session.getAttributes().end()) {
        return false;
    }

    bool caseSensitive = isCaseSensitive(attributeId);

    DDF val = const_cast<DDF&>(attr->second).first();
    while (!val.isnull()) {
        int result = caseSensitive ? strcmp(val.string(), value) : strcasecmp(val.string(), value);
        if (result == 0) {
            return true;
        }
        val = const_cast<DDF&>(attr->second).next();
    }

    return false;
}

bool DefaultAttributeConfiguration::hasMatchingValue(
    const Session& session, const char* attributeId, const regexp::regex& expression
    ) const
{
    static regexp::regex_constants::match_flag_type match_flags =
        regexp::regex_constants::match_any | regexp::regex_constants::match_not_null;

    const auto& attr = session.getAttributes().find(attributeId);
    if (attr == session.getAttributes().end()) {
        return false;
    }

    DDF val = const_cast<DDF&>(attr->second).first();
    while (!val.isnull()) {
        if (m_partialRegexMatching ? regexp::regex_search(val.string(), expression, match_flags) :
                regexp::regex_match(val.string(), expression, match_flags)) {
            return true;
        }
        val = const_cast<DDF&>(attr->second).next();
    }

    return false;
}

const char* DefaultAttributeConfiguration::getFirstValue(const Session& session, const char* attributeId) const
{
    const auto& attr = session.getAttributes().find(attributeId);
    if (attr == session.getAttributes().end()) {
        return nullptr;
    }

    return const_cast<DDF&>(attr->second).first().string();
}
