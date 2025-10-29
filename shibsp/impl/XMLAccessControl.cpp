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
 * XMLAccessControl.cpp
 *
 * XML-based access control syntax.
 */

#include "internal.h"
#include "exceptions.h"

#include "AccessControl.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "attribute/AttributeConfiguration.h"
#include "logging/Category.h"
#include "remoting/ddf.h"
#include "session/SessionCache.h"
#include "util/Lockable.h"
#include "util/Misc.h"
#include "util/ReloadableXMLFile.h"

#include <algorithm>
#include <memory>
#include <set>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>

#ifdef SHIBSP_USE_BOOST_REGEX
# include <boost/regex.hpp>
namespace regexp = boost;
#else
# include <regex>
namespace regexp = std;
#endif

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {

    class Rule : public AccessControl, public NoOpSharedLockable
    {
    public:
        Rule(const ptree& pt);
        ~Rule() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        string m_alias;
        set <string> m_vals;
    };

    class RuleRegex : public AccessControl, public NoOpSharedLockable
    {
    public:
        RuleRegex(const ptree& pt);
        ~RuleRegex() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        string m_alias;
        string m_exp;
        regexp::regex m_re;
    };

    class TimeRule : public AccessControl, public NoOpSharedLockable
    {
    public:
        TimeRule(const string& name, const ptree& pt);
        ~TimeRule() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

        enum time_type_t {
            TM_AUTHN, TM_TIME, TM_YEAR, TM_MONTH, TM_DAY, TM_HOUR, TM_MINUTE, TM_SECOND, TM_WDAY
        };
    private:
        time_type_t m_type;
        enum { OP_LT, OP_LE, OP_EQ, OP_GE, OP_GT } m_op;
        time_t m_value;
    };

    class Operator : public AccessControl, public NoOpSharedLockable
    {
    public:
        Operator(const string& name, const ptree& pt);
        ~Operator() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum operator_t { OP_NOT, OP_AND, OP_OR } m_op;
        vector<unique_ptr<AccessControl>> m_operands;
    };

    static const char AND_PROP_PATH[] =             "AND";
    static const char OR_PROP_PATH[] =              "OR";
    static const char NOT_PROP_PATH[] =             "NOT";
    static const char ACCESS_CONTROL_PROP_PATH[] =  "AccessControl";
    static const char REQUIRE_PROP_PATH[] =         "<xmlattr>.require";
    static const char RULE_PROP_PATH[] =            "Rule";
    static const char RULE_REGEX_PROP_PATH[] =      "RuleRegex";
    static const char TIMESINCEAUTHN_PROP_PATH[] =  "TimeSinceAuthn";
    static const char TIME_PROP_PATH[] =            "Time";
    static const char DAY_PROP_PATH[] =             "Day";
    static const char DAYOFWEEK_PROP_PATH[] =       "DayOfWeek";
    static const char HOUR_PROP_PATH[] =            "Hour";
    static const char MINUTE_PROP_PATH[] =          "Minute";
    static const char MONTH_PROP_PATH[] =           "Month";
    static const char SECOND_PROP_PATH[] =          "Second";
    static const char YEAR_PROP_PATH[] =            "Year";

    // Indexed time rules for comparison/lookup in constructors.
    static map<string,TimeRule::time_type_t> g_timeRules = {
        { TIMESINCEAUTHN_PROP_PATH, TimeRule::TM_AUTHN },
        { TIME_PROP_PATH, TimeRule::TM_TIME },
        { DAY_PROP_PATH, TimeRule::TM_DAY },
        { DAYOFWEEK_PROP_PATH, TimeRule::TM_WDAY },
        { HOUR_PROP_PATH, TimeRule::TM_HOUR },
        { MINUTE_PROP_PATH, TimeRule::TM_MINUTE },
        { MONTH_PROP_PATH, TimeRule::TM_MONTH },
        { SECOND_PROP_PATH, TimeRule::TM_SECOND },
        { YEAR_PROP_PATH, TimeRule::TM_YEAR }
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLAccessControl : public AccessControl, public ReloadableXMLFile
    {
    public:
        XMLAccessControl(ptree& pt)
            : ReloadableXMLFile(ACCESS_CONTROL_PROP_PATH, pt, Category::getInstance(SHIBSP_LOGCAT ".AccessControl.XML")) {
            if (!load().second) {
                throw ConfigurationException("Initial AccessControl configuration was invalid.");
            }
        }

        ~XMLAccessControl() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    protected:
        pair<bool,ptree*> load() noexcept;

    private:
        unique_ptr<AccessControl> processChild(const string& name, const ptree& pt);
        unique_ptr<AccessControl> m_rootAuthz;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif
}

namespace shibsp {
    AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(ptree& pt, bool deprecationSupport)
    {
        return new XMLAccessControl(pt);
    }
};

void SHIBSP_API shibsp::registerAccessControls()
{
    AgentConfig& conf=AgentConfig::getConfig();
    conf.AccessControlManager.registerFactory(XML_ACCESS_CONTROL, XMLAccessControlFactory);
}

AccessControl::AccessControl()
{
}

AccessControl::~AccessControl()
{
}

Rule::Rule(const ptree& pt) : m_alias(pt.get(REQUIRE_PROP_PATH, ""))
{
    if (m_alias.empty()) {
        throw ConfigurationException("Access control rule missing require attribute");
    }

    if (m_alias == "authnContextClassRef") {
        AgentConfig::getConfig().deprecation().warn(
            "Rule specifying authnContextClassRef is deprecated and will be removed from a future version");
    }

    string vals = pt.get_value("");
    if (vals.empty()) {
        return; // empty rule
    }

    static const char LIST_PROP_PATH[] = "list";
    static string_to_bool_translator tr;
    bool listflag = pt.get(LIST_PROP_PATH, true);
    if (!listflag) {
        m_vals.insert(vals);
        return;
    }

    split_to_container(m_vals, vals.c_str());
    if (m_vals.empty())
        throw ConfigurationException("Rule did not contain any usable values.");
}

AccessControl::aclresult_t Rule::authorized(const SPRequest& request, const Session* session) const
{
    // We can make this more complex later using pluggable comparison functions,
    // but for now, just a straight port to the new Attribute API.

    string actual_alias(m_alias);

    // Map alias in rule to the attribute.
    if (!session) {
        request.warn("AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.debug("AccessControl rule accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "user") {
        if (m_vals.find(request.getRemoteUser()) != m_vals.end()) {
            request.debug(string("AccessControl rule expecting REMOTE_USER (") + request.getRemoteUser() + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    
    // Last two rule types rely on AttributeConfiguration...
    
    const AttributeConfiguration& attributeConfig = request.getAgent().getAttributeConfiguration(
        request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME)
        );

    if (m_alias == "authnContextClassRef") {
        actual_alias = attributeConfig.getString(
            AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_NAME,
            AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT);
    }

    // Empty case is historical and not terribly smart, but we'll brute force it.
    if (m_vals.empty()) {
        if (session->getAttributes().find(actual_alias.c_str()) != session->getAttributes().end()) {
            request.debug(string("AccessControl rule requires presence of attribute (") + actual_alias + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    // Otherwise call into the helper logic to handle matching process..
    if (attributeConfig.hasMatchingValue(*session, actual_alias.c_str(), m_vals)) {
        request.debug(string("AccessControl rule satisfied for attribute (") + actual_alias + "), authz granted");
        return shib_acl_true;
    }

    return shib_acl_false;
}

RuleRegex::RuleRegex(const ptree& pt)
    : m_alias(pt.get(REQUIRE_PROP_PATH, "")), m_exp(pt.get_value(""))
{
    if (m_alias.empty() || m_exp.empty()) {
        throw ConfigurationException("Access control rule missing require attribute or element content.");
    }

    if (m_alias == "authnContextClassRef") {
        AgentConfig::getConfig().deprecation().warn(
            "Rule specifying authnContextClassRef is deprecated and will be removed from a future version");
    }

    static const char CASE_SENSITIVE_PROP_PATH[] = "caseSensitive";
    static string_to_bool_translator tr;
    bool caseSensitive = pt.get(CASE_SENSITIVE_PROP_PATH, true);
    try {
        regexp::regex_constants::syntax_option_type flags = regexp::regex_constants::extended | regexp::regex_constants::optimize;
        if (!caseSensitive) {
            flags |= regexp::regex_constants::icase;
        }
        m_re = regexp::regex(m_exp, flags);
    }
    catch (const regexp::regex_error&) {
        throw ConfigurationException("Caught exception while parsing RuleRegex regular expression.");
    }
}

AccessControl::aclresult_t RuleRegex::authorized(const SPRequest& request, const Session* session) const
{
    static regexp::regex_constants::match_flag_type match_flags = regexp::regex_constants::match_any | regexp::regex_constants::match_not_null;

    string actual_alias(m_alias);

    if (!session) {
        request.warn("AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.debug("AccessControl rule accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "user") {

        bool partial = request.getAgent().getBool(
            Agent::PARTIAL_REGEX_MATCHING_PROP_NAME, Agent::PARTIAL_REGEX_MATCHING_PROP_DEFAULT);

        bool result = partial ? regexp::regex_search(request.getRemoteUser(), m_re, match_flags) :
                regexp::regex_match(request.getRemoteUser(), m_re, match_flags);
        if (result) {
            request.debug(string("AccessControl rule expecting REMOTE_USER regex (") + m_exp + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    // Last two rule types rely on AttributeConfiguration...
    
    const AttributeConfiguration& attributeConfig = request.getAgent().getAttributeConfiguration(
        request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME)
        );

    if (m_alias == "authnContextClassRef") {
        actual_alias = attributeConfig.getString(
            AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_NAME,
            AttributeConfiguration::LEGACY_CLASSREF_ATTRIBUTE_PROP_DEFAULT);
    }

    // Call into the helper logic to handle matching process..
    if (attributeConfig.hasMatchingValue(*session, actual_alias.c_str(), m_re)) {
        request.debug(
            string("AccessControl rule for attribute (") + actual_alias + ") expecting regex (" + m_exp  + ", authz granted");
        return shib_acl_true;
    }

    return shib_acl_false;
}

TimeRule::TimeRule(const string& name, const ptree& pt)
{
    // The TimeSinceAuthn rule operates on a Duration inside the element body,
    // which should be the value of the tree.

    if (name == TIMESINCEAUTHN_PROP_PATH) {
        m_type = TM_AUTHN;
        if ((m_value = parseISODuration(pt.get_value(""))) < 0) {
            throw ConfigurationException("Unable to parse duration in TimeSinceAuthn rule.");
        }
        return;
    }
    
    // Anything else we have to parse the element body.
    string s = pt.get_value("");
    boost::trim(s);
    vector<string> tokens;
    if (boost::split(tokens, s, boost::is_space(), boost::algorithm::token_compress_on).size() != 2) {
        throw ConfigurationException("Time-based rule requires element content of the form \"LT|LE|EQ|GE|GT value\".");
    }
    string& op = tokens.front();
    if (op == "LT")         { m_op = OP_LT; }
    else if (op == "LE")    { m_op = OP_LE; }
    else if (op == "EQ")    { m_op = OP_EQ; }
    else if (op == "GE")    { m_op = OP_GE; }
    else if (op == "GT")    { m_op = OP_GT; }
    else {
        throw ConfigurationException("First component of time-based rule must be one of LT, LE, EQ, GE, GT.");
    }

    if (name == TIME_PROP_PATH) {
        m_type = g_timeRules[name];
        if ((m_value = parseISODateTime(tokens.back())) < 0) {
            throw ConfigurationException("Error parsing timestamp in Time rule.");
        }
        return;
    }

    const auto i = g_timeRules.find(name);
    if (i != g_timeRules.end()) {
        m_type = i->second;
        m_value = boost::lexical_cast<time_t>(tokens.back());
    }
    else {
        throw ConfigurationException("Unrecognized time-based rule.");
    }
}

AccessControl::aclresult_t TimeRule::authorized(const SPRequest& request, const Session* session) const
{
    time_t operand = 0;

    if (m_type == TM_AUTHN) {
        if (session) {
            // Locate the Attribute to be used for accessing the auth timestamp.
            const AttributeConfiguration& config = request.getAgent().getAttributeConfiguration(
                request.getRequestSettings().first->getString(RequestMapper::ATTRIBUTE_CONFIG_ID_PROP_NAME));
            const auto attr = session->getAttributes().find(
                config.getString(AttributeConfiguration::LEGACY_AUTHTIME_ATTRIBUTE_PROP_NAME,
                    AttributeConfiguration::LEGACY_AUTHTIME_ATTRIBUTE_PROP_DEFAULT));
            if (attr == session->getAttributes().end()) {
                request.debug("Attribute carrying authentication time unnvailable");
                return shib_acl_false;
            }

            DDF val = const_cast<DDF&>(attr->second).first();
            if (val.isstring()) {
                const char* authtime = const_cast<DDF&>(attr->second).first().string();
                if (authtime) {
                    if ((operand = parseISODateTime(authtime)) < 0) {
                       request.error("Error parsing authentication time from designated Attribute.");
                       return shib_acl_false;
                    }
                }
            }
            else if (val.islong()) {
                operand = val.longinteger();
            }
            
            if (operand > 0) {
                if (time(nullptr) - operand <= m_value) {
                    return shib_acl_true;
                }

                request.debug("elapsed time since authentication exceeds limit");
                return shib_acl_false;
            }
            else {
                request.debug("Attribute carrying authentication time unnvailable");
                return shib_acl_false;
            }
        }
        else {
            request.debug("session unnvailable");
            return shib_acl_false;
        }
    }

    // Extract value from tm struct or time directly.
    operand = time(nullptr);
    if (m_type != TM_TIME) {
#ifndef HAVE_LOCALTIME_R
        struct tm* ptime = localtime(&operand);
#else
        struct tm res;
        struct tm* ptime = localtime_r(&operand, &res);
#endif
        switch (m_type) {
            case TM_YEAR:
                operand = ptime->tm_year + 1900;
                break;
            case TM_MONTH:
                operand = ptime->tm_mon + 1;
                break;
            case TM_DAY:
                operand = ptime->tm_mday;
                break;
            case TM_HOUR:
                operand = ptime->tm_hour;
                break;
            case TM_MINUTE:
                operand = ptime->tm_min;
                break;
            case TM_SECOND:
                operand = ptime->tm_sec;
                break;
            case TM_WDAY:
                operand = ptime->tm_wday;
                break;
        }
    }

    // Compare operand to test value in rule using rule operator.
    switch (m_op) {
        case OP_LT:
            return (operand < m_value) ? shib_acl_true : shib_acl_false;
        case OP_LE:
            return (operand <= m_value) ? shib_acl_true : shib_acl_false;
        case OP_EQ:
            return (operand == m_value) ? shib_acl_true : shib_acl_false;
        case OP_GE:
            return (operand >= m_value) ? shib_acl_true : shib_acl_false;
        case OP_GT:
            return (operand > m_value) ? shib_acl_true : shib_acl_false;
    }
    return shib_acl_false;
}

Operator::Operator(const string& name, const ptree& pt)
{
    if (name == "NOT") {
        m_op = OP_NOT;
    }
    else if (name == "AND") {
        m_op = OP_AND;
    }
    else if (name == "OR") {
        m_op = OP_OR;
    }
    else {
        throw ConfigurationException(string("Unrecognized access control operator: ") + name);
    }

    for (const auto& child : pt) {
        if (child.first == RULE_PROP_PATH) {
            m_operands.push_back(unique_ptr<AccessControl>(new Rule(child.second)));
        }
        else if (child.first == RULE_REGEX_PROP_PATH) {
            m_operands.push_back(unique_ptr<AccessControl>(new RuleRegex(child.second)));
        }
        else if (child.first == AND_PROP_PATH || child.first == OR_PROP_PATH || child.first == NOT_PROP_PATH) {
            m_operands.push_back(unique_ptr<AccessControl>(new Operator(child.first, child.second)));
        }
        else if (g_timeRules.find(child.first) != g_timeRules.end()) {
            m_operands.push_back(unique_ptr<AccessControl>(new TimeRule(child.first, child.second)));
        }
        else if (child.first == "<xmlattr>") {
            continue;
        }
        else {
            throw ConfigurationException("Unrecognized child element in policy.");
        }
    }

    if (m_op == OP_NOT && m_operands.size() != 1) {
        throw ConfigurationException("NOT operator contained more than one child");
    }
}

AccessControl::aclresult_t Operator::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_NOT:
            switch (m_operands.front()->authorized(request,session)) {
                case shib_acl_true:
                    return shib_acl_false;
                case shib_acl_false:
                    return shib_acl_true;
                default:
                    return shib_acl_indeterminate;
            }

        case OP_AND:
        {
            // Look for a rule that returns non-true.
            for (const auto& i : m_operands) {
                if (i->authorized(request,session) != shib_acl_true)
                    return shib_acl_false;
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            // Look for a rule that returns true.
            for (const auto& i : m_operands) {
                if (i->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            return shib_acl_false;
        }
    }
    request.warn("unknown operation in access control policy, denying access");
    return shib_acl_false;
}

unique_ptr<AccessControl> XMLAccessControl::processChild(const string& name, const ptree& pt)
{
    if (name == RULE_PROP_PATH) {
        return unique_ptr<AccessControl>(new Rule(pt));
    }
    else if (name == RULE_REGEX_PROP_PATH) {
        return unique_ptr<AccessControl>(new RuleRegex(pt));
    }
    else if (name == AND_PROP_PATH || name == OR_PROP_PATH || name == NOT_PROP_PATH) {
        return unique_ptr<AccessControl>(new Operator(name, pt));
    }
    else if (g_timeRules.find(name) != g_timeRules.end()) {
        return unique_ptr<AccessControl>(new TimeRule(name, pt));
    }
    throw ConfigurationException("Unrecognized child element in policy.");
}

pair<bool,ptree*> XMLAccessControl::load() noexcept
{
    // Load from source using base class.
    pair<bool,ptree*> raw = ReloadableXMLFile::load();
    if (!raw.second) {
        return raw;
    }

    try {
        // If we own it, wrap it, but we don't retain use of it.
        unique_ptr<ptree> treejanitor(raw.first ? raw.second : nullptr);

        unique_ptr<AccessControl> authz;

        // We have to skip the <xmlattr> node if it appears.
        // In the inline case, there should be a child element named
        // AccessControl so we need to step down one level (and again
        // skip the <xmlattr> node.

        for (const auto& child : *raw.second) {
            if (child.first == "<xmlattr>") {
                continue;
            }
            else if (child.first == ACCESS_CONTROL_PROP_PATH) {
                for (const auto& child2 : child.second) {
                    if (child2.first == "<xmlattr>") {
                        continue;
                    }
                    else {
                        authz = processChild(child2.first, child2.second);
                    }
                }
            }
            else {
                authz = processChild(child.first, child.second);
            }
        }

        // Perform the swap inside a lock.
        unique_lock<ReloadableXMLFile> locker(*this);
        m_rootAuthz.swap(authz);
        updateModificationTime();
        return make_pair(false, raw.second);
    }
    catch (const exception& e) {
        m_log.error("exception processing AccessControl configuration: %s", e.what());
    }

    return make_pair(false, nullptr);
}

AccessControl::aclresult_t XMLAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    return m_rootAuthz ? m_rootAuthz->authorized(request,session) : shib_acl_false;
}
