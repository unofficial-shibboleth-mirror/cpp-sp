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
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "logging/Category.h"
#include "session/SessionCache.h"
#include "util/Lockable.h"
#include "util/Misc.h"
#include "util/ReloadableXMLFile.h"

#include <algorithm>
#include <memory>
#include <set>
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

    static const char ACCESS_CONTROL_PROP_PATH[] = "AccessControl";
    static const char REQUIRE_PROP_PATH[] = "<xmlattr>.require";
    static const char RULE_PROP_PATH[] = "Rule";
    static const char RULE_REGEX_PROP_PATH[] = "RuleRegex";

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

Rule::Rule(const ptree& pt) : m_alias(pt.get(REQUIRE_PROP_PATH, ""))
{
    if (m_alias.empty()) {
        throw ConfigurationException("Access control rule missing require attribute");
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
        request.log(Priority::SHIB_WARN, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.log(Priority::SHIB_DEBUG," AccessControl rule accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    if (m_alias == "user") {
        if (m_vals.find(request.getRemoteUser()) != m_vals.end()) {
            request.log(Priority::SHIB_DEBUG, string("AccessControl rule expecting REMOTE_USER (") + request.getRemoteUser() + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextClassRef") {
        actual_alias = request.getAgent().getString("legacy-classref-attribute", "Shib-AuthnContext-Class");
    }

    // Find the attribute(s) matching the require rule.
    pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> attrs =
        session->getIndexedAttributes().equal_range(actual_alias);
    if (attrs.first == attrs.second) {
        request.log(Priority::SHIB_WARN, string("AccessControl rule requires attribute (") + actual_alias + "), not found in session");
        return shib_acl_false;
    }
    else if (m_vals.empty()) {
        request.log(Priority::SHIB_DEBUG, string("AccessControl rule requires presence of attribute (") + actual_alias + "), authz granted");
        return shib_acl_true;
    }

    for (; attrs.first != attrs.second; ++attrs.first) {
        bool caseSensitive = attrs.first->second->isCaseSensitive();

        // Now we have to intersect the attribute's values against the rule's list.
        const vector<string>& vals = attrs.first->second->getSerializedValues();
        for (set<string>::const_iterator i = m_vals.begin(); i != m_vals.end(); ++i) {
            for (vector<string>::const_iterator j = vals.begin(); j != vals.end(); ++j) {
                if ((caseSensitive && *i == *j) || (!caseSensitive && !strcasecmp(i->c_str(),j->c_str()))) {
                    request.log(Priority::SHIB_DEBUG, string("AccessControl rule expecting (") + *j + "), authz granted");
                    return shib_acl_true;
                }
            }
        }
    }

    return shib_acl_false;
}

RuleRegex::RuleRegex(const ptree& pt)
    : m_alias(pt.get(REQUIRE_PROP_PATH, "")), m_exp(pt.get_value(""))
{
    if (m_alias.empty() || m_exp.empty())
        throw ConfigurationException("Access control rule missing require attribute or element content.");

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
        request.log(Priority::SHIB_WARN, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.log(Priority::SHIB_DEBUG,"AccessControl rule accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    if (m_alias == "user") {
        if (regexp::regex_match(request.getRemoteUser(), m_re, match_flags)) {
            request.log(Priority::SHIB_DEBUG, string("AccessControl rule expecting REMOTE_USER regex (") + m_exp + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextClassRef") {
        actual_alias = request.getAgent().getString("legacy-classref-attribute", "Shib-AuthnContext-Class");
    }

    // Find the attribute(s) matching the require rule.
    auto attrs = session->getIndexedAttributes().equal_range(actual_alias);
    if (attrs.first == attrs.second) {
        request.log(Priority::SHIB_WARN, string("AccessControl rule requires attribute (") + actual_alias + "), not found in session");
        return shib_acl_false;
    }

    for (; attrs.first != attrs.second; ++attrs.first) {
        // Now we have to intersect the attribute's values against the regular expression.
        for (const string& v : attrs.first->second->getSerializedValues()) {
            if (regexp::regex_match(v, m_re, match_flags)) {
                request.log(Priority::SHIB_DEBUG, string("AccessControl rule expecting regex (") + m_exp + "), authz granted");
                return shib_acl_true;
            }
        }
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
        else if (child.first != "<xmlattr>") {
            m_operands.push_back(unique_ptr<AccessControl>(new Operator(child.first, child.second)));
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
    request.log(Priority::SHIB_WARN,"unknown operation in access control policy, denying access");
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
    else {
        return unique_ptr<AccessControl>(new Operator(name, pt));
    }
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
