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
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "util/Lockable.h"
#include "util/Misc.h"
#include "util/ReloadableXMLFile.h"

#include <algorithm>
#include <memory>
#include <regex>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace boost::property_tree;
using namespace boost;
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
        regex m_re;
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
        XMLAccessControl(const ptree& pt)
            : ReloadableXMLFile(ACCESS_CONTROL_PROP_PATH, pt, Category::getInstance(SHIBSP_LOGCAT ".AccessControl.XML")) {
            load(); // guarantees an exception or the policy is loaded
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
    AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(const ptree& pt, bool deprecationSupport)
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

    trim(vals);
    split(m_vals, vals, boost::is_space(), algorithm::token_compress_on);
    if (m_vals.empty())
        throw ConfigurationException("Rule did not contain any usable values.");
}

AccessControl::aclresult_t Rule::authorized(const SPRequest& request, const Session* session) const
{
    // We can make this more complex later using pluggable comparison functions,
    // but for now, just a straight port to the new Attribute API.

    // Map alias in rule to the attribute.
    if (!session) {
        request.log(SPRequest::SPWarn, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.log(SPRequest::SPDebug,"AccessControl plugin accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    if (m_alias == "user") {
        if (m_vals.find(request.getRemoteUser()) != m_vals.end()) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting REMOTE_USER (") + request.getRemoteUser() + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextClassRef") {
        const char* ref = session->getAuthnContextClassRef();
        if (ref && m_vals.find(ref) != m_vals.end()) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextClassRef (") + ref + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextDeclRef") {
        const char* ref = session->getAuthnContextDeclRef();
        if (ref && m_vals.find(ref) != m_vals.end()) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextDeclRef (") + ref + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    // Find the attribute(s) matching the require rule.
    pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> attrs =
        session->getIndexedAttributes().equal_range(m_alias);
    if (attrs.first == attrs.second) {
        request.log(SPRequest::SPWarn, string("rule requires attribute (") + m_alias + "), not found in session");
        return shib_acl_false;
    }
    else if (m_vals.empty()) {
        request.log(SPRequest::SPDebug, string("AccessControl plugin requires presence of attribute (") + m_alias + "), authz granted");
        return shib_acl_true;
    }

    for (; attrs.first != attrs.second; ++attrs.first) {
        bool caseSensitive = attrs.first->second->isCaseSensitive();

        // Now we have to intersect the attribute's values against the rule's list.
        const vector<string>& vals = attrs.first->second->getSerializedValues();
        for (set<string>::const_iterator i = m_vals.begin(); i != m_vals.end(); ++i) {
            for (vector<string>::const_iterator j = vals.begin(); j != vals.end(); ++j) {
                if ((caseSensitive && *i == *j) || (!caseSensitive && !strcasecmp(i->c_str(),j->c_str()))) {
                    request.log(SPRequest::SPDebug, string("AccessControl plugin expecting (") + *j + "), authz granted");
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
        // TODO: more flag options, particular for dialect.
        regex::flag_type flags = regex_constants::optimize;
        if (!caseSensitive) {
            flags |= regex_constants::icase;
        }
        m_re = regex(m_exp, flags);
    }
    catch (const regex_error&) {
        throw ConfigurationException("Caught exception while parsing RuleRegex regular expression.");
    }
}

AccessControl::aclresult_t RuleRegex::authorized(const SPRequest& request, const Session* session) const
{
    // TODO: Have to confirm we want regex_match here vs. regex_search.
    // TODO: Have to consider match_flags as well, particularly against some open issues raised against the Xerces behavior.

    // Map alias in rule to the attribute.

    if (!session) {
        request.log(SPRequest::SPWarn, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }

    if (m_alias == "valid-user") {
        if (session) {
            request.log(SPRequest::SPDebug,"AccessControl plugin accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    if (m_alias == "user") {
        if (regex_match(request.getRemoteUser(), m_re)) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting REMOTE_USER (") + m_exp + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextClassRef") {
        if (session->getAuthnContextClassRef() && regex_match(session->getAuthnContextClassRef(), m_re)) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextClassRef (") + m_exp + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextDeclRef") {
        if (session->getAuthnContextDeclRef() && regex_match(session->getAuthnContextDeclRef(), m_re)) {
            request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextDeclRef (") + m_exp + "), authz granted");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    // Find the attribute(s) matching the require rule.
    auto attrs = session->getIndexedAttributes().equal_range(m_alias);
    if (attrs.first == attrs.second) {
        request.log(SPRequest::SPWarn, string("rule requires attribute (") + m_alias + "), not found in session");
        return shib_acl_false;
    }

    for (; attrs.first != attrs.second; ++attrs.first) {
        // Now we have to intersect the attribute's values against the regular expression.
        for (const string& v : attrs.first->second->getSerializedValues()) {
            if (regex_match(v, m_re)) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting (") + m_exp + "), authz granted");
                return shib_acl_true;
            }
        }
    }

    return shib_acl_false;
}

Operator::Operator(const string& name, const ptree& pt)
{
    if (name == "NOT")
        m_op=OP_NOT;
    else if (name == "AND")
        m_op=OP_AND;
    else if (name == "OR")
        m_op=OP_OR;
    else
        throw ConfigurationException("Unrecognized access control rule type");

    for (const auto& child : pt) {
        if (child.first == RULE_PROP_PATH) {
            m_operands.push_back(unique_ptr<AccessControl>(new Rule(child.second)));
        }
        else if (child.first == RULE_REGEX_PROP_PATH) {
            m_operands.push_back(unique_ptr<AccessControl>(new RuleRegex(child.second)));
        }
        else {
            m_operands.push_back(unique_ptr<AccessControl>(new Operator(child.first, child.second)));
        }
    }

    if (m_op == OP_NOT && m_operands.size() != 1) {
        throw new ConfigurationException("NOT operator contained more than one child");
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
                if (i->authorized(request,session) != shib_acl_true)
                    return shib_acl_false;
            }
            return shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn,"unknown operation in access control policy, denying access");
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
    else if (name != "<xmlattr>") {
        return unique_ptr<AccessControl>(new Operator(name, pt));
    }
    else {
        return nullptr;
    }
}

pair<bool,ptree*> XMLAccessControl::load() noexcept
{
    // Load from source using base class.
    pair<bool,ptree*> raw = ReloadableXMLFile::load();
    if (!raw.second) {
        return raw;
    }

    // If we own it, wrap it, but we don't retain use of it.
    unique_ptr<ptree> treejanitor(raw.first ? raw.second : nullptr);

    // This is tentative and almost certainly wrong due to the way the XML
    // worked in the original config.

    // In the inline case, there should be a child element named
    // AccessControl so we need to step down one level.
    unique_ptr<AccessControl> authz;
    const auto& child = raw.second->front();
    if (child.first == ACCESS_CONTROL_PROP_PATH) {
        const auto& child2 = child.second.front();
        authz = processChild(child2.first, child2.second);
    } else {
        authz = processChild(child.first, child.second);
    }

    if (authz) {
    // Perform the swap inside a lock.
#ifdef HAVE_CXX14
        unique_lock<ReloadableXMLFile> locker(*this);
#endif
        m_rootAuthz.swap(authz);
    }

    return make_pair(false, nullptr);
}

AccessControl::aclresult_t XMLAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    return m_rootAuthz ? m_rootAuthz->authorized(request,session) : shib_acl_false;
}
