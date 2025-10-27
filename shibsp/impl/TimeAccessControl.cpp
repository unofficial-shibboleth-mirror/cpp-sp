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
 * TimeAccessControl.cpp
 *
 * Access control plugin for time-based policies.
 */

#include "internal.h"
#include "exceptions.h"

#include "AccessControl.h"
#include "Agent.h"
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
        Rule(const string& name, const ptree& pt);
        ~Rule() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum { TM_AUTHN, TM_TIME, TM_YEAR, TM_MONTH, TM_DAY, TM_HOUR, TM_MINUTE, TM_SECOND, TM_WDAY } m_type;
        enum { OP_LT, OP_LE, OP_EQ, OP_GE, OP_GT } m_op;
        time_t m_value;
    };

    class TimeAccessControl : public AccessControl, public NoOpSharedLockable
    {
    public:
        TimeAccessControl(const ptree& pt);
        ~TimeAccessControl() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum { OP_AND, OP_OR } m_op;
        vector<unique_ptr<Rule>> m_rules;
    };
}

namespace shibsp {
    AccessControl* SHIBSP_DLLLOCAL TimeAccessControlFactory(ptree& pt, bool deprecationSupport)
    {
        return new TimeAccessControl(pt);
    }
};

Rule::Rule(const string& name, const ptree& pt)
{
    static const char Day[] =               "Day";
    static const char DayOfWeek[] =         "DayOfWeek";
    static const char Hour[] =              "Hour";
    static const char Minute[] =            "Minute";
    static const char Month[] =             "Month";
    static const char Second[] =            "Second";
    static const char Time[] =              "Time";
    static const char TimeSinceAuthn[] =    "TimeSinceAuthn";
    static const char Year[] =              "Year";

    // The TimeSinceAuthn rule operates on a Duration inside the element body,
    // which should be the value of the tree.

    if (name == TimeSinceAuthn) {
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

    if (name == Time) {
        m_type = TM_TIME;
        if ((m_value = parseISODateTime(tokens.back())) < 0) {
            throw ConfigurationException("Error parsing timestamp in Time rule.");
        }
        return;
    }

    m_value = boost::lexical_cast<time_t>(tokens.back());
    if (name == Year)           { m_type = TM_YEAR; }
    else if (name == Month)     { m_type = TM_MONTH; }
    else if (name == Day)       { m_type = TM_DAY; }
    else if (name == Hour)      { m_type = TM_HOUR; }
    else if (name == Minute)    { m_type = TM_MINUTE; }
    else if (name == Second)    { m_type = TM_SECOND; }
    else if (name == DayOfWeek) { m_type = TM_WDAY; }
    else {
        throw ConfigurationException("Unrecognized time-based rule.");
    }
}

AccessControl::aclresult_t Rule::authorized(const SPRequest& request, const Session* session) const
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
                    if (operand = parseISODateTime(authtime) < 0) {
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

TimeAccessControl::TimeAccessControl(const ptree& pt) : m_op(OP_AND)
{
    static const char OPERATOR_PROP_PATH[] = "<xmlattr>.operator";
    static const char OR_OPERATOR_VALUE[] = "OR";
    static const char AND_OPERATOR_VALUE[] = "AND";

    string op = pt.get(OPERATOR_PROP_PATH, AND_OPERATOR_VALUE);
    if (op == AND_OPERATOR_VALUE) {
        m_op = OP_AND;
    }
    else if (op == OR_OPERATOR_VALUE) {
        m_op = OP_OR;
    }
    else {
        throw ConfigurationException("Unrecognized operator in Time AccessControl configuration.");
    }

    for (const auto& child : pt) {
        if (child.first != "<xmlattr>") {
            m_rules.push_back(unique_ptr<Rule>(new Rule(child.first, child.second)));
        }
    }

    if (m_rules.empty())
        throw ConfigurationException("Time AccessControl plugin requires at least one rule.");
}


AccessControl::aclresult_t TimeAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_AND:
        {
            for (auto& rule : m_rules) {
                if (rule->authorized(request, session) != shib_acl_true) {
                    request.debug("time-based rule unsuccessful, denying access");
                    return shib_acl_false;
                }
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            for (auto& rule : m_rules) {
                if (rule->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            request.debug("all time-based rules unsuccessful, denying access");
            return shib_acl_false;
        }
    }
    request.warn("unknown operator in access control policy, denying access");
    return shib_acl_false;
}
