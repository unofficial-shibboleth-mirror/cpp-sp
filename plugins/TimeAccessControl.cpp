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
 * TimeAccessControl.cpp
 *
 * Access control plugin for time-based policies.
 */

#include "internal.h"

#include <shibsp/exceptions.h>
#include <shibsp/AccessControl.h>
#include <shibsp/SessionCache.h>
#include <shibsp/SPRequest.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xmltooling/unicode.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

namespace shibsp {

    class Rule : public AccessControl
    {
    public:
        Rule(const DOMElement* e);
        ~Rule() {}

        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum { TM_AUTHN, TM_TIME, TM_YEAR, TM_MONTH, TM_DAY, TM_HOUR, TM_MINUTE, TM_SECOND, TM_WDAY } m_type;
        enum { OP_LT, OP_LE, OP_EQ, OP_GE, OP_GT } m_op;
        time_t m_value;
    };

    class TimeAccessControl : public AccessControl
    {
    public:
        TimeAccessControl(const DOMElement* e);
        ~TimeAccessControl() {}

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum { OP_AND, OP_OR } m_op;
        ptr_vector<Rule> m_rules;
    };

    AccessControl* SHIBSP_DLLLOCAL TimeAccessControlFactory(const DOMElement* const & e)
    {
        return new TimeAccessControl(e);
    }

    static const XMLCh _operator[] =        UNICODE_LITERAL_8(o,p,e,r,a,t,o,r);
    static const XMLCh AND[] =              UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =               UNICODE_LITERAL_2(O,R);
    static const XMLCh Day[] =              UNICODE_LITERAL_3(D,a,y);
    static const XMLCh DayOfWeek[] =        UNICODE_LITERAL_9(D,a,y,O,f,W,e,e,k);
    static const XMLCh Hour[] =             UNICODE_LITERAL_4(H,o,u,r);
    static const XMLCh Minute[] =           UNICODE_LITERAL_6(M,i,n,u,t,e);
    static const XMLCh Month[] =            UNICODE_LITERAL_5(M,o,n,t,h);
    static const XMLCh Second[] =           UNICODE_LITERAL_6(S,e,c,o,n,d);
    static const XMLCh Time[] =             UNICODE_LITERAL_4(T,i,m,e);
    static const XMLCh TimeSinceAuthn[] =   UNICODE_LITERAL_14(T,i,m,e,S,i,n,c,e,A,u,t,h,n);
    static const XMLCh Year[] =             UNICODE_LITERAL_4(Y,e,a,r);
}

Rule::Rule(const DOMElement* e)
{
    if (XMLString::equals(e->getLocalName(), TimeSinceAuthn)) {
        m_type = TM_AUTHN;
        DateTime dur(e->getTextContent());
        dur.parseDuration();
        m_value = dur.getEpoch(true);
        return;
    }
    
    auto_ptr_char temp(e->getTextContent());
    string s(temp.get() ? temp.get() : "");
    vector<string> tokens;
    if (split(tokens, s, is_space(), algorithm::token_compress_on).size() != 2)
        throw ConfigurationException("Time-based rule requires element content of the form \"LT|LE|EQ|GE|GT value\".");
    string& op = tokens.front();
    if (op == "LT")         m_op = OP_LT;
    else if (op == "LE")    m_op = OP_LE;
    else if (op == "EQ")    m_op = OP_EQ;
    else if (op == "GE")    m_op = OP_GE;
    else if (op == "GT")    m_op = OP_GT;
    else
        throw ConfigurationException("First component of time-based rule must be one of LT, LE, EQ, GE, GT.");

    if (XMLString::equals(e->getLocalName(), Time)) {
        m_type = TM_TIME;
        auto_ptr_XMLCh widen(tokens.back().c_str());
        DateTime dt(widen.get());
        dt.parseDateTime();
        m_value = dt.getEpoch();
        return;
    }

    m_value = lexical_cast<time_t>(tokens.back());

    if (XMLString::equals(e->getLocalName(), Year))             m_type = TM_YEAR;
    else if (XMLString::equals(e->getLocalName(), Month))       m_type = TM_MONTH;
    else if (XMLString::equals(e->getLocalName(), Day))         m_type = TM_DAY;
    else if (XMLString::equals(e->getLocalName(), Hour))        m_type = TM_HOUR;
    else if (XMLString::equals(e->getLocalName(), Minute))      m_type = TM_MINUTE;
    else if (XMLString::equals(e->getLocalName(), Second))      m_type = TM_SECOND;
    else if (XMLString::equals(e->getLocalName(), DayOfWeek))   m_type = TM_WDAY;
    else
        throw ConfigurationException("Unrecognized time-based rule.");
}

/*
<AccessControlProvider type="Time" operator="AND|OR">
    <TimeSinceAuthn>PT1H</TimeSinceAuthn>
    <Time> LT|LE|EQ|GE|GT ISO </Time>
    <Year> LT|LE|EQ|GE|GT nn </Year>
    <Month> LT|LE|EQ|GE|GT nn </Month>
    <Day> LT|LE|EQ|GE|GT nn </Day>
    <Hour> LT|LE|EQ|GE|GT nn </Hour>
    <Minute> LT|LE|EQ|GE|GT nn </Minute>
    <Second> LT|LE|EQ|GE|GT nn </Second>
    <DayOfWeek> LT|LE|EQ|GE|GT 0-6 </DayOfWeek>
</AccessControlProvider>
*/

AccessControl::aclresult_t Rule::authorized(const SPRequest& request, const Session* session) const
{
    time_t operand = 0;

    if (m_type == TM_AUTHN) {
        if (session) {
            auto_ptr_XMLCh atime(session->getAuthnInstant());
            if (atime.get()) {
                try {
                    DateTime dt(atime.get());
                    dt.parseDateTime();
                    if (time(nullptr) - dt.getEpoch() <= m_value)
                        return shib_acl_true;
                    request.log(SPRequest::SPDebug, "elapsed time since authentication exceeds limit");
                    return shib_acl_false;
                }
                catch (std::exception& e) {
                    request.log(SPRequest::SPError, e.what());
                }
            }
        }
        request.log(SPRequest::SPDebug, "session or authentication time unavailable");
        return shib_acl_false;
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

TimeAccessControl::TimeAccessControl(const DOMElement* e) : m_op(OP_AND)
{
    const XMLCh* op = e ? e->getAttributeNS(nullptr, _operator) : nullptr;
    if (XMLString::equals(op, OR))
        m_op = OP_OR;
    else if (op && *op && !XMLString::equals(op, AND))
        throw ConfigurationException("Unrecognized operator in Time AccessControl configuration.");

    e = XMLHelper::getFirstChildElement(e);
    while (e) {
        auto_ptr<Rule> np(new Rule(e));
        m_rules.push_back(np.get());
        np.release();
        e = XMLHelper::getNextSiblingElement(e);
    }
    if (m_rules.empty())
        throw ConfigurationException("Time AccessControl plugin requires at least one rule.");
}

AccessControl::aclresult_t TimeAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_AND:
        {
            for (ptr_vector<Rule>::const_iterator i = m_rules.begin(); i != m_rules.end(); ++i) {
                if (i->authorized(request, session) != shib_acl_true) {
                    request.log(SPRequest::SPDebug, "time-based rule unsuccessful, denying access");
                    return shib_acl_false;
                }
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            for (ptr_vector<Rule>::const_iterator i = m_rules.begin(); i != m_rules.end(); ++i) {
                if (i->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            request.log(SPRequest::SPDebug, "all time-based rules unsuccessful, denying access");
            return shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn, "unknown operator in access control policy, denying access");
    return shib_acl_false;
}
