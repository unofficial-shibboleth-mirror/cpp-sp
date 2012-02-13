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

#include <algorithm>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xmltooling/unicode.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace xmltooling;
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
        string m_alias;
        set <string> m_vals;
    };

    class RuleRegex : public AccessControl
    {
    public:
        RuleRegex(const DOMElement* e);
        ~RuleRegex() {}

        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        string m_alias;
        auto_arrayptr<char> m_exp;
        scoped_ptr<RegularExpression> m_re;
    };

    class Operator : public AccessControl
    {
    public:
        Operator(const DOMElement* e);
        ~Operator() {}

        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum operator_t { OP_NOT, OP_AND, OP_OR } m_op;
        ptr_vector<AccessControl> m_operands;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLAccessControl : public AccessControl, public ReloadableXMLFile
    {
    public:
        XMLAccessControl(const DOMElement* e)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AccessControl.XML")) {
            background_load(); // guarantees an exception or the policy is loaded
        }

        ~XMLAccessControl() {
            shutdown();
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        scoped_ptr<AccessControl> m_rootAuthz;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(const DOMElement* const & e)
    {
        return new XMLAccessControl(e);
    }

    static const XMLCh _AccessControl[] =   UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh _Handler[] =         UNICODE_LITERAL_7(H,a,n,d,l,e,r);
    static const XMLCh ignoreCase[] =       UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh ignoreOption[] =     UNICODE_LITERAL_1(i);
    static const XMLCh _list[] =            UNICODE_LITERAL_4(l,i,s,t);
    static const XMLCh require[] =          UNICODE_LITERAL_7(r,e,q,u,i,r,e);
    static const XMLCh NOT[] =              UNICODE_LITERAL_3(N,O,T);
    static const XMLCh AND[] =              UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =               UNICODE_LITERAL_2(O,R);
    static const XMLCh _Rule[] =            UNICODE_LITERAL_4(R,u,l,e);
    static const XMLCh _RuleRegex[] =       UNICODE_LITERAL_9(R,u,l,e,R,e,g,e,x);
}

Rule::Rule(const DOMElement* e) : m_alias(XMLHelper::getAttrString(e, nullptr, require))
{
    if (m_alias.empty())
        throw ConfigurationException("Access control rule missing require attribute");
    if (!e->hasChildNodes())
        return; // empty rule

    auto_arrayptr<char> vals(toUTF8(e->getTextContent()));
    if (!vals.get() || !*vals.get())
        throw ConfigurationException("Unable to convert Rule content into UTF-8.");

    bool listflag = XMLHelper::getAttrBool(e, true, _list);
    if (!listflag) {
        m_vals.insert(vals.get());
        return;
    }

    string temp(vals.get());
    split(m_vals, temp, boost::is_space(), algorithm::token_compress_on);
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

RuleRegex::RuleRegex(const DOMElement* e)
    : m_alias(XMLHelper::getAttrString(e, nullptr, require)),
        m_exp(toUTF8(e->hasChildNodes() ? e->getFirstChild()->getNodeValue() : nullptr))
{
    if (m_alias.empty() || !m_exp.get() || !*m_exp.get())
        throw ConfigurationException("Access control rule missing require attribute or element content.");

    bool ignore = XMLHelper::getAttrBool(e, false, ignoreCase);
    try {
        m_re.reset(new RegularExpression(e->getFirstChild()->getNodeValue(), (ignore ? ignoreOption : &chNull)));
    }
    catch (XMLException& ex) {
        auto_ptr_char tmp(ex.getMessage());
        throw ConfigurationException("Caught exception while parsing RuleRegex regular expression: $1", params(1,tmp.get()));
    }
}

AccessControl::aclresult_t RuleRegex::authorized(const SPRequest& request, const Session* session) const
{
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

    try {
        if (m_alias == "user") {
            if (m_re->matches(request.getRemoteUser().c_str())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting REMOTE_USER (") + m_exp.get() + "), authz granted");
                return shib_acl_true;
            }
            return shib_acl_false;
        }
        else if (m_alias == "authnContextClassRef") {
            if (session->getAuthnContextClassRef() && m_re->matches(session->getAuthnContextClassRef())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextClassRef (") + m_exp.get() + "), authz granted");
                return shib_acl_true;
            }
            return shib_acl_false;
        }
        else if (m_alias == "authnContextDeclRef") {
            if (session->getAuthnContextDeclRef() && m_re->matches(session->getAuthnContextDeclRef())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextDeclRef (") + m_exp.get() + "), authz granted");
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

        for (; attrs.first != attrs.second; ++attrs.first) {
            // Now we have to intersect the attribute's values against the regular expression.
            const vector<string>& vals = attrs.first->second->getSerializedValues();
            for (vector<string>::const_iterator j = vals.begin(); j != vals.end(); ++j) {
                if (m_re->matches(j->c_str())) {
                    request.log(SPRequest::SPDebug, string("AccessControl plugin expecting (") + m_exp.get() + "), authz granted");
                    return shib_acl_true;
                }
            }
        }
    }
    catch (XMLException& ex) {
        auto_ptr_char tmp(ex.getMessage());
        request.log(SPRequest::SPError, string("caught exception while parsing RuleRegex regular expression: ") + tmp.get());
    }

    return shib_acl_false;
}

Operator::Operator(const DOMElement* e)
{
    if (XMLString::equals(e->getLocalName(),NOT))
        m_op=OP_NOT;
    else if (XMLString::equals(e->getLocalName(),AND))
        m_op=OP_AND;
    else if (XMLString::equals(e->getLocalName(),OR))
        m_op=OP_OR;
    else
        throw ConfigurationException("Unrecognized operator in access control rule");

    e=XMLHelper::getFirstChildElement(e);
    if (XMLString::equals(e->getLocalName(),_Rule))
        m_operands.push_back(new Rule(e));
    else if (XMLString::equals(e->getLocalName(),_RuleRegex))
        m_operands.push_back(new RuleRegex(e));
    else
        m_operands.push_back(new Operator(e));

    if (m_op==OP_NOT)
        return;

    e=XMLHelper::getNextSiblingElement(e);
    while (e) {
        if (XMLString::equals(e->getLocalName(),_Rule))
            m_operands.push_back(new Rule(e));
        else if (XMLString::equals(e->getLocalName(),_RuleRegex))
            m_operands.push_back(new RuleRegex(e));
        else
            m_operands.push_back(new Operator(e));
        e=XMLHelper::getNextSiblingElement(e);
    }
}

AccessControl::aclresult_t Operator::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_NOT:
            switch (m_operands.front().authorized(request,session)) {
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
            for (ptr_vector<AccessControl>::const_iterator i = m_operands.begin(); i != m_operands.end(); ++i) {
                if (i->authorized(request,session) != shib_acl_true)
                    return shib_acl_false;
            }
            return shib_acl_true;

            ptr_vector<AccessControl>::const_iterator i = find_if(
                m_operands.begin(), m_operands.end(),
                boost::bind(&AccessControl::authorized, _1, boost::cref(request), session) != shib_acl_true
                );
            return (i != m_operands.end()) ? shib_acl_false : shib_acl_true;
        }

        case OP_OR:
        {
            // Look for a rule that returns true.
            ptr_vector<AccessControl>::const_iterator i = find_if(
                m_operands.begin(), m_operands.end(),
                boost::bind(&AccessControl::authorized, _1, boost::cref(request), session) == shib_acl_true
                );
            return (i != m_operands.end()) ? shib_acl_true : shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn,"unknown operation in access control policy, denying access");
    return shib_acl_false;
}

pair<bool,DOMElement*> XMLAccessControl::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    // Check for AccessControl wrapper and drop a level.
    if (XMLString::equals(raw.second->getLocalName(),_AccessControl)) {
        raw.second = XMLHelper::getFirstChildElement(raw.second);
        if (!raw.second)
            throw ConfigurationException("No child element found in AccessControl parent element.");
    }
    else if (XMLString::equals(raw.second->getLocalName(),_Handler)) {
        raw.second = XMLHelper::getFirstChildElement(raw.second);
        if (!raw.second)
            throw ConfigurationException("No child element found in Handler parent element.");
    }

    scoped_ptr<AccessControl> authz;
    if (XMLString::equals(raw.second->getLocalName(),_Rule))
        authz.reset(new Rule(raw.second));
    else if (XMLString::equals(raw.second->getLocalName(),_RuleRegex))
        authz.reset(new RuleRegex(raw.second));
    else
        authz.reset(new Operator(raw.second));

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_rootAuthz.swap(authz);

    return make_pair(false,(DOMElement*)nullptr);
}

AccessControl::aclresult_t XMLAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    return m_rootAuthz ? m_rootAuthz->authorized(request,session) : shib_acl_false;
}
