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
 * ChainingAccessControl.cpp
 *
 * Access control plugin that combines other plugins.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "SessionCache.h"
#include "SPRequest.h"

#include <algorithm>
#include <boost/ptr_container/ptr_vector.hpp>
#include <xmltooling/unicode.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

    class ChainingAccessControl : public AccessControl
    {
    public:
        ChainingAccessControl(const DOMElement* e);

        ~ChainingAccessControl() {}

        Lockable* lock() {
            for_each(m_ac.begin(), m_ac.end(), mem_fun_ref<Lockable*,Lockable>(&Lockable::lock));
            return this;
        }
        void unlock() {
            for_each(m_ac.begin(), m_ac.end(), mem_fun_ref<void,Lockable>(&Lockable::unlock));
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum operator_t { OP_AND, OP_OR } m_op;
        ptr_vector<AccessControl> m_ac;
    };

    AccessControl* SHIBSP_DLLLOCAL ChainingAccessControlFactory(const DOMElement* const & e)
    {
        return new ChainingAccessControl(e);
    }

    static const XMLCh _AccessControl[] =   UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh _operator[] =        UNICODE_LITERAL_8(o,p,e,r,a,t,o,r);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh AND[] =              UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =               UNICODE_LITERAL_2(O,R);

    extern AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(const DOMElement* const & e);
}

void SHIBSP_API shibsp::registerAccessControls()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.AccessControlManager.registerFactory(CHAINING_ACCESS_CONTROL, ChainingAccessControlFactory);
    conf.AccessControlManager.registerFactory(XML_ACCESS_CONTROL, XMLAccessControlFactory);
    conf.AccessControlManager.registerFactory("edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl", XMLAccessControlFactory);
}

AccessControl::AccessControl()
{
}

AccessControl::~AccessControl()
{
}

ChainingAccessControl::ChainingAccessControl(const DOMElement* e) : m_op(OP_AND)
{
    const XMLCh* op = e ? e->getAttributeNS(nullptr, _operator) : nullptr;
    if (XMLString::equals(op, OR))
        m_op = OP_OR;
    else if (op && *op && !XMLString::equals(op, AND))
        throw ConfigurationException("Missing or unrecognized operator in Chaining AccessControl configuration.");

    e = XMLHelper::getFirstChildElement(e, _AccessControl);
    while (e) {
        string t(XMLHelper::getAttrString(e, nullptr, _type));
        if (!t.empty()) {
            Category::getInstance(SHIBSP_LOGCAT".AccessControl.Chaining").info("building AccessControl provider of type (%s)...", t.c_str());
            auto_ptr<AccessControl> np(SPConfig::getConfig().AccessControlManager.newPlugin(t.c_str(), e));
            m_ac.push_back(np.get());
            np.release();
        }
        e = XMLHelper::getNextSiblingElement(e, _AccessControl);
    }
    if (m_ac.empty())
        throw ConfigurationException("Chaining AccessControl plugin requires at least one child plugin.");
}

AccessControl::aclresult_t ChainingAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_AND:
        {
            for (ptr_vector<AccessControl>::const_iterator i = m_ac.begin(); i != m_ac.end(); ++i) {
                if (i->authorized(request, session) != shib_acl_true) {
                    request.log(SPRequest::SPDebug, "embedded AccessControl plugin unsuccessful, denying access");
                    return shib_acl_false;
                }
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            for (ptr_vector<AccessControl>::const_iterator i = m_ac.begin(); i != m_ac.end(); ++i) {
                if (i->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            request.log(SPRequest::SPDebug, "all embedded AccessControl plugins unsuccessful, denying access");
            return shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn, "unknown operation in access control policy, denying access");
    return shib_acl_false;
}
