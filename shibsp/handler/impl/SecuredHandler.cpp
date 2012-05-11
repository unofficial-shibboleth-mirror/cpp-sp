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
 * SecuredHandler.cpp
 *
 * Pluggable runtime functionality that is protected by simple access control.
 */

#include "internal.h"
#include "SPRequest.h"
#include "handler/SecuredHandler.h"

#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL Blocker : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static Blocker g_Blocker;
};

SecuredHandler::SecuredHandler(
    const DOMElement* e,
    Category& log,
    const char* aclProperty,
    const char* defaultACL,
    DOMNodeFilter* filter,
    const map<string,string>* remapper
    ) : AbstractHandler(e, log, filter ? filter : &g_Blocker, remapper)
{
    if (SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        pair<bool,const char*> acl = getString(aclProperty);
        if (!acl.first && defaultACL) {
            m_log.info("installing default ACL (%s)", defaultACL);
            acl.first = true;
            acl.second = defaultACL;
        }
        if (acl.first) {
            string aclbuf(acl.second);
            vector<string> aclarray;
            split(aclarray, aclbuf, is_space(), algorithm::token_compress_on);
            for_each(aclarray.begin(), aclarray.end(), boost::bind(&SecuredHandler::parseACL, this, _1));
            if (m_acl.empty()) {
                m_log.warn("invalid CIDR range(s) in handler's acl property, allowing 127.0.0.1 and ::1 as a fall back");
                m_acl.push_back(IPRange::parseCIDRBlock("127.0.0.1"));
                m_acl.push_back(IPRange::parseCIDRBlock("::1"));
            }
        }
    }
}

SecuredHandler::~SecuredHandler()
{
}

void SecuredHandler::parseACL(const string& acl)
{
    try {
        m_acl.push_back(IPRange::parseCIDRBlock(acl.c_str()));
    }
    catch (std::exception& ex) {
        m_log.error("invalid CIDR block (%s): %s", acl.c_str(), ex.what());
    }
}

pair<bool,long> SecuredHandler::run(SPRequest& request, bool isHandler) const
{
    SPConfig& conf = SPConfig::getConfig();
    if (conf.isEnabled(SPConfig::InProcess) && !m_acl.empty()) {
        static bool (IPRange::* contains)(const char*) const = &IPRange::contains;
        if (find_if(m_acl.begin(), m_acl.end(), boost::bind(contains, _1, request.getRemoteAddr().c_str())) == m_acl.end()) {
            request.log(SPRequest::SPWarn, string("handler request blocked from invalid address (") + request.getRemoteAddr() + ')');
            istringstream msg("Access Denied");
            return make_pair(true, request.sendResponse(msg, HTTPResponse::XMLTOOLING_HTTP_STATUS_FORBIDDEN));
        }
    }
    return make_pair(false, 0L);
}
