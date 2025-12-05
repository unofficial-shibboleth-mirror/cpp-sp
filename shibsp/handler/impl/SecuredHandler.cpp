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
 * handler/impl/SecuredHandler.cpp
 *
 * Pluggable runtime functionality that is protected by simple access control.
 */

#include "internal.h"
#include "SPRequest.h"
#include "handler/SecuredHandler.h"
#include "logging/Category.h"
#include "util/Misc.h"

#include <sstream>
#include <algorithm>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

SecuredHandler::SecuredHandler(const ptree& pt, const char* aclProperty, const char* defaultACL)
    : AbstractHandler(pt)
{
    const char* acl = getString(aclProperty, defaultACL);
    if (acl) {
        vector<string> aclarray;
        split_to_container(aclarray, acl);
        for_each(aclarray.begin(), aclarray.end(), [this](const string& s){parseACL(s);});

        if (m_acl.empty()) {
            Category::getInstance(SHIBSP_LOGCAT "Handler").warn("invalid CIDR range(s) in handler's acl property, allowing 127.0.0.1 and ::1 as a fall back");
            m_acl.push_back(IPRange::parseCIDRBlock("127.0.0.1"));
            m_acl.push_back(IPRange::parseCIDRBlock("::1"));
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
    catch (const exception& ex) {
        Category::getInstance(SHIBSP_LOGCAT "Handler").error("invalid CIDR block (%s): %s", + acl.c_str(), ex.what());
    }
}

pair<bool,long> SecuredHandler::run(SPRequest& request, bool isHandler) const
{
    if (!m_acl.empty()) {
        auto contains = [&request](const IPRange& range) {
            return range.contains(request.getRemoteAddr().c_str());
        };

        if (find_if(m_acl.begin(), m_acl.end(), contains) == m_acl.end()) {
            request.warn("handler request blocked from invalid address (%s)", request.getRemoteAddr().c_str());
            istringstream msg("Access Denied");
            return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_FORBIDDEN));
        }
    }
    return make_pair(false, 0L);
}
