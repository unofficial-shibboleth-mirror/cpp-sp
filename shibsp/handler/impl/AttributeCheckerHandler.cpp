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
 * handler/impl/AttributeCheckerHandler.cpp
 *
 * Handler for checking a session for required attributes.
 */

#include "internal.h"
#include "AccessControl.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/AbstractHandler.h"
#include "logging/Category.h"
#include "session/SessionCache.h"

#include <memory>
#include <mutex>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    class SHIBSP_API AttributeCheckerHandler : public AbstractHandler
    {
    public:
        AttributeCheckerHandler(ptree& pt);
        virtual ~AttributeCheckerHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        void flushSession(SPRequest& request, time_t exp) const {
            try {
                request.getAgent().getSessionCache()->remove(request, exp);
            }
            catch (const std::exception&) {
            }
        }

        string m_redirectOnFailure;
        bool m_flushSession;
        vector<string> m_attributes;
        unique_ptr<AccessControl> m_acl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AttributeCheckerFactory(const pair<ptree&,const char*>& p, bool deprecationSupport)
    {
        return new AttributeCheckerHandler(p.first);
    }
};

AttributeCheckerHandler::AttributeCheckerHandler(ptree& pt)
    : AbstractHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".Handler.AttributeChecker"))
{
    m_redirectOnFailure = getString("redirectOnFailure", "");
    if (m_redirectOnFailure.empty())
        throw ConfigurationException("AttributeChecker missing required redirectOnFailure setting.");

    m_flushSession = getBool("flushSession", false);

    string attrs(getString("attributes", ""));
    if (!attrs.empty()) {
        boost::trim(attrs);
        boost::split(m_attributes, attrs, boost::is_space(), boost::algorithm::token_compress_on);
        if (m_attributes.empty())
            throw ConfigurationException("AttributeChecker unable to parse attributes setting.");
    }
    else if (hasProperty("path")) {
        m_log.debug("attempting installation of external AccessControl rule");
        m_acl.reset(AgentConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL, pt, false));
    }
    else {
        throw ConfigurationException("AttributeChecker requires either the attributes setting or path to ACL");
    }
}

pair<bool,long> AttributeCheckerHandler::run(SPRequest& request, bool isHandler) const
{
    // If the checking passes, we route to the return URL, target URL, or homeURL in that order.
    const char* returnURL = request.getParameter("return");
    const char* target = request.getParameter("target");
    if (!returnURL) {
        returnURL = target;
    }
    if (returnURL) {
        request.limitRedirect(returnURL);
    }
    else {
        returnURL = request.getRequestSettings().first->getString("homeURL", "/");
    }
       
    Session* session = nullptr;
    try {
        session = request.getSession(true, false, false);
        if (!session)
            request.log(Priority::SHIB_WARN, "AttributeChecker found session unavailable immediately after creation");
    }
    catch (const std::exception& ex) {
        request.log(Priority::SHIB_WARN, string("AttributeChecker caught exception accessing session immediately after creation: ") + ex.what());
    }

    unique_lock<Session> sessionLocker(*session, adopt_lock);

    bool checked = false;
    if (session) {
        if (!m_attributes.empty()) {
            const auto& indexed = session->getIndexedAttributes();
            // Lambda returns true if the candidate attribute ID is NOT in the session.
            auto absent = [&indexed](const string& id) {
                return indexed.find(id) == indexed.end();
            };

            // Look for an attribute in the list that is not in the session multimap.
            // If that fails, the check succeeds.
            checked = find_if(m_attributes.begin(), m_attributes.end(), absent) == m_attributes.end();
        }
        else {
            checked = (m_acl && m_acl->authorized(request, session) == AccessControl::shib_acl_true);
        }
    }

    if (checked) {
        string loc(returnURL);
        request.absolutize(loc);
        return make_pair(true, request.sendRedirect(loc.c_str()));
    }

    if (m_flushSession && session) {
        time_t revocationExp = session->getExpiration();
        sessionLocker.unlock(); // unlock the session
        flushSession(request, revocationExp);
    }

    return make_pair(true, request.sendRedirect(m_redirectOnFailure.c_str()));
}
