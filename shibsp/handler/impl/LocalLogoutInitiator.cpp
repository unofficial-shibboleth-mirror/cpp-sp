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
 * handler/impl/LocalLogoutInitiator.cpp
 * 
 * Logs out a session locally.
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutInitiator.h"
#include "logging/Category.h"
#include "session/SessionCache.h"

#include <mutex>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL LocalLogoutInitiator : public AbstractHandler, public LogoutInitiator
    {
    public:
        LocalLogoutInitiator(const ptree& pt);
        virtual ~LocalLogoutInitiator() {}
        
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL LocalLogoutInitiatorFactory(const pair<ptree&,const char*>& p, bool)
    {
        return new LocalLogoutInitiator(p.first);
    }
};

LocalLogoutInitiator::LocalLogoutInitiator(const ptree& pt)
    : AbstractHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".LogoutInitiator.Local"))
{
}

pair<bool,long> LocalLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class first.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    // When out of process, we run natively.
    unique_lock<Session> session;
    try {
        session = request.getSession(false, true);  // don't cache it and ignore all checks
    }
    catch (const std::exception& ex) {
        m_log.error("error accessing current session: %s", ex.what());
    }

    if (session) {
        // Do back channel notification.
        bool result;
        vector<string> sessions(1, session.mutex()->getID());
        result = notifyBackChannel(request, sessions, true);
        session.unlock();
        request.getAgent().getSessionCache()->remove(request);
        if (!result) {
            //return sendLogoutPage(request, "partial");
        }
    }

    // Route back to return location specified, or use the local template.
    const char* dest = request.getParameter("return");
    if (dest) {
        // Relative URLs get promoted, absolutes get validated.
        if (*dest == '/') {
            string d(dest);
            request.absolutize(d);
            return make_pair(true, request.sendRedirect(d.c_str()));
        }
        request.limitRedirect(dest);
        return make_pair(true, request.sendRedirect(dest));
    }

    //return sendLogoutPage(application, httpRequest, httpResponse, "local");
    return pair(false, 0);
}
