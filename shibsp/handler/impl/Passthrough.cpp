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
 * handler/impl/Passthrough.cpp
 *
 * Handler for unmolested tunnelling of Hub flows.
 * 
 * <p>Allows Hub to implement the entire process of handling a request.</p>
 */

#include "internal.h"
#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "logging/Category.h"
#include "remoting/RemotingService.h"
#include "util/Misc.h"

#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL Passthrough : public virtual AbstractHandler {
    public:
        Passthrough(const ptree& pt, const char* path);
        virtual ~Passthrough() {}

        pair<bool,long> run(SPRequest& request, bool isHandler) const;

    private:
        string m_operation;
        set<string> m_remotedHeaders;
        bool m_body;
        bool m_limitRedirects;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL PassthroughFactory(const pair<ptree&,const char*>& p, bool) {
        return new Passthrough(p.first, p.second);
    }
};

Passthrough::Passthrough(const ptree& pt, const char* path)
    : AbstractHandler(pt), m_body(false), m_limitRedirects(true)
{
    static const char OPERATION_PROP_NAME[] = "operation";
    static const char REMOTED_HEADERS_PROP_NAME[] = "remotedHeaders";
    static const char SEND_BODY_PROP_NAME[] = "sendBody";
    static const char LIMIT_REDIRECTS_PROP_NAME[] = "limitRedirects";

    static const char OPERATION_PROP_DEFAULT[] = "";
    static bool SEND_BODY_PROP_DEFAULT = false;
    static bool LIMIT_REDIRECTS_PROP_DEFAULT = true;

    m_operation = getString(OPERATION_PROP_NAME, OPERATION_PROP_DEFAULT);
    if (m_operation.empty()) {
        throw ConfigurationException("Passthrough handler missing required operation setting.");
    }

    const char* headers = getString(REMOTED_HEADERS_PROP_NAME);
    if (headers) {
        split_to_container(m_remotedHeaders, headers);
    }

    m_body = getBool(SEND_BODY_PROP_NAME, SEND_BODY_PROP_DEFAULT);
    m_limitRedirects = getBool(LIMIT_REDIRECTS_PROP_NAME, LIMIT_REDIRECTS_PROP_DEFAULT);
}

pair<bool,long> Passthrough::run(SPRequest& request, bool isHandler) const
{
    try {
        DDF input(m_operation.c_str());
        DDFJanitor inputJanitor(input);
        input.structure();
        input.addmember("application").string(
            request.getRequestSettings().first->getString(
                RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT));

        DDF wrapped = wrapRequest(request, m_remotedHeaders, m_body);
        input.add(wrapped);

        DDF output = request.getAgent().getRemotingService()->send(input);
        DDFJanitor outputJanitor(output);

        if (m_limitRedirects) {
            const char* url = output.getmember("http.redirect").string();
            if (url) {
                request.limitRedirect(url);
            }
        }

        return unwrapResponse(request, output);
    }
    catch (exception& ex) {
        AgentException* agent_ex = dynamic_cast<AgentException*>(&ex);
        if (agent_ex) {
            agent_ex->addProperty(AgentException::HANDLER_TYPE_PROP_NAME, PASSTHROUGH_HANDLER);
        }
        throw;
    }
}
