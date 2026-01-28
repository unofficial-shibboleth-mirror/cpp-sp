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
 * remoting/impl/RemotingService.cpp
 *
 * Remoting service for agent/hub communication.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "SPRequest.h"
#include "RequestMapper.h"
#include "remoting/RemotingService.h"
#include "remoting/SecretSource.h"
#include "util/PropertySet.h"

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
#ifdef WIN32
    extern RemotingService* SHIBSP_DLLLOCAL WinHTTPRemotingServiceFactory(ptree& pt, bool deprecationSupport);
#else
    extern RemotingService* SHIBSP_DLLLOCAL CurlHTTPRemotingServiceFactory(ptree& pt, bool deprecationSupport);
#endif
};

void SHIBSP_API shibsp::registerRemotingServices()
{
#ifdef WIN32
    AgentConfig::getConfig().RemotingServiceManager.registerFactory(WIN_HTTP_REMOTING_SERVICE, WinHTTPRemotingServiceFactory);
#else
    AgentConfig::getConfig().RemotingServiceManager.registerFactory(CURL_HTTP_REMOTING_SERVICE, CurlHTTPRemotingServiceFactory);
#endif
}

RemotingService::RemotingService() {}

RemotingService::~RemotingService() {}

DDF RemotingService::build(const char* opname, const SPRequest& request) const
{
    // Extracts call metadata from request.
    return build(
        opname,
        request.getRequestSettings().first->getString(
            RequestMapper::APPLICATION_ID_PROP_NAME, RequestMapper::APPLICATION_ID_PROP_DEFAULT),
        request.getRequestID());
}
