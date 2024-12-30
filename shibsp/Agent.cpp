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
 * Agent.cpp
 *
 * Base class implementation for a Shibboleth agent.
 */

#include "internal.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/SessionInitiator.h"
#include "util/Date.h"
#include "util/PathResolver.h"
#include "util/URLEncoder.h"

#include <fstream>
#include <sstream>
#ifdef HAVE_CXX14
# include <shared_mutex>
#endif
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

using namespace shibsp;
using namespace std;

Agent::Agent()
{
    m_authTypes.insert("shibboleth");
}

Agent::~Agent()
{
}

// TODO: we'll eventually copy/port in substantially similar versions of the old ServiceProvider
// method impls.

pair<bool,long> Agent::doAuthentication(AgentRequest& request, bool handler) const
{
}

pair<bool,long> Agent::doAuthorization(AgentRequest& request) const
{
}

pair<bool,long> Agent::doExport(AgentRequest& request, bool requireSession) const
{
}

pair<bool,long> Agent::doHandler(AgentRequest& request) const
{
}
