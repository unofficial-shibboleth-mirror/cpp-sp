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
 * exceptions.cpp
 * 
 * Exception classes.
 */
 
#include "internal.h"
#include "exceptions.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "io/HTTPResponse.h"
#include "logging/Priority.h"
#include "util/URLEncoder.h"

#include <sstream>

using namespace shibsp;
using namespace std;

const char AgentException::HANDLER_TYPE_PROP_NAME[] = "handlerType";
const char AgentException::EVENT_PROP_NAME[] = "event";
const char AgentException::TARGET_PROP_NAME[] = "target";

AgentException::AgentException(const char* msg) : m_status(0)
{
    if (msg)
        m_msg = msg;
}

AgentException::AgentException(const string& msg) : m_status(0), m_msg(msg)
{
}

AgentException::~AgentException() noexcept
{
}

const char* AgentException::what() const noexcept
{
    return m_msg.c_str();
}

long AgentException::getStatusCode() const noexcept
{
    return m_status;
}

void AgentException::setStatusCode(long code) noexcept
{
    m_status = code;
}

const char* AgentException::getProperty(const char* name) const noexcept
{
    const auto& prop = m_props.find(name);
    return prop != m_props.end() ? prop->second.c_str() : nullptr;
}

const unordered_map<string,string>& AgentException::getProperties() const noexcept
{
    return m_props;
}

void AgentException::addProperties(const unordered_map<string,string>& props)
{
    for (const auto& p : props) {
        m_props.insert(p);
    }
}

void AgentException::addProperty(const char* name, const char* value)
{
    if (name && value) {
        m_props[name] = value;
    }
}

string AgentException::toQueryString() const
{
    string q;
    const URLEncoder& enc = AgentConfig::getConfig().getURLEncoder();
    for (const auto& p : m_props) {
        if (!q.empty())
            q += '&';
        q = q + p.first + '=' + enc.encode(p.second.c_str());
    }
    return q;
}

void AgentException::log(const SPRequest& request, Priority::Value priority) const
{
    request.log(priority, *this);
}
