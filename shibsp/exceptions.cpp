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
#include "AgentConfig.h"
#include "exceptions.h"
#include "io/HTTPResponse.h"
#include "util/URLEncoder.h"

using namespace shibsp;
using namespace std;

agent_exception::agent_exception(const char* msg) : m_status(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR)
{
    if (msg)
        m_msg = msg;
}

agent_exception::agent_exception(const string& msg) : m_status(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), m_msg(msg)
{
}

agent_exception::~agent_exception() noexcept
{
}

const char* agent_exception::what() const noexcept
{
    return m_msg.c_str();
}

int agent_exception::getStatusCode() const noexcept
{
    return m_status;
}

void agent_exception::setStatusCode(int code) noexcept
{
    m_status = code;
}

const unordered_map<string,string>& agent_exception::getProperties() const noexcept
{
    return m_props;
}

void agent_exception::addProperties(const unordered_map<string,string>& props)
{
    for (const auto& p : props) {
        m_props.insert(p);
    }
}

void agent_exception::addProperty(const char* name, const char* value)
{
    if (name && value) {
        m_props[name] = value;
    }
}

string agent_exception::toQueryString() const
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
