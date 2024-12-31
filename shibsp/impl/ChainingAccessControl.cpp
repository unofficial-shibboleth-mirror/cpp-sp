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
 * impl/ChainingAccessControl.cpp
 *
 * Access control plugin that combines other plugins.
 */

#include "internal.h"
#include "exceptions.h"

#include "AccessControl.h"
#include "AgentConfig.h"
#include "SessionCache.h"
#include "SPRequest.h"

#include <algorithm>
#include <memory>
#include <vector>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {
    extern AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(ptree& pt, bool deprecationSupport);
}

AccessControl::AccessControl()
{
}

AccessControl::~AccessControl()
{
}


namespace {

    class ChainingAccessControl : public AccessControl
    {
    public:
        ChainingAccessControl(ptree& pt, bool deprecationSupport);

        ~ChainingAccessControl() {}

        void lock_shared() {
            for (auto& i : m_ac) {
                i->lock_shared();
            }
        }
        bool try_lock_shared() {
            // This shouldn't be needed, so just fail it.
            return false;
        }
        void unlock_shared() {
            for (auto& i : m_ac) {
                i->unlock_shared();
            }
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum operator_t { OP_AND, OP_OR } m_op;
        vector<unique_ptr<AccessControl>> m_ac;
    };

    AccessControl* SHIBSP_DLLLOCAL ChainingAccessControlFactory(ptree& pt, bool deprecationSupport)
    {
        return new ChainingAccessControl(pt, deprecationSupport);
    }
}

void SHIBSP_API shibsp::registerAccessControls()
{
    AgentConfig& conf=AgentConfig::getConfig();
    conf.AccessControlManager.registerFactory(CHAINING_ACCESS_CONTROL, ChainingAccessControlFactory);
    conf.AccessControlManager.registerFactory(XML_ACCESS_CONTROL, XMLAccessControlFactory);
}

ChainingAccessControl::ChainingAccessControl(ptree& pt, bool deprecationSupport) : m_op(OP_AND)
{
    static const char OPERATOR_PROP_PATH[] = "<xmlattr>.operator";
    static const char AND_OPERATOR[] = "AND";
    static const char OR_OPERATOR[] = "OR";
    const boost::optional<string> op = pt.get_optional<string>(OPERATOR_PROP_PATH);
    if (!op) {
        throw ConfigurationException("Missing operator in Chaining AccessControl configuration.");
    }
    else if (op.get() == OR_OPERATOR) {
        m_op = OP_OR;
    } else if (op.get() == AND_OPERATOR) {
        m_op = OP_AND;
    } else {
        throw ConfigurationException("Unsupported operator in Chaining AccessControl configuration.");
    }

    Category& log = Category::getInstance(SHIBSP_LOGCAT ".AccessControl.Chaining");

    static const char ACCESS_CONTROL_PROP_PATH[] = "AccessControl";
    for (const auto& child : pt) {
        if (child.first != ACCESS_CONTROL_PROP_PATH) {
            continue;
        }

        static const char TYPE_PROP_PATH[] = "<xmlattr>.type";
        const boost::optional<string> type = child.second.get_optional<string>(TYPE_PROP_PATH);
        if (!type) {
            throw ConfigurationException("Missing type in AccessControl configuration.");
        }

        log.info("building AccessControl provider of type (%s)...", type.get().c_str());
        m_ac.push_back(unique_ptr<AccessControl>(
            AgentConfig::getConfig().AccessControlManager.newPlugin(type.get(), pt, deprecationSupport)
        ));
    }

    if (m_ac.empty()) {
        throw ConfigurationException("Chaining AccessControl plugin requires at least one child plugin.");
    }
}

AccessControl::aclresult_t ChainingAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_AND:
        {
            for (const auto& i : m_ac) {
                if (i->authorized(request, session) != shib_acl_true) {
                    request.log(SPRequest::SPDebug, "embedded AccessControl plugin unsuccessful, denying access");
                    return shib_acl_false;
                }
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            for (const auto& i : m_ac) {
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
