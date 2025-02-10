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
 * handler/impl/TokenCOnsumer.cpp
 *
 * SSO protocol response handler.
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "logging/Category.h"

#include <ctime>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {
    class SHIBSP_DLLLOCAL TokenConsumer : public virtual AbstractHandler {
    public:
        TokenConsumer(const ptree& pt, const char* path);
        virtual ~TokenConsumer() {}

        pair<bool,long> run(SPRequest& request, bool isHandler) const;

    private:
        string m_path;
        vector<string> m_remotedHeaders;
    };
};

namespace shibsp {
    Handler* SHIBSP_DLLLOCAL TokenConsumerFactory(const pair<ptree&,const char*>& p, bool) {
        return new TokenConsumer(p.first, p.second);
    }
};

TokenConsumer::TokenConsumer(const ptree& pt, const char* path)
    : AbstractHandler(pt, Category::getInstance(SHIBSP_LOGCAT ".Handler.TokenConsumer")),
        m_path(path), m_remotedHeaders({ "Cookie" })
{

}

pair<bool,long> TokenConsumer::run(SPRequest& request, bool isHandler) const
{
    return make_pair(false, 0);
}
