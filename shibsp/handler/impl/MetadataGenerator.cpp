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
 * handler/impl/MetadataGenerator.cpp
 *
 * Handler for generating "approximate" metadata based on SP configuration.
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/SecuredHandler.h"
#include "logging/Category.h"
#include "util/Misc.h"

#include <sstream>
#include <string>
#include <vector>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_API MetadataGenerator : public SecuredHandler
    {
    public:
        MetadataGenerator(const ptree& pt);
        virtual ~MetadataGenerator() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        vector<string> m_bases;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL MetadataGeneratorFactory(const pair<ptree&,const char*>& p, bool)
    {
        return new MetadataGenerator(p.first);
    }

};

MetadataGenerator::MetadataGenerator(const ptree& pt) : SecuredHandler(pt)
{
    const char* bases = getString("baseURLs");
    if (bases) {
        split_to_container(m_bases, bases);
    }
}

pair<bool,long> MetadataGenerator::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    try {
        // TODO
    }
    catch (const exception& ex) {
        request.error(string("error while processing request: ") + ex.what());
        istringstream msg("Metadata Request Failed");
        return make_pair(true, request.sendResponse(msg, HTTPResponse::SHIBSP_HTTP_STATUS_ERROR));
    }
    return ret;
}
