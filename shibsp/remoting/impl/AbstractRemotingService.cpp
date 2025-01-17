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
 * remoting/impl/AbstractRemotingService.cpp
 *
 * Base class for remoting services.
 */

#include "internal.h"

#include "remoting/impl/AbstractRemotingService.h"

#include <sstream>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

AbstractRemotingService::AbstractRemotingService(const ptree&) {}

AbstractRemotingService::~AbstractRemotingService() {}

DDF AbstractRemotingService::send(const DDF& in) const
{
    stringstream buf;
    buf << in;

    DDF output;
    send(buf) >> output;

    return output;
}