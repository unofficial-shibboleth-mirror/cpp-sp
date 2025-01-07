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
 * handler/impl/SessionInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/SessionInitiator.h"
#include "logging/Category.h"
#include "util/Misc.h"

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

SessionInitiator::SessionInitiator(const ptree& pt, Category& log) : AbstractHandler(pt, log)
{
}

SessionInitiator::~SessionInitiator()
{
}

const set<string>& SessionInitiator::getSupportedOptions() const
{
    return m_supportedOptions;
}

bool SessionInitiator::checkCompatibility(SPRequest& request, bool isHandler) const
{
    bool isPassive = false;
    if (isHandler) {
        const char* flag = request.getParameter("isPassive");
        if (flag) {
            string_to_bool_translator tr;
            boost::optional<bool> b = tr.get_value(flag);
            isPassive = b.has_value() ? b.get() : false;
        }
        else {
            isPassive = getBool("isPassive", false);
        }
    }
    else {
        // It doesn't really make sense to use isPassive with automated sessions, but...
        if (request.getRequestSettings().first->hasProperty("isPassive")) {
            isPassive = request.getRequestSettings().first->getBool("isPassive", false);
        } else {
            isPassive = getBool("isPassive", false);
        }
    }

    // Check for support of isPassive if it's used.
    if (isPassive && getSupportedOptions().count("isPassive") == 0) {
        throw ConfigurationException("Unsupported option (isPassive) supplied to SessionInitiator.");
    }

    return true;
}

pair<bool,long> SessionInitiator::run(SPRequest& request, bool isHandler) const
{
    /*
    cleanRelayState(request);

    const char* entityID = nullptr;
    pair<bool,const char*> param = getString("entityIDParam");
    if (isHandler) {
        entityID = request.getParameter(param.first ? param.second : "entityID");
        if (!param.first && (!entityID || !*entityID))
            entityID=request.getParameter("providerId");
    }
    if (!entityID || !*entityID) {
        param.second = request.getRequestSettings().first->getString("entityID");
        if (param.second)
            entityID = param.second;
    }
    if (!entityID || !*entityID)
        entityID = getString("entityID").second;

    string copy(entityID ? entityID : "");

    try {
        return run(request, copy, isHandler);
    }
    catch (exception& ex) {
        // If it's a handler operation, and isPassive is used or returnOnError is set, we trap the error.
        if (isHandler) {
            bool returnOnError = false;
            const char* flag = request.getParameter("isPassive");
            if (flag && (*flag == 't' || *flag == '1')) {
                returnOnError = true;
            }
            else {
                pair<bool,bool> flagprop = getBool("isPassive");
                if (flagprop.first && flagprop.second) {
                    returnOnError = true;
                }
                else {
                    flag = request.getParameter("returnOnError");
                    if (flag) {
                        returnOnError = (*flag=='1' || *flag=='t');
                    }
                    else {
                        flagprop = getBool("returnOnError");
                        returnOnError = (flagprop.first && flagprop.second);
                    }
                }
            }

            if (returnOnError) {
                // Log it and attempt to recover relay state so we can get back.
                m_log.error(ex.what());
                m_log.info("trapping SessionInitiator error condition and returning to target location");
                flag = request.getParameter("target");
                string target(flag ? flag : "");
                recoverRelayState(request, target, false);
                request.limitRedirect(target.c_str());
                return make_pair(true, request.sendRedirect(target.c_str()));
            }
        }
        throw;
    }
    */
    return pair(true,0);
}
