/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * SessionInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating sessions.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "SPRequest.h"
#include "handler/SessionInitiator.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

SessionInitiator::SessionInitiator()
{
}

SessionInitiator::~SessionInitiator()
{
}

const char* SessionInitiator::remap(const char* src, Category& log) const
{
    if (XMLString::equals(src, "defaultACSIndex")) {
        SPConfig::getConfig().deprecation().warn("old setting - remapping property (defaultACSIndex) to (acsIndex)");
        return "acsIndex";
    }
    else {
        return src;
    }
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
            isPassive = (*flag=='1' || *flag=='t');
        }
        else {
            pair<bool,bool> flagprop = getBool("isPassive");
            isPassive = (flagprop.first && flagprop.second);
        }
    }
    else {
        // It doesn't really make sense to use isPassive with automated sessions, but...
        pair<bool,bool> flagprop;
        if (request.getRequestSettings().first->hasProperty("isPassive")) {
            flagprop.second = request.getRequestSettings().first->getBool("isPassive", false);
            flagprop.first = true;
        }
        if (!flagprop.first)
            flagprop = getBool("isPassive");
        isPassive = (flagprop.first && flagprop.second);
    }

    // Check for support of isPassive if it's used.
    if (isPassive && getSupportedOptions().count("isPassive") == 0) {
        if (getParent()) {
            log(Priority::SHIB_INFO, "handler does not support isPassive option");
            return false;
        }
        throw ConfigurationException("Unsupported option (isPassive) supplied to SessionInitiator.");
    }

    return true;
}

pair<bool,long> SessionInitiator::run(SPRequest& request, bool isHandler) const
{
    cleanRelayState(request.getApplication(), request, request);

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
                log(Priority::SHIB_ERROR, ex.what());
                log(Priority::SHIB_INFO, "trapping SessionInitiator error condition and returning to target location");
                flag = request.getParameter("target");
                string target(flag ? flag : "");
                recoverRelayState(request.getApplication(), request, request, target, false);
                request.getApplication().limitRedirect(request, target.c_str());
                return make_pair(true, request.sendRedirect(target.c_str()));
            }
        }
        throw;
    }
}
