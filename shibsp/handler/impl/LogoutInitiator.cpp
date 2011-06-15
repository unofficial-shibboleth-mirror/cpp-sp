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
 * LogoutInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating logout.
 */

#include "internal.h"
#include "handler/LogoutInitiator.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<const DOMElement*,const char*> >::Factory ChainingLogoutInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<const DOMElement*,const char*> >::Factory SAML2LogoutInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<const DOMElement*,const char*> >::Factory LocalLogoutInitiatorFactory;
};

void SHIBSP_API shibsp::registerLogoutInitiators()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.LogoutInitiatorManager.registerFactory(CHAINING_LOGOUT_INITIATOR, ChainingLogoutInitiatorFactory);
    conf.LogoutInitiatorManager.registerFactory(SAML2_LOGOUT_INITIATOR, SAML2LogoutInitiatorFactory);
    conf.LogoutInitiatorManager.registerFactory(LOCAL_LOGOUT_INITIATOR, LocalLogoutInitiatorFactory);
}

LogoutInitiator::LogoutInitiator()
{
}

LogoutInitiator::~LogoutInitiator()
{
}

#ifndef SHIBSP_LITE
const char* LogoutInitiator::getType() const
{
    return "LogoutInitiator";
}
#endif
