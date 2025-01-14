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
#pragma once

// Windows
#include <Windows.h>
#include <http.h>
#include "httpserv.h"

// Shibboleth
#define SHIBSP_LITE
#include "config_win32.h"
#include <shibsp/Agent.h>
#include <shibsp/AgentConfig.h>
#include <shibsp/exceptions.h>
#include <shibsp/logging/Priority.h>
#include <shibsp/platform/iis/ModuleConfig.h>
#include <shibsp/util/PropertySet.h>

//
// Miscelanea
//
#include <memory>
#include <string>

using namespace shibsp::iis;
using namespace shibsp;
using namespace std;

// Globals.
namespace Config {
    static const char* SpoofHeaderName = "ShibSpoofCheck";

    extern HINSTANCE g_hinstDLL;
    extern AgentConfig* g_Config;
    extern unique_ptr<ModuleConfig> g_ModuleConfig;
    extern string g_spoofKey;
    extern bool g_checkSpoofing;
    extern bool g_catchAll;
}

// TODO: Replace with standard logging calls.
BOOL LogEvent(
    WORD  wType,
    DWORD  dwEventID,
    Priority::Value priority,
    LPCSTR  message);