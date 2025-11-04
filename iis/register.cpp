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

#define _CRT_RAND_S
// https://stackoverflow.com/questions/1301277/c-boost-whats-the-cause-of-this-warning

#define _SCL_SECURE_NO_WARNINGS 1

// Project
#include "iis.hpp"
#include "ShibHttpModule.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include "NativeEventLog.h"

namespace Config {
    HINSTANCE g_hinstDLL;
    AgentConfig* g_Config = nullptr;
    unique_ptr<ModuleConfig> g_ModuleConfig;
    string g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
}

using namespace Config;


static void _my_invalid_parameter_handler(
    const wchar_t * expression,
    const wchar_t * function,
    const wchar_t * file,
    unsigned int line,
    uintptr_t pReserved
)
{
    return;
}

class ShibModuleFactory : public IHttpModuleFactory {
public:
    ShibModuleFactory() {
    };
    virtual HRESULT GetHttpModule(
        CHttpModule **  ppModule,
        _In_ IModuleAllocator *     pAllocator
    )
    {
        *ppModule = new ShibHttpModule();
        return S_OK;
    }

    virtual VOID Terminate()
    {
        Category::getInstance(SHIBSP_LOGCAT ".IIS").info("IIS module is terminating");
        delete this;
    }
};

//
// Log to the event log if there is a chance that Logging hasn't been initialized
//
static
void
ReportInitializationError(
    const char* operation,
    const char* additionalInfo = nullptr
)
{
    string message(operation);

    if (additionalInfo)
        message += additionalInfo;
    const char* msgs[2]{ "II7 Initialization" , message.c_str()};

    const HANDLE eventSource = ::RegisterEventSourceA(NULL, SHIB_EVENT_SOURCE_NAME);
    ::ReportEventA(eventSource, EVENTLOG_ERROR_TYPE, (WORD)SHIBSP_CATEGORY_CRIT, SHIBSP_LOG_CRIT, NULL, 2, 0, msgs, NULL);
    ::DeregisterEventSource(eventSource);

}

extern "C"
HRESULT
__declspec(dllexport)
__stdcall
RegisterModule(
    DWORD                           dwServerVersion,
    IHttpModuleRegistrationInfo *   pModuleInfo,
    IHttpServer *                   pHttpServer
)
{
    if (g_Config) {
        // Safe, since we're already init'd.
        Category::getInstance(SHIBSP_LOGCAT ".IIS").warn("reentrant IIS module initialization, ignoring...");
        return S_OK;
    }

    g_Config = &AgentConfig::getConfig();

    try {
        if (!g_Config->init(nullptr, nullptr, true)) {
            ReportInitializationError("IIS module failed during library initialization");
            g_Config=nullptr;
            return E_FAIL;
        }
    }
    catch (const exception& ex) {

            ReportInitializationError("IIS module failed during library initialization : ", ex.what());
            g_Config = nullptr;
            return E_FAIL;
    }

    try {
        if (!g_Config->start())
            throw runtime_error("unknown error");
    }
    catch (const std::exception& ex) {
        ReportInitializationError("IIS module failed during library start : ", ex.what());
        g_Config->term();
        g_Config = nullptr;
        return E_FAIL;
    }

    Category& log = Category::getInstance(SHIBSP_LOGCAT ".IIS");

    // Access implementation-specifics and create site mappings.
    const Agent& agent = g_Config->getAgent();

    try {
        unique_ptr<ModuleConfig> newModuleConfig(iis::ModuleConfig::newModuleConfig());
        g_ModuleConfig.swap(newModuleConfig);
    } catch (const exception& ex) {
        log.crit("IIS module failed during module configuration installation: %s", ex.what());
        g_Config=nullptr;
        return E_FAIL;
    }

    g_checkSpoofing = agent.getBool(Agent::CHECK_SPOOFING_PROP_NAME, Agent::CHECK_SPOOFING_PROP_DEFAULT);
    g_catchAll = agent.getBool(Agent::CATCH_ALL_PROP_NAME, Agent::CATCH_ALL_PROP_DEFAULT);

    if (g_checkSpoofing) {
        g_spoofKey = agent.getString(Agent::SPOOF_KEY_PROP_NAME, "");
        if (g_spoofKey.empty()) {
            _invalid_parameter_handler old = _set_invalid_parameter_handler(_my_invalid_parameter_handler);
            unsigned int randkey=0, randkey2=0, randkey3=0, randkey4=0;
            if (rand_s(&randkey) == 0 && rand_s(&randkey2) == 0 && rand_s(&randkey3) == 0 && rand_s(&randkey4) == 0) {
                _set_invalid_parameter_handler(old);
                g_spoofKey = boost::lexical_cast<string>(randkey) + boost::lexical_cast<string>(randkey2) +
                    boost::lexical_cast<string>(randkey3) + boost::lexical_cast<string>(randkey4);
            }
            else {
                _set_invalid_parameter_handler(old);
                log.crit("IIS module failed to generate a random anti-spoofing key");
                g_Config->term();
                g_Config = nullptr;
                return E_FAIL;
            }
        }
    }

    HRESULT hr = pModuleInfo->SetRequestNotifications(new ShibModuleFactory(), RQ_BEGIN_REQUEST | RQ_AUTHENTICATE_REQUEST, 0);
    if (SUCCEEDED(hr))
        log.info("IIS module initialized");

    return hr;
}
