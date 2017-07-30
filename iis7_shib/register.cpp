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

#define _CRT_RAND_S
// https://stackoverflow.com/questions/1301277/c-boost-whats-the-cause-of-this-warning

#define _SCL_SECURE_NO_WARNINGS 1

// Project
#include "IIS7_shib.hpp"
#include "ShibHttpModule.hpp"
#include "../util/RegistrySignature.h"
#include <xmltooling/logging.h>
#pragma warning(disable: 4996)
#include <boost/algorithm/string.hpp>


namespace Config {
    HINSTANCE g_hinstDLL;
    SPConfig* g_Config = nullptr;
    map<string, site_t> g_Sites;
    bool g_bNormalizeRequest = true;
    string g_unsetHeaderValue, g_spoofKey;
    bool g_checkSpoofing = true;
    bool g_catchAll = false;
    bool g_bSafeHeaderNames = false;
    bool g_bUseHeaders = false;
    bool g_bUseVariables = true;
    vector<string> g_NoCerts;
    vector<string> g_RoleAttributeNames;
    wstring g_authNRole;
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
    ShibModuleFactory() {};
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
        delete this;
    }
};

extern "C"
_declspec(dllexport)
HRESULT
__stdcall
RegisterModule(
    DWORD                           dwServerVersion,
    IHttpModuleRegistrationInfo *   pModuleInfo,
    IHttpServer *                   pHttpServer
)
{
    if (g_Config) {
        LogEvent(nullptr, EVENTLOG_WARNING_TYPE, SHIB_NATIVE_REENTRANT_INIT, nullptr,
                 "Reentrant filter initialization, ignoring...");
        return S_OK;
    }

    RegistrySignature::CheckSigResult checkSig = RegistrySignature::CheckSignature('IIS7');
    if (RegistrySignature::CheckSigResult::Failed == checkSig) {
        LogEvent(nullptr, EVENTLOG_WARNING_TYPE, SHIB_NATIVE_CANNOT_CHECK_SIGNATURE, nullptr,
                 "Couldn't Check signature");
    }
    else if (RegistrySignature::CheckSigResult::Mismatched == checkSig) {
        LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_CANNOT_CHECK_SIGNATURE, nullptr,
                 "ISAPI Filter is already running, exiting");
        return FALSE;
    }

    g_Config = &SPConfig::getConfig();
    g_Config->setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::RequestMapping |
        SPConfig::InProcess |
        SPConfig::Logging |
        SPConfig::Handlers
    );
    if (!g_Config->init()) {
        g_Config = nullptr;
        LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_STARTUP_FAILED, nullptr,
                 "Filter startup failed during library initialization, check native log for help.");
        return E_FAIL;
    }

    try {
        if (!g_Config->instantiate(nullptr, true))
            throw runtime_error("unknown error");
    } catch (std::exception& ex) {
        g_Config->term();
        g_Config=nullptr;
        LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_STARTUP_FAILED_EXCEPTION, nullptr, ex.what());
        return FALSE;
    }

    // Access implementation-specifics and site mappings.
    ServiceProvider* sp = g_Config->getServiceProvider();
    Locker locker(sp);
    const PropertySet* props = sp->getPropertySet("InProcess");
    if (props) {
        pair<bool, bool> flag = props->getBool("checkSpoofing");
        g_checkSpoofing = !flag.first || flag.second;
        flag = props->getBool("catchAll");
        g_catchAll = flag.first && flag.second;

        pair<bool, const char*> unsetValue = props->getString("unsetHeaderValue");
        if (unsetValue.first)
            g_unsetHeaderValue = unsetValue.second;
        if (g_checkSpoofing) {
            unsetValue = props->getString("spoofKey");
            if (unsetValue.first)
                g_spoofKey = unsetValue.second;
            else {
                _invalid_parameter_handler old = _set_invalid_parameter_handler(_my_invalid_parameter_handler);
                unsigned int randkey=0, randkey2=0, randkey3=0, randkey4=0;
                if (rand_s(&randkey) == 0 && rand_s(&randkey2) == 0 && rand_s(&randkey3) == 0 && rand_s(&randkey4) == 0) {
                    _set_invalid_parameter_handler(old);
                    g_spoofKey = lexical_cast<string>(randkey) + lexical_cast<string>(randkey2) +
                        lexical_cast<string>(randkey3) + lexical_cast<string>(randkey4);
                }
                else {
                    _set_invalid_parameter_handler(old);
                    LogEvent(nullptr, EVENTLOG_ERROR_TYPE, SHIB_NATIVE_CANNOT_CREATE_ANTISPOOF, nullptr,
                             "Filter failed to generate a random anti-spoofing key (if this is Windows 2000 set one manually).");
                    locker.assign();    // pops lock on SP config
                    g_Config->term();
                    g_Config = nullptr;
                    return FALSE;
                }
            }
        }

        props = props->getPropertySet("ISAPI");
        if (props) {
            flag = props->getBool("normalizeRequest");
            g_bNormalizeRequest = !flag.first || flag.second;
            flag = props->getBool("safeHeaderNames");
            g_bSafeHeaderNames = flag.first && flag.second;
            flag = props->getBool("useHeaders");
            g_bUseHeaders = flag.first && flag.second;
            flag = props->getBool("useVariables");
            g_bUseVariables= !flag.first || flag.second;

            const DOMElement* site = XMLHelper::getFirstChildElement(props->getElement(), Site);
            while (site) {
                string id(XMLHelper::getAttrString(site, "", id));
                if (!id.empty())
                    g_Sites.insert(make_pair(id, site_t(site)));
                site = XMLHelper::getNextSiblingElement(site, Site);
            }
            const PropertySet* roles = props->getPropertySet("Roles");
            if (roles) {
                const pair<bool, const char*> authNRoleFlag = roles->getString("authNRole");
                xmltooling::auto_ptr_XMLCh rolestr(authNRoleFlag.first? authNRoleFlag.second : "ShibbolethAuthN");
                g_authNRole = rolestr.get();

                const pair<bool, const char*> theRoles = roles->getString("roleAttributes");
                if (theRoles.first) {
#pragma warning(disable: 4996)
                    boost::split(g_RoleAttributeNames, theRoles.second, boost::algorithm::is_space(), boost::algorithm::token_compress_on);
                }
            } else {
                g_authNRole = L"ShibbolethAuthN";
            }
        }
    }

    HRESULT hr = pModuleInfo->SetRequestNotifications(new ShibModuleFactory(), 
                                                      RQ_BEGIN_REQUEST | RQ_AUTHENTICATE_REQUEST | RQ_PRE_EXECUTE_REQUEST_HANDLER,
                                                      RQ_AUTHENTICATE_REQUEST);

    if (SUCCEEDED(hr))
    LogEvent(nullptr, EVENTLOG_INFORMATION_TYPE, SHIB_NATIVE_INITIALIZED, nullptr, "Filter initialized...");

    return hr;
}

BOOL LogEvent(
    LPCSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCSTR  message)
{
    LPCSTR  messages[] ={ message, nullptr };
    DWORD gle = GetLastError();

    HANDLE hElog = RegisterEventSource(lpUNCServerName, "Shibboleth NATIVE Filter");
    BOOL res = ReportEvent(hElog, wType, CATEGORY_NATIVE, dwEventID, lpUserSid, 1, sizeof(DWORD), messages, &gle);
    return (DeregisterEventSource(hElog) && res);
}


