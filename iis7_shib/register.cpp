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
#include <xmltooling/logging.h>
#pragma warning(disable: 4996)
#include <codecvt> // 16 bit to 8 bit and vice versa chars
#include <boost/algorithm/string.hpp>

using xmltooling::logging::Category;
using xmltooling::logging::Priority;

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
    wstring g_handlerPrefix(L"");
    bool g_bUseVariables = true;
    vector<string> g_NoCerts;
    vector<string> g_RoleAttributeNames;
    wstring g_authNRole(L"ShibbolethAuthN");
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
        Category::getInstance(SHIBSP_LOGCAT ".IISNative").info("IIS module is terminating");
        delete this;
    }
};

extern "C"
HRESULT
__stdcall
RegisterModule(
    DWORD                           dwServerVersion,
    IHttpModuleRegistrationInfo *   pModuleInfo,
    IHttpServer *                   pHttpServer
)
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".IISNative");

    if (g_Config) {
        log.warn("reentrant IIS module initialization, ignoring...");
        return S_OK;
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
        log.fatal("IIS module failed during library initialization, check native log for help");
        return E_FAIL;
    }

    try {
        if (!g_Config->instantiate(nullptr, true))
            throw runtime_error("unknown error");
    } catch (const std::exception& ex) {
        log.fatal("IIS module failed during library initialization: %s", ex.what());
        g_Config->term();
        g_Config=nullptr;
        return E_FAIL;
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
                    log.fatal("IIS module failed to generate a random anti-spoofing key");
                    locker.assign();    // pops lock on SP config
                    g_Config->term();
                    g_Config = nullptr;
                    return E_FAIL;
                }
            }
        }

        props = props->getPropertySet("ISAPI");
        if (props) {
            flag = props->getBool("normalizeRequest");
            g_bNormalizeRequest = !flag.first || flag.second;
            flag = props->getBool("useHeaders");
            g_bUseHeaders = flag.first && flag.second;
            flag = props->getBool("useVariables");
            g_bUseVariables= !flag.first || flag.second;
            flag = props->getBool("safeHeaderNames");
            if (g_bUseHeaders)
            	g_bSafeHeaderNames = !flag.first || flag.second;
            else
            	g_bSafeHeaderNames = flag.first && flag.second;

            const string prefix(XMLHelper::getAttrString(props->getElement(), "/Shibboleth.sso", handlerPrefix));
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            g_handlerPrefix = converter.from_bytes(prefix);

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

                if (authNRoleFlag.first) {
                    wstring rolestr(converter.from_bytes(string(authNRoleFlag.second)));

                    g_authNRole = rolestr;
                }

                const pair<bool, const char*> theRoles = roles->getString("roleAttributes");
                if (theRoles.first) {
                    boost::split(g_RoleAttributeNames, theRoles.second, boost::algorithm::is_space(), boost::algorithm::token_compress_on);
                }
            }
        }
    }

    HRESULT hr = pModuleInfo->SetRequestNotifications(new ShibModuleFactory(), RQ_BEGIN_REQUEST | RQ_AUTHENTICATE_REQUEST, 0);

    if (SUCCEEDED(hr))
        log.info("IIS module initialized");

    return hr;
}
