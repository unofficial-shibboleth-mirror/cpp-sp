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

#include "iis.hpp"

#include "shibsp/io/HTTPResponse.h"

#include "ShibHttpModule.hpp"
#include "IIS7Request.hpp"

#include <process.h>
#include <winreg.h>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

using namespace Config;
using namespace std;

REQUEST_NOTIFICATION_STATUS
ShibHttpModule::DoHandler(
    _In_ IHttpContext *         pHttpContext,
    _In_ IHttpEventProvider *   pProvider
)
{
    const PropertySet* site = g_ModuleConfig->getSiteConfig(
        boost::lexical_cast<string>(pHttpContext->GetSite()->GetSiteId()).c_str());
    if (!site)
        return RQ_NOTIFICATION_CONTINUE;

    //
    // Standard Windows UTFS -> wstring convert with different error handling
    //
    string prefix(site->getString(ModuleConfig::HANDLER_PREFIX_PROP_NAME, ModuleConfig::HANDLER_PREFIX_PROP_DEFAULT));
    DWORD sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, prefix.c_str(), -1, nullptr, 0);

    LPWSTR output = new WCHAR[sizeNeeded + 1];
    if (output == nullptr) {
        (void)pHttpContext->GetResponse()->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), 
                                                     "Fatal Server Error: MultiByteToWideChar failed",
                                                     0,
                                                     HRESULT_FROM_WIN32(GetLastError()));
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }
    ZeroMemory(output, sizeof(WCHAR) * (sizeNeeded + 1));

    if (MultiByteToWideChar(CP_UTF8, 0, prefix.c_str(), -1, output, sizeNeeded) == 0) {
        (void)pHttpContext->GetResponse()->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR),
                                                     "Fatal Server Error: MultiByteToWideChar failed",
                                                     0,
                                                     HRESULT_FROM_WIN32(GetLastError()));
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

    wstring handlerPrefix(output);
    delete[] output;

    //
    // We used to only call the constructor if we knew the request is for us,
    // but we cannot tell anymore.
    //
    IIS7Request handler(pHttpContext, pProvider, false, *site);

    pair<bool, long> res = handler.getAgent().doHandler(handler);

    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }
    return RQ_NOTIFICATION_CONTINUE;
}

REQUEST_NOTIFICATION_STATUS
ShibHttpModule::DoFilter(
    _In_ IHttpContext * pHttpContext,
    _In_ IHttpEventProvider *  pProvider
)
{
    const IHttpRequest* req = pHttpContext->GetRequest();

    const PropertySet* site = g_ModuleConfig->getSiteConfig(
        boost::lexical_cast<string>(pHttpContext->GetSite()->GetSiteId()).c_str());
    if (!site)
        return RQ_NOTIFICATION_CONTINUE;

    IIS7Request filter(pHttpContext, pProvider, true, *site);

    pair<bool, long> res = filter.getAgent().doAuthentication(filter, true);
    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }

    if (!g_spoofKey.empty() && filter.isUseHeaders()) {
        const HRESULT hr(pHttpContext->GetRequest()->SetHeader(SpoofHeaderName, g_spoofKey.c_str(), static_cast<USHORT>(g_spoofKey.length()), TRUE));
        if (FAILED(hr)) {
            (void)pHttpContext->GetResponse()->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Error", 0, hr);
            return RQ_NOTIFICATION_FINISH_REQUEST;
        }
    }
    res = filter.getAgent().doExport(filter);
    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }

    res = filter.getAgent().doAuthorization(filter);
    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }
    return RQ_NOTIFICATION_CONTINUE;
}

// RQ_BEGIN_REQUEST
REQUEST_NOTIFICATION_STATUS
ShibHttpModule::OnBeginRequest(
    _In_ IHttpContext *         pHttpContext,
    _In_ IHttpEventProvider *   pProvider
)
{
    IHttpResponse* res = pHttpContext->GetResponse();
    try {
        return DoHandler(pHttpContext, pProvider);
    }
    catch (const bad_alloc&) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Memory Error", 0, E_OUTOFMEMORY);
    }
    catch (long e) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Win32 Error", 0, HRESULT_FROM_WIN32(e));
    }
    catch (const std::exception& e) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), e.what());
    }
    catch (...) {
        if (g_catchAll) {
            res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Error Caught");
        }
        else {
            throw;
        }
    }
    pHttpContext->SetRequestHandled();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}

// RQ_AUTHENTICATE_REQUEST 
REQUEST_NOTIFICATION_STATUS
ShibHttpModule::OnAuthenticateRequest(
    _In_ IHttpContext *             pHttpContext,
    _In_ IAuthenticationProvider *  pProvider
)
{
    IHttpResponse* res = pHttpContext->GetResponse();
    try {
        return DoFilter(pHttpContext, pProvider);
    }
    catch (const bad_alloc&) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Memory Error", 0, E_OUTOFMEMORY);
    }
    catch (long e) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Win32 Error", 0, HRESULT_FROM_WIN32(e));
    }
    catch (const std::exception& e) {
        res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), e.what());
    }
    catch (...) {
        if (g_catchAll) {
            res->SetStatus(static_cast<USHORT>(HTTPResponse::SHIBSP_HTTP_STATUS_ERROR), "Fatal Server Error Caught");
        }
        else {
            throw;
        }
    }
    pHttpContext->SetRequestHandled();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}
