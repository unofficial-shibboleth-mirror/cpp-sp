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

#include "IIS7_shib.hpp"

#include "io/HTTPResponse.h"

#include "ShibHttpModule.hpp"
#include "IIS7Request.hpp"
#include "IIS7_shib.hpp"

#include <process.h>
#include <winreg.h>

#include <boost/algorithm/string.hpp>

using namespace Config;
using namespace std;

REQUEST_NOTIFICATION_STATUS
ShibHttpModule::DoHandler(
    _In_ IHttpContext *         pHttpContext,
    _In_ IHttpEventProvider *   pProvider
)
{
    // Quickly check the URL.
    // Calling GetScriptName is safe here since we don't care about "visible to other filters" paths, just our path.
    // This saves us converting from 8 bit ascii up to 16 bit for the compare against something which was only in 16
    // bits to speed this path.  In V4 we can look at the local request
    const wstring url(pHttpContext->GetScriptName());
    if (url.length() < g_handlerPrefix.length() || !starts_with(url, g_handlerPrefix))
        return RQ_NOTIFICATION_CONTINUE;

    map<string,site_t>::const_iterator map_i = g_Sites.find(lexical_cast<string>(pHttpContext->GetSite()->GetSiteId()));
    if (map_i == g_Sites.end())
        return RQ_NOTIFICATION_CONTINUE;

    IIS7Request handler(pHttpContext, pProvider, false, map_i->second);

    pair<bool, long> res = handler.getServiceProvider().doHandler(handler);

    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }
    return RQ_NOTIFICATION_CONTINUE;
}

REQUEST_NOTIFICATION_STATUS
ShibHttpModule::DoFilter(
    _In_ IHttpContext *             pHttpContext,
    _In_ IHttpEventProvider *  pProvider
)
{
    const IHttpRequest* req = pHttpContext->GetRequest();

    map<string,site_t>::const_iterator map_i = g_Sites.find(lexical_cast<string>(pHttpContext->GetSite()->GetSiteId()));
    if (map_i == g_Sites.end())
        return RQ_NOTIFICATION_CONTINUE;

    IIS7Request filter(pHttpContext, pProvider, true, map_i->second);

    pair<bool, long> res = filter.getServiceProvider().doAuthentication(filter, true);
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
    res = filter.getServiceProvider().doExport(filter);
    if (res.first) {
        return static_cast<REQUEST_NOTIFICATION_STATUS>(res.second);
    }

    res = filter.getServiceProvider().doAuthorization(filter);
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
