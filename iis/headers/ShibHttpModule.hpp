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

#pragma once
#include "iis.hpp"

class ShibHttpModule : public CHttpModule {
public:
    ShibHttpModule()
    {}

    ~ShibHttpModule()
    {};

    // RQ_BEGIN_REQUEST
    REQUEST_NOTIFICATION_STATUS
        OnBeginRequest(
            _In_ IHttpContext *         pHttpContext,
            _In_ IHttpEventProvider *   pProvider
        );

    // RQ_AUTHENTICATE_REQUEST
    REQUEST_NOTIFICATION_STATUS
        OnAuthenticateRequest(
            _In_ IHttpContext *             pHttpContext,
            _In_ IAuthenticationProvider *  pProvider
        );

private:
    REQUEST_NOTIFICATION_STATUS
        DoHandler(
            _In_ IHttpContext *         pHttpContext,
            _In_ IHttpEventProvider *   pProvider
        );

    REQUEST_NOTIFICATION_STATUS
        DoFilter(
            _In_ IHttpContext *         pHttpContext,
            _In_ IHttpEventProvider *   pProvider
        );
};

