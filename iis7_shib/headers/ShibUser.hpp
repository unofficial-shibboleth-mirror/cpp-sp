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

class ShibUser : public IHttpUser {

    // An IHttpUser which allows us to supply REMOTE_USER.
    // Also, a testbed for Roles Based AuthN.

public:
    ShibUser(std::string username);
            
    PCWSTR
    GetRemoteUserName(
        VOID
    );

    PCWSTR
    GetUserName(
        VOID
    );

    PCWSTR
    GetAuthenticationType(
        VOID
    );

    PCWSTR
    GetPassword(
        VOID
    );

    HANDLE
    GetImpersonationToken(
        VOID
    );

    HANDLE
    GetPrimaryToken(
        VOID
    );

    VOID
    ReferenceUser(
        VOID
    );

    VOID
    DereferenceUser(
        VOID
    );

    BOOL
    SupportsIsInRole(
        VOID
    );

    HRESULT
    IsInRole(
        _In_  PCWSTR  pszRoleName,
        _Out_ BOOL *  pfInRole
    );

    PVOID
    GetUserVariable(
        _In_ PCSTR    pszVariableName
    );

private:
    const auto_ptr_XMLCh m_widen;
    volatile unsigned int m_refCount;

};