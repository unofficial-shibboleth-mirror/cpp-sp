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
#include "ShibUser.hpp"
#include <codecvt> // 16 bit to 8 bit and vice versa chars


ShibUser::ShibUser(std::string name, set<wstring> roles) : m_refCount(1), m_roles(roles)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    m_username = converter.from_bytes(string(name));
}

PCWSTR
ShibUser::GetRemoteUserName(VOID)
{
    return m_username.c_str();
}

PCWSTR
ShibUser::GetUserName(VOID)
{
    return m_username.c_str();
}

PCWSTR
ShibUser::GetAuthenticationType(VOID)
{
    return L"Shibboleth";
}

PCWSTR
ShibUser::GetPassword(VOID)
{
    return nullptr;
}

HANDLE
ShibUser::GetImpersonationToken(VOID)
{
    return nullptr;
}

HANDLE
ShibUser::GetPrimaryToken(VOID)
{
    return nullptr;
}

VOID
ShibUser::ReferenceUser(VOID)
{
    InterlockedIncrement(&m_refCount);
}

VOID
ShibUser::DereferenceUser(VOID)
{
    unsigned int  i = InterlockedDecrement(&m_refCount);
    if (0 == i) {
        delete this;
    }
}

BOOL
ShibUser::SupportsIsInRole(VOID)
{
    return TRUE;
}

HRESULT
ShibUser::IsInRole(_In_  PCWSTR  pszRoleName, _Out_ BOOL *  pfInRole)
{
    wstring role(pszRoleName);

    if (m_roles.find(role) != m_roles.end()) {
        *pfInRole = TRUE;
    }
    else {
        *pfInRole = FALSE;
    }


    return S_OK;
}

PVOID
ShibUser::GetUserVariable(_In_ PCSTR    pszVariableName)
{
    static char empty[] = "";
    return  empty;
}

