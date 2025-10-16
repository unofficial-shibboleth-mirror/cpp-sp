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
#include "ShibUser.hpp"

ShibUser::ShibUser(std::wstring name, set<wstring> roles) : m_refCount(1), m_roles(roles), m_username(name)
{
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

