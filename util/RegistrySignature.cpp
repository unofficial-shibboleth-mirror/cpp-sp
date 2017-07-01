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

/*
 *  RegistrySignature.cpp : simple bit of code to check for and write
 *  a signature into the registry.
 *    - if it's not there we create a volatile key, write it and say "OK"
 *    - if it is there and the same then we say OK
 *    - if it is there and differs then we delete thekey (resetting the trigger) and say NOT OK
 */

#include "RegistrySignature.h"

namespace RegistrySignature
{ 
    CheckSigResult CheckSignature(const DWORD Signature)
    {
#if _WIN32_WINNT < 0x0600
        // Supress downrev (==VC2010 builds)
        return Matched;
#else
        const WCHAR KeyName[] = L"SOFTWARE\\Shibboleth\\IsapiPlugin";
        const WCHAR ValueName[] = L"Signature";

        struct HKEY_HOLDER {
        private:
            HKEY handle;
        public:
            HKEY_HOLDER(HKEY what)
            {
                handle = what;
            }
            ~HKEY_HOLDER()
            {
                RegCloseKey(handle);
            }
        };

        HKEY handle;
        DWORD disposition, key, keySize;
        LONG result;
        result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, KeyName, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &handle, &disposition);
        if (result != ERROR_SUCCESS) {
            return Failed;
        }
        HKEY_HOLDER holder(handle);
        if (disposition == REG_OPENED_EXISTING_KEY) {
            keySize = sizeof(key);
            result = RegGetValueW(handle, nullptr, ValueName, RRF_RT_DWORD, NULL, &key, &keySize);
            if (result == ERROR_SUCCESS) {
                if (key != Signature) {
                    result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, KeyName);
                    return Mismatched;
                }
                else {
                    return Matched;
                }
            }
        }
        result = RegSetValueExW(handle, ValueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&Signature), sizeof(Signature));

        return (ERROR_SUCCESS == result) ? Matched : Failed;
#endif
    }
}
