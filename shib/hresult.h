/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* 
 * hresult.h - Code definitions
= */

#ifndef __shibhresult_h__
#define __shibhresult_h__

#include <saml/hresult.h>

/* Codes from 0x9000 - 0x9FFF in FACILITY_ITF are reserved for the Shibboleth Core */

#define SHIB_E_FIRST MAKE_HRESULT(SEVERITY_ERROR,FACILITY_ITF,SAML_E_LAST + 0x0001)
#define SHIB_E_LAST MAKE_HRESULT(SEVERITY_ERROR,FACILITY_ITF,SAML_E_LAST + 0x1000)

#define SHIB_S_FIRST MAKE_HRESULT(SEVERITY_SUCCESS,FACILITY_ITF,SAML_S_LAST + 0x0001)
#define SHIB_S_LAST MAKE_HRESULT(SEVERITY_SUCCESS,FACILITY_ITF,SAML_S_LAST + 0x1000

/* Specific code definitions */

#define SHIB_E_UNSPECIFIED              (SHIB_E_FIRST + 0L)

#endif
