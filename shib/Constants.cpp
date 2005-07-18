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

/* Constants.cpp - Shibboleth URI constants

   Scott Cantor
   2/20/02

   $History:$
*/

#include "internal.h"

using namespace shibboleth;

const XMLCh Constants::SHIB_NS[] = // urn:mace:shibboleth:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh Constants::SHIB_ATTRIBUTE_NAMESPACE_URI[] = // urn:mace:shibboleth:1.0:attributeNamespace:uri
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
    chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_u, chLatin_r, chLatin_i, chNull
};

const XMLCh Constants::SHIB_NAMEID_FORMAT_URI[] = // urn:mace:shibboleth:1.0:nameIdentifier
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e,
    chLatin_I, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_r, chNull
};

const XMLCh Constants::SHIB_LEGACY_AUTHNREQUEST_PROFILE_URI[] = // urn:mace:shibboleth:1.0:profiles:LegacyAuthnRequest
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_L, chLatin_e, chLatin_g, chLatin_a, chLatin_c, chLatin_y,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chNull
};

const XMLCh Constants::SHIB_AUTHNREQUEST_PROFILE_URI[] = // urn:mace:shibboleth:1.0:profiles:AuthnRequest
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chNull
};

const XMLCh Constants::SHIB_SESSIONINIT_PROFILE_URI[] = // urn:mace:shibboleth:sp:1.3:SessionInit
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_s, chLatin_p, chColon, chDigit_1, chPeriod, chDigit_3, chColon,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n, chLatin_I, chLatin_n, chLatin_i, chLatin_t, chNull
};

const XMLCh Constants::SHIB_LOGOUT_PROFILE_URI[] = // urn:mace:shibboleth:sp:1.3:Logout
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_s, chLatin_p, chColon, chDigit_1, chPeriod, chDigit_3, chColon,
  chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chNull
};

const XMLCh Constants::InvalidHandle[] =
{ chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d,
  chLatin_H, chLatin_a, chLatin_n, chLatin_d, chLatin_l, chLatin_e, chNull
};
