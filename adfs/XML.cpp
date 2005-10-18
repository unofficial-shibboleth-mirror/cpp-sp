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

/* XML.cpp - XML constants

   Scott Cantor
   6/4/02

   $History:$
*/

#include "internal.h"

// Namespace and schema string literals

const XMLCh adfs::XML::WSFED_NS[] = // http://schemas.xmlsoap.org/ws/2003/07/secext
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chLatin_s, chPeriod,
  chLatin_x, chLatin_m, chLatin_l, chLatin_s, chLatin_o, chLatin_a, chLatin_p, chPeriod,
  chLatin_o, chLatin_r, chLatin_g, chForwardSlash, chLatin_w, chLatin_s, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_3, chForwardSlash, chDigit_0, chDigit_7, chForwardSlash,
  chLatin_s, chLatin_e, chLatin_c, chLatin_e, chLatin_x, chLatin_t, chNull
};

const XMLCh adfs::XML::WSTRUST_NS[] = // http://schemas.xmlsoap.org/ws/2005/02/trust
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chLatin_s, chPeriod,
  chLatin_x, chLatin_m, chLatin_l, chLatin_s, chLatin_o, chLatin_a, chLatin_p, chPeriod,
  chLatin_o, chLatin_r, chLatin_g, chForwardSlash, chLatin_w, chLatin_s, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_5, chForwardSlash, chDigit_0, chDigit_2, chForwardSlash,
  chLatin_t, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chNull
};

const XMLCh adfs::XML::WSTRUST_SCHEMA_ID[] =
{ chLatin_W, chLatin_S, chDash, chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh adfs::XML::Literals::RequestedSecurityToken[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_e, chLatin_d,
  chLatin_S, chLatin_e, chLatin_c, chLatin_u, chLatin_r, chLatin_i, chLatin_t, chLatin_y,
  chLatin_T, chLatin_o, chLatin_k, chLatin_e, chLatin_n, chNull
};

const XMLCh adfs::XML::Literals::RequestSecurityTokenResponse[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t,
  chLatin_S, chLatin_e, chLatin_c, chLatin_u, chLatin_r, chLatin_i, chLatin_t, chLatin_y,
  chLatin_T, chLatin_o, chLatin_k, chLatin_e, chLatin_n,
  chLatin_R, chLatin_e, chLatin_s, chLatin_p, chLatin_o, chLatin_n, chLatin_s, chLatin_e, chNull
};
