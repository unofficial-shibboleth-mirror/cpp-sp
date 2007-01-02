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

const XMLCh XML::SHIB_NS[] = // urn:mace:shibboleth:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::SHIB_SCHEMA_ID[] = // shibboleth.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, 
  chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::CREDS_NS[] = // urn:mace:shibboleth:credentials:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_c, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::CREDS_SCHEMA_ID[] = // credentials.xsd
{ chLatin_c, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s,
  chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

// Shibboleth vocabulary literals

const XMLCh XML::Literals::CAPath[] =
{ chLatin_C, chLatin_A, chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::Certificate[] =
{ chLatin_C, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_e, chNull };

const XMLCh XML::Literals::Class[] =
{ chLatin_c, chLatin_l, chLatin_a, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::Credentials[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s, chNull };

const XMLCh XML::Literals::CustomResolver[]=
{ chLatin_C, chLatin_u, chLatin_s, chLatin_t, chLatin_o, chLatin_m,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::FileResolver[]=
{ chLatin_F, chLatin_i, chLatin_l, chLatin_e,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::format[] =
{ chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chNull };

const XMLCh XML::Literals::Id[] = { chLatin_I, chLatin_d, chNull };

const XMLCh XML::Literals::Key[] =
{ chLatin_K, chLatin_e, chLatin_y, chNull };

const XMLCh XML::Literals::password[] =
{ chLatin_p, chLatin_a, chLatin_s, chLatin_s, chLatin_w, chLatin_o, chLatin_r, chLatin_d, chNull };

const XMLCh XML::Literals::Path[] =
{ chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::Accept[]=
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_p, chLatin_t, chNull };

const XMLCh XML::Literals::Alias[]=
{ chLatin_A, chLatin_l, chLatin_i, chLatin_a, chLatin_s, chNull };

const XMLCh XML::Literals::AnyAttribute[] =
{ chLatin_A, chLatin_n, chLatin_y,
  chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chNull
};

const XMLCh XML::Literals::AnySite[]=
{ chLatin_A, chLatin_n, chLatin_y, chLatin_S, chLatin_i, chLatin_t, chLatin_e, chNull };

const XMLCh XML::Literals::AnyValue[]=
{ chLatin_A, chLatin_n, chLatin_y, chLatin_V, chLatin_a, chLatin_l, chLatin_u, chLatin_e, chNull };

const XMLCh XML::Literals::AttributeAcceptancePolicy[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_p, chLatin_t, chLatin_a, chLatin_n, chLatin_c, chLatin_e,
  chLatin_P, chLatin_o, chLatin_l, chLatin_i, chLatin_c, chLatin_y, chNull
};

const XMLCh XML::Literals::AttributeRule[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_R, chLatin_u, chLatin_l, chLatin_e, chNull
};

const XMLCh XML::Literals::CaseSensitive[] =
{ chLatin_C, chLatin_a, chLatin_s, chLatin_e,
  chLatin_S, chLatin_e, chLatin_n, chLatin_s, chLatin_i, chLatin_t, chLatin_i, chLatin_v, chLatin_e, chNull
};

const XMLCh XML::Literals::Factory[]=
{ chLatin_F, chLatin_a, chLatin_c, chLatin_t, chLatin_o, chLatin_r, chLatin_y, chNull };

const XMLCh XML::Literals::Header[]=
{ chLatin_H, chLatin_e, chLatin_a, chLatin_d, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Name[]=
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::Namespace[]=
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chNull };

const XMLCh XML::Literals::Scope[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chNull };

const XMLCh XML::Literals::Scoped[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chLatin_d, chNull };

const XMLCh XML::Literals::SiteRule[] =
{ chLatin_S, chLatin_i, chLatin_t, chLatin_e, chLatin_R, chLatin_u, chLatin_l, chLatin_e, chNull };

const XMLCh XML::Literals::Type[]=
{ chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull };

const XMLCh XML::Literals::Value[] =
{ chLatin_V, chLatin_a, chLatin_l, chLatin_u, chLatin_e, chNull };

const XMLCh XML::Literals::literal[] =
{ chLatin_l, chLatin_i, chLatin_t, chLatin_e, chLatin_r, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::regexp[] =
{ chLatin_r, chLatin_e, chLatin_g, chLatin_e, chLatin_x, chLatin_p, chNull };

const XMLCh XML::Literals::xpath[] =
{ chLatin_x, chLatin_p, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::url[] = { chLatin_u, chLatin_r, chLatin_l, chNull };

const XMLCh XML::Literals::AccessControl[] =
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s,
  chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_r, chLatin_o, chLatin_l, chNull
};

const XMLCh XML::Literals::AND[] =
{ chLatin_A, chLatin_N, chLatin_D, chNull };

const XMLCh XML::Literals::NOT[] =
{ chLatin_N, chLatin_O, chLatin_T, chNull };

const XMLCh XML::Literals::OR[] =
{ chLatin_O, chLatin_R, chNull };

const XMLCh XML::Literals::require[] =
{ chLatin_r, chLatin_e, chLatin_q, chLatin_u, chLatin_i, chLatin_r, chLatin_e, chNull };

const XMLCh XML::Literals::Rule[] =
{ chLatin_R, chLatin_u, chLatin_l, chLatin_e, chNull };
