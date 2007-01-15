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

/**
 * SPConstants.cpp
 * 
 * SP XML namespace constants 
 */

#include "internal.h"
#include "util/SPConstants.h"
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibspconstants;

const XMLCh shibspconstants::SHIB1_PROTOCOL_ENUM[] = // urn:mace:shibboleth:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh shibspconstants::SHIBMD_NS[] = // urn:mace:shibboleth:metadata:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh shibspconstants::SHIBMD_PREFIX[] = UNICODE_LITERAL_6(s,h,i,b,m,d);

const XMLCh shibspconstants::SHIB2SPCONFIG_NS[] = // urn:mace:shibboleth:sp:config:2.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_s, chLatin_p, chColon, chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chColon,
  chDigit_2, chPeriod, chDigit_0, chNull
};

const XMLCh shibspconstants::SHIB1SPCONFIG_NS[] = // urn:mace:shibboleth:target:config:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_t, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t, chColon,
  chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI[] = // urn:mace:shibboleth:1.0:attributeNamespace:uri
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
    chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_u, chLatin_r, chLatin_i, chNull
};

const XMLCh shibspconstants::SHIB1_NAMEID_FORMAT_URI[] = // urn:mace:shibboleth:1.0:nameIdentifier
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e,
    chLatin_I, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_e, chLatin_r, chNull
};

const XMLCh shibspconstants::SHIB1_AUTHNREQUEST_PROFILE_URI[] = // urn:mace:shibboleth:1.0:profiles:AuthnRequest
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chNull
};

const char shibspconstants::SHIB1_SESSIONINIT_PROFILE_URI[] = "urn:mace:shibboleth:sp:1.3:SessionInit";

const char shibspconstants::SHIB1_LOGOUT_PROFILE_URI[] = "urn:mace:shibboleth:sp:1.3:Logout";
