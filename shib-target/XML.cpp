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

using namespace shibtarget;

const char XML::MemorySessionCacheType[] =  "edu.internet2.middleware.shibboleth.sp.provider.MemorySessionCacheProvider";
const char XML::MySQLSessionCacheType[] =   "edu.internet2.middleware.shibboleth.sp.provider.MySQLSessionCacheProvider";
const char XML::ODBCSessionCacheType[] =    "edu.internet2.middleware.shibboleth.sp.provider.ODBCSessionCacheProvider";

const char XML::MySQLReplayCacheType[] =    "edu.internet2.middleware.shibboleth.sp.provider.MySQLReplayCacheProvider";
const char XML::ODBCReplayCacheType[] =     "edu.internet2.middleware.shibboleth.sp.provider.ODBCReplayCacheProvider";

const char XML::XMLRequestMapType[] =       "edu.internet2.middleware.shibboleth.sp.provider.XMLRequestMapProvider";
const char XML::NativeRequestMapType[] =    "edu.internet2.middleware.shibboleth.sp.provider.NativeRequestMapProvider";
const char XML::LegacyRequestMapType[] =    "edu.internet2.middleware.shibboleth.target.provider.XMLRequestMap";

const char XML::htAccessControlType[] =     "edu.internet2.middleware.shibboleth.sp.apache.provider.htAccessControl";
const char XML::XMLAccessControlType[] =    "edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl";

const XMLCh XML::SHIBTARGET_NS[] = // urn:mace:shibboleth:target:config:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_t, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t, chColon,
  chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::SHIBTARGET_SCHEMA_ID[] = // shibboleth-targetconfig-1.0.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chDash,
  chLatin_t, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t, chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chDash,
  chDigit_1, chPeriod, chDigit_0, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::SAML2ASSERT_NS[] = // urn:oasis:names:tc:SAML:2.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::SAML2ASSERT_SCHEMA_ID[] = // saml-schema-assertion-2.0.xsd
{ chLatin_s, chLatin_a, chLatin_m, chLatin_l, chDash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chDash,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chDash,
  chDigit_2, chPeriod, chDigit_0, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::SAML2META_NS[] = // urn:oasis:names:tc:SAML:2.0:metadata
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull
};

const XMLCh XML::SAML2META_SCHEMA_ID[] = // saml-schema-metadata-2.0.xsd
{ chLatin_s, chLatin_a, chLatin_m, chLatin_l, chDash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chDash,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chDash,
  chDigit_2, chPeriod, chDigit_0, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::XMLENC_NS[] = // http://www.w3.org/2001/04/xmlenc#
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w, chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_1, chForwardSlash, chDigit_0, chDigit_4, chForwardSlash,
  chLatin_x, chLatin_m, chLatin_l, chLatin_e, chLatin_n, chLatin_c, chPound, chNull
};

const XMLCh XML::XMLENC_SCHEMA_ID[] = // xenc-schema.xsd
{ chLatin_x, chLatin_e, chLatin_n, chLatin_c, chDash,
  chLatin_s, chLatin_c, chLatin_h, chLatin_e, chLatin_m, chLatin_a, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::Literals::AAPProvider[] =
{ chLatin_A, chLatin_A, chLatin_P, chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::AccessControlProvider[] =
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s,
  chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_r, chLatin_o, chLatin_l,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::AccessControl[] =
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s,
  chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_r, chLatin_o, chLatin_l, chNull
};

const XMLCh XML::Literals::acl[] =
{ chLatin_a, chLatin_c, chLatin_l, chNull };

const XMLCh XML::Literals::applicationId[] =
{ chLatin_a, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_I, chLatin_d, chNull
};

const XMLCh XML::Literals::Application[] =
{ chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::Applications[] =
{ chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chNull };

const XMLCh XML::Literals::AssertionConsumerService[] =
{ chLatin_A, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_o, chLatin_n, chLatin_s, chLatin_u, chLatin_m, chLatin_e, chLatin_r,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AttributeFactory[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_F, chLatin_a, chLatin_c, chLatin_t, chLatin_o, chLatin_r, chLatin_y, chNull
};

const XMLCh XML::Literals::config[] =
{ chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chNull };

const XMLCh XML::Literals::CredentialsProvider[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::CredentialUse[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l,
  chLatin_U, chLatin_s, chLatin_e, chNull
};

const XMLCh XML::Literals::DiagnosticService[] =
{ chLatin_D, chLatin_i, chLatin_a, chLatin_g, chLatin_n, chLatin_o, chLatin_s, chLatin_t, chLatin_i, chLatin_c,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::echo[] =
{ chLatin_e, chLatin_c, chLatin_h, chLatin_o, chNull };

const XMLCh XML::Literals::Extensions[] =
{ chLatin_E, chLatin_x, chLatin_t, chLatin_e, chLatin_n, chLatin_s, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chNull };

const XMLCh XML::Literals::fatal[]= { chLatin_f, chLatin_a, chLatin_t, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::FederationProvider[] =
{ chLatin_F, chLatin_e, chLatin_d, chLatin_e, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::Global[] =
{ chLatin_G, chLatin_l, chLatin_o, chLatin_b, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::Host[]= { chLatin_H, chLatin_o, chLatin_s, chLatin_t, chNull };

const XMLCh XML::Literals::htaccess[]=
{ chLatin_h, chLatin_t, chLatin_a, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::Implementation[] =
{ chLatin_I, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::index[] =
{ chLatin_i, chLatin_n, chLatin_d, chLatin_e, chLatin_x, chNull };

const XMLCh XML::Literals::InProcess[] =
{ chLatin_I, chLatin_n, chLatin_P, chLatin_r, chLatin_o, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::isDefault[] =
{ chLatin_i, chLatin_s, chLatin_D, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t, chNull };

const XMLCh XML::Literals::Library[] =
{ chLatin_L, chLatin_i, chLatin_b, chLatin_r, chLatin_a, chLatin_r, chLatin_y, chNull };

const XMLCh XML::Literals::Listener[] =
{ chLatin_L, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Local[] =
{ chLatin_L, chLatin_o, chLatin_c, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::log[] =
{ chLatin_l, chLatin_o, chLatin_g, chNull };

const XMLCh XML::Literals::logger[] =
{ chLatin_l, chLatin_o, chLatin_g, chLatin_g, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::MemorySessionCache[] =
{ chLatin_M, chLatin_e, chLatin_m, chLatin_o, chLatin_r, chLatin_y,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::MetadataProvider[] =
{ chLatin_M, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::MySQLReplayCache[] =
{ chLatin_M, chLatin_y, chLatin_S, chLatin_Q, chLatin_L,
  chLatin_R, chLatin_e, chLatin_p, chLatin_l, chLatin_a, chLatin_y,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::MySQLSessionCache[] =
{ chLatin_M, chLatin_y, chLatin_S, chLatin_Q, chLatin_L,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::name[]= { chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::Name[]= { chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::ODBCReplayCache[] =
{ chLatin_O, chLatin_D, chLatin_B, chLatin_C,
  chLatin_R, chLatin_e, chLatin_p, chLatin_l, chLatin_a, chLatin_y,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::ODBCSessionCache[] =
{ chLatin_O, chLatin_D, chLatin_B, chLatin_C,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::OutOfProcess[] =
{ chLatin_O, chLatin_u, chLatin_t, chLatin_O, chLatin_f,
  chLatin_P, chLatin_r, chLatin_o, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull
};

const XMLCh XML::Literals::Path[]= { chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::path[]= { chLatin_p, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::RelyingParty[] =
{ chLatin_R, chLatin_e, chLatin_l, chLatin_y, chLatin_i, chLatin_n, chLatin_g, chLatin_P, chLatin_a, chLatin_r, chLatin_t, chLatin_y, chNull };

const XMLCh XML::Literals::ReplayCache[] =
{ chLatin_R, chLatin_e, chLatin_p, chLatin_l, chLatin_a, chLatin_y, chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull };

const XMLCh XML::Literals::RequestMap[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_M, chLatin_a, chLatin_p, chNull };

const XMLCh XML::Literals::RequestMapProvider[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_M, chLatin_a, chLatin_p,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::SessionCache[] =
{ chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::SessionInitiator[] =
{ chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_I, chLatin_n, chLatin_i, chLatin_t, chLatin_i, chLatin_a, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::SHAR[]= { chLatin_S, chLatin_H, chLatin_A, chLatin_R, chNull };

const XMLCh XML::Literals::ShibbolethTargetConfig[] =
{ chLatin_S, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h,
  chLatin_T, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t,
  chLatin_C, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chNull
};

const XMLCh XML::Literals::SHIRE[]= { chLatin_S, chLatin_H, chLatin_I, chLatin_R, chLatin_E, chNull };

const XMLCh XML::Literals::Signing[] = { chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_i, chLatin_n, chLatin_g, chNull };

const XMLCh XML::Literals::SingleLogoutService[] =
{ chLatin_S, chLatin_i, chLatin_n, chLatin_g, chLatin_l, chLatin_e,
  chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::SPConfig[] =
{ chLatin_S, chLatin_P, chLatin_C, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chNull };

const XMLCh XML::Literals::TCPListener[] =
{ chLatin_T, chLatin_C, chLatin_P, chLatin_L, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::TLS[]= { chLatin_T, chLatin_L, chLatin_S, chNull };

const XMLCh XML::Literals::TrustProvider[] =
{ chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::type[]= { chLatin_t, chLatin_y, chLatin_p, chLatin_e, chNull };

const XMLCh XML::Literals::UnixListener[] =
{ chLatin_U, chLatin_n, chLatin_i, chLatin_x, chLatin_L, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_e, chLatin_r, chNull };
