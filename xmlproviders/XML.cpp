/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* XML.cpp - XML constants

   Scott Cantor
   6/4/02

   $History:$
*/

#include "internal.h"

// Namespace and schema string literals

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

const XMLCh XML::TRUST_NS[] = // urn:mace:shibboleth:trust:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_t, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chColon, chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::TRUST_SCHEMA_ID[] = // shibboleth-trust-1.0.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chDash,
  chLatin_t, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chDash, chDigit_1, chPeriod, chDigit_0, chPeriod,
  chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::SHIB_NS[] = // urn:mace:shibboleth:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::SHIB_SCHEMA_ID[] = // shibboleth.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, 
  chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::SAML2ASSERT_NS[] = // urn:oasis:names:tc:SAML:2.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::SAML2ASSERT_SCHEMA_ID[] = // sstc-saml-schema-assertion-2.0.xsd
{ chLatin_s, chLatin_s, chLatin_t, chLatin_c, chDash, chLatin_s, chLatin_a, chLatin_m, chLatin_l, chDash,
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

const XMLCh XML::SAML2META_SCHEMA_ID[] = // sstc-saml-schema-metadata-2.0.xsd
{ chLatin_s, chLatin_s, chLatin_t, chLatin_c, chDash, chLatin_s, chLatin_a, chLatin_m, chLatin_l, chDash,
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

const XMLCh XML::XMLSIG_RETMETHOD_RAWX509[] = // http://www.w3.org/2000/09/xmldsig#rawX509Certificate
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w, chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_0, chForwardSlash, chDigit_0, chDigit_9, chForwardSlash,
  chLatin_x, chLatin_m, chLatin_l, chLatin_d, chLatin_s, chLatin_i, chLatin_g, chPound,
  chLatin_r, chLatin_a, chLatin_w, chLatin_X, chDigit_5, chDigit_0, chDigit_9,
    chLatin_C, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_e, chNull
};

const XMLCh XML::XMLSIG_RETMETHOD_RAWX509CRL[] = // // http://www.w3.org/2000/09/xmldsig-more#rawX509CRL
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w, chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_0, chForwardSlash, chDigit_0, chDigit_9, chForwardSlash,
  chLatin_x, chLatin_m, chLatin_l, chLatin_d, chLatin_s, chLatin_i, chLatin_g, chDash,
  chLatin_m, chLatin_o, chLatin_r, chLatin_e, chPound,
  chLatin_r, chLatin_a, chLatin_w, chLatin_X, chDigit_5, chDigit_0, chDigit_9, chLatin_C, chLatin_R, chLatin_L, chNull
};

const XMLCh XML::SHIB_RETMETHOD_PEMX509[] = // urn:mace:shibboleth:RetrievalMethod:pemX509Certificate
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_R, chLatin_e, chLatin_t, chLatin_r, chLatin_i, chLatin_e, chLatin_v, chLatin_a, chLatin_l,
  chLatin_M, chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chColon,
  chLatin_p, chLatin_e, chLatin_m, chLatin_X, chDigit_5, chDigit_0, chDigit_9,
    chLatin_C, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_e, chNull
};

const XMLCh XML::SHIB_RETMETHOD_PEMX509CRL[] = // urn:mace:shibboleth:RetrievalMethod:pemX509CRL
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chLatin_R, chLatin_e, chLatin_t, chLatin_r, chLatin_i, chLatin_e, chLatin_v, chLatin_a, chLatin_l,
  chLatin_M, chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chColon,
  chLatin_p, chLatin_e, chLatin_m, chLatin_X, chDigit_5, chDigit_0, chDigit_9, chLatin_C, chLatin_R, chLatin_L, chNull
};

// Shibboleth vocabulary literals

const XMLCh XML::Literals::Scope[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chNull };

const XMLCh XML::Literals::AttributeAuthority[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_y, chNull
};

const XMLCh XML::Literals::Contact[]=
{ chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_a, chLatin_c, chLatin_t, chNull };

const XMLCh XML::Literals::Domain[]=
{ chLatin_D, chLatin_o, chLatin_m, chLatin_a, chLatin_i, chLatin_n, chNull };

const XMLCh XML::Literals::Email[]=
{ chLatin_E, chLatin_m, chLatin_a, chLatin_i, chLatin_l, chNull };

const XMLCh XML::Literals::ErrorURL[]=
{ chLatin_E, chLatin_r, chLatin_r, chLatin_o, chLatin_r, chLatin_U, chLatin_R, chLatin_L, chNull };

const XMLCh XML::Literals::HandleService[]=
{ chLatin_H, chLatin_a, chLatin_n, chLatin_d, chLatin_l, chLatin_e,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull };

const XMLCh XML::Literals::InvalidHandle[]=
{ chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d,
  chLatin_H, chLatin_a, chLatin_n, chLatin_d, chLatin_l, chLatin_e, chNull };

const XMLCh XML::Literals::Location[]=
{ chLatin_L, chLatin_o, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::Name[]=
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::OriginSite[]=
{ chLatin_O, chLatin_r, chLatin_i, chLatin_g, chLatin_i, chLatin_n, chLatin_S, chLatin_i, chLatin_t, chLatin_e, chNull };

const XMLCh XML::Literals::SiteGroup[]=
{ chLatin_S, chLatin_i, chLatin_t, chLatin_e, chLatin_G, chLatin_r, chLatin_o, chLatin_u, chLatin_p, chNull };

const XMLCh XML::Literals::CAPath[] =
{ chLatin_C, chLatin_A, chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::Class[] =
{ chLatin_c, chLatin_l, chLatin_a, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::Credentials[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s, chNull };

const XMLCh XML::Literals::CustomResolver[]=
{ chLatin_C, chLatin_u, chLatin_s, chLatin_t, chLatin_o, chLatin_m,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Exponent[] =
{ chLatin_E, chLatin_x, chLatin_p, chLatin_o, chLatin_n, chLatin_e, chLatin_n, chLatin_t, chNull };

const XMLCh XML::Literals::FileResolver[]=
{ chLatin_F, chLatin_i, chLatin_l, chLatin_e,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::format[] =
{ chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chNull };

const XMLCh XML::Literals::Id[] = { chLatin_I, chLatin_d, chNull };

const XMLCh XML::Literals::KeyAuthority[] =
{ chLatin_K, chLatin_e, chLatin_y,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_y, chNull };

const XMLCh XML::Literals::KeyName[] =
{ chLatin_K, chLatin_e, chLatin_y, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::Modulus[] =
{ chLatin_M, chLatin_o, chLatin_d, chLatin_u, chLatin_l, chLatin_u, chLatin_s, chNull };

const XMLCh XML::Literals::password[] =
{ chLatin_p, chLatin_a, chLatin_s, chLatin_s, chLatin_w, chLatin_o, chLatin_r, chLatin_d, chNull };

const XMLCh XML::Literals::Path[] =
{ chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::RetrievalMethod[] =
{ chLatin_R, chLatin_e, chLatin_t, chLatin_r, chLatin_i, chLatin_e, chLatin_v, chLatin_a, chLatin_l,
  chLatin_M, chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chNull };

const XMLCh XML::Literals::RSAKeyValue[] =
{ chLatin_R, chLatin_S, chLatin_A, chLatin_K, chLatin_e, chLatin_y, chLatin_V, chLatin_a, chLatin_l, chLatin_u, chLatin_e, chNull };

const XMLCh XML::Literals::Trust[] =
{ chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chNull };

const XMLCh XML::Literals::URI[] =
{ chLatin_U, chLatin_R, chLatin_I, chNull };

const XMLCh XML::Literals::VerifyDepth[] =
{ chLatin_V, chLatin_e, chLatin_r, chLatin_i, chLatin_f, chLatin_y, chLatin_D, chLatin_e, chLatin_p, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::X509CRL[] =
{ chLatin_X, chDigit_5, chDigit_0, chDigit_9, chLatin_C, chLatin_R, chLatin_L, chNull };

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

const XMLCh XML::Literals::Namespace[]=
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chNull };

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

const XMLCh XML::Literals::administrative[] =
{ chLatin_a, chLatin_m, chLatin_i, chLatin_n, chLatin_i, chLatin_s, chLatin_t, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_v, chLatin_e, chNull };

const XMLCh XML::Literals::billing[] =
{ chLatin_b, chLatin_i, chLatin_l, chLatin_l, chLatin_i, chLatin_n, chLatin_g, chNull };

const XMLCh XML::Literals::other[] =
{ chLatin_o, chLatin_t, chLatin_h, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::support[] =
{ chLatin_s, chLatin_u, chLatin_p, chLatin_p, chLatin_o, chLatin_r, chLatin_t, chNull };

const XMLCh XML::Literals::technical[] =
{ chLatin_t, chLatin_e, chLatin_c, chLatin_h, chLatin_n, chLatin_i, chLatin_c, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::url[] = { chLatin_u, chLatin_r, chLatin_l, chNull };

const XMLCh XML::Literals::AdditionalMetadataLocation[] =
{ chLatin_A, chLatin_d, chLatin_d, chLatin_i, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_a, chLatin_l,
  chLatin_M, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a,
  chLatin_L, chLatin_o, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::AffiliateMember[] =
{ chLatin_A, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_e,
  chLatin_M, chLatin_e, chLatin_m, chLatin_b, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::AffiliationDescriptor[] =
{ chLatin_A, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::affiliationOwnerID[] =
{ chLatin_a, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_O, chLatin_w, chLatin_n, chLatin_e, chLatin_r, chLatin_I, chLatin_D, chNull
};

const XMLCh XML::Literals::Algorithm[] =
{ chLatin_A, chLatin_l, chLatin_g, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_h, chLatin_m, chNull };

const XMLCh XML::Literals::ArtifactResolutionService[] =
{ chLatin_A, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_a, chLatin_c, chLatin_t,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_u, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AssertionConsumerService[] =
{ chLatin_A, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_o, chLatin_n, chLatin_s, chLatin_u, chLatin_m, chLatin_e, chLatin_r,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AssertionIDRequestService[] =
{ chLatin_A, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_I, chLatin_D,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AttributeAuthorityDescriptor[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_y,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::AttributeConsumingService[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_C, chLatin_o, chLatin_n, chLatin_s, chLatin_u, chLatin_m, chLatin_i, chLatin_n, chLatin_g,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AttributeProfile[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_P, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chNull
};

const XMLCh XML::Literals::AttributeService[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AuthnAuthorityDescriptor[] =
{ chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_y,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::AuthnQueryService[] =
{ chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n, chLatin_Q, chLatin_u, chLatin_e, chLatin_r, chLatin_y,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::AuthnRequestsSigned[] =
{ chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_s,
  chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_e, chLatin_d, chNull
};

const XMLCh XML::Literals::AuthzService[] =
{ chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_z,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::cacheDuration[] =
{ chLatin_c, chLatin_a, chLatin_c, chLatin_h, chLatin_e,
  chLatin_D, chLatin_u, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::Company[] =
{ chLatin_C, chLatin_o, chLatin_m, chLatin_p, chLatin_a, chLatin_n, chLatin_y, chNull };

const XMLCh XML::Literals::ContactPerson[] =
{ chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_a, chLatin_c, chLatin_t,
  chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::contactType[] =
{ chLatin_c, chLatin_o, chLatin_n, chLatin_t, chLatin_a, chLatin_c, chLatin_t, chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull };

const XMLCh XML::Literals::EmailAddress[] =
{ chLatin_E, chLatin_m, chLatin_a, chLatin_i, chLatin_l,
  chLatin_A, chLatin_d, chLatin_d, chLatin_r, chLatin_e, chLatin_s, chLatin_s, chNull
};

const XMLCh XML::Literals::encryption[] =
{ chLatin_e, chLatin_n, chLatin_c, chLatin_r, chLatin_y, chLatin_p, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::EncryptionMethod[] =
{ chLatin_E, chLatin_n, chLatin_c, chLatin_r, chLatin_y, chLatin_p, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_M, chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chNull
};

const XMLCh XML::Literals::EntitiesDescriptor[] =
{ chLatin_E, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_i, chLatin_e, chLatin_s,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::EntityDescriptor[] =
{ chLatin_E, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_y,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::entityID[] =
{ chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_y, chLatin_I, chLatin_D, chNull};

const XMLCh XML::Literals::errorURL[] =
{ chLatin_e, chLatin_r, chLatin_r, chLatin_o, chLatin_r, chLatin_U, chLatin_R, chLatin_L, chNull};

const XMLCh XML::Literals::Extensions[] =
{ chLatin_E, chLatin_x, chLatin_t, chLatin_e, chLatin_n, chLatin_s, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chNull };

const XMLCh XML::Literals::GivenName[] =
{ chLatin_G, chLatin_i, chLatin_v, chLatin_e, chLatin_n, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::IDPSSODescriptor[] =
{ chLatin_I, chLatin_D, chLatin_P, chLatin_S, chLatin_S, chLatin_O,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::index[] =
{ chLatin_i, chLatin_n, chLatin_d, chLatin_e, chLatin_x, chNull };

const XMLCh XML::Literals::isDefault[] =
{ chLatin_i, chLatin_s, chLatin_D, chLatin_e, chLatin_f, chLatin_a, chLatin_u, chLatin_l, chLatin_t, chNull };

const XMLCh XML::Literals::isRequired[] =
{ chLatin_i, chLatin_s, chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_i, chLatin_r, chLatin_e, chLatin_d, chNull };

const XMLCh XML::Literals::KeyDescriptor[] =
{ chLatin_K, chLatin_e, chLatin_y,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::KeySize[] =
{ chLatin_K, chLatin_e, chLatin_y, chLatin_S, chLatin_i, chLatin_z, chLatin_e, chNull };

const XMLCh XML::Literals::ManageNameIDService[] =
{ chLatin_M, chLatin_a, chLatin_n, chLatin_a, chLatin_g, chLatin_e,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_I, chLatin_D,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::NameIDFormat[] =
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_I, chLatin_D,
  chLatin_F, chLatin_o, chLatin_r, chLatin_m, chLatin_a, chLatin_t, chNull
};

const XMLCh XML::Literals::NameIDMappingService[] =
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_I, chLatin_D,
  chLatin_M, chLatin_a, chLatin_p, chLatin_p, chLatin_i, chLatin_n, chLatin_g,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::OAEParams[] =
{ chLatin_O, chLatin_A, chLatin_E, chLatin_P, chLatin_a, chLatin_r, chLatin_a, chLatin_m, chLatin_s, chNull };

const XMLCh XML::Literals::Organization[] =
{ chLatin_O, chLatin_r, chLatin_g, chLatin_a, chLatin_n, chLatin_i, chLatin_z, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::OrganizationName[] =
{ chLatin_O, chLatin_r, chLatin_g, chLatin_a, chLatin_n, chLatin_i, chLatin_z, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh XML::Literals::OrganizationDisplayName[] =
{ chLatin_O, chLatin_r, chLatin_g, chLatin_a, chLatin_n, chLatin_i, chLatin_z, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_D, chLatin_i, chLatin_s, chLatin_p, chLatin_l, chLatin_a, chLatin_y,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh XML::Literals::OrganizationURL[] =
{ chLatin_O, chLatin_r, chLatin_g, chLatin_a, chLatin_n, chLatin_i, chLatin_z, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_U, chLatin_R, chLatin_L, chNull
};

const XMLCh XML::Literals::PDPDescriptor[] =
{ chLatin_P, chLatin_D, chLatin_P,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::protocolSupportEnumeration[] =
{ chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l,
  chLatin_S, chLatin_u, chLatin_p, chLatin_p, chLatin_o, chLatin_r, chLatin_t,
  chLatin_E, chLatin_n, chLatin_u, chLatin_m, chLatin_e, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::RequestedAttribute[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_e, chLatin_d,
  chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chNull
};

const XMLCh XML::Literals::ResponseLocation[] =
{ chLatin_R, chLatin_e, chLatin_s, chLatin_p, chLatin_o, chLatin_n, chLatin_s, chLatin_e,
  chLatin_L, chLatin_o, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::RoleDescriptor[] =
{ chLatin_R, chLatin_o, chLatin_l, chLatin_e,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r,
  chNull
};

const XMLCh XML::Literals::ServiceDescription[] =
{ chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh XML::Literals::ServiceName[] =
{ chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh XML::Literals::signing[] =
{ chLatin_s, chLatin_i, chLatin_g, chLatin_n, chLatin_i, chLatin_n, chLatin_g, chNull };

const XMLCh XML::Literals::SingleLogoutService[] =
{ chLatin_S, chLatin_i, chLatin_n, chLatin_g, chLatin_l, chLatin_e,
  chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::SingleSignOnService[] =
{ chLatin_S, chLatin_i, chLatin_n, chLatin_g, chLatin_l, chLatin_e,
  chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_O, chLatin_n,
  chLatin_S, chLatin_e, chLatin_r, chLatin_v, chLatin_i, chLatin_c, chLatin_e, chNull
};

const XMLCh XML::Literals::SPSSODescriptor[] =
{ chLatin_S, chLatin_P, chLatin_S, chLatin_S, chLatin_O,
  chLatin_D, chLatin_e, chLatin_s, chLatin_c, chLatin_r, chLatin_i, chLatin_p, chLatin_t, chLatin_o, chLatin_r, chNull
};

const XMLCh XML::Literals::SurName[] =
{ chLatin_S, chLatin_u, chLatin_r, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::TelephoneNumber[] =
{ chLatin_T, chLatin_e, chLatin_l, chLatin_e, chLatin_p, chLatin_h, chLatin_o, chLatin_n, chLatin_e,
  chLatin_N, chLatin_u, chLatin_m, chLatin_b, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::use[] = { chLatin_u, chLatin_s, chLatin_e, chNull };

const XMLCh XML::Literals::validUntil[] =
{ chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d, chLatin_U, chLatin_n, chLatin_t, chLatin_i, chLatin_l, chNull };

const XMLCh XML::Literals::WantAuthnRequestsSigned[] =
{ chLatin_W, chLatin_a, chLatin_n, chLatin_t, chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_n,
  chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_s,
  chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_e, chLatin_d, chNull
};

const XMLCh XML::Literals::WantAssertionsSigned[] =
{ chLatin_W, chLatin_a, chLatin_n, chLatin_t,
  chLatin_A, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_s,
  chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_e, chLatin_d, chNull
};
