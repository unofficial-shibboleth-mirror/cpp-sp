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

using namespace shibboleth;


// Namespace and schema string literals

const XMLCh XML::SHIB_NS[] = // urn:mace:shibboleth:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, 
  chColon, chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh XML::SHIB_SCHEMA_ID[] = // shibboleth.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, 
  chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};


// Shibboleth vocabulary literals

const XMLCh XML::Literals::AttributeValueType[] =
{ chLatin_A, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e,
  chLatin_V, chLatin_a, chLatin_l, chLatin_u, chLatin_e, chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull
};

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

const XMLCh XML::Literals::CertificateRef[]=
{ chLatin_C, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_f, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_e,
  chLatin_R, chLatin_e, chLatin_f, chNull };

const XMLCh XML::Literals::Class[] =
{ chLatin_C, chLatin_l, chLatin_a, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::Credentials[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s, chNull };

const XMLCh XML::Literals::CustomCredResolver[]=
{ chLatin_C, chLatin_u, chLatin_s, chLatin_t, chLatin_o, chLatin_m, chLatin_C, chLatin_r, chLatin_e, chLatin_d,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Exponent[] =
{ chLatin_E, chLatin_x, chLatin_p, chLatin_o, chLatin_n, chLatin_e, chLatin_n, chLatin_t, chNull };

const XMLCh XML::Literals::FileCredResolver[]=
{ chLatin_F, chLatin_i, chLatin_l, chLatin_e, chLatin_C, chLatin_r, chLatin_e, chLatin_d,
  chLatin_R, chLatin_e, chLatin_s, chLatin_o, chLatin_l, chLatin_v, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Id[] = { chLatin_I, chLatin_d, chNull };

const XMLCh XML::Literals::KeyAuthority[] =
{ chLatin_K, chLatin_e, chLatin_y,
  chLatin_A, chLatin_u, chLatin_t, chLatin_h, chLatin_o, chLatin_r, chLatin_i, chLatin_t, chLatin_y, chNull };

const XMLCh XML::Literals::KeyRef[] =
{ chLatin_K, chLatin_e, chLatin_y, chLatin_R, chLatin_e, chLatin_f, chNull };

const XMLCh XML::Literals::KeyUse[] =
{ chLatin_K, chLatin_e, chLatin_y, chLatin_U, chLatin_s, chLatin_e, chNull };

const XMLCh XML::Literals::Modulus[] =
{ chLatin_M, chLatin_o, chLatin_d, chLatin_u, chLatin_l, chLatin_u, chLatin_s, chNull };

const XMLCh XML::Literals::Password[] =
{ chLatin_P, chLatin_a, chLatin_s, chLatin_s, chLatin_w, chLatin_o, chLatin_r, chLatin_d, chNull };

const XMLCh XML::Literals::Path[] =
{ chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::RelyingParty[] =
{ chLatin_R, chLatin_e, chLatin_l, chLatin_y, chLatin_i, chLatin_n, chLatin_g,
  chLatin_P, chLatin_a, chLatin_r, chLatin_t, chLatin_y, chNull };

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

const XMLCh XML::Literals::Accept[]=
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_p, chLatin_t, chNull };

const XMLCh XML::Literals::Alias[]=
{ chLatin_A, chLatin_l, chLatin_i, chLatin_a, chLatin_s, chNull };

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

const XMLCh XML::Literals::Factory[]=
{ chLatin_F, chLatin_a, chLatin_c, chLatin_t, chLatin_o, chLatin_r, chLatin_y, chNull };

const XMLCh XML::Literals::Header[]=
{ chLatin_H, chLatin_e, chLatin_a, chLatin_d, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::Namespace[]=
{ chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chNull };

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

const XMLCh XML::Literals::technical[] =
{ chLatin_t, chLatin_e, chLatin_c, chLatin_h, chLatin_n, chLatin_i, chLatin_c, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::administrative[] =
{ chLatin_a, chLatin_m, chLatin_i, chLatin_n, chLatin_i, chLatin_s, chLatin_t, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_v, chLatin_e, chNull };

const XMLCh XML::Literals::billing[] =
{ chLatin_b, chLatin_i, chLatin_l, chLatin_l, chLatin_i, chLatin_n, chLatin_g, chNull };

const XMLCh XML::Literals::other[] =
{ chLatin_o, chLatin_t, chLatin_h, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::xmlns_shib[]=
{ chLatin_x, chLatin_m, chLatin_l, chLatin_n, chLatin_s, chColon, chLatin_s, chLatin_h, chLatin_i, chLatin_b, chNull };
