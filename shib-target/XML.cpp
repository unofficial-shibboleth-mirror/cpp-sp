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

using namespace shibtarget;

const char XML::htaccessType[] =            "edu.internet2.middleware.shibboleth.target.provider.htaccess";
const char XML::MemorySessionCacheType[] =  "edu.internet2.middleware.shibboleth.target.provider.MemorySessionCache";
const char XML::MySQLSessionCacheType[] =   "edu.internet2.middleware.shibboleth.target.provider.MySQLSessionCache";
const char XML::RequestMapType[] =          "edu.internet2.middleware.shibboleth.target.provider.XMLRequestMap";
const char XML::TCPListenerType[] =         "edu.internet2.middleware.shibboleth.target.provider.TCPListener";
const char XML::UnixListenerType[] =        "edu.internet2.middleware.shibboleth.target.provider.UnixListener";

const XMLCh XML::SHIBTARGET_SCHEMA_ID[] = // shibboleth-targetconfig-1.0.xsd
{ chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chDash,
  chLatin_t, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t, chLatin_c, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chDash,
  chDigit_1, chPeriod, chDigit_0, chPeriod, chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh XML::Literals::AAPProvider[] =
{ chLatin_A, chLatin_A, chLatin_P, chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::AccessControlProvider[] =
{ chLatin_A, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s,
  chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_r, chLatin_o, chLatin_l,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::applicationId[] =
{ chLatin_a, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_I, chLatin_d, chNull
};

const XMLCh XML::Literals::Application[] =
{ chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::Applications[] =
{ chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chNull };

const XMLCh XML::Literals::CredentialsProvider[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l, chLatin_s,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::CredentialUse[] =
{ chLatin_C, chLatin_r, chLatin_e, chLatin_d, chLatin_e, chLatin_n, chLatin_t, chLatin_i, chLatin_a, chLatin_l,
  chLatin_U, chLatin_s, chLatin_e, chNull
};

const XMLCh XML::Literals::Extensions[] =
{ chLatin_E, chLatin_x, chLatin_t, chLatin_e, chLatin_n, chLatin_s, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chNull };

const XMLCh XML::Literals::fatal[]= { chLatin_f, chLatin_a, chLatin_t, chLatin_a, chLatin_l, chNull };

const XMLCh XML::Literals::FederationProvider[] =
{ chLatin_F, chLatin_e, chLatin_d, chLatin_e, chLatin_r, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::Host[]= { chLatin_H, chLatin_o, chLatin_s, chLatin_t, chNull };

const XMLCh XML::Literals::htaccess[]=
{ chLatin_h, chLatin_t, chLatin_a, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull };

const XMLCh XML::Literals::Implementation[] =
{ chLatin_I, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };

const XMLCh XML::Literals::Library[] =
{ chLatin_L, chLatin_i, chLatin_b, chLatin_r, chLatin_a, chLatin_r, chLatin_y, chNull };

const XMLCh XML::Literals::Listener[] =
{ chLatin_L, chLatin_i, chLatin_s, chLatin_t, chLatin_e, chLatin_n, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::logger[] = { chLatin_l, chLatin_o, chLatin_g, chLatin_g, chLatin_e, chLatin_r, chNull };

const XMLCh XML::Literals::MemorySessionCache[] =
{ chLatin_M, chLatin_e, chLatin_m, chLatin_o, chLatin_r, chLatin_y,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::MySQLSessionCache[] =
{ chLatin_M, chLatin_y, chLatin_S, chLatin_Q, chLatin_L,
  chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::name[]= { chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::Name[]= { chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };

const XMLCh XML::Literals::Path[]= { chLatin_P, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::path[]= { chLatin_p, chLatin_a, chLatin_t, chLatin_h, chNull };

const XMLCh XML::Literals::RelyingParty[] =
{ chLatin_R, chLatin_e, chLatin_l, chLatin_y, chLatin_i, chLatin_n, chLatin_g, chLatin_P, chLatin_a, chLatin_r, chLatin_t, chLatin_y, chNull };

const XMLCh XML::Literals::RequestMap[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_M, chLatin_a, chLatin_p, chNull };

const XMLCh XML::Literals::RequestMapProvider[] =
{ chLatin_R, chLatin_e, chLatin_q, chLatin_u, chLatin_e, chLatin_s, chLatin_t, chLatin_M, chLatin_a, chLatin_p,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::RevocationProvider[] =
{ chLatin_R, chLatin_e, chLatin_v, chLatin_o, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_o, chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_r, chNull
};

const XMLCh XML::Literals::SessionCache[] =
{ chLatin_S, chLatin_e, chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n,
  chLatin_C, chLatin_a, chLatin_c, chLatin_h, chLatin_e, chNull
};

const XMLCh XML::Literals::SHAR[]= { chLatin_S, chLatin_H, chLatin_A, chLatin_R, chNull };

const XMLCh XML::Literals::ShibbolethTargetConfig[] =
{ chLatin_S, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h,
  chLatin_T, chLatin_a, chLatin_r, chLatin_g, chLatin_e, chLatin_t,
  chLatin_C, chLatin_o, chLatin_n, chLatin_f, chLatin_i, chLatin_g, chNull
};

const XMLCh XML::Literals::SHIRE[]= { chLatin_S, chLatin_H, chLatin_I, chLatin_R, chLatin_E, chNull };

const XMLCh XML::Literals::Signing[] = { chLatin_S, chLatin_i, chLatin_g, chLatin_n, chLatin_i, chLatin_n, chLatin_g, chNull };

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
