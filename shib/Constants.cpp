/* Constants.cpp - Shibboleth URI constants

   Scott Cantor
   2/20/02

   $History:$
*/

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

#include <shib.h>

const XMLCh shibboleth::Constants::POLICY_CLUBSHIB[] = // http://middleware.internet2.edu/shibboleth/clubs/clubshib/2002/05/
{ chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
  chLatin_m, chLatin_i, chLatin_d, chLatin_d, chLatin_l, chLatin_e, chLatin_w, chLatin_a, chLatin_r, chLatin_e, chPeriod,
      chLatin_i, chLatin_n, chLatin_t, chLatin_e, chLatin_r, chLatin_n, chLatin_e, chLatin_t, chDigit_2, chPeriod,
      chLatin_e, chLatin_d, chLatin_u, chForwardSlash,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chForwardSlash,
  chLatin_c, chLatin_l, chLatin_u, chLatin_b, chLatin_s, chForwardSlash,
  chLatin_c, chLatin_l, chLatin_u, chLatin_b, chLatin_s, chLatin_h, chLatin_i, chLatin_b, chForwardSlash,
  chDigit_2, chDigit_0, chDigit_0, chDigit_2, chForwardSlash, chDigit_0, chDigit_5, chForwardSlash, chNull
};

const XMLCh shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI[] = // urn:mace:shibboleth:1.0:attributeNamespace:uri
{
  chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_s, chLatin_h, chLatin_i, chLatin_b, chLatin_b, chLatin_o, chLatin_l, chLatin_e, chLatin_t, chLatin_h, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chLatin_p, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_u, chLatin_r, chLatin_i, chNull
};
