/* XML.cpp - XML constants

   Scott Cantor
   6/4/02

   $History:$
*/

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

#include <shib.h>
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

const XMLCh XML::Literals::InvalidHandle[]=
{ chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d,
  chLatin_H, chLatin_a, chLatin_n, chLatin_d, chLatin_l, chLatin_e, chNull };

const XMLCh XML::Literals::xmlns_shib[]=
{ chLatin_x, chLatin_m, chLatin_l, chLatin_n, chLatin_s, chColon, chLatin_s, chLatin_h, chLatin_i, chLatin_b, chNull };
