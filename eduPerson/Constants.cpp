/* Constants.cpp - eduPerson URI constants

   Scott Cantor
   6/21/02

   $History:$
*/

#ifdef WIN32
# define EDUPERSON_EXPORTS __declspec(dllexport)
#endif

#include <eduPerson.h>

const XMLCh eduPerson::XML::EDUPERSON_NS[] = // urn:mace:eduPerson:1.0
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
  chDigit_1, chPeriod, chDigit_0, chNull
};

const XMLCh eduPerson::XML::EDUPERSON_SCHEMA_ID[] = // eduPerson.xsd
{ chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chPeriod,
  chLatin_x, chLatin_s, chLatin_d, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_PRINCIPAL_NAME[] = // urn:mace:eduPerson:1.0:eduPersonPrincipalName
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_i, chLatin_n, chLatin_c, chLatin_i, chLatin_p, chLatin_a, chLatin_l,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_AFFILIATION[] = // urn:mace:eduPerson:1.0:eduPersonAffiliation
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_A, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_PRIMARY_AFFILIATION[] = // urn:mace:eduPerson:1.0:eduPersonPrimaryAffiliation
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_i, chLatin_m, chLatin_a, chLatin_r, chLatin_y,
  chLatin_A, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_ENTITLEMENT[] = // urn:mace:eduPerson:1.0:eduPersonEntitlement
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
  chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_E, chLatin_n, chLatin_t, chLatin_i, chLatin_t, chLatin_l, chLatin_e, chLatin_m, chLatin_e, chLatin_n, chLatin_t, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_PRINCIPAL_NAME_TYPE[] = // eduPersonPrincipalNameType
{ chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_P, chLatin_r, chLatin_i, chLatin_n, chLatin_c, chLatin_i, chLatin_p, chLatin_a, chLatin_l,
  chLatin_N, chLatin_a, chLatin_m, chLatin_e, chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull
};

const XMLCh eduPerson::Constants::EDUPERSON_AFFILIATION_TYPE[] = // eduPersonAffiliationType
{ chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n,
  chLatin_A, chLatin_f, chLatin_f, chLatin_i, chLatin_l, chLatin_i, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n,
  chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull
};
