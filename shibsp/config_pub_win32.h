/* if you have the gssapi libraries */
#undef SHIBSP_HAVE_GSSAPI

/* if you have the GNU gssapi libraries */
#undef SHIBSP_HAVE_GSSGNU

/* if you have the Heimdal gssapi libraries */
#undef SHIBSP_HAVE_GSSHEIMDAL

/* if you have the MIT gssapi libraries */
#undef SHIBSP_HAVE_GSSMIT

/* Define to 1 if log4cpp library is used. */
#undef SHIBSP_LOG4CPP

/* Define to 1 if log4shib library is used. */
#define SHIBSP_LOG4SHIB 1

#include <xercesc/util/XercesVersion.hpp>

#if (XERCES_VERSION_MAJOR < 3)
# define SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE 1
# define SHIBSP_XERCESC_SHORT_ACCEPTNODE 1
#endif

#ifndef XMLTOOLING_NO_XMLSEC
# include <xsec/framework/XSECDefs.hpp>
# if (_XSEC_VERSION_FULL >= 10600)
#  define SHIBSP_XMLSEC_WHITELISTING 1
# endif
#endif
