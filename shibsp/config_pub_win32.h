/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

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
