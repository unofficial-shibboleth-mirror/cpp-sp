/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * version.h
 *
 * Library version macros and constants.
 */

#ifndef __shibsp_version_h__
#define __shibsp_version_h__

// This is all based on Xerces, on the theory it might be useful to
// support this kind of stuff in the future. If they ever yank some
// of this stuff, it can be copied into here.

#include <shibsp/base.h>

// ---------------------------------------------------------------------------
// V E R S I O N   S P E C I F I C A T I O N

/**
 * MODIFY THESE NUMERIC VALUES TO COINCIDE WITH SHIBSP LIBRARY VERSION
 * AND DO NOT MODIFY ANYTHING ELSE IN THIS VERSION HEADER FILE
 */

#define SHIBSP_VERSION_MAJOR 4
#define SHIBSP_VERSION_MINOR 0
#define SHIBSP_VERSION_REVISION 0

/** DO NOT MODIFY BELOW THIS LINE */

// ---------------------------------------------------------------------------
// T W O   A R G U M E N T   C O N C A T E N A T I O N   M A C R O S

// two argument concatenation routines
#define CAT2_SEP_UNDERSCORE(a, b) #a "_" #b
#define CAT2_SEP_PERIOD(a, b) #a "." #b
#define CAT2_SEP_NIL(a, b) #a #b
#define CAT2_RAW_NUMERIC(a, b) a ## b

// two argument macro invokers
#define INVK_CAT2_SEP_UNDERSCORE(a,b) CAT2_SEP_UNDERSCORE(a,b)
#define INVK_CAT2_SEP_PERIOD(a,b)     CAT2_SEP_PERIOD(a,b)
#define INVK_CAT2_STR_SEP_NIL(a,b)    CAT2_SEP_NIL(a,b)
#define INVK_CAT2_RAW_NUMERIC(a,b)    CAT2_RAW_NUMERIC(a,b)

// ---------------------------------------------------------------------------
// T H R E E   A R G U M E N T   C O N C A T E N A T I O N   M A C R O S

// three argument concatenation routines
#define CAT3_SEP_UNDERSCORE(a, b, c) #a "_" #b "_" #c
#define CAT3_SEP_PERIOD(a, b, c) #a "." #b "." #c
#define CAT3_SEP_NIL(a, b, c) #a #b #c
#define CAT3_RAW_NUMERIC(a, b, c) a ## b ## c
#define CAT3_RAW_NUMERIC_SEP_UNDERSCORE(a, b, c) a ## _ ## b ## _ ## c

// three argument macro invokers
#define INVK_CAT3_SEP_UNDERSCORE(a,b,c) CAT3_SEP_UNDERSCORE(a,b,c)
#define INVK_CAT3_SEP_PERIOD(a,b,c)     CAT3_SEP_PERIOD(a,b,c)
#define INVK_CAT3_SEP_NIL(a,b,c)        CAT3_SEP_NIL(a,b,c)
#define INVK_CAT3_RAW_NUMERIC(a,b,c)    CAT3_RAW_NUMERIC(a,b,c)
#define INVK_CAT3_RAW_NUMERIC_SEP_UNDERSCORE(a,b,c)    CAT3_RAW_NUMERIC_SEP_UNDERSCORE(a,b,c)

// ---------------------------------------------------------------------------
// C A L C U L A T E   V E R S I O N   -   E X P A N D E D   F O R M

#define MULTIPLY(factor,value) factor * value
#define CALC_EXPANDED_FORM(a,b,c) ( MULTIPLY(10000,a) + MULTIPLY(100,b) + MULTIPLY(1,c) )

/**
 * MAGIC THAT AUTOMATICALLY GENERATES THE FOLLOWING:
 *
 *	gShibSPVersionStr, gShibSPFullVersionStr, gShibSPMajVersion, gShibSPMinVersion, gShibSPRevision
 */

// ---------------------------------------------------------------------------
// V E R S I O N   I N F O R M A T I O N

// ShibSP version strings; these particular macros cannot be used for
// conditional compilation as they are not numeric constants

#define SHIBSP_FULLVERSIONSTR INVK_CAT3_SEP_UNDERSCORE(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_FULLVERSIONDOT INVK_CAT3_SEP_PERIOD(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_FULLVERSIONNUM INVK_CAT3_SEP_NIL(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)
#define SHIBSP_VERSIONSTR     INVK_CAT2_SEP_UNDERSCORE(SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR)

extern SHIBSP_API const char* const    gShibSPVersionStr;
extern SHIBSP_API const char* const    gShibSPFullVersionStr;
extern SHIBSP_API const char* const    gShibSPDotVersionStr;
extern SHIBSP_API const unsigned int   gShibSPMajVersion;
extern SHIBSP_API const unsigned int   gShibSPMinVersion;
extern SHIBSP_API const unsigned int   gShibSPRevision;

// ShibSP version numeric constants that can be used for conditional
// compilation purposes.

#define _SHIBSP_VERSION CALC_EXPANDED_FORM (SHIBSP_VERSION_MAJOR,SHIBSP_VERSION_MINOR,SHIBSP_VERSION_REVISION)

#endif /* __shibsp_version_h__ */
