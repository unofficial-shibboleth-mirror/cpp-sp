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

/**
 * @file shibsp/base.h
 *
 * Base header file definitions
 * Must be included prior to including any other header
 */

#ifndef __shibsp_base_h__
#define __shibsp_base_h__

#ifdef SHIBSP_LITE
# define XMLTOOLING_LITE
# include <xmltooling/base.h>
#else
# include <saml/base.h>
#endif

#if defined (_MSC_VER) || defined(__BORLANDC__)
  #include <shibsp/config_pub_win32.h>
#else
  #include <shibsp/config_pub.h>
#endif

// Windows and GCC4 Symbol Visibility Macros
#ifdef WIN32
  #define SHIBSP_IMPORT __declspec(dllimport)
  #define SHIBSP_EXPORT __declspec(dllexport)
  #define SHIBSP_DLLLOCAL
  #define SHIBSP_DLLPUBLIC
#else
  #define SHIBSP_IMPORT
  #ifdef GCC_HASCLASSVISIBILITY
    #define SHIBSP_EXPORT __attribute__ ((visibility("default")))
    #define SHIBSP_DLLLOCAL __attribute__ ((visibility("hidden")))
    #define SHIBSP_DLLPUBLIC __attribute__ ((visibility("default")))
  #else
    #define SHIBSP_EXPORT
    #define SHIBSP_DLLLOCAL
    #define SHIBSP_DLLPUBLIC
  #endif
#endif

// Define SHIBSP_API for DLL builds
#ifdef SHIBSP_EXPORTS
  #define SHIBSP_API SHIBSP_EXPORT
#else
  #define SHIBSP_API SHIBSP_IMPORT
#endif

// Throwable classes must always be visible on GCC in all binaries
#ifdef WIN32
  #define SHIBSP_EXCEPTIONAPI(api) api
#elif defined(GCC_HASCLASSVISIBILITY)
  #define SHIBSP_EXCEPTIONAPI(api) SHIBSP_EXPORT
#else
  #define SHIBSP_EXCEPTIONAPI(api)
#endif

#ifdef WIN32

/** Default catalog path on Windows. */
# define SHIBSP_SCHEMAS "c:/opt/shibboleth-sp/share/xml/xmltooling/catalog.xml;c:/opt/shibboleth-sp/share/xml/opensaml/saml20-catalog.xml;c:/opt/shibboleth-sp/share/xml/opensaml/saml11-catalog.xml;c:/opt/shibboleth-sp/share/xml/shibboleth/catalog.xml"

/** Default name of configuration file on Windows. */
# define SHIBSP_CONFIG "shibboleth2.xml"

/**
 * Controls default logging level of console tools and other situations
 * where fully-configured logging isn't used.
 */
#define SHIBSP_LOGGING "console.logger"

/** Default prefix for installation (used to resolve relative paths). */
#define SHIBSP_PREFIX  "c:/opt/shibboleth-sp"

/** Library directory for installation (used to resolve relative paths). */
#define SHIBSP_LIBDIR  "lib"

/** Log directory for installation (used to resolve relative paths). */
#define SHIBSP_LOGDIR  "var/log"

/** Configuration directory for installation (used to resolve relative paths). */
#define SHIBSP_CFGDIR  "etc"

/** Runtime state directory for installation (used to resolve relative paths). */
#define SHIBSP_RUNDIR  "var/run"

/** XML directory for installation (used to resolve relative paths). */
#define SHIBSP_XMLDIR  "share/xml"

#else
# include <shibsp/paths.h>
#endif

/** Logging category for Service Provider functions. */
#define SHIBSP_LOGCAT "Shibboleth"

/** Logging category for Service Provider auditing. */
#define SHIBSP_TX_LOGCAT "Shibboleth-TRANSACTION"

#endif /* __shibsp_base_h__ */
