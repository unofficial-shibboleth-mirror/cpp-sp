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
 * @file shibsp/base.h
 *
 * Base header file definitions
 * Must be included prior to including any other header
 */

#ifndef __shibsp_base_h__
#define __shibsp_base_h__

#if defined (_MSC_VER) || defined(__BORLANDC__)
  #include <shibsp/config_pub_win32.h>
#else
  #include <shibsp/config_pub.h>
#endif

// Windows and GCC4 Symbol Visibility Macros
#ifdef WIN32
  #define SHIBSP_IMPORT
  #define SHIBSP_EXPORT
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

/**
 * Blocks copy c'tor and assignment operator for a class.
 */
#define MAKE_NONCOPYABLE(type) \
    private: \
        type(const type&) = delete; \
        type& operator=(const type&) = delete; \
        type(const type&&) = delete; \
        type& operator=(type&&) = delete

/** Logging category for Service Provider functions. */
#define SHIBSP_LOGCAT "Shibboleth"

/** Logging category for Service Provider auditing. */
#define SHIBSP_TX_LOGCAT "Shibboleth-TRANSACTION"

/** Default name of configuration file. */
# define SHIBSP_CONFIG  "agent.ini"

#ifdef WIN32

/** Default prefix for installation (used to resolve relative paths). */
#define SHIBSP_PREFIX   "c:/opt/shibboleth-sp"

#ifdef _WIN64

/** Library directory for installation (used to resolve relative paths). */
#define SHIBSP_LIBDIR   "lib64"

#else

/** Library directory for installation (used to resolve relative paths). */
#define SHIBSP_LIBDIR   "lib"

#endif

/** Log directory for installation (used to resolve relative paths). */
#define SHIBSP_LOGDIR   "var/log"

/** Configuration directory for installation (used to resolve relative paths). */
#define SHIBSP_CFGDIR   "etc"

/** Runtime state directory for installation (used to resolve relative paths). */
#define SHIBSP_RUNDIR   "var/run"

/** Cache directory for installation (used to resolve relative paths). */
#define SHIBSP_CACHEDIR "var/cache"

#else
# include <shibsp/paths.h>
#endif

#endif /* __shibsp_base_h__ */
