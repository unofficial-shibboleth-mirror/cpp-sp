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

/*
 *  internal.h - internally visible classes
 */

#ifndef __shibsp_internal_h__
#define __shibsp_internal_h__

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif

#if defined (_MSC_VER)
# define _CRT_SECURE_NO_DEPRECATE 1
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _SCL_SECURE_NO_WARNINGS 1
# define XSEC_HAVE_OPENSSL 1
#endif

// Export public APIs
#ifndef SHIBSP_EXPORTS
#define SHIBSP_EXPORTS
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include "base.h"

#include <memory>

#endif /* __shibsp_internal_h__ */
