/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* internal.h

   Scott Cantor
   2/14/04

   $History:$
*/

#ifndef __internal_h__
#define __internal_h__

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include <shib-target/shib-target.h>
#include <openssl/ssl.h>
#include <xmltooling/util/NDC.h>

#define XMLPROVIDERS_LOGCAT "XMLProviders"

#define SHIB_L(s) ::XML::Literals::s
#define SHIB_L_QNAME(p,s) ::XML::Literals::p##_##s

class XML
{
public:
        // URI constants
    static const XMLCh SHIB_NS[];
    static const XMLCh SHIB_SCHEMA_ID[];

    struct Literals
    {
        // SAML attribute constants
        static const XMLCh Accept[];
        static const XMLCh Alias[];
        static const XMLCh AnyAttribute[];
        static const XMLCh AnySite[];
        static const XMLCh AnyValue[];
        static const XMLCh AttributeAcceptancePolicy[];
        static const XMLCh AttributeRule[];
        static const XMLCh CaseSensitive[];
        static const XMLCh Factory[];
        static const XMLCh Header[];
        static const XMLCh Name[];
        static const XMLCh Namespace[];
        static const XMLCh Scope[];
        static const XMLCh Scoped[];
        static const XMLCh SiteRule[];
        static const XMLCh Type[];
        static const XMLCh Value[];

        static const XMLCh literal[];
        static const XMLCh regexp[];
        static const XMLCh xpath[];

        static const XMLCh url[];
        
        // access control constants
        static const XMLCh AccessControl[];
        static const XMLCh AND[];
        static const XMLCh NOT[];
        static const XMLCh OR[];
        static const XMLCh require[];
        static const XMLCh Rule[];
    };
};

#endif
