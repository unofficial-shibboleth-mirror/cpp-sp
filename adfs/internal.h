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

#include <saml/saml.h>
#include <shib/shib.h>
#include <shib-target/shib-target.h>
#include <shib-target/hresult.h>

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#if defined(HAVE_LOG4SHIB)
# include <log4shib/Category.hh>
# include <log4shib/FixedContextCategory.hh>
namespace adfs {
    namespace logging = log4shib;
};
#elif defined(HAVE_LOG4CPP)
# include <log4cpp/Category.hh>
# include <log4cpp/FixedContextCategory.hh>
namespace adfs {
    namespace logging = log4cpp;
};
#else
# error "Supported logging library not available."
#endif


#define ADFS_LOGCAT "shibtarget"
#define SHIBTRAN_LOGCAT "Shibboleth-TRANSACTION"
#define ADFS_L(s) adfs::XML::Literals::s

namespace adfs {

    extern shibtarget::IListener* g_MemoryListener;

    class XML
    {
    public:
        // URI constants
        static const XMLCh WSFED_NS[];          // http://schemas.xmlsoap.org/ws/2003/07/secext
        static const XMLCh WSTRUST_NS[];        // http://schemas.xmlsoap.org/ws/2005/02/trust
        static const XMLCh WSTRUST_SCHEMA_ID[];
        
        struct Literals
        {
            static const XMLCh RequestedSecurityToken[];
            static const XMLCh RequestSecurityTokenResponse[];
        };
    };

    // TODO: Publish these classes for reuse by extensions.
    class CgiParse
    {
    public:
        CgiParse(const char* data, unsigned int len);
        ~CgiParse();
        const char* get_value(const char* name) const;
        
        static char x2c(char *what);
        static void url_decode(char *url);
        static std::string url_encode(const char* s);
    private:
        char * fmakeword(char stop, unsigned int *cl, const char** ppch);
        char * makeword(char *line, char stop);
        void plustospace(char *str);
    
        std::map<std::string,char*> kvp_map;
    };

    // Helper class for SAML 2.0 Common Domain Cookie operations
    class CommonDomainCookie
    {
    public:
        CommonDomainCookie(const char* cookie);
        ~CommonDomainCookie() {}
        saml::Iterator<std::string> get() {return m_list;}
        const char* set(const char* providerId);
        static const char CDCName[];
    private:
        std::string m_encoded;
        std::vector<std::string> m_list;
    };
    
    saml::SAMLAuthenticationStatement* checkAssertionProfile(const saml::SAMLAssertion* a);
}

#endif
