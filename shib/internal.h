/*
 * The OpenSAML License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of OpenSAML nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact opensaml@opensaml.org
 *
 * Products derived from this software may not be called OpenSAML, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may OpenSAML appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* internal.h - internally visible classes

   Scott Cantor
   9/6/02

   $History:$
*/

#ifndef __shib_internal_h__
#define __shib_internal_h__

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include <xmlsec/keysmngr.h>

#include "shib.h"
#include "shib-threads.h"

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth
{
    class SHIB_EXPORTS XMLOriginSiteMapper : public IOriginSiteMapper
    {
    public:
        XMLOriginSiteMapper(const char* registryURI, const char* calist=NULL, const saml::X509Certificate* verifyKey=NULL);
        ~XMLOriginSiteMapper();

        virtual saml::Iterator<saml::xstring> getHandleServiceNames(const XMLCh* originSite);
        virtual const saml::X509Certificate* getHandleServiceCert(const XMLCh* handleService);
        virtual saml::Iterator<std::pair<saml::xstring,bool> > getSecurityDomains(const XMLCh* originSite);
        virtual const char* getTrustedRoots();

    private:
        void validateSignature(const saml::X509Certificate* verifyKey, DOMElement* e);

        struct OriginSite
        {
            std::vector<saml::xstring> m_handleServices;
            std::vector<std::pair<saml::xstring,bool> > m_domains;
        };

        std::string m_calist;
        std::map<saml::xstring,OriginSite*> m_sites;
        std::map<saml::xstring,saml::X509Certificate*> m_hsCerts;
    };

    class AAP
    {
    public:
        AAP(const char* uri);
        bool accept(const XMLCh* name, const XMLCh* originSite, DOMElement* e);

    private:
        struct AttributeRule
        {
            enum value_type { literal, regexp, xpath };
            typedef std::vector<std::pair<value_type,saml::xstring> > SiteRule;
            SiteRule m_anySiteRule;
            std::map<saml::xstring,SiteRule> m_siteMap;
        };

        std::map<saml::xstring,AttributeRule> m_attrMap;
    };

    class ShibInternalConfig : public ShibConfig
    {
    public:
        ShibInternalConfig() : m_AAP(NULL), m_mapper(NULL), m_manager(NULL), m_lock(NULL),
            m_shutdown_wait(NULL), m_refresh_thread(NULL), m_shutdown(false) {}

        // global per-process setup and shutdown of runtime
        bool init();
        void term();

        IOriginSiteMapper* getMapper();
        void releaseMapper(IOriginSiteMapper* mapper);
        void refresh();

        AAP* m_AAP;
    private:
        IOriginSiteMapper* m_mapper;
        xmlSecKeysMngrPtr m_manager;
        RWLock* m_lock;
        static void* refresh_fn(void*);
        bool m_shutdown;
        CondWait* m_shutdown_wait;
        Thread*  m_refresh_thread;
    };
}

#endif
