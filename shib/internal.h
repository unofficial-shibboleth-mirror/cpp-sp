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

#include "shib.h"
#include "shib-threads.h"

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth
{
    class SHIB_EXPORTS XMLOriginSiteMapper : public IOriginSiteMapper
    {
    public:
        XMLOriginSiteMapper(const char* pathname);
        ~XMLOriginSiteMapper();

        virtual const char* getContactName(const XMLCh* originSite) const;
        virtual const char* getContactEmail(const XMLCh* originSite) const;
        virtual const char* getErrorURL(const XMLCh* originSite) const;
        virtual saml::Iterator<saml::xstring> getHandleServiceNames(const XMLCh* originSite) const;
        virtual XSECCryptoX509* getHandleServiceCert(const XMLCh* handleService) const;
        virtual saml::Iterator<std::pair<saml::xstring,bool> > getSecurityDomains(const XMLCh* originSite) const;
        virtual time_t getTimestamp() const { return m_filestamp; }

    private:
        struct OriginSite
        {
            OriginSite(const XMLCh* contactName, const XMLCh* contactEmail, const XMLCh* errorURL) :
                m_contactName(XMLString::transcode(contactName)), m_contactEmail(XMLString::transcode(contactEmail)),
                m_errorURL(XMLString::transcode(errorURL)) {}

            std::auto_ptr<char> m_contactName,m_contactEmail,m_errorURL;
            std::vector<saml::xstring> m_handleServices;
            std::vector<std::pair<saml::xstring,bool> > m_domains;
        };

        std::map<saml::xstring,OriginSite*> m_sites;
        std::map<saml::xstring,XSECCryptoX509*> m_hsCerts;
        time_t m_filestamp;
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
        ShibInternalConfig() : m_AAP(NULL), m_mapper(NULL), m_lock(NULL) {}

        // global per-process setup and shutdown of runtime
        bool init();
        void term();

        IOriginSiteMapper* getMapper();
        void releaseMapper(IOriginSiteMapper* mapper);

        AAP* m_AAP;
    private:
        IOriginSiteMapper* m_mapper;
        RWLock* m_lock;
    };
}

#endif
