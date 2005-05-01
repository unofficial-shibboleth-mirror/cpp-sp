/*
 * The Shibboleth License, Version 1.
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
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
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

#include <log4cpp/Category.hh>

#define SHIB_LOGCAT "Shibboleth"

namespace shibboleth {
    class BasicTrust : public ITrust
    {
    public:
        BasicTrust(const DOMElement* e);
        ~BasicTrust();

        bool validate(void* certEE, const saml::Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName=true);
        bool validate(const saml::SAMLSignedObject& token, const IRoleDescriptor* role, ITrust* certValidator=NULL);
    
    protected:
        std::vector<saml::KeyInfoResolver*> m_resolvers;
    };

    class ScopedAttribute : public saml::SAMLAttribute
    {
    public:
        ScopedAttribute(
            const XMLCh* name=NULL,
            const XMLCh* ns=NULL,
            const saml::QName* type=NULL,
            long lifetime=0,
            const saml::Iterator<const XMLCh*>& scopes=EMPTY(const XMLCh*),
            const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*)
            );
        ScopedAttribute(DOMElement* e);
        ScopedAttribute(std::istream& in);
        ~ScopedAttribute();
    
        saml::SAMLObject* clone() const;
        
        saml::Iterator<const XMLCh*> getValues() const;
        saml::Iterator<std::string> getSingleByteValues() const;
        void setValues(const saml::Iterator<const XMLCh*>& values=EMPTY(const XMLCh*));
        void addValue(const XMLCh* value);
        void removeValue(unsigned int index);
        
        static const XMLCh Scope[];
    protected:
        void valueToDOM(unsigned int index, DOMElement* e) const;
        void valueFromDOM(DOMElement* e);
        void ownStrings();
        
        std::vector<const XMLCh*> m_scopes;
        mutable std::vector<const XMLCh*> m_scopedValues;
    };
}

#endif
