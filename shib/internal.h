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
        void removeValue(unsigned long index);
        
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
