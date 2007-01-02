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

/* XMLCredentials.cpp - a credentials implementation that uses an XML file

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>
#include <shibsp/exceptions.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace shibboleth;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;
using xmlsignature::CredentialResolver;

namespace {
    
    class XMLCredentialsImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLCredentialsImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLCredentialsImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
        ~XMLCredentialsImpl();
        
        typedef map<string,CredentialResolver*> resolvermap_t;
        resolvermap_t m_resolverMap;
    };

    class XMLCredentials : public ICredentials, public ReloadableXMLFile
    {
    public:
        XMLCredentials(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLCredentials() {}
        
        CredentialResolver* lookup(const char* id) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };

}

saml::IPlugIn* XMLCredentialsFactory(const DOMElement* e)
{
    auto_ptr<XMLCredentials> creds(new XMLCredentials(e));
    creds->getImplementation();
    return creds.release();
}

ReloadableXMLFileImpl* XMLCredentials::newImplementation(const char* pathname, bool first) const
{
    return new XMLCredentialsImpl(pathname);
}

ReloadableXMLFileImpl* XMLCredentials::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLCredentialsImpl(e);
}

static const XMLCh Id[] = UNICODE_LITERAL_2(I,d);
static const XMLCh type[] = UNICODE_LITERAL_4(t,y,p,e);
static const XMLCh FileResolver[] = UNICODE_LITERAL_12(F,i,l,e,R,e,s,o,l,v,e,r);

void XMLCredentialsImpl::init()
{
#ifdef _DEBUG
    NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Credentials");

    DOMElement* child=XMLHelper::getFirstChildElement(m_root);
    while (child) {
        string cr_type;
        auto_ptr_char id(child->getAttributeNS(NULL,Id));
        if (!id.get()) {
            child = XMLHelper::getNextSiblingElement(child);
            continue;
        }
        
        if (XMLString::equals(child->getLocalName(),FileResolver))
            cr_type=FILESYSTEM_CREDENTIAL_RESOLVER;
        else {
            xmltooling::auto_ptr_char c(child->getAttributeNS(NULL,type));
            cr_type=c.get();
        }
        
        if (!cr_type.empty()) {
            try {
                CredentialResolver* plugin=
                    XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(cr_type.c_str(),child);
                m_resolverMap[id.get()] = plugin;
            }
            catch (exception& e) {
                log.error("failed to instantiate credential resolver (%s): %s", id.get(), e.what());
            }
        }
        else {
            log.error("unknown type of credential resolver (%s)", id.get());
        }
        
        child = XMLHelper::getNextSiblingElement(child);
    }
}

XMLCredentialsImpl::~XMLCredentialsImpl()
{
    for_each(m_resolverMap.begin(),m_resolverMap.end(),xmltooling::cleanup_pair<string,CredentialResolver>());
}

CredentialResolver* XMLCredentials::lookup(const char* id) const
{
    if (id) {
        XMLCredentialsImpl* impl=dynamic_cast<XMLCredentialsImpl*>(getImplementation());
        XMLCredentialsImpl::resolvermap_t::const_iterator i=impl->m_resolverMap.find(id);
        if (i!=impl->m_resolverMap.end())
            return i->second;
    }
    return NULL;
}
