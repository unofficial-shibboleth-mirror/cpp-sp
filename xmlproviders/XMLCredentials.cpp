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

#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

namespace {
    
    class XMLCredentialsImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLCredentialsImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLCredentialsImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
        ~XMLCredentialsImpl();
        
        typedef map<string,ICredResolver*> resolvermap_t;
        resolvermap_t m_resolverMap;
    };

    class XMLCredentials : public ICredentials, public ReloadableXMLFile
    {
    public:
        XMLCredentials(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLCredentials() {}
        
        const ICredResolver* lookup(const char* id) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };

}

IPlugIn* XMLCredentialsFactory(const DOMElement* e)
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

void XMLCredentialsImpl::init()
{
#ifdef _DEBUG
    saml::NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".Credentials");

    try {
        if (!saml::XML::isElementNamed(m_root,::XML::CREDS_NS,SHIB_L(Credentials))) {
            log.error("Construction requires a valid creds file: (creds:Credentials as root element)");
            throw CredentialException("Construction requires a valid creds file: (creds:Credentials as root element)");
        }

        DOMElement* child=saml::XML::getFirstChildElement(m_root);
        while (child) {
            string cr_type;
            auto_ptr<char> id(XMLString::transcode(child->getAttributeNS(NULL,SHIB_L(Id))));
            
            if (saml::XML::isElementNamed(child,::XML::CREDS_NS,SHIB_L(FileResolver)))
                cr_type="edu.internet2.middleware.shibboleth.common.Credentials.FileCredentialResolver";
            else if (saml::XML::isElementNamed(child,::XML::CREDS_NS,SHIB_L(CustomResolver))) {
                auto_ptr_char c(child->getAttributeNS(NULL,SHIB_L(Class)));
                cr_type=c.get();
            }
            
            if (!cr_type.empty()) {
                try {
                    IPlugIn* plugin=SAMLConfig::getConfig().getPlugMgr().newPlugin(cr_type.c_str(),child);
                    ICredResolver* cr=dynamic_cast<ICredResolver*>(plugin);
                    if (cr)
                        m_resolverMap[id.get()]=cr;
                    else {
                        log.error("plugin was not a credential resolver");
                        throw UnsupportedExtensionException("plugin was not a credential resolver");
                    }
                }
                catch (SAMLException& e) {
                    log.error("failed to instantiate credential resolver (%s): %s", id.get(), e.what());
                    throw;
                }
            }
            else {
                log.error("unknown or unimplemented type of credential resolver (%s)", id.get());
                throw CredentialException("Unknown or unimplemented type of credential resolver");
            }
            
            child=saml::XML::getNextSiblingElement(child);
        }
    }
    catch (SAMLException& e) {
        log.errorStream() << "Error while parsing creds configuration: " << e.what() << CategoryStream::ENDLINE;
        this->~XMLCredentialsImpl();
        throw;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("Unexpected error while parsing creds configuration");
        this->~XMLCredentialsImpl();
        throw;
    }
#endif
}

XMLCredentialsImpl::~XMLCredentialsImpl()
{
    for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
        delete j->second;
}

const ICredResolver* XMLCredentials::lookup(const char* id) const
{
    if (id) {
        XMLCredentialsImpl* impl=dynamic_cast<XMLCredentialsImpl*>(getImplementation());
        XMLCredentialsImpl::resolvermap_t::const_iterator i=impl->m_resolverMap.find(id);
        if (i!=impl->m_resolverMap.end())
            return i->second;
    }
    return NULL;
}
