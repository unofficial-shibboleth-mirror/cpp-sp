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
    XMLCredentials* creds=new XMLCredentials(e);
    try {
        creds->getImplementation();
    }
    catch (...) {
        delete creds;
        throw;
    }
    return creds;    
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
    NDC ndc("XMLCredentialsImpl");
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".XMLCredentialsImpl");

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
        for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
            delete j->second;
        throw;
    }
    catch (...) {
        log.error("Unexpected error while parsing creds configuration");
        for (resolvermap_t::iterator j=m_resolverMap.begin(); j!=m_resolverMap.end(); j++)
            delete j->second;
        throw;
    }
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
