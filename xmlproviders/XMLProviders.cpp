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


/* XMLProviders.cpp - bootstraps the extension library

   Scott Cantor
   2/14/04

   $History:$
*/

#ifdef WIN32
# define XML_EXPORTS __declspec(dllexport)
#else
# define XML_EXPORTS
#endif

#include "internal.h"
#include <log4cpp/Category.hh>
#include <openssl/err.h>

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;

// Metadata Factories

PlugManager::Factory XMLMetadataFactory;
PlugManager::Factory XMLRevocationFactory;
PlugManager::Factory XMLTrustFactory;
PlugManager::Factory XMLCredentialsFactory;
PlugManager::Factory XMLAAPFactory;
PlugManager::Factory FileCredResolverFactory;


extern "C" SAMLAttribute* ShibAttributeFactory(DOMElement* e)
{
    DOMNode* n=e->getFirstChild();
    while (n && n->getNodeType()!=DOMNode::ELEMENT_NODE)
        n=n->getNextSibling();
    if (n && static_cast<DOMElement*>(n)->hasAttributeNS(NULL,SHIB_L(Scope)))
        return new ScopedAttribute(e);
    return new SAMLAttribute(e);
}

void log_openssl()
{
    const char* file;
    const char* data;
    int flags,line;

    unsigned long code=ERR_get_error_line_data(&file,&line,&data,&flags);
    while (code) {
        Category& log=Category::getInstance("OpenSSL");
        log.errorStream() << "error code: " << code << " in " << file << ", line " << line << CategoryStream::ENDLINE;
        if (data && (flags & ERR_TXT_STRING))
            log.errorStream() << "error data: " << data << CategoryStream::ENDLINE;
        code=ERR_get_error_line_data(&file,&line,&data,&flags);
    }
}

X509* B64_to_X509(const char* buf)
{
    BIO* bmem = BIO_new_mem_buf((void*)buf,-1);
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    X509* x=NULL;
    d2i_X509_bio(b64,&x);
    if (!x)
        log_openssl();
    BIO_free_all(b64);
    return x;
}

X509_CRL* B64_to_CRL(const char* buf)
{
    BIO* bmem = BIO_new_mem_buf((void*)buf,-1);
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    X509_CRL* x=NULL;
    d2i_X509_CRL_bio(b64,&x);
    if (!x)
        log_openssl();
    BIO_free_all(b64);
    return x;
}

extern "C" int XML_EXPORTS saml_extension_init(void*)
{
    // Register extension schemas.
    saml::XML::registerSchema(::XML::SHIB_NS,::XML::SHIB_SCHEMA_ID);
    saml::XML::registerSchema(::XML::TRUST_NS,::XML::TRUST_SCHEMA_ID);
    saml::XML::registerSchema(::XML::CREDS_NS,::XML::CREDS_SCHEMA_ID);

    // Register metadata factories
    ShibConfig& conf=ShibConfig::getConfig();
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.common.provider.XMLMetadata",&XMLMetadataFactory);
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.common.provider.XMLRevocation",&XMLRevocationFactory);
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.common.provider.XMLTrust",&XMLTrustFactory);
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.common.Credentials",&XMLCredentialsFactory);
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.common.Credentials.FileCredentialResolver",&FileCredResolverFactory);
    conf.m_plugMgr.regFactory("edu.internet2.middleware.shibboleth.target.provider.XMLAAP",&XMLAAPFactory);

    SAMLAttribute::setFactory(&ShibAttributeFactory);

    return 0;
}

extern "C" void XML_EXPORTS saml_extension_term()
{
    // Unregister metadata factories
    ShibConfig& conf=ShibConfig::getConfig();
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.common.provider.XMLMetadata");
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.common.provider.XMLRevocation");
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.common.provider.XMLTrust");
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.common.Credentials");
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.common.Credentials.FileCredentialResolver");
    conf.m_plugMgr.unregFactory("edu.internet2.middleware.shibboleth.target.provider.XMLAAP");

    SAMLAttribute::setFactory(NULL);
}
