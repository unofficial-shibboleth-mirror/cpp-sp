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


/* ShibConfig.cpp - Shibboleth runtime configuration

   Scott Cantor
   6/4/02

   $History:$
*/

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define SHIB_INSTANTIATE

#include "internal.h"
#include "shib-threads.h"

#include <openssl/err.h>

using namespace saml;
using namespace shibboleth;
using namespace log4cpp;
using namespace std;


SAML_EXCEPTION_FACTORY(ResourceAccessException);
SAML_EXCEPTION_FACTORY(MetadataException);
SAML_EXCEPTION_FACTORY(CredentialException);
SAML_EXCEPTION_FACTORY(InvalidHandleException);
SAML_EXCEPTION_FACTORY(InvalidSessionException);

PlugManager::Factory BasicTrustFactory;
PlugManager::Factory ShibbolethTrustFactory;

namespace {
    ShibConfig g_config;
    vector<Mutex*> g_openssl_locks;
#ifdef HAVE_GOOD_STL
    map<xstring,const IAttributeFactory*> attrMap;
#else
    map<XMLCh*,const IAttributeFactory*> attrMap;
#endif
}

extern "C" SAMLAttribute* ShibAttributeFactory(DOMElement* e)
{
    // First check for an explicit factory.
#ifdef HAVE_GOOD_STL
    map<xstring,const IAttributeFactory*>::const_iterator i=attrMap.find(e->getAttributeNS(NULL,L(AttributeName)));
#else
    const XMLCh* aname=e->getAttributeNS(NULL,L(AttributeName));
    map<XMLCh*,const IAttributeFactory*>::const_iterator i;
    for (i=attrMap.begin(); i!=attrMap.end(); i++)
        if (!XMLString::compareString(aname,i->first))
            break;
#endif
    if (i!=attrMap.end())
        return i->second->build(e);

    // Now check for a Scope attribute to ensure proper value handling whenever possible.
    DOMElement* n=saml::XML::getFirstChildElement(e,saml::XML::SAML_NS,L(AttributeValue));
    if (n && n->hasAttributeNS(NULL,ScopedAttribute::Scope))
        return new ScopedAttribute(e);
        
    // Just use the default class.
    return new SAMLAttribute(e);
}

void ShibConfig::regAttributeMapping(const XMLCh* name, const IAttributeFactory* factory)
{
    if (name && factory) {
#ifdef HAVE_GOOD_STL
        attrMap[name]=factory;
#else
        attrMap.insert(make_pair(XMLString::replicate(name),factory));
#endif
    }
}

void ShibConfig::unregAttributeMapping(const XMLCh* name)
{
    if (name) {
#ifdef HAVE_GOOD_STL
        attrMap.erase(name);
#else
        for (map<XMLCh*,const IAttributeFactory*>::iterator i=attrMap.begin(); i!=attrMap.end(); i++) {
            if (!XMLString::compareString(name,i->first)) {
                XMLCh* temp=i->first;
                XMLString::release(&temp);
                attrMap.erase(i);
                break;
            }
        }
#endif
    }
}

void ShibConfig::clearAttributeMappings()
{
#ifndef HAVE_GOOD_STL
    for (map<XMLCh*,const IAttributeFactory*>::iterator i=attrMap.begin(); i!=attrMap.end(); i++) {
        XMLCh* temp=i->first;
        XMLString::release(&temp);
    }
#endif
    attrMap.clear();
}

extern "C" void openssl_locking_callback(int mode,int n,const char *file,int line)
{
    if (mode & CRYPTO_LOCK)
        g_openssl_locks[n]->lock();
    else
        g_openssl_locks[n]->unlock();
}

#ifndef WIN32
extern "C" unsigned long openssl_thread_id(void)
{
    return (unsigned long)(pthread_self());
}
#endif

bool ShibConfig::init()
{
    REGISTER_EXCEPTION_FACTORY(ResourceAccessException);
    REGISTER_EXCEPTION_FACTORY(MetadataException);
    REGISTER_EXCEPTION_FACTORY(CredentialException);
    REGISTER_EXCEPTION_FACTORY(InvalidHandleException);
    REGISTER_EXCEPTION_FACTORY(InvalidSessionException);

    // Register plugin factories (some are legacy aliases)
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.common.provider.BasicTrust",&BasicTrustFactory);
    conf.getPlugMgr().regFactory("edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust",&ShibbolethTrustFactory);

    // Set up OpenSSL locking.
	for (int i=0; i<CRYPTO_num_locks(); i++)
        g_openssl_locks.push_back(Mutex::create());
	CRYPTO_set_locking_callback(openssl_locking_callback);
#ifndef WIN32
    CRYPTO_set_id_callback(openssl_thread_id);
#endif

    SAMLAttribute::setFactory(&ShibAttributeFactory);
    return true;
}

void ShibConfig::term()
{
    SAMLAttribute::setFactory(NULL);
    clearAttributeMappings();
   
    CRYPTO_set_locking_callback(NULL);
    for (vector<Mutex*>::iterator j=g_openssl_locks.begin(); j!=g_openssl_locks.end(); j++)
        delete (*j);
    g_openssl_locks.clear();

    // Unregister plugin factories
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.common.provider.BasicTrust");
    conf.getPlugMgr().unregFactory("edu.internet2.middleware.shibboleth.common.provider.ShibbolethTrust");
}

ShibConfig& ShibConfig::getConfig()
{
    return g_config;
}

void shibboleth::annotateException(SAMLException& e, const IEntityDescriptor* entity, bool rethrow)
{
    if (entity) {
        auto_ptr_char id(entity->getId());
        e.addProperty("providerId",id.get());
        Iterator<const IRoleDescriptor*> roles=entity->getRoleDescriptors();
        while (roles.hasNext()) {
            const IRoleDescriptor* role=roles.next();
            if (role->isValid()) {
                const char* temp=role->getErrorURL();
                if (temp) {
                    e.addProperty("errorURL",temp);
                    break;
                }
            }
        }

        Iterator<const IContactPerson*> i=entity->getContactPersons();
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if ((c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support)) {
                const char* fname=c->getGivenName();
                const char* lname=c->getSurName();
                if (fname && lname) {
                    string contact=string(fname) + ' ' + lname;
                    e.addProperty("contactName",contact.c_str());
                }
                else if (fname)
                    e.addProperty("contactName",fname);
                else if (lname)
                    e.addProperty("contactName",lname);
                Iterator<string> emails=c->getEmailAddresses();
                if (emails.hasNext())
                    e.addProperty("contactEmail",emails.next().c_str());
                break;
            }
        }
    }
    
    if (rethrow)
        throw e;
}

void shibboleth::annotateException(saml::SAMLException& e, const IRoleDescriptor* role, bool rethrow)
{
    if (role) {
        auto_ptr_char id(role->getEntityDescriptor()->getId());
        e.addProperty("providerId",id.get());
        const char* temp=role->getErrorURL();
        if (role->getErrorURL())
            e.addProperty("errorURL",role->getErrorURL());

        Iterator<const IContactPerson*> i=role->getContactPersons();
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if ((c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support)) {
                const char* fname=c->getGivenName();
                const char* lname=c->getSurName();
                if (fname && lname) {
                    string contact=string(fname) + ' ' + lname;
                    e.addProperty("contactName",contact.c_str());
                }
                else if (fname)
                    e.addProperty("contactName",fname);
                else if (lname)
                    e.addProperty("contactName",lname);
                Iterator<string> emails=c->getEmailAddresses();
                if (emails.hasNext())
                    e.addProperty("contactEmail",emails.next().c_str());
                break;
            }
        }
    }
    
    if (rethrow)
        throw e;
}
