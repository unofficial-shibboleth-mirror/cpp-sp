/*
 *  Copyright 2001-2007 Internet2
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

/* ShibConfig.cpp - Shibboleth runtime configuration

   Scott Cantor
   6/4/02

   $History:$
*/

#define SHIB_INSTANTIATE
#include "internal.h"

#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <xmltooling/util/Threads.h>

using namespace saml;
using namespace shibboleth;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;


namespace {
    ShibConfig g_config;
    vector<Mutex*> g_openssl_locks;
#ifdef HAVE_GOOD_STL
    map<xmltooling::xstring,const IAttributeFactory*> attrMap;
#else
    map<XMLCh*,const IAttributeFactory*> attrMap;
#endif
}

extern "C" SAMLAttribute* ShibAttributeFactory(DOMElement* e)
{
    // First check for an explicit factory.
#ifdef HAVE_GOOD_STL
    map<xmltooling::xstring,const IAttributeFactory*>::const_iterator i=attrMap.find(e->getAttributeNS(NULL,L(AttributeName)));
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
}

ShibConfig& ShibConfig::getConfig()
{
    return g_config;
}
