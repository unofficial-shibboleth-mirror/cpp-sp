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

/* Metadata.h - glue classes that interface to metadata providers

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

using namespace shibboleth;
using namespace saml;
using namespace std;

const IProvider* Metadata::lookup(const XMLCh* providerId)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    const IProvider* ret=NULL;
    m_metadatas.reset();
    while (m_metadatas.hasNext()) {
        IMetadata* i=m_metadatas.next();
        i->lock();
        if (ret=i->lookup(providerId)) {
            m_mapper=i;
            return ret;
        }
        i->unlock();
    }
    return NULL;
}

Metadata::~Metadata()
{
    if (m_mapper)
        m_mapper->unlock();
}

Iterator<void*> Revocation::getRevocationLists(const IProvider* provider, const IProviderRole* role)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    m_revocations.reset();
    while (m_revocations.hasNext()) {
        IRevocation* i=m_revocations.next();
        i->lock();
        Iterator<void*> ret=i->getRevocationLists(provider,role);
        if (ret.size()) {
            m_mapper=i;
            return ret;
        }
        i->unlock();
    }
    return EMPTY(void*);
}

Revocation::~Revocation()
{
    if (m_mapper)
        m_mapper->unlock();
}

bool Trust::validate(
    const Iterator<IRevocation*>& revocations,
    const IProviderRole* role, const SAMLSignedObject& token,
    const Iterator<IMetadata*>& metadatas) const
{
    m_trusts.reset();
    while (m_trusts.hasNext()) {
        if (m_trusts.next()->validate(revocations,role,token,metadatas))
            return true;
    }
    return false;
}

bool Trust::attach(const Iterator<IRevocation*>& revocations, const IProviderRole* role, void* ctx) const
{
    m_trusts.reset();
    while (m_trusts.hasNext()) {
        if (m_trusts.next()->attach(revocations,role,ctx))
            return true;
    }
    return false;
}

const ICredResolver* Credentials::lookup(const char* id)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    const ICredResolver* ret=NULL;
    m_creds.reset();
    while (m_creds.hasNext()) {
        ICredentials* i=m_creds.next();
        i->lock();
        if (ret=i->lookup(id)) {
            m_mapper=i;
            return ret;
        }
        i->unlock();
    }
    return NULL;
}

Credentials::~Credentials()
{
    if (m_mapper)
        m_mapper->unlock();
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const XMLCh* attrName, const XMLCh* attrNamespace) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext()) {
        IAAP* i=aaps.next();
        i->lock();
        if (m_rule=i->lookup(attrName,attrNamespace)) {
            m_mapper=i;
            break;
        }
        i->unlock();
    }
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const char* alias) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext()) {
        IAAP* i=aaps.next();
        i->lock();
        if (m_rule=i->lookup(alias)) {
            m_mapper=i;
            break;
        }
        i->unlock();
    }
}

AAP::~AAP()
{
    if (m_mapper)
        m_mapper->unlock();
}

void AAP::apply(const saml::Iterator<IAAP*>& aaps, const IProvider* originSite, saml::SAMLAssertion& assertion)
{
    saml::NDC("apply");
    log4cpp::Category& log=log4cpp::Category::getInstance(SHIB_LOGCAT".AAP");
    
    // First check for no providers or AnyAttribute.
    if (aaps.size()==0) {
        log.debug("no filters specified, accepting entire assertion");
        return;
    }
    aaps.reset();
    while (aaps.hasNext()) {
        if (aaps.next()->anyAttribute()) {
            log.debug("any attribute enabled, accepting entire assertion");
            return;
        }
    }
    
    // Check each statement.
    Iterator<SAMLStatement*> statements=assertion.getStatements();
    for (unsigned int scount=0; scount < statements.size();) {
        SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(statements[scount]);
        if (!s) {
            scount++;
            continue;
        }
        
        // Check each attribute.
        Iterator<SAMLAttribute*> attrs=s->getAttributes();
        for (unsigned int acount=0; acount < attrs.size();) {
            SAMLAttribute* a=attrs[acount];

            AAP rule(aaps,a->getName(),a->getNamespace());
            if (rule.fail()) {
                if (log.isWarnEnabled()) {
                    auto_ptr_char temp(a->getName());
                    log.warn("no rule found for attribute (%s), filtering it out",temp.get());
                }
                s->removeAttribute(acount);
                continue;
            }
            
            try {
                rule->apply(originSite,*a);
                acount++;
            }
            catch (SAMLException&) {
                // The attribute is now defunct.
                log.info("no values remain, removing attribute");
                s->removeAttribute(acount);
            }
        }

        try {
            s->checkValidity();
            scount++;
        }
        catch (SAMLException&) {
            // The statement is now defunct.
            log.info("no attributes remain, removing statement");
            assertion.removeStatement(scount);
        }
    }
    
    // Now see if we trashed it irrevocably.
    assertion.checkValidity();
}
