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

/* Metadata.h - glue classes that interface to metadata providers

   Scott Cantor
   9/27/02

   $History:$
*/

#include "internal.h"

using namespace shibboleth;
using namespace saml;
using namespace std;

const IEntityDescriptor* Metadata::lookup(const XMLCh* id, bool strict)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    const IEntityDescriptor* ret=NULL;
    m_metadatas.reset();
    while (m_metadatas.hasNext()) {
        m_mapper=m_metadatas.next();
        m_mapper->lock();
        if (ret=m_mapper->lookup(id,strict)) {
            return ret;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
    return NULL;
}

const IEntityDescriptor* Metadata::lookup(const char* id, bool strict)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    const IEntityDescriptor* ret=NULL;
    m_metadatas.reset();
    while (m_metadatas.hasNext()) {
        m_mapper=m_metadatas.next();
        m_mapper->lock();
        if (ret=m_mapper->lookup(id,strict)) {
            return ret;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
    return NULL;
}

const IEntityDescriptor* Metadata::lookup(const SAMLArtifact* artifact)
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    const IEntityDescriptor* ret=NULL;
    m_metadatas.reset();
    while (m_metadatas.hasNext()) {
        m_mapper=m_metadatas.next();
        m_mapper->lock();
        if (ret=m_mapper->lookup(artifact)) {
            return ret;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
    return NULL;
}

Metadata::~Metadata()
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
}

bool Trust::validate(const SAMLSignedObject& token, const IRoleDescriptor* role) const
{
    m_trusts.reset();
    while (m_trusts.hasNext()) {
        if (m_trusts.next()->validate(token,role))
            return true;
    }
    return false;
}

bool Trust::validate(void* certEE, const Iterator<void*>& certChain, const IRoleDescriptor* role, bool checkName) const
{
    m_trusts.reset();
    while (m_trusts.hasNext()) {
        if (m_trusts.next()->validate(certEE,certChain,role,checkName))
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
        m_mapper=m_creds.next();
        m_mapper->lock();
        if (ret=m_mapper->lookup(id)) {
            return ret;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
    return NULL;
}

Credentials::~Credentials()
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const XMLCh* attrName, const XMLCh* attrNamespace) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext()) {
        m_mapper=aaps.next();
        m_mapper->lock();
        if (m_rule=m_mapper->lookup(attrName,attrNamespace)) {
            break;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const char* alias) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext()) {
        m_mapper=aaps.next();
        m_mapper->lock();
        if (m_rule=m_mapper->lookup(alias)) {
            break;
        }
        m_mapper->unlock();
        m_mapper=NULL;
    }
}

AAP::~AAP()
{
    if (m_mapper) {
        m_mapper->unlock();
        m_mapper=NULL;
    }
}

void AAP::apply(const saml::Iterator<IAAP*>& aaps, saml::SAMLAssertion& assertion, const IEntityDescriptor* source)
{
#ifdef _DEBUG
    saml::NDC("apply");
#endif
    log4cpp::Category& log=log4cpp::Category::getInstance(SHIB_LOGCAT".AAP");
    
    // First check for no providers or AnyAttribute.
    if (aaps.size()==0) {
        log.info("no filters specified, accepting entire assertion");
        return;
    }
    aaps.reset();
    while (aaps.hasNext()) {
        IAAP* p=aaps.next();
        Locker locker(p);
        if (p->anyAttribute()) {
            log.info("any attribute enabled, accepting entire assertion");
            return;
        }
    }
    
    // Check each statement.
    const IAttributeRule* rule=NULL;
    Iterator<SAMLStatement*> statements=assertion.getStatements();
    for (unsigned int scount=0; scount < statements.size();) {
        SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(statements[scount]);
        if (!s) {
            scount++;
            continue;
        }
        
        // Check each attribute, applying any matching rules.
        Iterator<SAMLAttribute*> attrs=s->getAttributes();
        for (unsigned long acount=0; acount < attrs.size();) {
            SAMLAttribute* a=attrs[acount];
            bool ruleFound=false;
            aaps.reset();
            while (aaps.hasNext()) {
                IAAP* i=aaps.next();
                Locker locker(i);
                if (rule=i->lookup(a->getName(),a->getNamespace())) {
                    ruleFound=true;
                    try {
                        rule->apply(*a,source);
                    }
                    catch (SAMLException&) {
                        // The attribute is now defunct.
                        log.info("no values remain, removing attribute");
                        s->removeAttribute(acount--);
                        break;
                    }
                }
            }
            if (!ruleFound) {
                if (log.isWarnEnabled()) {
                    auto_ptr_char temp(a->getName());
                    log.warn("no rule found for attribute (%s), filtering it out",temp.get());
                }
                s->removeAttribute(acount--);
            }
            acount++;
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
