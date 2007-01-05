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
#include <xmltooling/util/NDC.h>

using namespace shibboleth;
using namespace opensaml::saml2md;
using namespace saml;
using namespace std;

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

void AAP::apply(const saml::Iterator<IAAP*>& aaps, saml::SAMLAssertion& assertion, const RoleDescriptor* role)
{
#ifdef _DEBUG
    xmltooling::NDC("apply");
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
        xmltooling::Locker locker(p);
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
                xmltooling::Locker locker(i);
                if (rule=i->lookup(a->getName(),a->getNamespace())) {
                    ruleFound=true;
                    try {
                        rule->apply(*a,role);
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
