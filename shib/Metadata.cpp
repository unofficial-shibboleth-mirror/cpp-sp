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
#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace std;

OriginMetadata::OriginMetadata(const Iterator<IMetadata*>& metadatas, const XMLCh* site) : m_mapper(NULL), m_site(NULL)
{
    metadatas.reset();
    while (metadatas.hasNext())
    {
        IMetadata* i=metadatas.next();
        i->lock();
        if (m_site=dynamic_cast<const IOriginSite*>(i->lookup(site)))
        {
            m_mapper=i;
            break;
        }
        i->unlock();
    }
}

OriginMetadata::~OriginMetadata()
{
    if (m_mapper)
        m_mapper->unlock();
}

Iterator<XSECCryptoX509*> Trust::getCertificates(const XMLCh* subject)
{
    if (m_mapper)
    {
        m_mapper->unlock();
        m_mapper=NULL;
    }
    
    m_trusts.reset();
    while (m_trusts.hasNext())
    {
        ITrust* i=m_trusts.next();
        i->lock();
        Iterator<XSECCryptoX509*> iter=i->getCertificates(subject);
        if (iter.size())
        {
            m_mapper=i;
            return iter;
        }
        i->unlock();
    }
    return EMPTY(XSECCryptoX509*);
}

bool Trust::validate(const ISite* site, Iterator<XSECCryptoX509*> certs) const
{
    bool ret=false;
    m_trusts.reset();
    while (!ret && m_trusts.hasNext())
    {
        ITrust* i=m_trusts.next();
        i->lock();
        ret=i->validate(site,certs);
        i->unlock();
    }
    return ret;
}

bool Trust::validate(const ISite* site, Iterator<const XMLCh*> certs) const
{
    bool ret=false;
    m_trusts.reset();
    while (!ret && m_trusts.hasNext())
    {
        ITrust* i=m_trusts.next();
        i->lock();
        ret=i->validate(site,certs);
        i->unlock();
    }
    return ret;
}

bool Trust::attach(const ISite* site, SSL_CTX* ctx) const
{
    bool ret=false;
    m_trusts.reset();
    while (!ret && m_trusts.hasNext())
    {
        ITrust* i=m_trusts.next();
        i->lock();
        ret=i->attach(site,ctx);
        i->unlock();
    }
    return ret;
}

Trust::~Trust()
{
    if (m_mapper)
        m_mapper->unlock();
}

bool Credentials::attach(const saml::Iterator<ICredentials*>& creds, const XMLCh* subject, const ISite* relyingParty, SSL_CTX* ctx)
{
    bool ret=false;
    creds.reset();
    while (!ret && creds.hasNext())
    {
        ICredentials* i=creds.next();
        i->lock();
        ret=i->attach(subject,relyingParty,ctx);
        i->unlock();
        
    }
    return ret;
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const XMLCh* attrName, const XMLCh* attrNamespace) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext())
    {
        IAAP* i=aaps.next();
        i->lock();
        if (m_rule=i->lookup(attrName,attrNamespace))
        {
            m_mapper=i;
            break;
        }
        i->unlock();
    }
}

AAP::AAP(const saml::Iterator<IAAP*>& aaps, const char* alias) : m_mapper(NULL), m_rule(NULL)
{
    aaps.reset();
    while (aaps.hasNext())
    {
        IAAP* i=aaps.next();
        i->lock();
        if (m_rule=i->lookup(alias))
        {
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

void AAP::apply(const saml::Iterator<IAAP*>& aaps, const IOriginSite* originSite, saml::SAMLAssertion& assertion)
{
    saml::NDC("apply");
    log4cpp::Category& log=log4cpp::Category::getInstance(SHIB_LOGCAT".AAP");
    
    // Check each statement.
    Iterator<SAMLStatement*> statements=assertion.getStatements();
    for (unsigned int scount=0; scount < statements.size();) {
        SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(statements[scount]);
        if (!s)
            continue;
        
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
