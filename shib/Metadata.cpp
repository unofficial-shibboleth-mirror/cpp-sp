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

OriginMetadata::OriginMetadata(const XMLCh* site) : m_mapper(NULL), m_site(NULL)
{
    Iterator<IMetadata*> it=ShibConfig::getConfig().getMetadataProviders();
    while (it.hasNext())
    {
        IMetadata* i=it.next();
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
    
    Iterator<ITrust*> it=ShibConfig::getConfig().getTrustProviders();
    while (it.hasNext())
    {
        ITrust* i=it.next();
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
    Iterator<ITrust*> it=ShibConfig::getConfig().getTrustProviders();
    while (!ret && it.hasNext())
    {
        ITrust* i=it.next();
        i->lock();
        ret=i->validate(site,certs);
        i->unlock();
    }
    return ret;
}

bool Trust::validate(const ISite* site, Iterator<const XMLCh*> certs) const
{
    bool ret=false;
    Iterator<ITrust*> it=ShibConfig::getConfig().getTrustProviders();
    while (!ret && it.hasNext())
    {
        ITrust* i=it.next();
        i->lock();
        ret=i->validate(site,certs);
        i->unlock();
    }
    return ret;
}

Trust::~Trust()
{
    if (m_mapper)
        m_mapper->unlock();
}

AAP::AAP(const XMLCh* attrName, const XMLCh* attrNamespace) : m_mapper(NULL), m_rule(NULL)
{
    Iterator<IAAP*> it=ShibConfig::getConfig().getAAPProviders();
    while (it.hasNext())
    {
        IAAP* i=it.next();
        i->lock();
        if (m_rule=i->lookup(attrName,attrNamespace))
        {
            m_mapper=i;
            break;
        }
        i->unlock();
    }
}

AAP::AAP(const char* alias) : m_mapper(NULL), m_rule(NULL)
{
    Iterator<IAAP*> it=ShibConfig::getConfig().getAAPProviders();
    while (it.hasNext())
    {
        IAAP* i=it.next();
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
