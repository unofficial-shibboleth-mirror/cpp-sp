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

/* ShibPOSTProfile.cpp - Shibboleth-specific wrapper around SAML POST profile

   Scott Cantor
   8/12/02

   $History:$
*/

#include "internal.h"

#include <ctime>

using namespace shibboleth;
using namespace saml;
using namespace std;

ShibPOSTProfile::ShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds)
    : m_ttlSeconds(ttlSeconds), m_algorithm(SAMLSignedObject::RSA_SHA1), m_issuer(NULL)
{
    if (!receiver || !*receiver || ttlSeconds <= 0)
        throw SAMLException(SAMLException::REQUESTER, "ShibPOSTProfile() found a null or invalid argument");

    m_receiver = XMLString::replicate(receiver);

    while (policies.hasNext())
        m_policies.push_back(XMLString::replicate(policies.next()));
}

ShibPOSTProfile::ShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* issuer)
    : m_ttlSeconds(0), m_algorithm(SAMLSignedObject::RSA_SHA1), m_receiver(NULL)
{
    if (!issuer || !*issuer)
        throw SAMLException(SAMLException::REQUESTER, "ShibPOSTProfile() found a null or invalid argument");

    m_issuer = XMLString::replicate(issuer);

    while (policies.hasNext())
        m_policies.push_back(XMLString::replicate(policies.next()));
}

ShibPOSTProfile::~ShibPOSTProfile()
{
    delete[] m_issuer;
    delete[] m_receiver;

    for (vector<const XMLCh*>::iterator i=m_policies.begin(); i!=m_policies.end(); i++)
        delete[] const_cast<XMLCh*>(*i);
}

SAMLAssertion* ShibPOSTProfile::getSSOAssertion(const SAMLResponse& r)
{
    return SAMLPOSTProfile::getSSOAssertion(r,Iterator<const XMLCh*>(m_policies));
}

SAMLAuthenticationStatement* ShibPOSTProfile::getSSOStatement(const SAMLAssertion& a)
{
    return SAMLPOSTProfile::getSSOStatement(a);
}

SAMLResponse* ShibPOSTProfile::accept(const XMLByte* buf)
{
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    SAMLResponse* r = SAMLPOSTProfile::accept(buf, m_receiver, m_ttlSeconds);

    // Now we do some more non-crypto (ie. cheap) work to match up the origin site
    // with its associated data. If we can't even find a SSO statement in the response
    // we just return the response to the caller, who will presumably notice this.
    const SAMLAssertion* assertion = getSSOAssertion(*r);
    if (!assertion)
        return r;

    const SAMLAuthenticationStatement* sso = getSSOStatement(*assertion);
    if (!sso)
        return r;

    // Examine the subject information.
    const SAMLSubject* subject = sso->getSubject();
    if (!subject->getNameQualifier())
        throw SAMLException(SAMLException::RESPONDER, "ShibPOSTProfile::accept() requires subject name qualifier");

    const XMLCh* originSite = subject->getNameQualifier();
    const XMLCh* handleService = assertion->getIssuer();

    // Is this a trusted HS?
    Iterator<xstring> hsNames=ShibConfig::getConfig().origin_mapper->getHandleServiceNames(originSite);
    bool bFound = false;
    while (!bFound && hsNames.hasNext())
        if (!XMLString::compareString(hsNames.next().c_str(),handleService))
            bFound = true;
    if (!bFound)
        throw SAMLException(SAMLException::RESPONDER, "ShibPOSTProfile::accept() detected an untrusted HS for the origin site");

    const Key* hsKey=ShibConfig::getConfig().origin_mapper->getHandleServiceKey(handleService);

    // Signature verification now takes place. We check the assertion and the response.
    // Assertion signing is optional, response signing is mandatory.
    if (assertion->isSigned())
        verifySignature(*assertion, handleService, hsKey);
    verifySignature(*r, handleService, hsKey);

    return r;
}

SAMLResponse* ShibPOSTProfile::prepare(const XMLCh* recipient,
                                       const XMLCh* name,
                                       const XMLCh* nameQualifier,
                                       const XMLCh* subjectIP,
                                       const XMLCh* authMethod,
                                       time_t authInstant,
                                       const Iterator<SAMLAuthorityBinding*>& bindings,
                                       const saml::Key& responseKey, const saml::X509Certificate* responseCert,
                                       const saml::Key* assertionKey, const saml::X509Certificate* assertionCert)
{
#ifdef WIN32
    struct tm* ptime=gmtime(&authInstant);
#else
    struct tm res;
    struct tm* ptime=gmtime_r(&authInstant,&res);
#endif
    char timebuf[32];
    strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
    auto_ptr<XMLCh> timeptr(XMLString::transcode(timebuf));
    XMLDateTime authDateTime(timeptr.get());

    SAMLResponse* r = SAMLPOSTProfile::prepare(recipient,m_issuer,Iterator<const XMLCh*>(m_policies),name,
                                               nameQualifier,NULL,subjectIP,authMethod,authDateTime,bindings);
    if (assertionKey)
    {
        const X509Certificate* acerts[]={ assertionCert };
        (r->getAssertions().next())->sign(m_algorithm,*assertionKey,
            assertionCert ? ArrayIterator<const X509Certificate*>(acerts) : Iterator<const X509Certificate*>());
    }

    const X509Certificate* rcerts[]={ responseCert };
    r->sign(m_algorithm,responseKey,
        assertionCert ? ArrayIterator<const X509Certificate*>(rcerts) : Iterator<const X509Certificate*>());

    return r;
}

bool ShibPOSTProfile::checkReplayCache(const SAMLAssertion& a)
{
    // Default implementation uses the basic replay cache implementation.
    return SAMLPOSTProfile::checkReplayCache(a);
}

void ShibPOSTProfile::verifySignature(const SAMLSignedObject& obj, const XMLCh* signerName, const saml::Key* knownKey)
{
    if (knownKey)
        obj.verify(*knownKey);
    else
        obj.verify();
}
