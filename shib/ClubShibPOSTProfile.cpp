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

/* ClubShibPOSTProfile.cpp - Club-Shib wrapper around SAML POST profile

   Scott Cantor
   8/15/02

   $History:$
*/

#include "internal.h"

using namespace shibboleth;
using namespace saml;
using namespace std;

ClubShibPOSTProfile::ClubShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds)
    : ShibPOSTProfile(policies,receiver,ttlSeconds)
{
    return;
    bool found=false;
    for (vector<const XMLCh*>::iterator i=m_policies.begin(); !found && i!=m_policies.end(); i++)
        if (!XMLString::compareString(Constants::POLICY_INCOMMON,*i))
            found=true;
    if (!found)
        throw SAMLException(SAMLException::REQUESTER, "ClubShibPOSTProfile() policy array must include InCommon");
}

ClubShibPOSTProfile::ClubShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* issuer)
    : ShibPOSTProfile(policies,issuer)
{
    return;
    bool found=false;
    for (vector<const XMLCh*>::iterator i=m_policies.begin(); !found && i!=m_policies.end(); i++)
        if (!XMLString::compareString(Constants::POLICY_INCOMMON,*i))
            found=true;
    if (!found)
        throw SAMLException(SAMLException::REQUESTER, "ClubShibPOSTProfile() policy array must include InCommon");
}

ClubShibPOSTProfile::~ClubShibPOSTProfile()
{
}

SAMLResponse* ClubShibPOSTProfile::prepare(
    const XMLCh* recipient,
    const XMLCh* name,
    const XMLCh* nameQualifier,
    const XMLCh* subjectIP,
    const XMLCh* authMethod,
    time_t authInstant,
    const saml::Iterator<saml::SAMLAuthorityBinding*>& bindings,
    XSECCryptoKey* responseKey,
    const Iterator<XSECCryptoX509*>& responseCerts,
    XSECCryptoKey* assertionKey,
    const Iterator<XSECCryptoX509*>& assertionCerts
    )
{
    if (responseKey->getKeyType()!=XSECCryptoKey::KEY_RSA_PRIVATE || responseKey->getKeyType()!=XSECCryptoKey::KEY_RSA_PAIR)
        throw TrustException(SAMLException::RESPONDER, "ClubShibPOSTProfile::prepare() requires the response key be an RSA private key");
    if (assertionKey && assertionKey->getKeyType()!=XSECCryptoKey::KEY_RSA_PRIVATE || assertionKey->getKeyType()!=XSECCryptoKey::KEY_RSA_PAIR)
        throw TrustException(SAMLException::RESPONDER, "ClubShibPOSTProfile::prepare() requires the assertion key be an RSA private key");

    return ShibPOSTProfile::prepare(recipient,name,nameQualifier,subjectIP,authMethod,authInstant,bindings,
                                    responseKey,responseCerts,assertionKey,assertionCerts);
}

void ClubShibPOSTProfile::verifySignature(const SAMLSignedObject& obj, const XMLCh* signerName, XSECCryptoKey* knownKey)
{
    ShibPOSTProfile::verifySignature(obj,signerName,knownKey);
    if (obj.getSignatureAlgorithm()!=SIGNATURE_RSA)
        throw TrustException("ClubShibPOSTProfile::verifySignature() requires the RSA signature algorithm");
}
