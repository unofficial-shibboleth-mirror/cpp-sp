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

#include <openssl/x509v3.h>

using namespace shibboleth;
using namespace saml;
using namespace std;

ShibPOSTProfile::ShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* receiver, int ttlSeconds)
    : m_ttlSeconds(ttlSeconds), m_algorithm(SIGNATURE_RSA), m_issuer(NULL)
{
    if (!receiver || !*receiver || ttlSeconds <= 0)
        throw SAMLException(SAMLException::REQUESTER, "ShibPOSTProfile() found a null or invalid argument");

    m_receiver = XMLString::replicate(receiver);

    while (policies.hasNext())
        m_policies.push_back(XMLString::replicate(policies.next()));
}

ShibPOSTProfile::ShibPOSTProfile(const Iterator<const XMLCh*>& policies, const XMLCh* issuer)
    : m_ttlSeconds(0), m_algorithm(SIGNATURE_RSA), m_receiver(NULL)
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

const SAMLAssertion* ShibPOSTProfile::getSSOAssertion(const SAMLResponse& r)
{
    return SAMLPOSTProfile::getSSOAssertion(r,Iterator<const XMLCh*>(m_policies));
}

const SAMLAuthenticationStatement* ShibPOSTProfile::getSSOStatement(const SAMLAssertion& a)
{
    return SAMLPOSTProfile::getSSOStatement(a);
}

const XMLCh* ShibPOSTProfile::getOriginSite(const saml::SAMLResponse& r)
{
    Iterator<SAMLAssertion*> ia=r.getAssertions();
    while (ia.hasNext())
    {
        Iterator<SAMLStatement*> is=ia.next()->getStatements();
        while (is.hasNext())
        {
            SAMLStatement* s=is.next();
            SAMLAuthenticationStatement* as=dynamic_cast<SAMLAuthenticationStatement*>(s);
            if (as)
                return as->getSubject()->getNameQualifier();
        }
    }
    return NULL;
}

SAMLResponse* ShibPOSTProfile::accept(const XMLByte* buf, XMLCh** originSitePtr)
{
    // The built-in SAML functionality will do most of the basic non-crypto checks.
    // Note that if the response only contains a status error, it gets tossed out
    // as an exception.
    auto_ptr<SAMLResponse> r(SAMLPOSTProfile::accept(buf, m_receiver, m_ttlSeconds, false));

    // Now we do some more non-crypto (ie. cheap) work to match up the origin site
    // with its associated data.
    const SAMLAssertion* assertion = NULL;
    const SAMLAuthenticationStatement* sso = NULL;

    try
    {
        assertion = getSSOAssertion(*r);
        sso = getSSOStatement(*assertion);
    }
    catch (...)
    {
        // We want to try our best to locate an origin site name so we can fill it in.
        if (originSitePtr)
            *originSitePtr=XMLString::replicate(getOriginSite(*r));
        throw;
    }

    // Examine the subject information.
    const SAMLSubject* subject = sso->getSubject();
    if (!subject->getNameQualifier())
        throw InvalidAssertionException(SAMLException::RESPONDER, "ShibPOSTProfile::accept() requires subject name qualifier");

    const XMLCh* originSite = subject->getNameQualifier();
    if (originSitePtr)
        *originSitePtr=XMLString::replicate(originSite);
    const XMLCh* handleService = assertion->getIssuer();

    // Is this a trusted HS?
    const IAuthority* hs=NULL;
    OriginMetadata mapper(originSite);
    Iterator<const IAuthority*> hsi=mapper.fail() ? Iterator<const IAuthority*>() : mapper->getHandleServices();
    bool bFound = false;
    while (!bFound && hsi.hasNext())
    {
        hs=hsi.next();
        if (!XMLString::compareString(hs->getName(),handleService))
            bFound = true;
    }
    if (!bFound)
        throw TrustException(SAMLException::RESPONDER, "ShibPOSTProfile::accept() detected an untrusted HS for the origin site");

    Trust t;
    Iterator<XSECCryptoX509*> certs=t.getCertificates(hs->getName());
    Iterator<XSECCryptoX509*> certs2=t.getCertificates(originSite);

    // Signature verification now takes place. We check the assertion and the response.
    // Assertion signing is optional, response signing is mandatory.
    bool bVerified=false;
    if (assertion->isSigned())
    {
        while (!bVerified && certs.hasNext())
        {
            try {
                verifySignature(*assertion, mapper, handleService, certs.next()->clonePublicKey());
                bVerified=true;
            }
            catch (InvalidCryptoException&) {
                // continue trying others
            }
        }
        while (!bVerified && certs2.hasNext())
        {
            try {
                verifySignature(*assertion, mapper, handleService, certs2.next()->clonePublicKey());
                bVerified=true;
            }
            catch (InvalidCryptoException&) {
                // continue trying others
            }
        }
        if (!bVerified)
            verifySignature(*assertion, mapper, handleService);
    }

    bVerified=false;
    while (!bVerified && certs.hasNext())
    {
        try {
            verifySignature(*r, mapper, handleService, certs.next()->clonePublicKey());
            bVerified=true;
        }
        catch (InvalidCryptoException&) {
            // continue trying others
        }
    }
    while (!bVerified && certs2.hasNext())
    {
        try {
            verifySignature(*r, mapper, handleService, certs2.next()->clonePublicKey());
            bVerified=true;
        }
        catch (InvalidCryptoException&) {
            // continue trying others
        }
    }
    if (!bVerified)
        verifySignature(*r, mapper, handleService);

    return r.release();
}

SAMLResponse* ShibPOSTProfile::prepare(
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
                                               nameQualifier,Constants::SHIB_NAMEID_FORMAT_URI,subjectIP,authMethod,authDateTime,bindings);
    if (assertionKey)
        (r->getAssertions().next())->sign(m_algorithm,assertionKey,assertionCerts);

    r->sign(m_algorithm,responseKey,responseCerts);

    return r;
}

bool ShibPOSTProfile::checkReplayCache(const SAMLAssertion& a)
{
    // Default implementation uses the basic replay cache implementation.
    return SAMLPOSTProfile::checkReplayCache(a);
}

void ShibPOSTProfile::verifySignature(
    const SAMLSignedObject& obj, const IOriginSite* originSite, const XMLCh* signerName, XSECCryptoKey* knownKey
    )
{
    obj.verify(knownKey);
    
    // If not using a known key, perform additional trust checking on the certificate.
    if (!knownKey)
    {
        vector<const XMLCh*> certs;
        for (unsigned int i=0; i<obj.getX509CertificateCount(); i++)
            certs.push_back(obj.getX509Certificate(i));

        // Compare the name in the end entity certificate to the signer's name.
        auto_ptr<char> temp(XMLString::transcode(certs[0]));
        X509* x=B64_to_X509(temp.get());
        if (!x)
            throw TrustException("ShibPOSTProfile::verifySignature() unable to decode X.509 signing certificate");

        bool match=false;
        auto_ptr<char> sn(XMLString::transcode(signerName));

        char data[256];
        X509_NAME* subj;
        if ((subj=X509_get_subject_name(x)) && X509_NAME_get_text_by_NID(subj,NID_commonName,data,256)>0)
        {
            data[255]=0;
#ifdef HAVE_STRCASECMP
            if (!strcasecmp(data,sn.get()))
                match=true;
#else
            if (!stricmp(data,sn.get()))
                match=true;
#endif
        }

        if (!match)
        {
            int extcount=X509_get_ext_count(x);
            for (int c=0; c<extcount; c++)
            {
                X509_EXTENSION* ext=X509_get_ext(x,c);
                const char* extstr=OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
                if (!strcmp(extstr,"subjectAltName"))
                {
                    X509V3_EXT_METHOD* meth=X509V3_EXT_get(ext);
                    if (!meth || !meth->d2i || !meth->i2v || !ext->value->data)
                        break;
                    unsigned char* data=ext->value->data;
                    STACK_OF(CONF_VALUE)* val=meth->i2v(meth,meth->d2i(NULL,&data,ext->value->length),NULL);
                    for (int j=0; j<sk_CONF_VALUE_num(val); j++)
                    {
                        CONF_VALUE* nval=sk_CONF_VALUE_value(val,j);
                        if (!strcmp(nval->name,"DNS") && !strcmp(nval->value,sn.get()))
                        {
                            match=true;
                            break;
                        }
                    }
                }
                if (match)
                    break;
            }
        }

        X509_free(x);

        if (!match)
            throw TrustException("ShibPOSTProfile::verifySignature() cannot match CN or subjectAltName against signer");

        // Ask the site to determine the trustworthiness of the certificate.
        if (!originSite->validate(certs))
            throw TrustException("ShibPOSTProfile::verifySignature() cannot validate the provided signing certificate(s)");
    }
}
