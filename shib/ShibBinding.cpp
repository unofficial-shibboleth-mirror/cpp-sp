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


/* ShibBinding.cpp - Shibboleth version of SAML Binding with SSL callback

   Scott Cantor
   10/30/03
   
   $History:$
*/

#include "internal.h"

using namespace std;
using namespace log4cpp;
using namespace shibboleth;
using namespace saml;

bool shibboleth::ssl_ctx_callback(void* ssl_ctx, void* userptr)
{
    NDC("ssl_ctx_callback");
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibBinding");
    
    try {
        log.debug("OpenSAML invoked the SSL context callback");
        ShibBinding* b = reinterpret_cast<ShibBinding*>(userptr);
        Credentials c(b->m_creds);
        const ICredResolver* cr=c.lookup(b->m_credResolverId);
        if (cr)
            cr->attach(ssl_ctx);
        else {
            log.error("unable to attach credentials to request");
            return false;
        }
        
        Trust t(b->m_trusts);
        if (!t.attach(b->m_revocations, b->m_AA, ssl_ctx)) {
            log.error("no appropriate key authorities to attach, blocking unverifiable request");
            return false;
        }
    }
    catch (SAMLException& e) {
        log.error(string("caught a SAML exception while attaching credentials to request: ") + e.what());
        return false;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("caught an unknown exception while attaching credentials to request");
        return false;
    }
#endif
    return true;
}

SAMLResponse* ShibBinding::send(
    SAMLRequest& req,
    const IAttributeAuthorityRole* AA,
    const char* credResolverId,
    const Iterator<const XMLCh*>& audiences,
    const Iterator<SAMLAuthorityBinding*>& bindings,
    SAMLConfig::SAMLBindingConfig& conf
    )
{
    NDC ndc("send");
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibBinding");
    
    static const XMLCh VER[] = {chDigit_1, chNull};
    static const saml::QName qname(saml::XML::SAMLP_NS,L(AttributeQuery));
    
    conf.ssl_ctx_callback=reinterpret_cast<SAMLConfig::SAMLBindingConfig::ssl_ctx_callback_fn>(ssl_ctx_callback);
    conf.ssl_ctx_data=this;
    m_AA=AA;
    m_credResolverId=credResolverId;
    
    // First try any bindings provided by caller.
    const XMLCh* prevBinding=NULL;
    Trust t(m_trusts);
    while (bindings.hasNext()) {
        SAMLAuthorityBinding* ab=bindings.next();
        try {
            if (XMLString::compareString(prevBinding,ab->getBinding())) {
                delete m_binding;
                m_binding=SAMLBinding::getInstance(ab->getBinding());
                prevBinding=ab->getBinding();
            }
            auto_ptr<SAMLResponse> r(m_binding->send(*ab, req, conf));
            if (r->isSigned() && !t.validate(m_revocations,m_AA,*r))
                throw TrustException("ShibBinding::send() unable to verify signed response");
            Iterator<SAMLAssertion*> _a=r->getAssertions();
            for (unsigned long i=0; i < _a.size(); i++) {
                // Check any conditions.
                Iterator<SAMLCondition*> conds=_a[i]->getConditions();
                while (conds.hasNext()) {
                    SAMLAudienceRestrictionCondition* cond=dynamic_cast<SAMLAudienceRestrictionCondition*>(conds.next());
                    if (!cond || !cond->eval(audiences)) {
                        log.warn("assertion condition is false, removing it");
                        r->removeAssertion(i);
                        i--;
                        break;
                    }
                }
                
                // Check signature.
                if (_a[i]->isSigned() && !t.validate(m_revocations,m_AA,*(_a[i]))) {
                    log.warn("signed assertion failed to validate, removing it");
                    r->removeAssertion(i);
                    i--;
                }
            }
            
            // Any left?
            if (r->getAssertions().size())
                return r.release();
            else
                log.warn("all assertions removed from response, dumping it");
        }
        catch (SAMLException& e) {
            log.error("caught SAML exception during SAML attribute query: %s", e.what());
        }
    }
    
    // Now try metadata.
    Iterator<const IEndpoint*> endpoints=m_AA->getAttributeServices();
    while (endpoints.hasNext()) {
        const IEndpoint* ep=endpoints.next();
        const XMLCh* ver=ep->getVersion();
        // Skip anything versioned at other than 1.
        if (ver && *ver && XMLString::compareString(ver,VER))
            continue;
        try {
            if (XMLString::compareString(prevBinding,ep->getBinding())) {
                delete m_binding;
                m_binding=SAMLBinding::getInstance(ep->getBinding());
                prevBinding=ep->getBinding();
            }
            SAMLAuthorityBinding ab(qname,ep->getBinding(),ep->getLocation());
            auto_ptr<SAMLResponse> r(m_binding->send(ab, req, conf));
            if (r->isSigned() && !t.validate(m_revocations,m_AA,*r))
                throw TrustException("ShibBinding::send() unable to verify signed response");

            Iterator<SAMLAssertion*> _a=r->getAssertions();
            for (unsigned long i=0; i < _a.size();) {
                // Check any conditions.
                Iterator<SAMLCondition*> conds=_a[i]->getConditions();
                while (conds.hasNext()) {
                    SAMLAudienceRestrictionCondition* cond=dynamic_cast<SAMLAudienceRestrictionCondition*>(conds.next());
                    if (!cond || !cond->eval(audiences)) {
                        log.warn("assertion condition is false, removing it");
                        r->removeAssertion(i);
                    }
                }
                
                // Check signature.
                if (_a[i]->isSigned() && !t.validate(m_revocations,m_AA,*(_a[i]))) {
                    log.warn("signed assertion failed to validate, removing it");
                    r->removeAssertion(i);
                }
            }

            // Any left?
            if (r->getAssertions().size())
                return r.release();
            else
                log.warn("all assertions removed from response, dumping it");
        }
        catch (SAMLException& e) {
            log.error("caught SAML exception during SAML attribute query: %s", e.what());
        }
    }
    
    throw BindingException("ShibBinding::send() unable to successfully complete attribute query");
}
