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


/* ShibSOAPBinding.cpp - Shibboleth version of SOAP Binding with SSL callback

   Scott Cantor
   10/30/03
   
   $History:$
*/

#include "internal.h"

#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace shibboleth;
using namespace saml;

SAMLResponse* ShibSOAPBinding::send(const SAMLAuthorityBinding& bindingInfo, SAMLRequest& req, SAMLConfig::SAMLBindingConfig& conf)
{
    conf.ssl_ctx_callback=ssl_ctx_callback;
    conf.ssl_ctx_data=this;
    
    return SAMLSOAPBinding::send(bindingInfo, req, conf);
}

bool shibboleth::ssl_ctx_callback(void* ssl_ctx, void* userptr)
{
    try
    {
        ShibSOAPBinding* b = reinterpret_cast<ShibSOAPBinding*>(userptr);
        if (!Credentials::attach(b->m_creds, b->m_subject, b->m_relyingParty, reinterpret_cast<ssl_ctx_st*>(ssl_ctx)))
        {
            NDC("ssl_ctx_callback");
            Category::getInstance(SHIB_LOGCAT".ShibSOAPBinding").warn("found no appropriate credentials to attach, request will be anonymous");
        }

        Trust t(b->m_trusts);
        if (!t.attach(b->m_relyingParty, reinterpret_cast<ssl_ctx_st*>(ssl_ctx)))
        {
            NDC("ssl_ctx_callback");
            Category::getInstance(SHIB_LOGCAT".ShibSOAPBinding").warn("found no appropriate authorities to attach, request will be unverified");
        }
    }
    catch (SAMLException& e)
    {
        NDC("ssl_ctx_callback");
        Category::getInstance(SHIB_LOGCAT".ShibSOAPBinding").error(string("caught a SAML exception while attaching credentials to request: ") + e.what());
        return false;
    }
    catch (...)
    {
        NDC("ssl_ctx_callback");
        Category::getInstance(SHIB_LOGCAT".ShibSOAPBinding").error("caught an unknown exception while attaching credentials to request: ");
        return false;
    }

    return true;
}
