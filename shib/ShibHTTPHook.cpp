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


/* ShibHTTPHook.cpp - Shibboleth hook for SAML Binding with SSL callback

   Scott Cantor
   2/13/05
   
   $History:$
*/

#include "internal.h"

using namespace std;
using namespace log4cpp;
using namespace shibboleth;
using namespace saml;

bool shibboleth::ssl_ctx_callback(void* ssl_ctx, void* userptr)
{
#ifdef _DEBUG
    NDC("ssl_ctx_callback");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibHTTPHook");
    
    try {
        log.debug("OpenSAML invoked SSL context callback");
        ShibHTTPHook::ShibHTTPHookCallContext* ctx = reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(userptr);
        Credentials c(ctx->m_hook->m_creds);
        const ICredResolver* cr=c.lookup(ctx->m_credResolverId);
        if (cr)
            cr->attach(ssl_ctx);
        else {
            log.error("unable to attach credentials to request");
            return false;
        }
        
        Trust t(ctx->m_hook->m_trusts);
        if (!t.attach(ctx->m_hook->m_revocations, ctx->m_role, ssl_ctx)) {
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

bool ShibHTTPHook::outgoing(HTTPClient* conn, void* globalCtx, void* callCtx)
{
    // Sanity check...
    if (globalCtx != this)
        return false;
        
    // The callCtx is our nested context class. Copy in the parent pointer.
    reinterpret_cast<ShibHTTPHookCallContext*>(callCtx)->m_hook=this;
 
    // The hook function is called before connecting to the HTTP server. This
    // gives us a chance to attach our own SSL callback, and set a version header.
    if (!conn->setSSLCallback(ssl_ctx_callback,callCtx))
        return false;
    
    return conn->setRequestHeader("Shibboleth", PACKAGE_VERSION);
}
