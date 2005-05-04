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
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

using namespace std;
using namespace log4cpp;
using namespace shibboleth;
using namespace saml;

/*
 * Our verifier callback is a front-end for invoking each trust plugin until
 * success, or we run out of plugins.
 */
static int verify_callback(X509_STORE_CTX* x509_ctx, void* arg)
{
    Category::getInstance("OpenSSL").debug("invoking default X509 verify callback");
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
    ShibHTTPHook::ShibHTTPHookCallContext* ctx = reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(arg);
#else
    // Yes, this sucks. I'd use TLS, but there's no really obvious spot to put the thread key
    // and global variables suck too.
    ShibHTTPHook::ShibHTTPHookCallContext* ctx =
        reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(x509_ctx->depth);
#endif

    // Instead of using the supplied verifier, we let the plugins do whatever they want to do
    // with the untrusted certificates we find in the object. We can save a bit of memory by
    // just building a vector that points at them inside the supplied structure.
    vector<void*> chain;
    for (int i=0; i<sk_X509_num(x509_ctx->untrusted); i++)
        chain.push_back(sk_X509_value(x509_ctx->untrusted,i));
    
    Trust t(ctx->getHook()->getTrustProviders());
    if (!t.validate(x509_ctx->cert,chain,ctx->getRoleDescriptor(),false)) { // bypass name check (handled for us)
        x509_ctx->error=X509_V_ERR_APPLICATION_VERIFICATION;     // generic error, check log for plugin specifics
        return 0;
    }
    
    // Signal success. Hopefully it doesn't matter what's actually in the structure now.
    return 1;
}

/*
 * OpenSAML callback is invoked during SSL context setup, before the handshake.
 * We use it to attach credentials and our own certificate verifier callback above.
 */
static bool ssl_ctx_callback(void* ssl_ctx, void* userptr)
{
#ifdef _DEBUG
    saml::NDC("ssl_ctx_callback");
#endif
    Category& log=Category::getInstance(SHIB_LOGCAT".ShibHTTPHook");
    
    try {
        log.debug("OpenSAML invoked SSL context callback");
        ShibHTTPHook::ShibHTTPHookCallContext* ctx = reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(userptr);
        if (ctx->getCredResolverId()) {
            Credentials c(ctx->getHook()->getCredentialProviders());
            const ICredResolver* cr=c.lookup(ctx->getCredResolverId());
            if (cr)
                cr->attach(ssl_ctx);
            else {
                log.error("unable to attach credentials to request");
                return false;
            }
        }
        
        SSL_CTX_set_verify(reinterpret_cast<SSL_CTX*>(ssl_ctx),SSL_VERIFY_PEER,NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
        // With 0.9.7, we can pass a callback argument directly.
        SSL_CTX_set_cert_verify_callback(reinterpret_cast<SSL_CTX*>(ssl_ctx),verify_callback,userptr);
#else
        // With 0.9.6, there's no argument, so we're going to use a really embarrassing hack and
        // stuff the argument in the depth property where it will get copied to the context object
        // that's handed to the callback.
        SSL_CTX_set_cert_verify_callback(reinterpret_cast<SSL_CTX*>(ssl_ctx),reinterpret_cast<int (*)()>(verify_callback),NULL);
        SSL_CTX_set_verify_depth(reinterpret_cast<SSL_CTX*>(ssl_ctx),reinterpret_cast<int>(userptr));
#endif
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
    return conn->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT);
}
