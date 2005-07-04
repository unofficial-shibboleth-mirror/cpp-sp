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

/* ShibHTTPHook.cpp - Shibboleth hook for SAML Binding with SSL callback

   Scott Cantor
   2/13/05
   
   $History:$
*/

#include "internal.h"

#include <saml/version.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

using namespace std;
using namespace log4cpp;
using namespace shibtarget;
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
    // and global variables suck too. We can't access the X509_STORE_CTX depth directly because
    // OpenSSL only copies it into the context if it's >=0, and the unsigned pointer may be
    // negative in the SSL structure's int member.
    SSL* ssl = reinterpret_cast<SSL*>(X509_STORE_CTX_get_ex_data(x509_ctx,SSL_get_ex_data_X509_STORE_CTX_idx()));
    ShibHTTPHook::ShibHTTPHookCallContext* ctx =
        reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(SSL_get_verify_depth(ssl));
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
    Category& log=Category::getInstance(SHIBT_LOGCAT".ShibHTTPHook");
    
    try {
        log.debug("OpenSAML invoked SSL context callback");
        ShibHTTPHook::ShibHTTPHookCallContext* ctx = reinterpret_cast<ShibHTTPHook::ShibHTTPHookCallContext*>(userptr);
        const IPropertySet* credUse=ctx->getCredentialUse();
        pair<bool,const char*> TLS=credUse ? credUse->getString("TLS") : pair<bool,const char*>(false,NULL);
        if (TLS.first) {
            Credentials c(ctx->getHook()->getCredentialProviders());
            const ICredResolver* cr=c.lookup(TLS.second);
            if (cr)
                cr->attach(ssl_ctx);
            else
                log.error("unable to attach credentials to request using (%s), leaving anonymous",TLS.second);
        }
        else
            log.warn("no TLS credentials supplied, leaving anonymous");
        
        SSL_CTX_set_verify(reinterpret_cast<SSL_CTX*>(ssl_ctx),SSL_VERIFY_PEER,NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x00907000L)
        // With 0.9.7, we can pass a callback argument directly.
        SSL_CTX_set_cert_verify_callback(reinterpret_cast<SSL_CTX*>(ssl_ctx),verify_callback,userptr);
#else
        // With 0.9.6, there's no argument, so we're going to use a really embarrassing hack and
        // stuff the argument in the depth property where it will get copied to the context object
        // that's handed to the callback.
        SSL_CTX_set_cert_verify_callback(
            reinterpret_cast<SSL_CTX*>(ssl_ctx),
            reinterpret_cast<int (*)()>(verify_callback),
            NULL
            );
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

    // Clear authn status.
    reinterpret_cast<ShibHTTPHookCallContext*>(callCtx)->m_authenticated=false;
         
    // The callCtx is our nested context class. Copy in the parent pointer.
    reinterpret_cast<ShibHTTPHookCallContext*>(callCtx)->m_hook=this;
    
    // The hook function is called before connecting to the HTTP server. This
    // gives us a chance to attach our own SSL callback, and set a version header.
    if (!conn->setSSLCallback(ssl_ctx_callback,callCtx))
        return false;
    
    if (!conn->setRequestHeader("Shibboleth", PACKAGE_VERSION))
        return false;
    if (!conn->setRequestHeader("Xerces-C", XERCES_FULLVERSIONDOT))
        return false;
    if (!conn->setRequestHeader("XML-Security-C", XSEC_VERSION))
        return false;
    if (!conn->setRequestHeader("OpenSAML-C", OPENSAML_FULLVERSIONDOT))
        return false;

    // Check for HTTP authentication...
    const IPropertySet* credUse=reinterpret_cast<ShibHTTPHookCallContext*>(callCtx)->getCredentialUse();
    pair<bool,const char*> authType=credUse ? credUse->getString("authType") : pair<bool,const char*>(false,NULL);
    if (authType.first) {
#ifdef _DEBUG
        saml::NDC("outgoing");
#endif
        Category& log=Category::getInstance(SHIBT_LOGCAT".ShibHTTPHook");
        HTTPClient::auth_t type=HTTPClient::auth_none;
        pair<bool,const char*> username=credUse->getString("authUsername");
        pair<bool,const char*> password=credUse->getString("authPassword");
        if (!username.first || !password.first) {
            log.error("HTTP authType (%s) specified but authUsername or authPassword was missing", authType.second);
            return false;
        }
        else if (!strcmp(authType.second,"basic"))
            type = HTTPClient::auth_basic;
        else if (!strcmp(authType.second,"digest"))
            type = HTTPClient::auth_digest;
        else if (!strcmp(authType.second,"ntlm"))
            type = HTTPClient::auth_ntlm;
        else if (!strcmp(authType.second,"gss"))
            type = HTTPClient::auth_gss;
        else {
            log.error("Unknown authType (%s) specified in CredentialUse element", authType.second);
            return false;
        }
        log.debug("configured for HTTP authentication (method=%s, username=%s)", authType.second, username.second);
        return conn->setAuth(type,username.second,password.second);
    }

    // The best we can do is assume authentication succeeds because when libcurl reuses
    // SSL and HTTP connections, no callback is made. Since we always authenticate SSL connections,
    // the caller should check that the protocol is https.
    reinterpret_cast<ShibHTTPHookCallContext*>(callCtx)->setAuthenticated();
    return true;
}
