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

/*
 * shibrpc-server.cpp -- SHIBRPC Server implementation.  Originally created
 *                       as shibrpc-server-stubs.c; make sure that the function
 *                       prototypes here match those in shibrpc.x.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <saml/saml.h>
#include <shib-target/shibrpc.h>

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include <shib-target/shib-target.h>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

#include <sstream>
#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

extern IListener* g_MemoryListener;

static string get_threadid (const char* proc)
{
  static u_long counter = 0;
  ostringstream buf;
  buf << "[" << counter++ << "] " << proc;
  return buf.str();
}

static Category& get_category (void)
{
  return Category::getInstance("shibd.Listener");
}

extern "C" bool_t shibrpc_ping_2_svc(int *argp, int *result, struct svc_req *rqstp)
{
    g_MemoryListener->ping(*argp);
    *result=*argp;
    return TRUE;
}

extern "C" bool_t shibrpc_get_session_2_svc(
    shibrpc_get_session_args_2 *argp,
    shibrpc_get_session_ret_2 *result,
    struct svc_req *rqstp
    )
{
    Category& log = get_category();
    string ctx = get_threadid("sessionGet");
    saml::NDC ndc(ctx);

    if (!argp || !result) {
        log.error("RPC Argument Error");
        return FALSE;
    }

    memset(result, 0, sizeof (*result));
    result->provider_id = strdup("");
    result->auth_statement = strdup("");
    result->attr_response_pre = strdup("");
    result->attr_response_post = strdup("");

    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IApplication* app=conf->getApplication(argp->application_id);
    if (!app) {
        // Something's horribly wrong.
        log.error("couldn't find application (%s) for session", argp->application_id);
        SAMLException ex("Unable to locate application for session, deleted?");
        ostringstream os;
        os << ex;
        result->status=strdup(os.str().c_str());
        return TRUE;
    }
    
    ISessionCacheEntry* entry=NULL;
    try {
        // Delegate...
        g_MemoryListener->sessionGet(app,argp->cookie,argp->client_addr,&entry);

        // Set profile and provider
        result->profile = entry->getProfile();
        free(result->provider_id);
        result->provider_id = strdup(entry->getProviderId());
     
        // Now grab the serialized authentication statement and responses
        ostringstream os;
        os << *(entry->getAuthnStatement());
        free(result->auth_statement);
        result->auth_statement = strdup(os.str().c_str());
      
        ISessionCacheEntry::CachedResponse responses=entry->getResponse();
        if (!responses.empty()) {
            os.str("");
            os << *responses.unfiltered;
            free(result->attr_response_pre);
            result->attr_response_pre = strdup(os.str().c_str());

            os.str("");
            os << *responses.filtered;
            free(result->attr_response_post);
            result->attr_response_post = strdup(os.str().c_str());
        }

        // Ok, just release it.
        entry->unlock();
        entry=NULL;
        result->status=strdup("");
    }
    catch (SAMLException &e) {
        // If the entry is set, it happened after the call.
        if (entry) {
            entry->unlock();
            conf->getSessionCache()->remove(argp->cookie);
        }
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
    }
#ifndef _DEBUG
    catch (...) {
        // If the entry is set, it happened after the call.
        if (entry) {
            entry->unlock();
            conf->getSessionCache()->remove(argp->cookie);
        }
        InvalidSessionException ex("An unexpected error occurred while validating your session, and you must re-authenticate.");
        ostringstream os;
        os << ex;
        result->status = strdup(os.str().c_str());
    }
#endif

    return TRUE;
}

extern "C" bool_t
shibrpc_new_session_2_svc(
    shibrpc_new_session_args_2 *argp,
    shibrpc_new_session_ret_2 *result,
    struct svc_req *rqstp
    )
{
    Category& log = get_category();
    string ctx=get_threadid("sessionNew");
    saml::NDC ndc(ctx);

    if (!argp || !result) {
        log.error("Invalid RPC Arguments");
        return FALSE;
    }

    // Initialize the result structure
    memset (result, 0, sizeof(*result));
    result->cookie = strdup ("");
    result->target = strdup ("");
    result->provider_id = strdup("");

    // Access the application config.
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IApplication* app=conf->getApplication(argp->application_id);
    if (!app) {
        // Something's horribly wrong. Flush the session.
        log.error("couldn't find application for session");
        SAMLException ex("Unable to locate application for session, deleted?");
        ostringstream os;
        os << ex;
        result->status=strdup(os.str().c_str());
        return TRUE;
    }

    try {
        // Delagate the work...
        string target,cookie,provider_id;
        g_MemoryListener->sessionNew(
            app,
            argp->supported_profiles,
            argp->recipient,
            argp->packet,
            argp->client_addr,
            target,
            cookie,
            provider_id
            );

        // And let the user know.
        if (result->cookie) free(result->cookie);
        if (result->target) free(result->target);
        if (result->provider_id) free(result->provider_id);
        result->cookie = strdup(cookie.c_str());
        result->target = strdup(target.c_str());
        result->provider_id = strdup(provider_id.c_str());
        result->status = strdup("");
    }
    catch (SAMLException& e) {
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
    }
#ifndef _DEBUG
    catch (...) {
        SAMLException e("An unexpected error occurred while creating your session.");
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
    }
#endif

    return TRUE;
}

extern "C" bool_t
shibrpc_end_session_2_svc(
    shibrpc_end_session_args_2 *argp,
    shibrpc_end_session_ret_2 *result,
    struct svc_req *rqstp
    )
{
    Category& log = get_category();
    string ctx = get_threadid("sessionEnd");
    saml::NDC ndc(ctx);

    if (!argp || !result) {
        log.error("RPC Argument Error");
        return FALSE;
    }

    memset(result, 0, sizeof (*result));

    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    
    try {
        g_MemoryListener->sessionEnd(NULL,argp->cookie);
        result->status=strdup("");
    }
    catch (SAMLException& e) {
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
    }
#ifndef _DEBUG
    catch (...) {
        SAMLException ex("An unexpected error occurred while ending your session.");
        ostringstream os;
        os << ex;
        result->status = strdup(os.str().c_str());
    }
#endif
  
    return TRUE;
}

extern "C" int
shibrpc_prog_2_freeresult (SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
	xdr_free (xdr_result, result);

	/*
	 * Insert additional freeing code here, if needed
	 */

	return 1;
}
