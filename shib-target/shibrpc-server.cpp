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

#include "internal.h"

#include "shibrpc.h"

#include <sstream>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

static string get_threadid (const char* proc)
{
  static u_long counter = 0;
  ostringstream buf;
  buf << "[" << counter++ << "] " << proc;
  return buf.str();
}

static Category& get_category (void)
{
  return Category::getInstance("shibtarget.rpc-server");
}

extern "C" bool_t
shibrpc_ping_1_svc(int *argp, int *result, struct svc_req *rqstp)
{
  *result = (*argp)+1;
  return TRUE;
}

// Functions to map errors into IDL-defined status structure

void set_rpc_status(ShibRpcError *error, ShibRpcStatus status, const char* msg=NULL)
{
  error->status = status;
  if (status) {
    error->ShibRpcError_u.e.error = strdup(msg ? msg : "");
    error->ShibRpcError_u.e.provider = strdup("");
    error->ShibRpcError_u.e.url = strdup("");
    error->ShibRpcError_u.e.contact = strdup("");
    error->ShibRpcError_u.e.email = strdup("");
  }
}

void set_rpc_status(ShibRpcError *error, ShibTargetException& exc)
{
  error->status = exc.which();
  if (error->status) {
    error->ShibRpcError_u.e.error = strdup(exc.what() ? exc.what() : "");
    error->ShibRpcError_u.e.provider = strdup(exc.syswho() ? exc.syswho() : "");
    error->ShibRpcError_u.e.url = strdup(exc.where() ? exc.where() : "");
    error->ShibRpcError_u.e.contact = strdup(exc.who() ? exc.who() : "");
    error->ShibRpcError_u.e.email = strdup(exc.how() ? exc.how() : "");
  }
}

/*
void set_rpc_status_x(ShibRpcError *error, ShibRpcStatus status,
                        const char* msg=NULL, const XMLCh* origin=NULL)
{
  if (!status) {
    set_rpc_status(error, status);
    return;
  }
  auto_ptr_char orig(origin);
  set_rpc_status(error, status, msg, orig.get());
}
*/

extern "C" bool_t
shibrpc_session_is_valid_1_svc(shibrpc_session_is_valid_args_1 *argp,
			       shibrpc_session_is_valid_ret_1 *result,
			       struct svc_req *rqstp)
{
  Category& log = get_category();
  string ctx = get_threadid("session_is_valid");
  saml::NDC ndc(ctx);

  if (!argp || !result) {
    log.error ("RPC Argument Error");
    return FALSE;
  }

  memset (result, 0, sizeof (*result));
  
  log.debug ("checking: %s@%s (checkAddr=%s)",
	     argp->cookie.cookie, argp->cookie.client_addr,
	     argp->checkIPAddress ? "true" : "false");

  // See if the cookie exists...
  IConfig* conf=ShibTargetConfig::getConfig().getINI();
  Locker locker(conf);
  ISessionCacheEntry* entry = conf->getSessionCache()->find(argp->cookie.cookie);

  // If not, leave now..
  if (!entry) {
    log.debug ("Not found");
    set_rpc_status(&result->status, SHIBRPC_NO_SESSION, "No session exists for this cookie");
    return TRUE;
  }

  // TEST the session...
  try {

    // Try and locate support metadata for errors we throw.
    log.debug ("application: %s", argp->application_id);
    const IApplication* app=conf->getApplication(argp->application_id);
    if (!app)
        // Something's horribly wrong. Flush the session.
        throw ShibTargetException(SHIBRPC_NO_SESSION,"Unable to locate application for session, deleted?");

    Metadata m(app->getMetadataProviders());
    const IProvider* origin=m.lookup(entry->getStatement()->getSubject()->getNameQualifier());

    // Verify the address is the same
    if (argp->checkIPAddress) {
      log.debug ("Checking address against %s", entry->getClientAddress());
      if (strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
        log.debug ("IP Address mismatch");
        throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
            "Your IP address does not match the address in the original authentication.", origin);
      }
    }

    // and that the session is still valid...
    if (!entry->isValid(argp->lifetime, argp->timeout)) {
      log.debug ("Session expired");
      throw ShibTargetException(SHIBRPC_SESSION_EXPIRED, "Your session has expired, must re-authenticate.", origin);
    }

    // and now try to prefetch the attributes .. this could cause an
    // "error", which is why we call it here.
    try {
      entry->preFetch(15);	// give a 15-second window for the RM
    }
    catch (SAMLException &e) {
      log.debug ("prefetch failed with a SAML Exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str().c_str(), origin);
    }
#ifndef _DEBUG
    catch (...) {
      log.error ("prefetch caught an unknown exception");
      throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR,
            "An unknown error occured while pre-fetching attributes.", origin);
    }
#endif
  }
  catch (ShibTargetException &e) {
    entry->unlock();
    conf->getSessionCache()->remove(argp->cookie.cookie);
    set_rpc_status(&result->status, e);
    return TRUE;
  }

  // Ok, just release it.
  entry->unlock();

  // ok, we've succeeded..
  set_rpc_status(&result->status, SHIBRPC_OK);
  log.debug ("session ok");
  return TRUE;
}

extern "C" bool_t
shibrpc_new_session_1_svc(shibrpc_new_session_args_1 *argp,
			  shibrpc_new_session_ret_1 *result, struct svc_req *rqstp)
{
  Category& log = get_category();
  string ctx=get_threadid("new_session");
  saml::NDC ndc(ctx);

  if (!argp || !result) {
    log.error ("Invalid RPC Arguments");
    return FALSE;
  }

  // Initialize the result structure
  memset (result, 0, sizeof(*result));
  result->cookie = strdup ("");

  log.debug ("creating session for %s", argp->client_addr);
  log.debug ("shire location: %s", argp->shire_location);

  XMLByte* post=reinterpret_cast<XMLByte*>(argp->saml_post);
  auto_ptr_XMLCh location(argp->shire_location);

  SAMLResponse* r = NULL;
  const SAMLAuthenticationStatement* auth_st = NULL;
  XMLCh* origin = NULL;
 
  // Access the application config.
  IConfig* conf=ShibTargetConfig::getConfig().getINI();
  Locker locker(conf);
  const IApplication* app=conf->getApplication(argp->application_id);
 
  try
  {
    if (!app)
        // Something's horribly wrong.
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to locate application configuration, deleted?");
      
    // And build the POST profile wrapper.
    log.debug("create the POST profile");
    ShibPOSTProfile profile(app->getMetadataProviders(),app->getRevocationProviders(),app->getTrustProviders());
    
    const IProviderRole* role=NULL;
    try
    {
      // Try and accept the response...
      log.debug ("Trying to accept the post");
      r = profile.accept(post,location.get(),300,app->getAudiences(),&origin);

      // Try and map to metadata for support purposes.
      Metadata m(app->getMetadataProviders());
      const IProvider* provider=m.lookup(origin);
      if (provider) {
        Iterator<const IProviderRole*> roles=provider->getRoles();
        while (!role && roles.hasNext()) {
            const IProviderRole* _r=roles.next();
            if (dynamic_cast<const IIDPProviderRole*>(_r) && _r->hasSupport(Constants::SHIB_NS))
                role=_r;
        }
      }
      // This can't really happen, since the profile must have found a role.
      if (!role)
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,
            "Unable to locate role-specific metadata for identity provider", provider);
    
      // Make sure we got a response
      if (!r)
        throw ShibTargetException(SHIBRPC_RESPONSE_MISSING, "Failed to accept the response.", role);

      // Find the SSO Assertion
      log.debug ("Get the SSOAssertion");
      const SAMLAssertion* ssoAssertion = profile.getSSOAssertion(*r,app->getAudiences());

      // Check against the replay cache
      log.debug ("check replay cache");
      if (!profile.checkReplayCache(*ssoAssertion))
        throw ShibTargetException(SHIBRPC_ASSERTION_REPLAYED, "Duplicate assertion detected.", role);

      // Get the authentication statement we need.
      log.debug ("get SSOStatement");
      auth_st = profile.getSSOStatement(*ssoAssertion);

      // Maybe verify the origin address....
      if (argp->checkIPAddress) {
        log.debug ("check IP Address");

        // Verify the client address exists
        const XMLCh* ip = auth_st->getSubjectIP();
        if (ip && *ip) {
            log.debug ("verify client address");

            // Verify the client address matches authentication
            auto_ptr_char this_ip(ip);
            if (strcmp(argp->client_addr, this_ip.get()))
                throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
	                "The IP address provided by your origin site did not match your current address. "
	                "To correct this problem, you may need to bypass a local proxy server.",
				     role);
        }
      }
    }
    catch (SAMLException &e)
    {
      log.error ("caught SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException (SHIBRPC_SAML_EXCEPTION, os.str().c_str(), role);
    }
    catch (XMLException &e)
    {
      log.error ("received XML exception");
      auto_ptr_char msg(e.getMessage());
      throw ShibTargetException (SHIBRPC_XML_EXCEPTION, msg.get(), role);
    }
  }
  catch (ShibTargetException &e) {
    log.info ("FAILED: %s", e.what());
    delete r;
    if (origin) XMLString::release(&origin);
    set_rpc_status(&result->status, e);
    return TRUE;
  }
#ifndef _DEBUG
  catch (...) {
    log.error ("Unknown error");
    delete r;
    if (origin) XMLString::release(&origin);
    set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR, "An unknown exception occurred");
    return TRUE;
  }
#endif

  // It passes all our tests -- create a new session.
  log.info ("Creating new session");

  SAMLAuthenticationStatement* as=static_cast<SAMLAuthenticationStatement*>(auth_st->clone());

  // Create a new cookie
  string cookie = conf->getSessionCache()->generateKey();

  // Cache this session, possibly including response if attributes appear present.
  bool attributesPushed=false;
  Iterator<SAMLAssertion*> assertions=r->getAssertions();
  while (!attributesPushed && assertions.hasNext()) {
      Iterator<SAMLStatement*> statements=assertions.next()->getStatements();
      while (!attributesPushed && statements.hasNext()) {
          if (dynamic_cast<SAMLAttributeStatement*>(statements.next()))
            attributesPushed=true;
      }
  }
  conf->getSessionCache()->insert(cookie.c_str(), app, as, argp->client_addr, (attributesPushed ? r : NULL));
  
  // Maybe delete the response...
  if (!attributesPushed)
    delete r;

  // Delete the origin...
  if (origin) XMLString::release(&origin);

  // And let the user know.
  if (result->cookie) free(result->cookie);
  result->cookie = strdup(cookie.c_str());
  set_rpc_status(&result->status, SHIBRPC_OK);

  log.debug("new session id: %s", cookie.c_str());
  return TRUE;
}

extern "C" bool_t
shibrpc_get_assertions_1_svc(shibrpc_get_assertions_args_1 *argp,
			shibrpc_get_assertions_ret_1 *result, struct svc_req *rqstp)
{
  Category& log = get_category();
  string ctx = get_threadid("get_assertions");
  saml::NDC ndc(ctx);

  if (!argp || !result) {
    log.error ("Invalid RPC arguments");
    return FALSE;
  }

  memset (result, 0, sizeof (*result));

  log.debug ("get attrs for client at %s", argp->cookie.client_addr);
  log.debug ("cookie: %s", argp->cookie.cookie);
  log.debug ("application: %s", argp->application_id);

  // Find this session
  IConfig* conf=ShibTargetConfig::getConfig().getINI();
  Locker locker(conf);
  ISessionCacheEntry* entry = conf->getSessionCache()->find(argp->cookie.cookie);

  // If it does not exist, leave now..
  if (!entry) {
    log.error ("No Session");
    set_rpc_status(&result->status, SHIBRPC_NO_SESSION, "getattrs Internal error: no session");
    return TRUE;
  }

  // Try and locate support metadata for errors we throw.
  log.debug ("application: %s", argp->application_id);
  const IApplication* app=conf->getApplication(argp->application_id);
  if (!app)
      // Something's horribly wrong. Flush the session.
      throw ShibTargetException(SHIBRPC_NO_SESSION,"Unable to locate application for session, deleted?");

  Metadata m(app->getMetadataProviders());
  const IProvider* origin=m.lookup(entry->getStatement()->getSubject()->getNameQualifier());

  try {
    try {
      // Validate the client address (again?)
      if (argp->checkIPAddress && strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
        entry->unlock();
        log.error("IP Mismatch");
        throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
            "Your IP address does not match the address in the original authentication.", origin);
      }

      // grab the attributes for this resource
      Iterator<SAMLAssertion*> iter = entry->getAssertions();
      u_int size = iter.size();
      result->assertions.assertions_len = size;

      // if we have assertions...
      if (size) {

        // Build the response section
        ShibRpcXML* av = (ShibRpcXML*) malloc (size * sizeof (ShibRpcXML));
        result->assertions.assertions_val = av;

        // and then serialize them all...
        u_int i = 0;
        while (iter.hasNext()) {
          SAMLAssertion* as = iter.next();
          ostringstream os;
          os << *as;
          av[i++].xml_string = strdup(os.str().c_str());
        }
      }
    }
    catch (SAMLException &e) {
      entry->unlock();
      log.error ("caught SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str().c_str(), origin);
    }
#ifndef _DEBUG
    catch (...) {
      log.error ("caught an unknown exception");
      throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR,
            "An unknown error occured while fetching attributes.", origin);
    }
#endif
  }
  catch (ShibTargetException &e) {
    entry->unlock();
    set_rpc_status(&result->status, e);
    return TRUE;
  }


  // Now grab the serialized authentication statement
  result->auth_statement.xml_string = strdup(entry->getSerializedStatement());

  entry->unlock();

  // and let it fly
  set_rpc_status(&result->status, SHIBRPC_OK);

  log.debug ("returning");
  return TRUE;
}

extern "C" int
shibrpc_prog_1_freeresult (SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result)
{
	xdr_free (xdr_result, result);

	/*
	 * Insert additional freeing code here, if needed
	 */

	return 1;
}
