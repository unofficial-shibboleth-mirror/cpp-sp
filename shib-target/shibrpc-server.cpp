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

static string get_threadid (const char* proc)
{
  static u_long counter = 0;
  ostringstream buf;
  buf << "[" << counter++ << "] " << proc;
  return buf.str();
}

static Category& get_category (void)
{
  string ctx = "shibtarget.rpc-server";
  return Category::getInstance(ctx);
}

extern "C" bool_t
shibrpc_ping_1_svc(int *argp, int *result, struct svc_req *rqstp)
{
  *result = (*argp)+1;
  return TRUE;
}

void set_rpc_status(ShibRpcError *error, ShibRpcStatus status,
		    const char* msg, const char* origin)
{
  error->status = status;
  if (status) {
    error->ShibRpcError_u.e.error = strdup(msg ? msg : "");
    error->ShibRpcError_u.e.origin = strdup(origin ? origin : "");
  }
}

void set_rpc_status_x(ShibRpcError *error, ShibRpcStatus status,
		      const char* msg, const XMLCh* origin)
{
  if (!status) {
    set_rpc_status(error, status, NULL, NULL);
    return;
  }
  auto_ptr_char orig(origin);
  set_rpc_status(error, status, msg, orig.get());
}

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
  CCacheEntry *entry = g_shibTargetCCache->find(argp->cookie.cookie);

  // If not, leave now..
  if (!entry) {
    log.debug ("Not found");
    set_rpc_status(&result->status, SHIBRPC_NO_SESSION,
		   "No session exists for this cookie", "");
    return TRUE;
  }

  // TEST the session...
  try {

    // Grab the origin
    const XMLCh* origin = entry->getStatement()->getSubject()->getNameQualifier();

    // Verify the address is the same
    if (argp->checkIPAddress) {
      log.debug ("Checking address against %s", entry->getClientAddress());
      if (strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
	log.debug ("IP Address mismatch");

	throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
  "Your IP address does not match the address in the original authentication.",
				  origin);
      }
    }

    // and that the session is still valid...
    if (!entry->isSessionValid(argp->lifetime, argp->timeout)) {
      log.debug ("Session expired");
      throw ShibTargetException(SHIBRPC_SESSION_EXPIRED,
				"Your session has expired.  Re-authenticate.",
				origin);
    }

    // and now try to prefetch the attributes .. this could cause an
    // "error", which is why we call it here.
    try {
      log.debug ("resource: %s", argp->url);
      Resource r(argp->url);
      entry->preFetch(r,15);	// give a 15-second window for the RM

    } catch (SAMLException &e) {
      log.debug ("prefetch failed with a SAML Exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str(), origin);

    } catch (...) {
      log.error ("prefetch caught an unknown exception");
      throw ShibTargetException(SHIBRPC_UNKNOWN_ERROR,
		"An unknown error occured while pre-fetching attributes.",
				origin);
    }

  } catch (ShibTargetException &e) {
    entry->release();
    g_shibTargetCCache->remove (argp->cookie.cookie);
    set_rpc_status_x(&result->status, e.which(), e.what(), e.where());
    return TRUE;
  }

  // Ok, just release it.
  entry->release();

  // ok, we've succeeded..
  set_rpc_status(&result->status, SHIBRPC_OK, NULL, NULL);
  log.debug ("session ok");
  return TRUE;
}

extern "C" bool_t
shibrpc_new_session_1_svc(shibrpc_new_session_args_1 *argp,
			  shibrpc_new_session_ret_1 *result, struct svc_req *rqstp)
{
  Category& log = get_category();
  string ctx = get_threadid("new_session");
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

  // Pull in the Policies
  Iterator<const XMLCh*> policies=ShibTargetConfig::getConfig().getPolicies();

  // And grab the Profile
  // XXX: Create a "Global" POSTProfile instance per location...
  log.debug ("create the POST profile (%d policies)", policies.size());
  ShibPOSTProfile *profile =
    ShibPOSTProfileFactory::getInstance(policies,
					location.get(),
					3600);

  SAMLResponse* r = NULL;
  const SAMLAuthenticationStatement* auth_st = NULL;
  XMLCh* origin = NULL;

  try
  {
    try
    {
      // Make sure we've got a profile
      if (!profile)
	throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,
				  "Failed to obtain the profile");

      // Try and accept the response...
      log.debug ("Trying to accept the post");
      r = profile->accept(post, &origin);

      // Make sure we got a response
      if (!r)
	throw ShibTargetException(SHIBRPC_RESPONSE_MISSING,
				  "Failed to accept the response.",
				  origin);

      // Find the SSO Assertion
      log.debug ("Get the SSOAssertion");
      const SAMLAssertion* ssoAssertion = profile->getSSOAssertion(*r);

      // Check against the replay cache
      log.debug ("check replay cache");
      if (profile->checkReplayCache(*ssoAssertion) == false)
	throw ShibTargetException(SHIBRPC_ASSERTION_REPLAYED,
				  "Duplicate assertion found.",
				  origin);

      // Get the authentication statement we need.
      log.debug ("get SSOStatement");
      auth_st = profile->getSSOStatement(*ssoAssertion);

      // Maybe verify the origin address....
      if (argp->checkIPAddress) {
	log.debug ("check IP Address");

	// Verify the client address exists
	const XMLCh* ip = auth_st->getSubjectIP();
	if (!ip)
	  throw ShibTargetException(SHIBRPC_IPADDR_MISSING,
		    "The IP Address provided by your origin site was missing.",
				    origin);
	
	log.debug ("verify client address");
	// Verify the client address matches authentication
	auto_ptr_char this_ip(ip);
	if (strcmp (argp->client_addr, this_ip.get()))
	  throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
	    "The IP address provided by your origin site did not match "
	    "your current address.  "
	    "To correct this problem you may need to bypass a local proxy server.",
				    origin);
      }
    }
    catch (SAMLException &e)    // XXX refine this handler to catch and log different profile exceptions
    {
      log.error ("received SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException (SHIBRPC_SAML_EXCEPTION, os.str(), origin);
    }
    catch (XMLException &e)
    {
      log.error ("received XML exception");
      auto_ptr_char msg(e.getMessage());
      throw ShibTargetException (SHIBRPC_XML_EXCEPTION, msg.get(), origin);
    }
  }
  catch (ShibTargetException &e)
  {
    log.info ("FAILED: %s", e.what());
    if (r) delete r;
    if (origin) delete origin;
    set_rpc_status_x(&result->status, e.which(), e.what(), e.where());
    return TRUE;
  }
#if 1
  catch (...)
  {
    log.error ("Unknown error");
    if (r) delete r;
    if (origin) delete origin;
    set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR,
		   "An unknown exception occurred", "");
    return TRUE;
  }
#endif

  // It passes all our tests -- create a new session.
  log.info ("Creating new session");

  SAMLAuthenticationStatement* as=static_cast<SAMLAuthenticationStatement*>(auth_st->clone());

  // Create a new cookie
  SAMLIdentifier id;
  auto_ptr_char c(id);
  const char *cookie = c.get();

  // Cache this session with the cookie
  g_shibTargetCCache->insert(cookie, as, argp->client_addr);
  
  // Delete the response...
  delete r;

  // Delete the origin...
  XMLString::release(&origin);

  // And let the user know.
  if (result->cookie) free(result->cookie);
  result->cookie = strdup(cookie);
  set_rpc_status(&result->status, SHIBRPC_OK, NULL, NULL);

  log.debug("new session id: %s", cookie);
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
  log.debug ("resource: %s", argp->url);

  // Find this session
  CCacheEntry* entry = g_shibTargetCCache->find(argp->cookie.cookie);

  // If it does not exist, leave now..
  if (!entry) {
    log.error ("No Session");
    set_rpc_status(&result->status, SHIBRPC_NO_SESSION,
		   "getattrs Internal error: no session", "");
    return TRUE;
  }

  // Grab the origin
  const XMLCh* origin = entry->getStatement()->getSubject()->getNameQualifier();

  // Validate the client address (again?)
  if (argp->checkIPAddress &&
      strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
    log.error ("IP Mismatch");
    set_rpc_status_x(&result->status, SHIBRPC_IPADDR_MISMATCH,
   "Your IP address does not match the address in the original authentication.",
		     origin);
    entry->release();
    return TRUE;
  }

  try {
    // grab the attributes for this resource
    Resource resource(argp->url);
    Iterator<SAMLAssertion*> iter = entry->getAssertions(resource);
    u_int size = iter.size();
    result->assertions.assertions_len = size;

    // if we have assertions...
    if (size) {

      // Build the response section
      ShibRpcXML* av =
	(ShibRpcXML*) malloc (size * sizeof (ShibRpcXML));
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
  } catch (SAMLException& e) {
    log.error ("received SAML exception: %s", e.what());
    ostringstream os;
    os << e;
    set_rpc_status_x(&result->status, SHIBRPC_SAML_EXCEPTION,
		     strdup(os.str().c_str()), origin);
    entry->release();
    return TRUE;
  }

  // Now grab the serialized authentication statement
  result->auth_statement.xml_string = strdup(entry->getSerializedStatement());

  entry->release();

  // and let it fly
  set_rpc_status(&result->status, SHIBRPC_OK, NULL, NULL);

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
