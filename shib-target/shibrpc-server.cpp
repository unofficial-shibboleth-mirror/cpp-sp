/*
 * shibrpc-server.cpp -- SHIBRPC Server implementation.  Originally created
 *                       as shibrpc-server-stubs.c; make sure that the function
 *                       prototypes here match those in shibrpc.x.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shibrpc.h"
#include "shib-target.h"

#include <log4cpp/Category.hh>
#include <sstream>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

static std::string get_threadid (const char* proc)
{
  static u_long counter = 0;
  ostringstream buf;
  buf << "[" << counter++ << "] " << proc;
  return buf.str();
}

static log4cpp::Category& get_category (void)
{
  string ctx = "shibtarget.rpc-server";
  return log4cpp::Category::getInstance(ctx);
}

extern "C" bool_t
shibrpc_ping_1_svc(int *argp, int *result, struct svc_req *rqstp)
{
  *result = (*argp)+1;
  return TRUE;
}

extern "C" bool_t
shibrpc_session_is_valid_1_svc(shibrpc_session_is_valid_args_1 *argp,
			       shibrpc_session_is_valid_ret_1 *result,
			       struct svc_req *rqstp)
{
  log4cpp::Category& log = get_category();
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
    result->status = SHIBRPC_NO_SESSION;
    result->error_msg = strdup("No session exists for this cookie");
    return TRUE;
  }

  // Verify the address is the same
  if (argp->checkIPAddress) {
    log.debug ("Checking address against %s", entry->getClientAddress());
    if (strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
      log.debug ("IP Address mismatch");
      result->status = SHIBRPC_IPADDR_MISMATCH;
      result->error_msg = 
	strdup ("Your IP address does not match the address in the original authentication.");
      g_shibTargetCCache->remove (argp->cookie.cookie);
      return TRUE;
    }
  }

  // and that the session is still valid...
  if (!entry->isSessionValid(argp->lifetime, argp->timeout)) {
    log.debug ("Session expired");
    result->status = SHIBRPC_SESSION_EXPIRED;
    result->error_msg = strdup ("Your session has expired.  Re-authenticate.");
    g_shibTargetCCache->remove (argp->cookie.cookie);
    return TRUE;
  }

  // ok, we've succeeded..
  result->status = SHIBRPC_OK;
  result->error_msg = strdup("");
  log.debug ("session ok");
  return TRUE;
}

extern "C" bool_t
shibrpc_new_session_1_svc(shibrpc_new_session_args_1 *argp,
			  shibrpc_new_session_ret_1 *result, struct svc_req *rqstp)
{
  log4cpp::Category& log = get_category();
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
  auto_ptr<XMLCh> location(XMLString::transcode(argp->shire_location));

  // Pull in the Policies
  static const XMLCh* clubShib[] = {shibboleth::Constants::POLICY_CLUBSHIB};
  ArrayIterator<const XMLCh*> policies(clubShib);

  // And grab the Profile
  // XXX: Create a "Global" POSTProfile instance per location...
  log.debug ("create the POST profile (%d policies)", policies.size());
  ShibPOSTProfile *profile =
    ShibPOSTProfileFactory::getInstance(policies,
					location.get(),
					3600);

  SAMLResponse* r = NULL;
  SAMLAuthenticationStatement* auth_st = NULL;

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
      r = profile->accept(post);

      // Make sure we got a response
      if (!r)
	throw ShibTargetException(SHIBRPC_RESPONSE_MISSING,
				  "Failed to accept the response.");

      // Find the SSO Assertion
      log.debug ("Get the SSOAssertion");
      SAMLAssertion* ssoAssertion = profile->getSSOAssertion(*r);

      // Check against the replay cache
      log.debug ("check replay cache");
      if (profile->checkReplayCache(*ssoAssertion) == false)
	throw ShibTargetException(SHIBRPC_ASSERTION_REPLAYED,
				  "Duplicate assertion found.");

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
				    "The IP Address provided by your origin site was missing.");
	
	log.debug ("verify client address");
	// Verify the client address matches authentication
	auto_ptr<char> this_ip(XMLString::transcode(ip));
	if (strcmp (argp->client_addr, this_ip.get()))
	  throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
				    "The IP address provided by your origin site did not match your current address.  To correct this problem you may need to bypass a local proxy server.");
      }
    }
    catch (SAMLException &e)    // XXX refine this handler to catch and log different profile exceptions
    {
      log.error ("received SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException (SHIBRPC_SAML_EXCEPTION, os.str());
    }
    catch (XMLException &e)
    {
      log.error ("received XML exception");
      auto_ptr<char> msg(XMLString::transcode(e.getMessage()));
      throw ShibTargetException (SHIBRPC_XML_EXCEPTION, msg.get());
    }
  }
  catch (ShibTargetException &e)
  {
    log.info ("FAILED: %s", e.what());
    if (r) delete r;
    result->status = e.which();
    result->error_msg = strdup(e.what());
    return TRUE;
  }
#if 0
  catch (...)
  {
    log.error ("Unknown error");
    if (r) delete r;
    result->status = SHIBRPC_UNKNOWN_ERROR;
    result->error_msg = strdup("An unknown exception occurred");
    return TRUE;
  }
#endif

  // It passes all our tests -- create a new session.
  log.info ("Creating new session");

  SAMLAuthenticationStatement* as=static_cast<SAMLAuthenticationStatement*>(auth_st->clone());

  // Create a new cookie
  SAMLIdentifier id;
  auto_ptr<char> c(XMLString::transcode(id));
  char *cookie = c.get();

  // Cache this session with the cookie
  g_shibTargetCCache->insert(cookie, as, argp->client_addr);

  // Delete the response...
  delete r;

  // And let the user know.
  free (result->cookie);
  result->cookie = strdup(cookie);
  result->status = SHIBRPC_OK;
  result->error_msg = strdup("");

  log.debug ("new session id: %s", cookie);
  return TRUE;
}

extern "C" bool_t
shibrpc_get_assertions_1_svc(shibrpc_get_assertions_args_1 *argp,
			shibrpc_get_assertions_ret_1 *result, struct svc_req *rqstp)
{
  log4cpp::Category& log = get_category();
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
    result->status = SHIBRPC_NO_SESSION;
    result->error_msg = strdup("getattrs Internal error: no session");
    return TRUE;
  }

  // Validate the client address (again?)
  if (argp->checkIPAddress &&
      strcmp (argp->cookie.client_addr, entry->getClientAddress())) {
    log.error ("IP Mismatch");
    result->status = SHIBRPC_IPADDR_MISMATCH;
    result->error_msg =
      strdup("Your IP address does not match the address in the original authentication.");
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
    result->status = SHIBRPC_SAML_EXCEPTION;
    result->error_msg = strdup(os.str().c_str());
    return TRUE;
  }

  // and let it fly
  result->status = SHIBRPC_OK;
  result->error_msg = strdup("");

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
