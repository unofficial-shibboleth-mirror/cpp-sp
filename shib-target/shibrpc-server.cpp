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
shibrpc_ping_2_svc(int *argp, int *result, struct svc_req *rqstp)
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

extern "C" bool_t
shibrpc_get_session_2_svc(
    shibrpc_get_session_args_2 *argp,
    shibrpc_get_session_ret_2 *result,
    struct svc_req *rqstp
    )
{
  Category& log = get_category();
  string ctx = get_threadid("session_is_valid");
  saml::NDC ndc(ctx);

  if (!argp || !result) {
    log.error ("RPC Argument Error");
    return FALSE;
  }

  memset (result, 0, sizeof (*result));
  result->auth_statement.xml_string = strdup("");
  
  log.debug ("checking: %s@%s (checkAddr=%s)",
	     argp->cookie, argp->client_addr, argp->checkIPAddress ? "true" : "false");

  // See if the session exists...
  
  IConfig* conf=ShibTargetConfig::getConfig().getINI();
  Locker locker(conf);
  log.debug ("application: %s", argp->application_id);
  const IApplication* app=conf->getApplication(argp->application_id);
  if (!app) {
    // Something's horribly wrong.
    log.error("couldn't find application for session");
    set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR, "Unable to locate application for session, deleted?");
    return TRUE;
  }

  ISessionCacheEntry* entry = conf->getSessionCache()->find(argp->cookie,app);

  // If not, leave now..
  if (!entry) {
    log.debug ("Not found");
    set_rpc_status(&result->status, SHIBRPC_NO_SESSION, "No session exists for this key value");
    return TRUE;
  }

  // TEST the session...
  try {
    Metadata m(app->getMetadataProviders());
    const IEntityDescriptor* origin=m.lookup(entry->getAuthnStatement()->getSubject()->getNameIdentifier()->getNameQualifier());

    // Verify the address is the same
    if (argp->checkIPAddress) {
      log.debug ("Checking address against %s", entry->getClientAddress());
      if (strcmp (argp->client_addr, entry->getClientAddress())) {
        log.debug ("IP Address mismatch");
        throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
            "Your IP address does not match the address recorded at the time the session was established.", origin);
      }
    }

    // and that the session is still valid...
    if (!entry->isValid(argp->lifetime, argp->timeout)) {
      log.debug ("Session expired");
      throw ShibTargetException(SHIBRPC_SESSION_EXPIRED, "Your session has expired, and you must re-authenticate.", origin);
    }

    try {
      // Now grab the serialized authentication statement
      ostringstream os;
      os << *(entry->getAuthnStatement());
      free(result->auth_statement.xml_string);
      result->auth_statement.xml_string = strdup(os.str().c_str());
     
      // grab the attributes for this session
      Iterator<SAMLAssertion*> iter = entry->getAssertions();
      u_int size = iter.size();
    
      // if we have assertions...
      if (size) {
          // Build the response section
          ShibRpcXML* av = (ShibRpcXML*) malloc (size * sizeof (ShibRpcXML));
    
          // and then serialize them all...
          u_int i = 0;
          while (iter.hasNext()) {
            SAMLAssertion* as = iter.next();
            ostringstream os2;
            os2 << *as;
            av[i++].xml_string = strdup(os2.str().c_str());
          }
    
          // Set the results, once we know we've succeeded.
          result->assertions.assertions_len = size;
          result->assertions.assertions_val = av;
      }
    }
    catch (SAMLException &e) {
      log.error ("caught SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str().c_str(), origin);
    }
  }
  catch (ShibTargetException &e) {
      entry->unlock();
      log.error ("FAILED: %s", e.what());
      conf->getSessionCache()->remove(argp->cookie);
      set_rpc_status(&result->status, e);
      // Transaction Logging
      STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
      stc.getTransactionLog().infoStream() <<
          "Destroyed invalid session (ID: " <<
              argp->cookie <<
          ") with (applicationId: " <<
              argp->application_id <<
          "), request was from (ClientAddress: " <<
              argp->client_addr <<
          ")";
      stc.releaseTransactionLog();
      return TRUE;
  }
#ifndef _DEBUG
  catch (...) {
      entry->unlock();
      log.error ("Unknown exception");
      conf->getSessionCache()->remove(argp->cookie);
      set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR, "An unknown exception occurred");
      // Transaction Logging
      STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
      stc.getTransactionLog().infoStream() <<
          "Destroyed invalid session (ID: " <<
              argp->cookie <<
          ") with (applicationId: " <<
              argp->application_id <<
          "), request was from (ClientAddress: " <<
              argp->client_addr <<
          ")";
      stc.releaseTransactionLog();
      return TRUE;
  }
#endif

  // Ok, just release it.
  entry->unlock();

  // ok, we've succeeded..
  set_rpc_status(&result->status, SHIBRPC_OK);
  log.debug ("session ok");
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
  string ctx=get_threadid("new_session");
  saml::NDC ndc(ctx);

  if (!argp || !result) {
    log.error ("Invalid RPC Arguments");
    return FALSE;
  }

  // Initialize the result structure
  memset (result, 0, sizeof(*result));
  result->cookie = strdup ("");
  result->target = strdup ("");

  log.debug ("creating session for %s", argp->client_addr);
  log.debug ("recipient: %s", argp->recipient);
  log.debug ("application: %s", argp->application_id);

  auto_ptr_XMLCh recipient(argp->recipient);

  SAMLResponse* r = NULL;
  const SAMLAuthenticationStatement* auth_st = NULL;
  XMLCh* origin = NULL;
 
  // Access the application config.
  IConfig* conf=ShibTargetConfig::getConfig().getINI();
  Locker locker(conf);
  const IApplication* app=conf->getApplication(argp->application_id);
  if (!app) {
      // Something's horribly wrong. Flush the session.
      log.error ("couldn't find application for session");
      set_rpc_status(&result->status, SHIBRPC_INTERNAL_ERROR, "Unable to locate application for session, deleted?");
      return TRUE;
  }

  // TODO: Sub in call to getReplayCache() as the determinant.
  // For now, we always have a cache and use the flag...
  pair<bool,bool> checkReplay=pair<bool,bool>(false,false);
  const IPropertySet* props=app->getPropertySet("Sessions");
  if (props)
      checkReplay=props->getBool("checkReplay");
 
  const IRoleDescriptor* role=NULL;
  Metadata m(app->getMetadataProviders());
  SAMLBrowserProfile::BrowserProfileResponse bpr;
  try
  {
    if (!app)
        // Something's horribly wrong.
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,"Unable to locate application configuration, deleted?");
      
    try
    {
      auto_ptr<SAMLBrowserProfile::ArtifactMapper> artifactMapper(app->getArtifactMapper());
      
      // Try and run the profile.
      log.debug ("Executing browser profile...");
      bpr=app->getBrowserProfile()->receive(
        &origin,
        argp->packet,
        recipient.get(),
        SAMLBrowserProfile::Post,   // For now, we only handle POST.
        (!checkReplay.first || checkReplay.second) ? conf->getReplayCache() : NULL,
        artifactMapper.get()
        );

      // Try and map to metadata for support purposes.
      const IEntityDescriptor* provider=m.lookup(origin);
      if (provider) {
          const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
          role=IDP;
      }
      // This can't really happen, since the profile must have found a role.
      if (!role)
        throw ShibTargetException(SHIBRPC_INTERNAL_ERROR,
            "Unable to locate role-specific metadata for identity provider", provider);
    
      // Maybe verify the origin address....
      if (argp->checkIPAddress) {
        log.debug ("verify client address");

        // Verify the client address exists
        const XMLCh* ip = bpr.authnStatement->getSubjectIP();
        if (ip && *ip) {
            // Verify the client address matches authentication
            auto_ptr_char this_ip(ip);
            if (strcmp(argp->client_addr, this_ip.get()))
                throw ShibTargetException(SHIBRPC_IPADDR_MISMATCH,
	                "Your client's current IP address differs from the one used when you authenticated "
                    "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                    "Please contact your local support staff or help desk for assistance.",
				     role);
        }
      }
      
      // Verify condition(s) on authentication assertion.
      // Attribute assertions get filtered later, essentially just like an AAP.
      Iterator<SAMLCondition*> conditions=bpr.assertion->getConditions();
      while (conditions.hasNext()) {
        SAMLCondition* cond=conditions.next();
        const SAMLAudienceRestrictionCondition* ac=dynamic_cast<const SAMLAudienceRestrictionCondition*>(cond);
        if (!ac) {
            ostringstream os;
            os << *cond;
            log.error("Unrecognized Condition in authentication assertion (%s), tossing it.",os.str().c_str());
            throw FatalProfileException("Unable to start session due to unrecognized condition in authentication assertion.");
        }
        else if (!ac->eval(app->getAudiences())) {
            ostringstream os;
            os << *ac;
            log.error("Unacceptable AudienceRestrictionCondition in authentication assertion (%s), tossing it.",os.str().c_str());
            throw FatalProfileException("Unable to start session due to unacceptable AudienceRestrictionCondition in authentication assertion.");
        }
      }
    }
    catch (ReplayedAssertionException& e) {
      // Specific case where we have an error code.
      if (!role) {
          // Try and map to metadata for support purposes.
          const IEntityDescriptor* provider=m.lookup(origin);
          if (provider) {
              const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
              role=IDP;
          }
      }
      throw ShibTargetException(SHIBRPC_ASSERTION_REPLAYED, e.what(), role);
    }
    catch (SAMLException& e) {
      log.error ("caught SAML exception: %s", e.what());
      ostringstream os;
      os << e;
      if (!role) {
          // Try and map to metadata for support purposes.
          const IEntityDescriptor* provider=m.lookup(origin);
          if (provider) {
              const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
              role=IDP;
          }
      }
      throw ShibTargetException (SHIBRPC_SAML_EXCEPTION, os.str().c_str(), role);
    }
  }
  catch (ShibTargetException& e) {
    log.error ("FAILED: %s", e.what());
    bpr.clear();
    if (origin) XMLString::release(&origin);
    set_rpc_status(&result->status, e);
    return TRUE;
  }
#ifndef _DEBUG
  catch (...) {
    log.error ("Unknown error");
    bpr.clear();
    if (origin) XMLString::release(&origin);
    set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR, "An unknown exception occurred");
    return TRUE;
  }
#endif

  // It passes all our tests -- create a new session.
  log.info ("Creating new session");

  // Create a new session key.
  string cookie = conf->getSessionCache()->generateKey();

  // Are attributes present?
  bool attributesPushed=false;
  Iterator<SAMLAssertion*> assertions=bpr.response->getAssertions();
  while (!attributesPushed && assertions.hasNext()) {
      Iterator<SAMLStatement*> statements=assertions.next()->getStatements();
      while (!attributesPushed && statements.hasNext()) {
          if (dynamic_cast<SAMLAttributeStatement*>(statements.next()))
            attributesPushed=true;
      }
  }
  
  // Insertion into cache might fail.
  SAMLAuthenticationStatement* as=NULL;
  try {
      as=static_cast<SAMLAuthenticationStatement*>(bpr.authnStatement->clone());
      // TODO: we need to extract the Issuer and propagate that around as the origin site along
      // with the statement and attribute assertions.
      conf->getSessionCache()->insert(
        cookie.c_str(),
        app,
        as,
        argp->client_addr,
        (attributesPushed ? bpr.response : NULL),
        role
        );
  }
  catch (SAMLException& e) {
      log.error ("caught SAML exception during cache insertion: %s", e.what());
      delete as;
      ostringstream os;
      os << e;
      bpr.clear();
      if (origin) XMLString::release(&origin);
      ShibTargetException ex(SHIBRPC_SAML_EXCEPTION, os.str().c_str(), role);
      set_rpc_status(&result->status, ex);
      return TRUE;
  }
#ifndef _DEBUG
  catch (...) {
      log.error ("caught unknown exception during cache insertion");
      delete as;
      bpr.clear();
      if (origin) XMLString::release(&origin);
      set_rpc_status(&result->status, SHIBRPC_UNKNOWN_ERROR, "An unknown exception occurred");
      return TRUE;
  }
#endif
    
  // And let the user know.
  if (result->cookie) free(result->cookie);
  if (result->target) free(result->target);
  result->cookie = strdup(cookie.c_str());
  result->target = strdup(bpr.TARGET.c_str());
  set_rpc_status(&result->status, SHIBRPC_OK);

  // Maybe delete the response...
  if (!attributesPushed)
    bpr.clear();

  log.debug("new session id: %s", cookie.c_str());
  
  // Transaction Logging
  STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
  auto_ptr_char oname(origin);
  auto_ptr_char hname(as->getSubject()->getNameIdentifier()->getName());
  stc.getTransactionLog().infoStream() <<
    "New session (ID: " <<
        result->cookie <<
    ") with (applicationId: " <<
        argp->application_id <<
    ") for principal from (IdP: " <<
        oname.get() <<
    ") at (ClientAddress: " <<
        argp->client_addr <<
    ") with (NameIdentifier: " <<
        hname.get() <<
    ")";

  stc.releaseTransactionLog();

  // Delete the origin...
  if (origin) XMLString::release(&origin);

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
