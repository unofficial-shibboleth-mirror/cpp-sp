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

extern "C" bool_t
shibrpc_get_session_2_svc(
    shibrpc_get_session_args_2 *argp,
    shibrpc_get_session_ret_2 *result,
    struct svc_req *rqstp
    )
{
    Category& log = get_category();
    string ctx = get_threadid("get_session");
    saml::NDC ndc(ctx);

    if (!argp || !result) {
        log.error ("RPC Argument Error");
        return FALSE;
    }

    memset (result, 0, sizeof (*result));
    result->provider_id = strdup("");
    result->auth_statement = strdup("");
    result->attr_response_pre = strdup("");
    result->attr_response_post = strdup("");

    log.debug ("checking: %s@%s", argp->cookie, argp->client_addr);

    // See if the session exists...
  
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    log.debug ("application: %s", argp->application_id);
    const IApplication* app=conf->getApplication(argp->application_id);
    if (!app) {
        // Something's horribly wrong.
        log.error("couldn't find application for session");
        SAMLException ex("Unable to locate application for session, deleted?");
        ostringstream os;
        os << ex;
        result->status=strdup(os.str().c_str());
        return TRUE;
    }

    bool checkIPAddress=true;
    int lifetime=0,timeout=0;
    const IPropertySet* props=app->getPropertySet("Sessions");
    if (props) {
        pair<bool,unsigned int> p=props->getUnsignedInt("lifetime");
        if (p.first)
            lifetime = p.second;
        p=props->getUnsignedInt("timeout");
        if (p.first)
            timeout = p.second;
        pair<bool,bool> pcheck=props->getBool("checkAddress");
        if (pcheck.first)
            checkIPAddress = pcheck.second;
    }
    
    ISessionCacheEntry* entry = conf->getSessionCache()->find(argp->cookie,app);

    // If not, leave now..
    if (!entry) {
        log.debug("session not found");
        InvalidSessionException ex("No session exists for key value ($session_id)",namedparams(1,"session_id",argp->cookie));
        ostringstream os;
        os << ex;
        result->status=strdup(os.str().c_str());
        return TRUE;
    }

    // TEST the session...
    try {
        // Verify the address is the same
        if (checkIPAddress) {
            log.debug("Checking address against %s", entry->getClientAddress());
            if (strcmp(argp->client_addr, entry->getClientAddress())) {
                log.debug("client address mismatch");
                InvalidSessionException ex(
                    SESSION_E_ADDRESSMISMATCH,
                    "Your IP address (%1) does not match the address recorded at the time the session was established.",
                    params(1,argp->client_addr)
                    );
                Metadata m(app->getMetadataProviders());
                annotateException(ex,m.lookup(entry->getProviderId())); // throws it
            }
        }

        // and that the session is still valid...
        if (!entry->isValid(lifetime,timeout)) {
            log.debug("session expired");
            InvalidSessionException ex(SESSION_E_EXPIRED, "Your session has expired, and you must re-authenticate.");
            Metadata m(app->getMetadataProviders());
            annotateException(ex,m.lookup(entry->getProviderId())); // throws it
        }

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
    }
    catch (SAMLException &e) {
        entry->unlock();
        log.error("caught SAML exception: %s", e.what());
        conf->getSessionCache()->remove(argp->cookie);
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
      
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
        log.error("caught unknown exception");
        InvalidSessionException ex("An unexpected error occurred while validating your session, and you must re-authenticate.");
        Metadata m(app->getMetadataProviders());
        annotateException(ex,m.lookup(entry->getProviderId()),false);
        entry->unlock();
        conf->getSessionCache()->remove(argp->cookie);
        ostringstream os;
        os << ex;
        result->status = strdup(os.str().c_str());

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
    log.debug ("session ok");
    result->status=strdup("");
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

    // Access the application config.
    IConfig* conf=ShibTargetConfig::getConfig().getINI();
    Locker locker(conf);
    const IApplication* app=conf->getApplication(argp->application_id);
    if (!app) {
        // Something's horribly wrong. Flush the session.
        log.error ("couldn't find application for session");
        SAMLException ex("Unable to locate application for session, deleted?");
        ostringstream os;
        os << ex;
        result->status=strdup(os.str().c_str());
        return TRUE;
    }

    bool checkIPAddress=true;
    const IPropertySet* props=app->getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> pcheck=props->getBool("checkAddress");
        if (pcheck.first)
            checkIPAddress = pcheck.second;
    }

    pair<bool,bool> checkReplay=pair<bool,bool>(false,false);
    props=app->getPropertySet("Sessions");
    if (props)
        checkReplay=props->getBool("checkReplay");
 
    const IRoleDescriptor* role=NULL;
    Metadata m(app->getMetadataProviders());
    SAMLBrowserProfile::BrowserProfileResponse bpr;
    try {
        auto_ptr<SAMLBrowserProfile::ArtifactMapper> artifactMapper(app->getArtifactMapper());
      
        // Try and run the profile.
        log.debug("executing browser profile...");
        int allowed = 0;
        if (argp->supported_profiles & SAML11_POST)
            allowed |= SAMLBrowserProfile::Post;
        if (argp->supported_profiles & SAML11_ARTIFACT)
            allowed |= SAMLBrowserProfile::Artifact;
        bpr=app->getBrowserProfile()->receive(
            argp->packet,
            recipient.get(),
            allowed,
            (!checkReplay.first || checkReplay.second) ? conf->getReplayCache() : NULL,
            artifactMapper.get()
            );

        // Blow it away to clear any locks that might be held.
        delete artifactMapper.release();

        // Try and map to metadata (again).
        // Once the metadata layer is in the SAML core, the repetition should be fixed.
        const IEntityDescriptor* provider=m.lookup(bpr.assertion->getIssuer());
        if (!provider && bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier())
            provider=m.lookup(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        if (provider) {
            const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
            role=IDP;
        }
        
        // This isn't likely, since the profile must have found a role.
        if (!role) {
            MetadataException ex("Unable to locate role-specific metadata for identity provider.");
            annotateException(ex,provider); // throws it
        }
    
        // Maybe verify the origin address....
        if (checkIPAddress) {
            log.debug("verify client address");
            // Verify the client address exists
            const XMLCh* ip = bpr.authnStatement->getSubjectIP();
            if (ip && *ip) {
                // Verify the client address matches authentication
                auto_ptr_char this_ip(ip);
                if (strcmp(argp->client_addr, this_ip.get())) {
                    FatalProfileException ex(
                        SESSION_E_ADDRESSMISMATCH,
    	                "Your client's current address ($1) differs from the one used when you authenticated "
                        "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                        "Please contact your local support staff or help desk for assistance.",
                        params(1,argp->client_addr)
                        );
                    annotateException(ex,role); // throws it
                }
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
                FatalProfileException ex("Unable to create session due to unrecognized condition in authentication assertion.");
                annotateException(ex,role); // throws it
            }
            else if (!ac->eval(app->getAudiences())) {
                ostringstream os;
                os << *ac;
                log.error("Unacceptable AudienceRestrictionCondition in authentication assertion (%s), tossing it.",os.str().c_str());
                FatalProfileException ex("Unable to create session due to unacceptable AudienceRestrictionCondition in authentication assertion.");
                annotateException(ex,role); // throws it
            }
        }
    }
    catch (SAMLException& e) {
        bpr.clear();
        log.error("caught SAML exception: %s", e.what());
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
        return TRUE;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("unknown error");
        bpr.clear();
        SAMLException e("An unexpected error occurred while creating your session.");
        annotateException(e,role,false);
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
        return TRUE;
    }
#endif

    // It passes all our tests -- create a new session.
    log.info("creating new session");

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

    auto_ptr_char oname(role->getEntityDescriptor()->getId());
    auto_ptr_char hname(bpr.authnStatement->getSubject()->getNameIdentifier()->getName());

    try {
        // Insert into cache.
        auto_ptr<SAMLAuthenticationStatement> as(static_cast<SAMLAuthenticationStatement*>(bpr.authnStatement->clone()));
        conf->getSessionCache()->insert(
            cookie.c_str(),
            app,
            argp->client_addr,
            (bpr.profile==SAMLBrowserProfile::Post) ? SAML11_POST : SAML11_ARTIFACT,
            oname.get(),
            as.get(),
            (attributesPushed ? bpr.response : NULL),
            role
            );
        as.release();   // owned by cache now
    }
    catch (SAMLException& e) {
        bpr.clear();
        log.error("caught SAML exception: %s", e.what());
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
        return TRUE;
    }
#ifndef _DEBUG
    catch (...) {
        log.error("unknown error");
        bpr.clear();
        SAMLException e("An unexpected error occurred while creating your session.");
        annotateException(e,role,false);
        ostringstream os;
        os << e;
        result->status = strdup(os.str().c_str());
        return TRUE;
    }
#endif

    // And let the user know.
    if (result->cookie) free(result->cookie);
    if (result->target) free(result->target);
    result->cookie = strdup(cookie.c_str());
    result->target = strdup(bpr.TARGET.c_str());
    result->status = strdup("");

    // Maybe delete the response...
    if (!attributesPushed)
        bpr.clear();

    log.debug("new session id: %s", cookie.c_str());
  
    // Transaction Logging
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
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
