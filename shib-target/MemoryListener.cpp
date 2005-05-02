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
 * MemoryListener.cpp -- An actual implementation of the IListener functional methods
 *
 * Scott Cantor
 * 5/1/05
 *
 */

#include "internal.h"

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace {
    class MemoryListener : public virtual IListener
    {
    public:
        MemoryListener(const DOMElement* e) : log(&Category::getInstance(SHIBT_LOGCAT".Listener")) {}
        ~MemoryListener() {}

        bool create(ShibSocket& s) const {return true;}
        bool bind(ShibSocket& s, bool force=false) const {return true;}
        bool connect(ShibSocket& s) const {return true;}
        bool close(ShibSocket& s) const {return true;}
        bool accept(ShibSocket& listener, ShibSocket& s) const {return true;}

        void sessionNew(
            const IApplication* application,
            int supported_profiles,
            const char* recipient,
            const char* packet,
            const char* ip,
            std::string& target,
            std::string& cookie,
            std::string& provider_id
            ) const;
    
        void sessionGet(
            const IApplication* application,
            const char* cookie,
            const char* ip,
            ISessionCacheEntry** pentry
            ) const;
    
        void sessionEnd(
            const IApplication* application,
            const char* cookie
        ) const;
        
        void ping(int& i) const;

    private:
        Category* log;
    };
}

IPlugIn* MemoryListenerFactory(const DOMElement* e)
{
    return new MemoryListener(e);
}

void MemoryListener::sessionNew(
    const IApplication* app,
    int supported_profiles,
    const char* recipient,
    const char* packet,
    const char* ip,
    string& target,
    string& cookie,
    string& provider_id
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionNew");
#endif

    log->debug("creating session for %s", ip);
    log->debug("recipient: %s", recipient);
    log->debug("application: %s", app->getId());

    auto_ptr_XMLCh wrecipient(recipient);

    // Access the application config. It's already locked behind us.
    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    IConfig* conf=stc.getINI();

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
        log->debug("executing browser profile...");
        int allowed = 0;
        if (supported_profiles & SAML11_POST)
            allowed |= SAMLBrowserProfile::Post;
        if (supported_profiles & SAML11_ARTIFACT)
            allowed |= SAMLBrowserProfile::Artifact;
        bpr=app->getBrowserProfile()->receive(
            packet,
            wrecipient.get(),
            allowed,
            (!checkReplay.first || checkReplay.second) ? conf->getReplayCache() : NULL,
            artifactMapper.get()
            );

        // Blow it away to clear any locks that might be held.
        delete artifactMapper.release();

        // Try and map to metadata (again).
        // Once the metadata layer is in the SAML core, the repetition should be fixed.
        const IEntityDescriptor* provider=m.lookup(bpr.assertion->getIssuer());
        if (!provider && bpr.authnStatement->getSubject()->getNameIdentifier() &&
                bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier())
            provider=m.lookup(bpr.authnStatement->getSubject()->getNameIdentifier()->getNameQualifier());
        if (provider) {
            const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
            role=IDP;
        }
        
        // This isn't likely, since the profile must have found a role.
        if (!role) {
            MetadataException ex("Unable to locate role-specific metadata for identity provider.");
            annotateException(&ex,provider); // throws it
        }
    
        // Maybe verify the origin address....
        if (checkIPAddress) {
            log->debug("verifying client address");
            // Verify the client address exists
            const XMLCh* wip = bpr.authnStatement->getSubjectIP();
            if (wip && *wip) {
                // Verify the client address matches authentication
                auto_ptr_char this_ip(ip);
                if (strcmp(ip, this_ip.get())) {
                    FatalProfileException ex(
                        SESSION_E_ADDRESSMISMATCH,
                       "Your client's current address ($1) differs from the one used when you authenticated "
                        "to your identity provider. To correct this problem, you may need to bypass a proxy server. "
                        "Please contact your local support staff or help desk for assistance.",
                        params(1,ip)
                        );
                    annotateException(&ex,role); // throws it
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
                log->error("Unrecognized Condition in authentication assertion (%s), tossing it.",os.str().c_str());
                FatalProfileException ex("Unable to create session due to unrecognized condition in authentication assertion.");
                annotateException(&ex,role); // throws it
            }
            else if (!ac->eval(app->getAudiences())) {
                ostringstream os;
                os << *ac;
                log->error("Unacceptable AudienceRestrictionCondition in authentication assertion (%s), tossing it.",os.str().c_str());
                FatalProfileException ex("Unable to create session due to unacceptable AudienceRestrictionCondition in authentication assertion.");
                annotateException(&ex,role); // throws it
            }
        }
    }
    catch (SAMLException&) {
        bpr.clear();
        throw;
    }
    catch (...) {
        log->error("caught unknown exception");
        bpr.clear();
#ifdef _DEBUG
        throw;
#else
        SAMLException e("An unexpected error occurred while creating your session.");
        annotateException(&e,role);
#endif
    }

    // It passes all our tests -- create a new session.
    log->info("creating new session");

    // Create a new session key.
    cookie = conf->getSessionCache()->generateKey();

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
            ip,
            (bpr.profile==SAMLBrowserProfile::Post) ? SAML11_POST : SAML11_ARTIFACT,
            oname.get(),
            as.get(),
            (attributesPushed ? bpr.response : NULL),
            role
            );
        as.release();   // owned by cache now
    }
    catch (SAMLException&) {
        bpr.clear();
        throw;
    }
    catch (...) {
        log->error("caught unknown exception");
        bpr.clear();
#ifdef _DEBUG
        throw;
#else
        SAMLException e("An unexpected error occurred while creating your session.");
        annotateException(&e,role);
#endif
    }

    target = bpr.TARGET;
    provider_id = oname.get();

    // Maybe delete the response...
    if (!attributesPushed)
        bpr.clear();

    log->debug("new session id: %s", cookie.c_str());
  
    // Transaction Logging
    stc.getTransactionLog().infoStream() <<
        "New session (ID: " <<
            cookie <<
        ") with (applicationId: " <<
            app->getId() <<
        ") for principal from (IdP: " <<
            provider_id <<
        ") at (ClientAddress: " <<
            ip <<
        ") with (NameIdentifier: " <<
            hname.get() <<
        ")";

    stc.releaseTransactionLog();
}

void MemoryListener::sessionGet(
    const IApplication* app,
    const char* cookie,
    const char* ip,
    ISessionCacheEntry** pentry
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionGet");
#endif

    *pentry=NULL;
    log->debug("checking for session: %s@%s", cookie, ip);

    // See if the session exists...

    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    IConfig* conf=stc.getINI();
    log->debug("application: %s", app->getId());

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
    
    *pentry = conf->getSessionCache()->find(cookie,app);

    // If not, leave now..
    if (!*pentry) {
        log->debug("session not found");
        throw InvalidSessionException("No session exists for key value ($session_id)",namedparams(1,"session_id",cookie));
    }

    // TEST the session...
    try {
        // Verify the address is the same
        if (checkIPAddress) {
            log->debug("Checking address against %s", (*pentry)->getClientAddress());
            if (strcmp(ip, (*pentry)->getClientAddress())) {
                log->debug("client address mismatch");
                InvalidSessionException ex(
                    SESSION_E_ADDRESSMISMATCH,
                    "Your IP address (%1) does not match the address recorded at the time the session was established.",
                    params(1,ip)
                    );
                Metadata m(app->getMetadataProviders());
                annotateException(&ex,m.lookup((*pentry)->getProviderId())); // throws it
            }
        }

        // and that the session is still valid...
        if (!(*pentry)->isValid(lifetime,timeout)) {
            log->debug("session expired");
            InvalidSessionException ex(SESSION_E_EXPIRED, "Your session has expired, and you must re-authenticate.");
            Metadata m(app->getMetadataProviders());
            annotateException(&ex,m.lookup((*pentry)->getProviderId())); // throws it
        }
    }
    catch (SAMLException&) {
        (*pentry)->unlock();
        *pentry=NULL;
        conf->getSessionCache()->remove(cookie);
      
        // Transaction Logging
        stc.getTransactionLog().infoStream() <<
            "Destroyed invalid session (ID: " <<
                cookie <<
            ") with (applicationId: " <<
                app->getId() <<
            "), request was from (ClientAddress: " <<
                ip <<
            ")";
        stc.releaseTransactionLog();
        throw;
    }
    catch (...) {
        log->error("caught unknown exception");
#ifndef _DEBUG
        InvalidSessionException ex("An unexpected error occurred while validating your session, and you must re-authenticate.");
        Metadata m(app->getMetadataProviders());
        annotateException(&ex,m.lookup((*pentry)->getProviderId()),false);
#endif
        (*pentry)->unlock();
        *pentry=NULL;
        conf->getSessionCache()->remove(cookie);

        // Transaction Logging
        stc.getTransactionLog().infoStream() <<
            "Destroyed invalid session (ID: " <<
                cookie <<
            ") with (applicationId: " <<
                app->getId() <<
            "), request was from (ClientAddress: " <<
                ip <<
            ")";
        stc.releaseTransactionLog();

#ifdef _DEBUG
        throw;
#else
        ex.raise();
#endif
    }

    log->debug("session ok");
}

void MemoryListener::sessionEnd(
    const IApplication* application,
    const char* cookie
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("sessionEnd");
#endif

    log->debug("removing session: %s", cookie);

    STConfig& stc=static_cast<STConfig&>(ShibTargetConfig::getConfig());
    stc.getINI()->getSessionCache()->remove(cookie);
  
    // Transaction Logging
    stc.getTransactionLog().infoStream() << "Destroyed session (ID: " << cookie << ")";
    stc.releaseTransactionLog();
}

void MemoryListener::ping(int& i) const
{
    i++;
}
