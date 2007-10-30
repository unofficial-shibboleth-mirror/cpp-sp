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

/*
 * listener.cpp -- implementation of IListener functional methods that includes ADFS support
 *
 * Scott Cantor
 * 10/10/05
 *
 */

#include "internal.h"

#include <xercesc/framework/MemBufInputSource.hpp>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace adfs;
using namespace adfs::logging;

namespace {
    class ADFSListener : public virtual IListener
    {
    public:
        ADFSListener(const DOMElement* e) : log(&Category::getInstance(ADFS_LOGCAT".Listener")) {}
        ~ADFSListener() {}

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

IPlugIn* ADFSListenerFactory(const DOMElement* e)
{
    return new ADFSListener(e);
}

void ADFSListener::sessionNew(
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
    ShibTargetConfig& stc=ShibTargetConfig::getConfig();
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

    bool bADFS = false;
    SAMLBrowserProfile::BrowserProfileResponse bpr;

    // For now, just branch off to handle ADFS inline, I'll wrap all this up later.
    if (supported_profiles & ADFS_SSO) {
        log->debug("executing ADFS profile...");
        CgiParse parser(packet,strlen(packet));
        const char* param=parser.get_value("wa");
        if (param && !strcmp(param,"wsignin1.0")) {
            bADFS=true;
            param=parser.get_value("wresult");
            if (!param)
                throw FatalProfileException("ADFS profile required wresult parameter not found");
            
            log->debug("decoded ADFS Token response:\n%s",param);
            // wresult should carry an wst:RequestSecurityTokenResponse message so we parse it manually
            DOMDocument* rdoc=NULL;
            try {
                saml::XML::Parser p;
                static const XMLCh systemId[]={chLatin_W, chLatin_S, chDash, chLatin_T, chLatin_r, chLatin_u, chLatin_s, chLatin_t, chNull};
                MemBufInputSource membufsrc(reinterpret_cast<const XMLByte*>(param),strlen(param),systemId,false);
                Wrapper4InputSource dsrc(&membufsrc,false);
                rdoc=p.parse(dsrc);
        
                // Process the wrapper and extract the assertion.
                if (saml::XML::isElementNamed(rdoc->getDocumentElement(),adfs::XML::WSTRUST_NS,ADFS_L(RequestSecurityTokenResponse))) {
                    DOMElement* e=
                        saml::XML::getFirstChildElement(rdoc->getDocumentElement(),adfs::XML::WSTRUST_NS,ADFS_L(RequestedSecurityToken));
                    if (e) {
                        e=saml::XML::getFirstChildElement(e,saml::XML::SAML_NS,L(Assertion));
                        if (e) {

                            // Wrap the assertion DOM in a dummy samlp:Response for subsequent processing.
                            // We have to manually create the Response DOM first in order to avoid
                            // corrupting the namespace declarations in the Assertion.

                            static const XMLCh One[]={chDigit_1, chNull};
                            static const XMLCh dummyID[] = {chLatin_A, chLatin_D, chLatin_F, chLatin_S, chNull};
                            static const XMLCh samlp_Success[]=
                            { chLatin_s, chLatin_a, chLatin_m, chLatin_l, chLatin_p, chColon,
                              chLatin_S, chLatin_u, chLatin_c, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chNull };
                            DOMElement* rdom=rdoc->createElementNS(saml::XML::SAMLP_NS,L(Response));
                            rdom->setAttributeNS(saml::XML::XMLNS_NS,L_QNAME(xmlns,samlp),saml::XML::SAMLP_NS);
                            rdom->setAttributeNS(saml::XML::XMLNS_NS,L(xmlns),saml::XML::SAMLP_NS);
                            rdom->setAttributeNS(NULL,L(MajorVersion),One);
                            rdom->setAttributeNS(NULL,L(MinorVersion),One);
                            rdom->setAttributeNS(NULL,L(ResponseID),dummyID);
                            SAMLDateTime issued(time(NULL));
                            issued.parseDateTime();
                            rdom->setAttributeNS(NULL,L(IssueInstant),issued.getRawData());
                            DOMElement* status=rdoc->createElementNS(saml::XML::SAMLP_NS,L(Status));
                            rdom->appendChild(status);
                            DOMElement* code=rdoc->createElementNS(saml::XML::SAMLP_NS,L(StatusCode));
                            code->setAttributeNS(NULL,L(Value),samlp_Success);
                            status->appendChild(code);
                            rdom->appendChild(e);   // append the assertion
                            auto_ptr<SAMLResponse> response(new SAMLResponse(rdom));
                            response->setDocument(rdoc);    // give the Document to the response object
                            // root the response in the document so the signature will verify
                            rdoc->replaceChild(response->toDOM(rdoc,false),rdoc->getDocumentElement());
                            rdoc=NULL;
                            
                            // Try and map to metadata.
                            SAMLAssertion* assertion=response->getAssertions().next();
                            const IEntityDescriptor* provider=m.lookup(assertion->getIssuer());
                            if (provider)
                                role=provider->getIDPSSODescriptor(adfs::XML::WSFED_NS);
                            if (!role) {
                                MetadataException ex("unable to locate role-specific metadata for identity provider.");
                                annotateException(&ex,provider); // throws it
                            }
                            
                            try {
                                // Check over the assertion.
                                SAMLAuthenticationStatement* authnStatement=checkAssertionProfile(assertion);

                                if (!checkReplay.first || checkReplay.second) {
                                    auto_ptr_char id(assertion->getId());
                                    string key(id.get());
                                    key="P_" + key;
                                    if (!conf->getReplayCache()->check(key.c_str(),assertion->getNotOnOrAfter()->getEpoch()))
                                        throw ReplayedAssertionException(string("Rejecting replayed assertion ID (") + id.get() + ")");
                                }
                                
                                // Check signature.
                                log->debug("passing signed ADFS assertion to trust layer");
                                Trust t(app->getTrustProviders());
                                if (!t.validate(*assertion,role)) {
                                    log->error("unable to verify signed ADFS assertion");
                                    throw TrustException("unable to verify signed authentication assertion");
                                }
                                log->info("verified digital signature over ADFS assertion");
                                
                                // Now dummy up the SAML profile response wrapper.
                                param=parser.get_value("wctx");
                                if (param)
                                    bpr.TARGET=param;
                                bpr.profile=SAMLBrowserProfile::Post;   // not really, but...
                                bpr.response=response.release();
                                bpr.assertion=assertion;
                                bpr.authnStatement=authnStatement;
                            }
                            catch (SAMLException& ex) {
                                annotateException(&ex,role); // throws it
                            }
                        }
                    }
                }
                if (rdoc) {
                    rdoc->release();
                    rdoc=NULL;
                }
            }
            catch(...) {
                if (rdoc) rdoc->release();
                throw;
            }
        }
        if (bADFS && !bpr.response)
            throw FatalProfileException("ADFS profile was indicated, but processing was unsuccesful");
    }
    
    // If ADFS wasn't used, proceed to SAML processing up until we reach a common point.
    int minorVersion = 1;
    try {
        if (!bADFS) {
            int allowed = 0;
            if (supported_profiles & SAML11_POST || supported_profiles & SAML10_POST)
                allowed |= SAMLBrowserProfile::Post;
            if (supported_profiles & SAML11_ARTIFACT || supported_profiles & SAML10_ARTIFACT)
                allowed |= SAMLBrowserProfile::Artifact;
            minorVersion=(supported_profiles & SAML11_ARTIFACT || supported_profiles & SAML11_POST) ? 1 : 0;
    
            auto_ptr<SAMLBrowserProfile::ArtifactMapper> artifactMapper(app->getArtifactMapper());
      
            // Try and run the profile.
            log->debug("executing browser profile...");
            bpr=app->getBrowserProfile()->receive(
                packet,
                wrecipient.get(),
                allowed,
                (!checkReplay.first || checkReplay.second) ? conf->getReplayCache() : NULL,
                artifactMapper.get(),
                minorVersion
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
                const IIDPSSODescriptor* IDP=provider->getIDPSSODescriptor(
                    minorVersion==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
                    );
                role=IDP;
            }
            
            // This isn't likely, since the profile must have found a role.
            if (!role) {
                MetadataException ex("Unable to locate role-specific metadata for identity provider.");
                annotateException(&ex,provider); // throws it
            }
        }
        
        // At this point, we link back up and do the same work for ADFS and SAML.
        
        // Maybe verify the origin address....
        if (checkIPAddress) {
            log->debug("verifying client address");
            // Verify the client address exists
            const XMLCh* wip = bpr.authnStatement->getSubjectIP();
            if (wip && *wip) {
                // Verify the client address matches authentication
                auto_ptr_char this_ip(wip);
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
        // Attribute assertions get filtered later by the AAP.
        Iterator<SAMLCondition*> conditions=bpr.assertion->getConditions();
        while (conditions.hasNext()) {
            SAMLCondition* cond=conditions.next();
            const SAMLAudienceRestrictionCondition* ac=dynamic_cast<const SAMLAudienceRestrictionCondition*>(cond);
            if (!ac) {
                ostringstream os;
                os << *cond;
                log->error("Unrecognized Condition in authentication assertion (%s), tossing it.",os.str().c_str());
                FatalProfileException ex("unable to create session due to unrecognized condition in authentication assertion.");
                annotateException(&ex,role); // throws it
            }
            else if (!ac->eval(app->getAudiences())) {
                ostringstream os;
                os << *ac;
                log->error("Unacceptable AudienceRestrictionCondition in authentication assertion (%s), tossing it.",os.str().c_str());
                FatalProfileException ex("unable to create session due to unacceptable AudienceRestrictionCondition in authentication assertion.");
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
        // Create a new session key.
        cookie = conf->getSessionCache()->generateKey();

        // Insert into cache.
        auto_ptr<SAMLAuthenticationStatement> as(static_cast<SAMLAuthenticationStatement*>(bpr.authnStatement->clone()));
        conf->getSessionCache()->insert(
            cookie.c_str(),
            app,
            ip,
            (bADFS ? ADFS_SSO :
                ((bpr.profile==SAMLBrowserProfile::Post) ?
                    (minorVersion==1 ? SAML11_POST : SAML10_POST) : (minorVersion==1 ? SAML11_ARTIFACT : SAML10_ARTIFACT))),
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
    FixedContextCategory tranLog(SHIBTRAN_LOGCAT);
    tranLog.infoStream() <<
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
    //stc.releaseTransactionLog();
}

void ADFSListener::sessionGet(
    const IApplication* app,
    const char* cookie,
    const char* ip,
    ISessionCacheEntry** pentry
    ) const
{
    g_MemoryListener->sessionGet(app,cookie,ip,pentry);
}

void ADFSListener::sessionEnd(
    const IApplication* application,
    const char* cookie
    ) const
{
    g_MemoryListener->sessionEnd(application,cookie);
}

void ADFSListener::ping(int& i) const
{
    g_MemoryListener->ping(i);
}
