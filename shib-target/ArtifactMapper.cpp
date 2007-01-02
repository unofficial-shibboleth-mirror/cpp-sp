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

/* ArtifactMapper.cpp - a ShibTarget-aware SAML artifact->binding mapper

   Scott Cantor
   2/20/05

   $History:$
*/

#include "internal.h"
#include <saml/binding/SAMLArtifact.h>

using namespace shibsp;
using namespace shibtarget;
using namespace saml;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

SAMLResponse* STArtifactMapper::resolve(SAMLRequest* request)
{
    Category& log=Category::getInstance("shibtarget.ArtifactMapper");
    
    // First do a search for the issuer.
    SAMLArtifact* artifact=request->getArtifacts().next();
    auto_ptr<opensaml::SAMLArtifact> os2art(opensaml::SAMLArtifact::parse(artifact->encode().c_str()));

    MetadataProvider* m=m_app->getMetadataProvider();
    const EntityDescriptor* entity=m->getEntityDescriptor(os2art.get());
    if (!entity) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            opensaml::SAMLArtifact::toHex(artifact->getBytes()).c_str()
            );
        throw MetadataException("Metadata lookup failed, unable to determine artifact issuer");
    }
    
    xmltooling::auto_ptr_char issuer(entity->getEntityID());
    log.info("lookup succeeded, artifact issued by (%s)", issuer.get());
    
    // Sign it?
    const PropertySet* credUse=m_app->getCredentialUse(entity);
    pair<bool,bool> signRequest=credUse ? credUse->getBool("signRequest") : make_pair(false,false);
    pair<bool,const char*> signatureAlg=credUse ? credUse->getString("signatureAlg") : pair<bool,const char*>(false,NULL);
    if (!signatureAlg.first)
        signatureAlg.second=URI_ID_RSA_SHA1;
    pair<bool,const char*> digestAlg=credUse ? credUse->getString("digestAlg") : pair<bool,const char*>(false,NULL);
    if (!digestAlg.first)
        digestAlg.second=URI_ID_SHA1;
    pair<bool,bool> signedResponse=credUse ? credUse->getBool("signedResponse") : make_pair(false,false);
    pair<bool,const char*> signingCred=credUse ? credUse->getString("Signing") : pair<bool,const char*>(false,NULL);
    if (signRequest.first && signRequest.second && signingCred.first) {
        if (request->getMinorVersion()==1) {
            shibboleth::Credentials creds(ShibTargetConfig::getConfig().getINI()->getCredentialsProviders());
            const shibboleth::ICredResolver* cr=creds.lookup(signingCred.second);
            if (cr)
                request->sign(cr->getKey(),cr->getCertificates(),signatureAlg.second,digestAlg.second);
            else
                log.error("unable to sign artifact request, specified credential (%s) was not found",signingCred.second);
        }
        else
            log.error("unable to sign SAML 1.0 artifact request, only SAML 1.1 defines signing adequately");
    }

	SAMLResponse* response = NULL;
	bool authenticated = false;
    static const XMLCh https[] = {chLatin_h, chLatin_t, chLatin_t, chLatin_p, chLatin_s, chColon, chNull};

    // Depends on type of artifact.
    const SAMLArtifactType0001* type1=dynamic_cast<const SAMLArtifactType0001*>(artifact);
    if (type1) {
        // With type 01, any endpoint will do.
        const IDPSSODescriptor* idp=entity->getIDPSSODescriptor(
            request->getMinorVersion()==1 ? samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM
            );
        if (idp) {
		    ShibHTTPHook::ShibHTTPHookCallContext callCtx(credUse,idp);
            const vector<ArtifactResolutionService*>& endpoints=idp->getArtifactResolutionServices();
            for (vector<ArtifactResolutionService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
                const SAMLBinding* binding = m_app->getBinding((*ep)->getBinding());
                if (!binding) {
                    xmltooling::auto_ptr_char prot((*ep)->getBinding());
                    log.warn("skipping binding on unsupported protocol (%s)", prot.get());
                    continue;
                }
		        try {
		            response = binding->send((*ep)->getLocation(),*request,&callCtx);
		            if (log.isDebugEnabled())
		            	log.debugStream() << "SAML response from artifact request:\n" << *response << CategoryStream::ENDLINE;
		            
		            if (!response->getAssertions().hasNext()) {
		                delete response;
		                throw FatalProfileException("No SAML assertions returned in response to artifact profile request.");
		            }
		            authenticated = callCtx.isAuthenticated() && !XMLString::compareNString((*ep)->getLocation(),https,6);
		        }
		        catch (XMLToolingException& ex) {
		        	annotateException(&ex,idp); // rethrows it
		        }
                catch (exception& ex) {
                    opensaml::BindingException ex2(ex.what());
                    annotateException(&ex2,idp); // rethrows it
                }
            }
        }
    }
    else {
        const SAMLArtifactType0002* type2=dynamic_cast<const SAMLArtifactType0002*>(artifact);
        if (type2) {
            // With type 02, we have to find the matching location.
            const IDPSSODescriptor* idp=entity->getIDPSSODescriptor(
                request->getMinorVersion()==1 ? samlconstants::SAML11_PROTOCOL_ENUM : samlconstants::SAML10_PROTOCOL_ENUM
                );
            if (idp) {
    		    ShibHTTPHook::ShibHTTPHookCallContext callCtx(credUse,idp);
                const vector<ArtifactResolutionService*>& endpoints=idp->getArtifactResolutionServices();
                for (vector<ArtifactResolutionService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
                    xmltooling::auto_ptr_char loc((*ep)->getLocation());
                    if (strcmp(loc.get(),type2->getSourceLocation()))
                    	continue;
	                const SAMLBinding* binding = m_app->getBinding((*ep)->getBinding());
	                if (!binding) {
	                    xmltooling::auto_ptr_char prot((*ep)->getBinding());
	                    log.warn("skipping binding on unsupported protocol (%s)", prot.get());
	                    continue;
	                }
			        try {
			            response = binding->send((*ep)->getLocation(),*request,&callCtx);
			            if (log.isDebugEnabled())
			            	log.debugStream() << "SAML response from artifact request:\n" << *response << CategoryStream::ENDLINE;
			            
			            if (!response->getAssertions().hasNext()) {
			                delete response;
			                throw FatalProfileException("No SAML assertions returned in response to artifact profile request.");
			            }
                        authenticated = callCtx.isAuthenticated() && !XMLString::compareNString((*ep)->getLocation(),https,6);
			        }
		            catch (XMLToolingException& ex) {
		        	    annotateException(&ex,idp); // rethrows it
		            }
                    catch (exception& ex) {
                        opensaml::BindingException ex2(ex.what());
                        annotateException(&ex2,idp); // rethrows it
                    }
                }
            }
        }
        else {
            log.error("unrecognized artifact type (0x%s)", SAMLArtifact::toHex(artifact->getTypeCode()).c_str());
            throw xmltooling::UnknownExtensionException(
                string("Received unrecognized artifact type (0x") + SAMLArtifact::toHex(artifact->getTypeCode()) + ")"
                );
        }
    }
    
    if (!response) {
	    log.error("unable to locate acceptable binding/endpoint to resolve artifact");
	    MetadataException ex("Unable to locate acceptable binding/endpoint to resolve artifact.");
	    annotateException(&ex,entity); // throws it
    }
    else if (!response->isSigned()) {
    	if (!authenticated || (signedResponse.first && signedResponse.second)) {
	        log.error("unsigned response obtained, but it must be signed.");
	        XMLSecurityException ex("Unable to obtain a signed response from artifact request.");
		    annotateException(&ex,entity); // throws it
    	}
    }
    
    return response;
}
