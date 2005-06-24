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

/* ArtifactMapper.cpp - a ShibTarget-aware SAML artifact->binding mapper

   Scott Cantor
   2/20/05

   $History:$
*/

#include "internal.h"

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

SAMLResponse* STArtifactMapper::resolve(SAMLRequest* request)
{
    Category& log=Category::getInstance("shibtarget.ArtifactMapper");
    
    // First do a search for the issuer.
    SAMLArtifact* artifact=request->getArtifacts().next();
    Metadata m(m_app->getMetadataProviders());
    const IEntityDescriptor* entity=m.lookup(artifact);
    if (!entity) {
        log.error(
            "metadata lookup failed, unable to determine issuer of artifact (0x%s)",
            SAMLArtifact::toHex(artifact->getBytes()).c_str()
            );
        throw MetadataException("Metadata lookup failed, unable to determine artifact issuer");
    }
    
    auto_ptr_char issuer(entity->getId());
    log.info("lookup succeeded, artifact issued by (%s)", issuer.get());
    
    // Sign it?
    const IPropertySet* credUse=m_app->getCredentialUse(entity);
    pair<bool,bool> signRequest=credUse ? credUse->getBool("signRequest") : make_pair(false,false);
    pair<bool,bool> signedResponse=credUse ? credUse->getBool("signedResponse") : make_pair(false,false);
    pair<bool,const char*> signingCred=credUse ? credUse->getString("Signing") : pair<bool,const char*>(false,NULL);
    if (signRequest.first && signRequest.second && signingCred.first) {
        Credentials creds(ShibTargetConfig::getConfig().getINI()->getCredentialsProviders());
        const ICredResolver* cr=creds.lookup(signingCred.second);
        if (cr)
            request->sign(cr->getKey(),cr->getCertificates());
        else
            log.error("unable to sign artifact request, specified credential (%) was not found",signingCred.second);
    }

	SAMLResponse* response = NULL;
	bool authenticated = false;

    // Depends on type of artifact.
    const SAMLArtifactType0001* type1=dynamic_cast<const SAMLArtifactType0001*>(artifact);
    if (type1) {
        // With type 01, any endpoint will do.
        const IIDPSSODescriptor* idp=entity->getIDPSSODescriptor(
            request->getMinorVersion()==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
            );
        if (idp) {
		    ShibHTTPHook::ShibHTTPHookCallContext callCtx(credUse ? credUse->getString("TLS").second : NULL,idp);
            const IEndpointManager* mgr=idp->getArtifactResolutionServiceManager();
            Iterator<const IEndpoint*> eps=mgr ? mgr->getEndpoints() : EMPTY(const IEndpoint*);
            while (!response && eps.hasNext()) {
                const IEndpoint* ep=eps.next();
                const SAMLBinding* binding = m_app->getBinding(ep->getBinding());
                if (!binding) {
                    auto_ptr_char prot(ep->getBinding());
                    log.warn("skipping binding on unsupported protocol (%s)", prot.get());
                    continue;
                }
                auto_ptr_char loc(ep->getLocation());
		        try {
		            response = binding->send(ep->getLocation(),*request,&callCtx);
		            if (log.isDebugEnabled())
		            	log.debugStream() << "SAML response from artifact request:\n" << *response << CategoryStream::ENDLINE;
		            
		            if (!response->getAssertions().hasNext()) {
		                delete response;
		                throw FatalProfileException("No SAML assertions returned in response to artifact profile request.");
		            }
		            authenticated = callCtx.isAuthenticated();
		        }
		        catch (SAMLException& ex) {
		        	annotateException(&ex,idp); // rethrows it
		        }
            }
        }
    }
    else {
        const SAMLArtifactType0002* type2=dynamic_cast<const SAMLArtifactType0002*>(artifact);
        if (type2) {
            // With type 02, we have to find the matching location.
            const IIDPSSODescriptor* idp=entity->getIDPSSODescriptor(
                request->getMinorVersion()==1 ? saml::XML::SAML11_PROTOCOL_ENUM : saml::XML::SAML10_PROTOCOL_ENUM
                );
            if (idp) {
    		    ShibHTTPHook::ShibHTTPHookCallContext callCtx(credUse ? credUse->getString("TLS").second : NULL,idp);
                const IEndpointManager* mgr=idp->getArtifactResolutionServiceManager();
                Iterator<const IEndpoint*> eps=mgr ? mgr->getEndpoints() : EMPTY(const IEndpoint*);
                while (eps.hasNext()) {
                    const IEndpoint* ep=eps.next();
                    auto_ptr_char loc(ep->getLocation());
                    if (strcmp(loc.get(),type2->getSourceLocation()))
                    	continue;
	                const SAMLBinding* binding = m_app->getBinding(ep->getBinding());
	                if (!binding) {
	                    auto_ptr_char prot(ep->getBinding());
	                    log.warn("skipping binding on unsupported protocol (%s)", prot.get());
	                    continue;
	                }
			        try {
			            response = binding->send(ep->getLocation(),*request,&callCtx);
			            if (log.isDebugEnabled())
			            	log.debugStream() << "SAML response from artifact request:\n" << *response << CategoryStream::ENDLINE;
			            
			            if (!response->getAssertions().hasNext()) {
			                delete response;
			                throw FatalProfileException("No SAML assertions returned in response to artifact profile request.");
			            }
			            authenticated = callCtx.isAuthenticated();
			        }
			        catch (SAMLException& ex) {
			        	annotateException(&ex,idp); // rethrows it
			        }
                }
            }
        }
        else {
            log.error("unrecognized artifact type (0x%s)", SAMLArtifact::toHex(artifact->getTypeCode()).c_str());
            throw UnsupportedExtensionException(
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
	        TrustException ex("Unable to obtain a signed response from artifact request.");
		    annotateException(&ex,entity); // throws it
    	}
    }
    
    return response;
}
