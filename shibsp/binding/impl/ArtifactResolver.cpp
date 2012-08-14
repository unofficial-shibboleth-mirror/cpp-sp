/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * ArtifactResolver.cpp
 * 
 * SAML artifact resolver for SP use.
 */

#include "internal.h"
#include "Application.h"
#include "binding/ArtifactResolver.h"
#include "binding/SOAPClient.h"
#include "security/SecurityPolicy.h"
#include "util/SPConstants.h"

#include <fstream>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/PathResolver.h>
#include <saml/exceptions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/binding/SAML2Artifact.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/metadata/EndpointManager.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/util/SAMLConstants.h>

using namespace shibsp;
using namespace opensaml::saml1p;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

ArtifactResolver::ArtifactResolver()
{
}

ArtifactResolver::~ArtifactResolver()
{
}

bool ArtifactResolver::isSupported(const SSODescriptorType& ssoDescriptor) const
{
    if (MessageDecoder::ArtifactResolver::isSupported(ssoDescriptor))
        return true;

    EndpointManager<ArtifactResolutionService> mgr(ssoDescriptor.getArtifactResolutionServices());
    if (ssoDescriptor.hasSupport(samlconstants::SAML20P_NS)) {
        return (mgr.getByBinding(shibspconstants::SHIB2_BINDING_FILE) != nullptr);
    }

    return false;
}

saml1p::Response* ArtifactResolver::resolve(
    const vector<SAMLArtifact*>& artifacts,
    const IDPSSODescriptor& idpDescriptor,
    opensaml::SecurityPolicy& policy
    ) const
{
    MetadataCredentialCriteria mcc(idpDescriptor);
    shibsp::SecurityPolicy& sppolicy = dynamic_cast<shibsp::SecurityPolicy&>(policy);
    shibsp::SOAPClient soaper(sppolicy);

    bool foundEndpoint = false;
    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    saml1p::Response* response=nullptr;
    const vector<ArtifactResolutionService*>& endpoints=idpDescriptor.getArtifactResolutionServices();
    for (vector<ArtifactResolutionService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            foundEndpoint = true;
            auto_ptr_char loc((*ep)->getLocation());
            saml1p::Request* request = saml1p::RequestBuilder::buildRequest();
            request->setMinorVersion(idpDescriptor.hasSupport(samlconstants::SAML11_PROTOCOL_ENUM) ? 1 : 0);
            for (vector<SAMLArtifact*>::const_iterator a = artifacts.begin(); a!=artifacts.end(); ++a) {
                auto_ptr_XMLCh artbuf((*a)->encode().c_str());
                AssertionArtifact* aa = AssertionArtifactBuilder::buildAssertionArtifact();
                aa->setArtifact(artbuf.get());
                request->getAssertionArtifacts().push_back(aa);
            }

            SAML1SOAPClient client(soaper, false);
            client.sendSAML(request, sppolicy.getApplication().getId(), mcc, loc.get());
            response = client.receiveSAML();
        }
        catch (std::exception& ex) {
            Category::getInstance(SHIBSP_LOGCAT".ArtifactResolver").error("exception resolving SAML 1.x artifact(s): %s", ex.what());
            soaper.reset();
        }
    }

    if (!foundEndpoint)
        throw MetadataException("No compatible endpoint found in issuer's metadata.");
    else if (!response)
        throw BindingException("Unable to resolve artifact(s) into a SAML response.");
    const xmltooling::QName* code = (response->getStatus() && response->getStatus()->getStatusCode()) ? response->getStatus()->getStatusCode()->getValue() : nullptr;
    if (!code || *code != saml1p::StatusCode::SUCCESS) {
        auto_ptr<saml1p::Response> wrapper(response);
        BindingException ex("Identity provider returned a SAML error during artifact resolution.");
        annotateException(&ex, &idpDescriptor, response->getStatus());  // rethrow
    }

    // The SOAP client handles policy evaluation against the SOAP and Response layer,
    // but no security checking is done here.
    return response;
}

ArtifactResponse* ArtifactResolver::resolve(
    const SAML2Artifact& artifact,
    const SSODescriptorType& ssoDescriptor,
    opensaml::SecurityPolicy& policy
    ) const
{
    Category& log = Category::getInstance(SHIBSP_LOGCAT".ArtifactResolver");

    MetadataCredentialCriteria mcc(ssoDescriptor);
    shibsp::SecurityPolicy& sppolicy = dynamic_cast<shibsp::SecurityPolicy&>(policy);
    shibsp::SOAPClient soaper(sppolicy);

    bool foundEndpoint = false;
    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    ArtifactResponse* response=nullptr;

    vector<ArtifactResolutionService*>::const_iterator ep_start, ep_end;
    const vector<ArtifactResolutionService*>& endpoints = ssoDescriptor.getArtifactResolutionServices();
    ep_start = find_if(endpoints.begin(), endpoints.end(),
        boost::bind(&pair<bool,int>::second, boost::bind(&IndexedEndpointType::getIndex, _1)) == artifact.getEndpointIndex());
    if (ep_start == endpoints.end()) {
        ep_start = endpoints.begin();
        ep_end = endpoints.end();
    }
    else {
        ep_end = ep_start + 1;
    }

    const PropertySet* rp = sppolicy.getApplication().getRelyingParty(dynamic_cast<const EntityDescriptor*>(ssoDescriptor.getParent()));
    pair<bool,bool> artifactByFilesystem = rp->getBool("artifactByFilesystem");

    for (vector<ArtifactResolutionService*>::const_iterator ep = ep_start; !response && ep != ep_end; ++ep) {
        try {
            if (XMLString::equals((*ep)->getBinding(), binding.get())) {
                foundEndpoint = true;
                auto_ptr_char loc((*ep)->getLocation());
                ArtifactResolve* request = ArtifactResolveBuilder::buildArtifactResolve();
                Issuer* iss = IssuerBuilder::buildIssuer();
                request->setIssuer(iss);
                iss->setName(rp->getXMLString("entityID").second);
                auto_ptr_XMLCh artbuf(artifact.encode().c_str());
                Artifact* a = ArtifactBuilder::buildArtifact();
                a->setArtifact(artbuf.get());
                request->setArtifact(a);

                SAML2SOAPClient client(soaper, false);
                client.sendSAML(request, sppolicy.getApplication().getId(), mcc, loc.get());
                StatusResponseType* srt = client.receiveSAML();
                if (!(response = dynamic_cast<ArtifactResponse*>(srt))) {
                    delete srt;
                    break;
                }
            }
            else if (artifactByFilesystem.first && artifactByFilesystem.second && XMLString::equals((*ep)->getBinding(), shibspconstants::SHIB2_BINDING_FILE)) {
                // This implements a resolution process against the local file system for custom integration needs.
                // The local filesystem is presumed to be "secure" so that unsigned, unencrypted responses are acceptable.
                // The binding here is not SOAP, but rather REST-like, with the base location used to construct a filename
                // containing the artifact message handle.
                foundEndpoint = true;
                auto_ptr_char temp((*ep)->getLocation());
                if (temp.get()) {
                    string loc(temp.get());
                    if (starts_with(loc, "file://"))
                        loc = loc.substr(7);
                    XMLToolingConfig::getConfig().getPathResolver()->resolve(loc, PathResolver::XMLTOOLING_RUN_FILE);
                    loc += '/' + SAMLArtifact::toHex(artifact.getMessageHandle());
                    ifstream in(loc.c_str());
                    if (in) {
                        auto_ptr<XMLObject> xmlObject;
                        try {
                            DOMDocument* doc = (policy.getValidating() ? XMLToolingConfig::getConfig().getValidatingParser() : XMLToolingConfig::getConfig().getParser()).parse(in);
                            XercesJanitor<DOMDocument> docjanitor(doc);

                            if (log.isDebugEnabled()) {
                                string buf;
                                XMLHelper::serialize(doc->getDocumentElement(), buf);
                                log.debugStream() << "received XML:\n" << buf << logging::eol;
                            }
                            xmlObject.reset(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
                            docjanitor.release();
                        }
                        catch (std::exception&) {
                            in.close();
                            remove(loc.c_str());
                            throw;
                        }
                        in.close();
                        remove(loc.c_str());
                        if (response = dynamic_cast<ArtifactResponse*>(xmlObject.get())) {
                            xmlObject.release();
                            policy.setAuthenticated(true);
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        throw BindingException("Unable to open artifact response file ($1)", params(1, loc.c_str()));
                    }
                }
            }
        }
        catch (std::exception& ex) {
            log.error("exception resolving SAML 2.0 artifact: %s", ex.what());
            soaper.reset();
        }
    }

    if (!foundEndpoint)
        throw MetadataException("No compatible endpoint found in issuer's metadata.");
    else if (!response)
        throw BindingException("Unable to resolve artifact(s) into a SAML response.");
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
           !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        auto_ptr<ArtifactResponse> wrapper(response);
        BindingException ex("Identity provider returned a SAML error during artifact resolution.");
        annotateException(&ex, &ssoDescriptor, response->getStatus());  // rethrow
    }

    // The SOAP client handles policy evaluation against the SOAP and Response layer,
    // but no security checking is done here.
    return response;
}
