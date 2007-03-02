/*
 *  Copyright 2001-2007 Internet2
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

/**
 * samlquery.cpp
 * 
 * SAML Attribute Query tool layered on SP configuration
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/Application.h>
#include <shibsp/exceptions.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/binding/SOAPClient.h>
#include <shibsp/util/SPConstants.h>

#include <saml/binding/SecurityPolicy.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml1p;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

enum samlversion {
    v10, v11, v20
};

int main(int argc,char* argv[])
{
    char* n_param=NULL;
    char* q_param=NULL;
    char* f_param=NULL;
    char* a_param=NULL;
    char* path=NULL;
    char* config=NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-n") && i+1<argc)
            n_param=argv[++i];
        else if (!strcmp(argv[i],"-q") && i+1<argc)
            q_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            f_param=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            a_param=argv[++i];
    }

    if (!n_param || !q_param) {
        cerr << "usage: samlquery -n <name> -q <IdP> [-f <format URI> -a <application id>]" << endl;
        exit(0);
    }
    
    path=getenv("SHIBSP_SCHEMAS");
    if (!path)
        path=SHIBSP_SCHEMAS;
    config=getenv("SHIBSP_CONFIG");
    if (!config)
        config=SHIBSP_CONFIG;
    if (!a_param)
        a_param="default";

    XMLToolingConfig::getConfig().log_config(getenv("SHIBSP_LOGGING") ? getenv("SHIBSP_LOGGING") : SHIBSP_LOGGING);

    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::Credentials |
        SPConfig::OutOfProcess
        );
    if (!conf.init(path))
        return -10;

    try {
        static const XMLCh path[] = UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<DOMDocument> docjanitor(dummydoc);
        DOMElement* dummy = dummydoc->createElementNS(NULL,path);
        auto_ptr_XMLCh src(config);
        dummy->setAttributeNS(NULL,path,src.get());
        dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);

        conf.setServiceProvider(conf.ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
        conf.getServiceProvider()->init();
    }
    catch (exception&) {
        conf.term();
        return -20;
    }

    ServiceProvider* sp=conf.getServiceProvider();
    sp->lock();

    try {
        const Application* app=sp->getApplication(a_param);
        if (!app)
            throw ConfigurationException("Application ($1) not found in configuration.", params(1,a_param));

        auto_ptr_XMLCh domain(q_param);
        auto_ptr_XMLCh name(n_param);
        auto_ptr_XMLCh format(f_param);
        auto_ptr_XMLCh issuer(app->getString("providerId").second);

        MetadataProvider* m=app->getMetadataProvider();
        xmltooling::Locker mlocker(m);
        const EntityDescriptor* site=m->getEntityDescriptor(domain.get());
        if (!site)
            throw MetadataException("Unable to locate metadata for IdP ($1).", params(1,q_param));

        // Try to locate an AA role.
        samlversion ver;
        const AttributeAuthorityDescriptor* AA=NULL;
        if (AA=site->getAttributeAuthorityDescriptor(samlconstants::SAML20P_NS))
            ver = v20;
        else if (AA=site->getAttributeAuthorityDescriptor(samlconstants::SAML11_PROTOCOL_ENUM))
            ver = v11;
        else if (AA=site->getAttributeAuthorityDescriptor(samlconstants::SAML10_PROTOCOL_ENUM))
            ver = v10;
        else
            throw MetadataException("No AttributeAuthority role found in metadata.");

        SecurityPolicy policy;
        shibsp::SOAPClient soaper(*app,policy);

        if (ver == v20) {
            auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
            opensaml::saml2p::StatusResponseType* srt=NULL;
            const vector<AttributeService*>& endpoints=AA->getAttributeServices();
            for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !srt && ep!=endpoints.end(); ++ep) {
                try {
                    if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                        continue;
                    auto_ptr_char loc((*ep)->getLocation());
                    NameID* nameid = NameIDBuilder::buildNameID();
                    opensaml::saml2::Subject* subject = opensaml::saml2::SubjectBuilder::buildSubject();
                    subject->setNameID(nameid);
                    opensaml::saml2p::AttributeQuery* query = opensaml::saml2p::AttributeQueryBuilder::buildAttributeQuery();
                    query->setSubject(subject);
                    Issuer* iss = IssuerBuilder::buildIssuer();
                    query->setIssuer(iss);
                    nameid->setName(name.get());
                    nameid->setFormat(format.get() ? format.get() : NameID::TRANSIENT);
                    nameid->setNameQualifier(domain.get());
                    iss->setName(issuer.get());
                    SAML2SOAPClient client(soaper);
                    client.sendSAML(query, *AA, loc.get());
                    srt = client.receiveSAML();
                }
                catch (exception& ex) {
                    cerr << "Caught exception: " << ex.what() << endl << endl;
                    soaper.reset();
                }
            }

            if (!srt)
                throw BindingException("Unable to successfully query for attributes.");
            const opensaml::saml2p::Response* response = dynamic_cast<opensaml::saml2p::Response*>(srt);

            const vector<opensaml::saml2::Assertion*>& assertions = response->getAssertions();
            if (assertions.size())
                cout << *assertions.front();
            else
                cout << "No assertions found.";

            delete response;
        }
        else {
            auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
            const opensaml::saml1p::Response* response=NULL;
            const vector<AttributeService*>& endpoints=AA->getAttributeServices();
            for (vector<AttributeService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
                try {
                    if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                        continue;
                    auto_ptr_char loc((*ep)->getLocation());
                    NameIdentifier* nameid = NameIdentifierBuilder::buildNameIdentifier();
                    opensaml::saml1::Subject* subject = opensaml::saml1::SubjectBuilder::buildSubject();
                    subject->setNameIdentifier(nameid);
                    opensaml::saml1p::AttributeQuery* query = opensaml::saml1p::AttributeQueryBuilder::buildAttributeQuery();
                    query->setSubject(subject);
                    Request* request = RequestBuilder::buildRequest();
                    request->setAttributeQuery(query);
                    nameid->setName(name.get());
                    nameid->setFormat(format.get() ? format.get() : shibspconstants::SHIB1_NAMEID_FORMAT_URI);
                    nameid->setNameQualifier(domain.get());
                    query->setResource(issuer.get());
                    request->setMinorVersion(ver==v11 ? 1 : 0);
                    SAML1SOAPClient client(soaper);
                    client.sendSAML(request, *AA, loc.get());
                    response = client.receiveSAML();
                }
                catch (exception& ex) {
                    cerr << "Caught exception: " << ex.what() << endl << endl;
                    soaper.reset();
                }
            }

            if (!response)
                throw BindingException("Unable to successfully query for attributes.");

            const vector<opensaml::saml1::Assertion*>& assertions = response->getAssertions();
            if (assertions.size())
                cout << *assertions.front();
            else
                cout << "No assertions found.";

            delete const_cast<opensaml::saml1p::Response*>(response);
        }
    }
    catch(exception& ex) {
        cerr << ex.what() << endl;
    }

    sp->unlock();
    conf.term();
    return 0;
}
