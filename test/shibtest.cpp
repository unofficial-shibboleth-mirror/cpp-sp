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


#include "../shib-target/shib-target.h"

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

int main(int argc,char* argv[])
{
    char* h_param=NULL;
    char* q_param=NULL;
    char* f_param=NULL;
    char* a_param=NULL;
    char* path=NULL;
    char* config=NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-c") && i+1<argc)
            config=argv[++i];
        else if (!strcmp(argv[i],"-d") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"-h") && i+1<argc)
            h_param=argv[++i];
        else if (!strcmp(argv[i],"-q") && i+1<argc)
            q_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            f_param=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            a_param=argv[++i];
    }

    if (!h_param || !q_param) {
        cerr << "usage: shibtest -h <handle> -q <origin_site> [-f <format URI> -a <application_id> -d <schema path> -c <config>]" << endl;
        exit(0);
    }
    
    if (!path)
        path=getenv("SHIBSCHEMAS");
    if (!path)
        path=SHIB_SCHEMAS;
    if (!config)
        config=getenv("SHIBCONFIG");
    if (!config)
        config=SHIB_CONFIG;
    if (!a_param)
        a_param="default";

    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    conf.setFeatures(
        ShibTargetConfig::Metadata |
        ShibTargetConfig::Trust |
        ShibTargetConfig::Credentials |
        ShibTargetConfig::AAP |
        ShibTargetConfig::GlobalExtensions |
        ShibTargetConfig::SessionCache
        );
    if (!conf.init(path,config))
        return -10;

    try {
        const IApplication* app=conf.getINI()->getApplication(a_param);
        if (!app)
            throw SAMLException("specified <Application> section not found in configuration");

        auto_ptr_XMLCh domain(q_param);
        auto_ptr_XMLCh handle(h_param);
        auto_ptr_XMLCh format(f_param);
        auto_ptr_XMLCh resource(app->getString("providerId").second);

        auto_ptr<SAMLRequest> req(
            new SAMLRequest(
                new SAMLAttributeQuery(
                    new SAMLSubject(
                        new SAMLNameIdentifier(
                            handle.get(),
                            domain.get(),
                            format.get() ? format.get() : Constants::SHIB_NAMEID_FORMAT_URI
                            )
                        ),
                    resource.get(),
                    app->getAttributeDesignators().clone()
                    )
                )
            );

        Metadata m(app->getMetadataProviders());
        const IEntityDescriptor* site=m.lookup(domain.get());
        if (!site)
            throw SAMLException("Unable to locate specified origin site's metadata.");

        // Try to locate an AA role.
        const IAttributeAuthorityDescriptor* AA=site->getAttributeAuthorityDescriptor(saml::XML::SAML11_PROTOCOL_ENUM);
        if (!AA)
            throw SAMLException("Unable to locate metadata for origin site's Attribute Authority.");

        ShibHTTPHook::ShibHTTPHookCallContext ctx(app->getCredentialUse(site)->getString("TLS").second,AA);
        Trust t(app->getTrustProviders());

        SAMLResponse* response=NULL;
        Iterator<const IEndpoint*> endpoints=AA->getAttributeServiceManager()->getEndpoints();
        while (!response && endpoints.hasNext()) {
            const IEndpoint* ep=endpoints.next();
            try {
                // Get a binding object for this protocol.
                const SAMLBinding* binding = app->getBinding(ep->getBinding());
                if (!binding) {
                    continue;
                }
                auto_ptr<SAMLResponse> r(binding->send(ep->getLocation(), *(req.get()), &ctx));
                if (r->isSigned() && !t.validate(app->getRevocationProviders(),AA,*r))
                    throw TrustException("unable to verify signed response");
                response = r.release();
            }
            catch (SAMLException& e) {
                // Check for shib:InvalidHandle error and propagate it out.
                Iterator<saml::QName> codes=e.getCodes();
                if (codes.size()>1) {
                    const saml::QName& code=codes[1];
                    if (!XMLString::compareString(code.getNamespaceURI(),shibboleth::Constants::SHIB_NS) &&
                        !XMLString::compareString(code.getLocalName(), shibboleth::Constants::InvalidHandle)) {
                        codes.reset();
                        throw InvalidHandleException(codes,e.what());
                    }
                }
            }
        }

        if (!response)
            throw SAMLException("unable to successfully query for attributes");

        // Run it through the AAP. Note that we could end up with an empty response!
        Iterator<SAMLAssertion*> a=response->getAssertions();
        for (unsigned long c=0; c < a.size();) {
            try {
                AAP::apply(app->getAAPProviders(),*(a[c]),AA);
                c++;
            }
            catch (SAMLException&) {
                response->removeAssertion(c);
            }
        }

        Iterator<SAMLAssertion*> i=response->getAssertions();
        if (i.hasNext())
        {
            SAMLAssertion* a=i.next();
            cout << "Issuer: "; xmlout(cout,a->getIssuer()); cout << endl;
            const SAMLDateTime* exp=a->getNotOnOrAfter();
            cout << "Expires: ";
            if (exp)
              xmlout(cout,exp->getRawData());
            else
                cout << "None";
            cout << endl;

            Iterator<SAMLStatement*> j=a->getStatements();
            if (j.hasNext())
            {
                SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(j.next());
                if (s)
                {
                    const SAMLNameIdentifier* sub=s->getSubject()->getNameIdentifier();
                    cout << "Format: "; xmlout(cout,sub->getFormat()); cout << endl;
                    cout << "Domain: "; xmlout(cout,sub->getNameQualifier()); cout << endl;
                    cout << "Handle: "; xmlout(cout,sub->getName()); cout << endl;

                    Iterator<SAMLAttribute*> attrs=s->getAttributes();
                    while (attrs.hasNext())
                    {
                        SAMLAttribute* attr=attrs.next();
                        cout << "Attribute Name: "; xmlout(cout,attr->getName()); cout << endl;
                        Iterator<const XMLCh*> vals=attr->getValues();
                        while (vals.hasNext())
                        {
                            cout << "Attribute Value: ";
                            xmlout(cout,vals.next());
                            cout << endl;
                        }
                    }
                }
            }
        }
    }
    catch(SAMLException& e)
    {
        cerr << "caught a SAML exception: " << e.what() << endl;
    }
    catch(XMLException& e)
    {
        cerr << "caught an XML exception: "; xmlout(cerr,e.getMessage()); cerr << endl;
    }
    catch(...)
    {
        cerr << "caught an unknown exception" << endl;
    }

    conf.shutdown();
    return 0;
}
