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


#include <shib.h>
#include <eduPerson.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;

class DummyMapper : public IOriginSiteMapper
{
public:
    DummyMapper() {}
    ~DummyMapper();
    virtual Iterator<xstring> getHandleServiceNames(const XMLCh* originSite) { return Iterator<xstring>(); }
    virtual Key* getHandleServiceKey(const XMLCh* handleService) { return NULL; }
    virtual Iterator<xstring> getSecurityDomains(const XMLCh* originSite);
    virtual Iterator<X509Certificate*> getTrustedRoots() { return Iterator<X509Certificate*>(); }

private:
    typedef map<xstring,vector<xstring>*> domains_t;
    domains_t m_domains;
};

Iterator<xstring> DummyMapper::getSecurityDomains(const XMLCh* originSite)
{
    domains_t::iterator i=m_domains.find(originSite);
    if (i==m_domains.end())
    {
        vector<xstring>* pv=new vector<xstring>();
        pv->push_back(originSite);
        pair<domains_t::iterator,bool> p=m_domains.insert(domains_t::value_type(originSite,pv));
        i=p.first;
    }
    return Iterator<xstring>(*(i->second));
}

DummyMapper::~DummyMapper()
{
    for (domains_t::iterator i=m_domains.begin(); i!=m_domains.end(); i++)
        delete i->second;
}


extern "C" SAMLAttribute* scopedFactory(IDOM_Element* e)
{
    return new ScopedAttribute(e);
}

int main(int argc,char* argv[])
{
    DummyMapper mapper;
    SAMLConfig conf1;
    ShibConfig conf2;
    char* h_param=NULL;
    char* q_param=NULL;
    char* url_param=NULL;
    char* r_param=NULL;
    char* path="";

    for (int i=1; i<argc; i++)
    {
        if (!strcmp(argv[i],"-d") && i+1<argc)
            path=argv[++i];
        else if (!strcmp(argv[i],"-h") && i+1<argc)
            h_param=argv[++i];
        else if (!strcmp(argv[i],"-q") && i+1<argc)
            q_param=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            url_param=argv[++i];
        else if (!strcmp(argv[i],"-r") && i+1<argc)
            r_param=argv[++i];
    }

    if (!h_param || !q_param || !url_param)
    {
        cerr << "usage: shibtest -h <handle> -q <origin_site> -a <AA URL> [-r <resource URL> -d <schema path>]" << endl;
        exit(0);
    }

    conf1.schema_dir=path;
    conf1.bVerbose=true;
    if (!SAMLConfig::init(&conf1))
        cerr << "unable to initialize SAML runtime" << endl;

    conf2.origin_mapper=&mapper;
    if (!ShibConfig::init(&conf2))
        cerr << "unable to initialize Shibboleth runtime" << endl;

    saml::XML::registerSchema(eduPerson::XML::EDUPERSON_NS,eduPerson::XML::EDUPERSON_SCHEMA_ID);

    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_PRINCIPAL_NAME,
                              shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
                              &scopedFactory);
    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_AFFILIATION,
                              shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
                              &scopedFactory);

    try
    {
        auto_ptr<XMLCh> url(XMLString::transcode(url_param));
        SAMLAuthorityBinding binfo(saml::QName(saml::XML::SAMLP_NS,L(AttributeQuery)),SAMLBinding::SAML_SOAP_HTTPS,url.get());
        auto_ptr<XMLCh> domain(XMLString::transcode(q_param));
        auto_ptr<XMLCh> handle(XMLString::transcode(h_param));
        auto_ptr<XMLCh> resource(XMLString::transcode(r_param));
        SAMLRequest* req=new SAMLRequest(new SAMLAttributeQuery (new SAMLSubject(handle.get(),domain.get()),resource.get()));

        const XMLCh* policies[]={shibboleth::Constants::POLICY_CLUBSHIB};
        
        SAMLBinding* pBinding=SAMLBindingFactory::getInstance();
        SAMLResponse* resp=pBinding->send(binfo,*req);
        delete pBinding;

        Iterator<SAMLAssertion*> i=resp->getAssertions();
        if (i.hasNext())
        {
            SAMLAssertion* a=*i.next();
            cout << "Issuer: "; xmlout(cout,a->getIssuer()); cout << endl;
            const XMLDateTime* exp=a->getNotOnOrAfter();
            cout << "Expires: ";
            if (exp)
              xmlout(cout,exp->toString());
            else
                cout << "None";
            cout << endl;

            Iterator<SAMLStatement*> j=a->getStatements();
            if (j.hasNext())
            {
                SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(*j.next());
                if (s)
                {
                    const SAMLSubject* sub=s->getSubject();
                    cout << "Domain: "; xmlout(cout,sub->getNameQualifier()); cout << endl;
                    cout << "Handle: "; xmlout(cout,sub->getName()); cout << endl;

                    Iterator<SAMLAttribute*> attrs=s->getAttributes();
                    while (attrs.hasNext())
                    {
                        SAMLAttribute* attr=*attrs.next();
                        cout << "Attribute Name: "; xmlout(cout,attr->getName()); cout << endl;
                        cout << "Attribute Type: {";
                        xmlout(cout,attr->getType()->getNamespaceURI());
                        cout << "}:";
                        xmlout(cout,attr->getType()->getLocalName());
                        cout << endl;
                        
                        Iterator<xstring> vals=attr->getValues();
                        while (vals.hasNext())
                        {
                            cout << "Attribute Value: ";
                            xmlout(cout,vals.next()->c_str());
                            cout << endl;
                        }
                    }
                }
            }
        }

        delete resp;
    }
    catch(SAMLException& e)
    {
        cerr << "caught a SAML exception: " << e.what() << endl;
    }
    catch(XMLException& e)
    {
        cerr << "caught an XML exception: "; xmlout(cerr,e.getMessage()); cerr << endl;
    }
/*    catch(...)
    {
        cerr << "caught an unknown exception" << endl;
    }*/

    ShibConfig::term();
    SAMLConfig::term();
    return 0;
}
