#include <shib.h>
#include <eduPerson.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;

class MyMapper : public IOriginSiteMapper
{
public:
    MyMapper();
    Iterator<xstring> getHandleServiceNames(const XMLCh* originSite);
    void* getHandleServiceKey(const XMLCh* handleService);
    Iterator<xstring> getSecurityDomains(const XMLCh* originSite);
    Iterator<void*> getTrustedRoots();

private:
    vector<xstring> v;
    vector<void*> v2;
};

Iterator<xstring> MyMapper::getSecurityDomains(const XMLCh* originSite)
{
    return Iterator<xstring>(v);
}

Iterator<xstring> MyMapper::getHandleServiceNames(const XMLCh* originSite)
{
    return Iterator<xstring>(v);
}

void* MyMapper::getHandleServiceKey(const XMLCh* handleService)
{
    return NULL;
}

Iterator<void*> MyMapper::getTrustedRoots()
{
    return Iterator<void*>(v2);
}

MyMapper::MyMapper()
{
}

SAMLAttribute* scopedFactory(IDOM_Element* e)
{
    return new ScopedAttribute(e);
}

int main(int argc,char* argv[])
{
    MyMapper mapper;
    SAMLConfig conf1;
    ShibConfig conf2;
    char* h_param=NULL;
    char* q_param=NULL;
    char* url_param=NULL;
    char* r_param=NULL;
    char* path=NULL;

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
    if (!SAMLConfig::init(&conf1))
        cerr << "unable to initialize SAML runtime" << endl;

    conf2.origin_mapper=&mapper;
    if (!ShibConfig::init(&conf2))
        cerr << "unable to initialize Shibboleth runtime" << endl;


    saml::XML::registerSchema(EDUPERSON_NS,EDUPERSON_SCHEMA_ID);

    auto_ptr<XMLCh> ATTRNS(XMLString::transcode("urn:mace:shibboleth:1.0:attributeNamespace:uri"));
    auto_ptr<XMLCh> EPPN(XMLString::transcode("urn:mace:eduPerson:1.0:eduPersonPrincipalName"));
    auto_ptr<XMLCh> AFFIL(XMLString::transcode("urn:mace:eduPerson:1.0:eduPersonAffiliation"));

    SAMLAttribute::regFactory(EPPN.get(),ATTRNS.get(),&scopedFactory);
    SAMLAttribute::regFactory(AFFIL.get(),ATTRNS.get(),&scopedFactory);

    try
    {
        auto_ptr<XMLCh> url(XMLString::transcode(url_param));
        SAMLAuthorityBinding binfo(saml::QName(saml::XML::SAMLP_NS,L(AttributeQuery)),SAMLBinding::SAML_SOAP_HTTPS,url.get());
        auto_ptr<XMLCh> domain(XMLString::transcode(q_param));
        auto_ptr<XMLCh> handle(XMLString::transcode(h_param));
        auto_ptr<XMLCh> resource(XMLString::transcode(r_param));
        SAMLRequest* req=new SAMLRequest(new SAMLAttributeQuery (new SAMLSubject(handle.get(),domain.get()),resource.get()));

        const XMLCh* policies[]={Constants::POLICY_CLUBSHIB};
        
        SAMLBinding* pBinding=SAMLBindingFactory::getInstance(SAMLBinding::SAML_SOAP_HTTPS);
        SAMLResponse* resp=pBinding->send(binfo,*req);
        delete pBinding;

        SAMLResponse* r2=dynamic_cast<SAMLResponse*>(resp->clone());
        delete resp;

        Iterator<SAMLAssertion*> i=r2->getAssertions();
        if (i.hasNext())
        {
            SAMLAssertion* a=i.next();
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
                SAMLAttributeStatement* s=dynamic_cast<SAMLAttributeStatement*>(j.next());
                if (s)
                {
                    const SAMLSubject* sub=s->getSubject();
                    cout << "Domain: "; xmlout(cout,sub->getNameQualifier()); cout << endl;
                    cout << "Handle: "; xmlout(cout,sub->getName()); cout << endl;

                    Iterator<SAMLAttribute*> attrs=s->getAttributes();
                    while (attrs.hasNext())
                    {
                        SAMLAttribute* attr=attrs.next();
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
                            xmlout(cout,vals.next().c_str());
                            cout << endl;
                        }
                    }
                }
            }
        }

        delete r2;
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
