/* AffiliationAttribute.cpp - eduPersonAffiliation implementation

   Scott Cantor
   6/21/02

   $History:$
*/

#ifdef WIN32
# define EDUPERSON_EXPORTS __declspec(dllexport)
#endif

#include <eduPerson.h>
#include <shib.h>
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;
using namespace std;

AffiliationAttribute::AffiliationAttribute(const XMLCh* defaultScope, long lifetime, const XMLCh* scopes[], const XMLCh* values[])
    : ScopedAttribute(eduPerson::Constants::EDUPERSON_AFFILIATION,
		      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
		      defaultScope,NULL,lifetime,scopes,values)
{
    m_type=new saml::QName(eduPerson::XML::EDUPERSON_NS,eduPerson::Constants::EDUPERSON_AFFILIATION_TYPE);
}

AffiliationAttribute::AffiliationAttribute(IDOM_Element* e) : ScopedAttribute(e) {}

AffiliationAttribute::~AffiliationAttribute() {}

void AffiliationAttribute::addValues(IDOM_Element* e)
{
    // Our only special job is to check the type.
    IDOM_NodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeValue));
    for (int i=0; nlist && i<nlist->getLength(); i++)
    {
        auto_ptr<saml::QName> type(saml::QName::getQNameAttribute(static_cast<IDOM_Element*>(nlist->item(0)),saml::XML::XSI_NS,L(type)));
	if (!type.get() || XMLString::compareString(type->getNamespaceURI(),eduPerson::XML::EDUPERSON_NS) ||
	    XMLString::compareString(type->getLocalName(),eduPerson::Constants::EDUPERSON_AFFILIATION_TYPE))
	    throw InvalidAssertionException(SAMLException::RESPONDER,"AffiliationAttribute() found an invalid attribute value type");
	if (!m_type)
	    m_type=type.release();
	addValue(static_cast<IDOM_Element*>(nlist->item(i)));
    }
}

SAMLObject* AffiliationAttribute::clone() const
{
    AffiliationAttribute* dest=new AffiliationAttribute(m_defaultScope.c_str(),m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    dest->m_scopes.assign(m_scopes.begin(),m_scopes.end());
    return dest;
}
