/* PrimaryAffiliationAttribute.cpp - eduPersonPrimaryAffiliation implementation

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

PrimaryAffiliationAttribute::PrimaryAffiliationAttribute(const XMLCh* defaultScope, long lifetime, const XMLCh* scope, const XMLCh* value)
    : ScopedAttribute(eduPerson::Constants::EDUPERSON_PRIMARY_AFFILIATION,
		      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
		      defaultScope,NULL,lifetime,&scope,&value)
{
    m_type=new saml::QName(eduPerson::XML::EDUPERSON_NS,eduPerson::Constants::EDUPERSON_AFFILIATION_TYPE);
}

PrimaryAffiliationAttribute::PrimaryAffiliationAttribute(IDOM_Element* e) : ScopedAttribute(e) {}

void PrimaryAffiliationAttribute::addValues(IDOM_Element* e)
{
    // Our only special job is to check the type and verify at most one value.
    IDOM_NodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeValue));
    if (nlist && nlist->getLength()>1)
      throw InvalidAssertionException(SAMLException::RESPONDER,"PrimaryAffiliationAttribute::addValues() detected multiple attribute values");

    m_type=saml::QName::getQNameAttribute(static_cast<IDOM_Element*>(nlist->item(0)),saml::XML::XSI_NS,L(type));
    if (!m_type || XMLString::compareString(m_type->getNamespaceURI(),eduPerson::XML::EDUPERSON_NS) ||
	XMLString::compareString(m_type->getLocalName(),eduPerson::Constants::EDUPERSON_AFFILIATION_TYPE))
        throw InvalidAssertionException(SAMLException::RESPONDER,"PrimaryAffiliationAttribute() found an invalid attribute value type");
    addValue(static_cast<IDOM_Element*>(nlist->item(0)));
}

PrimaryAffiliationAttribute::~PrimaryAffiliationAttribute() {}

SAMLObject* PrimaryAffiliationAttribute::clone() const
{
    PrimaryAffiliationAttribute* dest=new PrimaryAffiliationAttribute(m_defaultScope.c_str(),m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    dest->m_scopes.assign(m_scopes.begin(),m_scopes.end());
    return dest;
}
