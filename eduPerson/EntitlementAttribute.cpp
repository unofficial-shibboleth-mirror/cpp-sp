/* EntitlementAttribute.cpp - eduPersonEntitlement implementation

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

static XMLCh anyURI[]={ chLatin_a, chLatin_n, chLatin_y, chLatin_U, chLatin_R, chLatin_I, chNull };

EntitlementAttribute::EntitlementAttribute(long lifetime, const XMLCh* values[])
    : SAMLAttribute(eduPerson::Constants::EDUPERSON_ENTITLEMENT,
		    shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
		    NULL,lifetime,values)
{
    m_type=new saml::QName(saml::XML::XSD_NS,anyURI);
}

EntitlementAttribute::EntitlementAttribute(IDOM_Element* e) : SAMLAttribute(e) {}

EntitlementAttribute::~EntitlementAttribute() {}

void EntitlementAttribute::addValues(IDOM_Element* e)
{
    // Our only special job is to check the type.
    IDOM_NodeList* nlist=e->getElementsByTagNameNS(saml::XML::SAML_NS,L(AttributeValue));
    for (int i=0; nlist && i<nlist->getLength(); i++)
    {
        auto_ptr<saml::QName> type(saml::QName::getQNameAttribute(static_cast<IDOM_Element*>(nlist->item(0)),saml::XML::XSI_NS,L(type)));
	if (!type.get() || XMLString::compareString(type->getNamespaceURI(),saml::XML::XSD_NS) ||
	    XMLString::compareString(type->getLocalName(),anyURI))
	    throw InvalidAssertionException(SAMLException::RESPONDER,"EntitlementAttribute() found an invalid attribute value type");
	if (!m_type)
	    m_type=type.release();
	addValue(static_cast<IDOM_Element*>(nlist->item(i)));
    }
}

SAMLObject* EntitlementAttribute::clone() const
{
    EntitlementAttribute* dest=new EntitlementAttribute(m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    return dest;
}
