/* ScopedAttribute.cpp - eduPerson scoped attribute base class

   Scott Cantor
   6/4/02

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

ScopedAttribute::ScopedAttribute(const XMLCh* name, const XMLCh* ns, const XMLCh* defaultScope,
                                 const saml::QName* type, long lifetime, const XMLCh* scopes[],
                                 const XMLCh* values[])
    : SAMLAttribute(name,ns,type,lifetime,values)
{
    if (defaultScope)
        m_defaultScope=defaultScope;

    for (unsigned int i=0; scopes && i<(sizeof(scopes)/sizeof(const XMLCh*)); i++)
        m_values.push_back(scopes[i]);
}

ScopedAttribute::ScopedAttribute(IDOM_Element* e) : SAMLAttribute(e)
{
    // Default scope comes from subject.
    IDOM_NodeList* nlist=
        static_cast<IDOM_Element*>(e->getParentNode())->getElementsByTagNameNS(saml::XML::SAML_NS,L(NameIdentifier));
    if (!nlist || nlist->getLength() != 1)
        throw InvalidAssertionException(SAMLException::RESPONDER,"ScopedAttribute() can't find saml:NameIdentifier in enclosing statement");
    m_defaultScope=static_cast<IDOM_Element*>(nlist->item(0))->getAttributeNS(NULL,L(NameQualifier));
}

ScopedAttribute::~ScopedAttribute() {}

bool ScopedAttribute::addValue(IDOM_Element* e)
{
    static XMLCh empty[] = {chNull};
    if (accept(e) && SAMLAttribute::addValue(e))
    {
        IDOM_Attr* scope=e->getAttributeNodeNS(NULL,Scope);
        m_scopes.push_back(scope ? scope->getNodeValue() : empty);
        return true;
    }
    return false;
}

bool ScopedAttribute::accept(IDOM_Element* e) const
{
    IOriginSiteMapper* mapper=ShibConfig::getConfig()->origin_mapper;
    Iterator<xstring> domains=mapper->getSecurityDomains(m_defaultScope.c_str());
    const XMLCh* this_scope=NULL;
    IDOM_Attr* scope=e->getAttributeNodeNS(NULL,Scope);
    if (scope)
        this_scope=scope->getNodeValue();
    if (!this_scope || !*this_scope)
        this_scope=m_defaultScope.c_str();

    while (domains.hasNext())
        if (domains.next()==this_scope)
            return true;
    return false;
}

Iterator<xstring> ScopedAttribute::getValues() const
{
    if (m_scopedValues.empty())
    {
        vector<xstring>::const_iterator j=m_scopes.begin();
        for (vector<xstring>::const_iterator i=m_values.begin(); i!=m_values.end(); i++, j++)
            m_scopedValues.push_back((*i) + chAt + ((*j)!=m_defaultScope && !j->empty() ? (*j) : m_defaultScope));
    }
    return Iterator<xstring>(m_scopedValues);
}

Iterator<string> ScopedAttribute::getSingleByteValues() const
{
    getValues();
    if (m_sbValues.empty())
    {
        for (vector<xstring>::const_iterator i=m_scopedValues.begin(); i!=m_scopedValues.end(); i++)
	{
	    auto_ptr<char> temp(XMLString::transcode(i->c_str()));
	    m_sbValues.push_back(temp.get());
	}
    }
    return Iterator<string>(m_sbValues);
}

SAMLObject* ScopedAttribute::clone() const
{
    ScopedAttribute* dest=new ScopedAttribute(m_name,m_namespace,m_defaultScope.c_str(),m_type,m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    dest->m_scopes.assign(m_scopes.begin(),m_scopes.end());
    dest->m_scopedValues.assign(m_scopedValues.begin(),m_scopedValues.end());
    return dest;
}

IDOM_Node* ScopedAttribute::toDOM(IDOM_Document* doc)
{
    // Already built?
    if (m_root)
        return m_root;

    // If no document provided, build a new one for our use.
    if (!doc)
    {
        IDOM_DOMImplementation* impl=IDOM_DOMImplementation::getImplementation();
        doc=m_document=impl->createDocument();
    }

    SAMLAttribute::toDOM(doc);

    int i=0;
    IDOM_Node* n=m_root->getFirstChild();
    while (n)
    {
        if (n->getNodeType()==IDOM_Node::ELEMENT_NODE)
        {
            if (!m_scopes[i].empty() && m_scopes[i]!=m_defaultScope)
                static_cast<IDOM_Element*>(n)->setAttributeNS(NULL,Scope,m_scopes[i].c_str());
            i++;
        }
        n=n->getNextSibling();
    }

    return m_root;
}

const XMLCh ScopedAttribute::Scope[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chNull };
