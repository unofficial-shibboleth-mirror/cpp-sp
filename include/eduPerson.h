/* eduPerson.h - Shibboleth eduPerson attribute extensions

   Scott Cantor
   6/4/02

   $History:$
*/

#ifndef __eduPerson_h__
#define __eduPerson_h__

#include <saml.h>

#ifdef WIN32
# ifndef EDUPERSON_EXPORTS
#  define EDUPERSON_EXPORTS __declspec(dllimport)
# endif
#else
# define EDUPERSON_EXPORTS
#endif

namespace eduPerson
{
    class EDUPERSON_EXPORTS ScopedAttribute : public saml::SAMLAttribute
    {
    public:
        ScopedAttribute(const XMLCh* name, const XMLCh* ns, const XMLCh* defaultScope, const saml::QName* type=NULL,
                        long lifetime=0, const XMLCh* scopes[]=NULL, const XMLCh* values[]=NULL);
        ScopedAttribute(IDOM_Element* e);
        virtual ~ScopedAttribute();

        virtual IDOM_Node* toDOM(IDOM_Document* doc=NULL);
        virtual saml::SAMLObject* clone() const;

        virtual saml::Iterator<saml::xstring> getValues() const;
        virtual saml::Iterator<std::string> getSingleByteValues() const;

        static const XMLCh Scope[];

    protected:
        virtual bool accept(IDOM_Element* e) const;
        virtual bool addValue(IDOM_Element* e);

        saml::xstring m_defaultScope;
        std::vector<saml::xstring> m_scopes;
        mutable std::vector<saml::xstring> m_scopedValues;
    };

    class EDUPERSON_EXPORTS EPPNAttribute : public ScopedAttribute
    {
    public:
        EPPNAttribute(const XMLCh* defaultScope, long lifetime=0, const XMLCh* scope=NULL, const XMLCh* value=NULL);
	EPPNAttribute(IDOM_Element* e);
	virtual ~EPPNAttribute();

	virtual void addValues(IDOM_Element* e);
	SAMLObject* clone() const;
    };

    class EDUPERSON_EXPORTS AffiliationAttribute : public ScopedAttribute
    {
    public:
        AffiliationAttribute(const XMLCh* defaultScope, long lifetime=0, const XMLCh* scopes[]=NULL, const XMLCh* values[]=NULL);
	AffiliationAttribute(IDOM_Element* e);
	virtual ~AffiliationAttribute();

	virtual void addValues(IDOM_Element* e);
	SAMLObject* clone() const;
    };

    class EDUPERSON_EXPORTS PrimaryAffiliationAttribute : public ScopedAttribute
    {
    public:
        PrimaryAffiliationAttribute(const XMLCh* defaultScope, long lifetime=0, const XMLCh* scope=NULL, const XMLCh* value=NULL);
	PrimaryAffiliationAttribute(IDOM_Element* e);
	virtual ~PrimaryAffiliationAttribute();

	virtual void addValues(IDOM_Element* e);
	SAMLObject* clone() const;
    };

    class EDUPERSON_EXPORTS EntitlementAttribute : public saml::SAMLAttribute
    {
    public:
        EntitlementAttribute(long lifetime=0, const XMLCh* values[]=NULL);
	EntitlementAttribute(IDOM_Element* e);
	virtual ~EntitlementAttribute();

	virtual void addValues(IDOM_Element* e);
	SAMLObject* clone() const;
    };

    struct EDUPERSON_EXPORTS XML
    {
        static const XMLCh EDUPERSON_NS[];
        static const XMLCh EDUPERSON_SCHEMA_ID[];
    };

    struct EDUPERSON_EXPORTS Constants
    {
        static const XMLCh EDUPERSON_PRINCIPAL_NAME[];
        static const XMLCh EDUPERSON_AFFILIATION[];
        static const XMLCh EDUPERSON_PRIMARY_AFFILIATION[];
        static const XMLCh EDUPERSON_ENTITLEMENT[];

        static const XMLCh EDUPERSON_PRINCIPAL_NAME_TYPE[];
        static const XMLCh EDUPERSON_AFFILIATION_TYPE[];
    };
}

#endif
