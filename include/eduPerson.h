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

        static const XMLCh Scope[];

    protected:
        virtual bool accept(IDOM_Element* e) const;
        virtual bool addValue(IDOM_Element* e);

        saml::xstring m_defaultScope;
        std::vector<saml::xstring> m_scopes;
        mutable std::vector<saml::xstring> m_scopedValues;
    };

    static const XMLCh EDUPERSON_NS[] = // urn:mace:eduPerson:1.0
    { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_m, chLatin_a, chLatin_c, chLatin_e, chColon,
      chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chColon,
      chDigit_1, chPeriod, chDigit_0, chNull
    };

    static const XMLCh EDUPERSON_SCHEMA_ID[] = // eduPerson.xsd
    { chLatin_e, chLatin_d, chLatin_u, chLatin_P, chLatin_e, chLatin_r, chLatin_s, chLatin_o, chLatin_n, chPeriod,
      chLatin_x, chLatin_s, chLatin_d, chNull
    };
}

#endif
