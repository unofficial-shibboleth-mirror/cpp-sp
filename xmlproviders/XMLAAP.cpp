/*
 *  Copyright 2001-2005 Internet2
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

/* XMLAAP.cpp - XML AAP implementation

   Scott Cantor
   12/21/02

   $History:$
*/

#include "internal.h"

#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;

#include <xercesc/util/regx/RegularExpression.hpp>

namespace {

    class XMLAAPImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLAAPImpl(const char* pathname) : ReloadableXMLFileImpl(pathname), anyAttribute(false) { init(); }
        XMLAAPImpl(const DOMElement* e) : ReloadableXMLFileImpl(e), anyAttribute(false) { init(); }
        void init();
        ~XMLAAPImpl();
        
        class AttributeRule : public IAttributeRule
        {
        public:
            AttributeRule(const DOMElement* e);
            ~AttributeRule() {}
            
            const XMLCh* getName() const { return m_name; }
            const XMLCh* getNamespace() const { return m_namespace; }
            const char* getAlias() const { return m_alias.get(); }
            const char* getHeader() const { return m_header.get(); }
            bool getCaseSensitive() const { return m_caseSensitive; }
            bool getScoped() const { return m_scoped; }
            void apply(SAMLAttribute& attribute, const IRoleDescriptor* role=NULL) const;
    
            enum value_type { literal, regexp, xpath };
        private:    
            const XMLCh* m_name;
            const XMLCh* m_namespace;
            auto_ptr_char m_alias;
            auto_ptr_char m_header;
            bool m_caseSensitive;
            bool m_scoped;

            struct SiteRule
            {
                SiteRule() : anyValue(false) {}
                bool anyValue;
                vector<pair<value_type,const XMLCh*> > valueDenials;
                vector<pair<value_type,const XMLCh*> > valueAccepts;
                vector<pair<value_type,const XMLCh*> > scopeDenials;
                vector<pair<value_type,const XMLCh*> > scopeAccepts;
            };
            
            value_type toValueType(const DOMElement* e);
            bool scopeCheck(
                const DOMElement* e,
                const IScopedRoleDescriptor* role,
                const vector<const SiteRule*>& ruleStack
                ) const;
            bool accept(const DOMElement* e, const IScopedRoleDescriptor* role=NULL) const;
            
            SiteRule m_anySiteRule;
    #ifdef HAVE_GOOD_STL
            typedef map<xstring,SiteRule> sitemap_t;
    #else
            typedef map<string,SiteRule> sitemap_t;
    #endif
            sitemap_t m_siteMap;
        };
    
        bool anyAttribute;
        vector<const IAttributeRule*> m_attrs;
        map<string,const IAttributeRule*> m_aliasMap;
    #ifdef HAVE_GOOD_STL
        typedef map<xstring,AttributeRule*> attrmap_t;
    #else
        typedef map<string,AttributeRule*> attrmap_t;
    #endif
        attrmap_t m_attrMap;
    };

    class XMLAAP : public IAAP, public ReloadableXMLFile
    {
    public:
        XMLAAP(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLAAP() {}
        
        bool anyAttribute() const {return static_cast<XMLAAPImpl*>(getImplementation())->anyAttribute;}
        const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const;
        const IAttributeRule* lookup(const char* alias) const;
        Iterator<const IAttributeRule*> getAttributeRules() const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };

}

IPlugIn* XMLAAPFactory(const DOMElement* e)
{
    auto_ptr<XMLAAP> aap(new XMLAAP(e));
    aap->getImplementation();
    return aap.release();
}

ReloadableXMLFileImpl* XMLAAP::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLAAPImpl(e);
}

ReloadableXMLFileImpl* XMLAAP::newImplementation(const char* pathname, bool first) const
{
    return new XMLAAPImpl(pathname);
}

void XMLAAPImpl::init()
{
#ifdef _DEBUG
    saml::NDC ndc("init");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");

    try
    {
        if (!saml::XML::isElementNamed(m_root,::XML::SHIB_NS,SHIB_L(AttributeAcceptancePolicy)))
        {
            log.error("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
            throw MalformedException("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
        }

        // Check for AnyAttribute element.
        DOMElement* anyAttr = saml::XML::getFirstChildElement(m_root,::XML::SHIB_NS,SHIB_L(AnyAttribute));
        if (anyAttr) {
            anyAttribute = true;
            log.warn("<AnyAttribute> found, will short-circuit all attribute value and scope filtering");
        }

        // Loop over the AttributeRule elements.
        DOMNodeList* nlist = m_root->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(AttributeRule));
        for (unsigned int i=0; nlist && i<nlist->getLength(); i++)
        {
            AttributeRule* rule=new AttributeRule(static_cast<DOMElement*>(nlist->item(i)));
#ifdef HAVE_GOOD_STL
            xstring key=rule->getName();
            key=key + chBang + chBang + (rule->getNamespace() ? rule->getNamespace() : Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
#else
            auto_ptr_char aname(rule->getName());
            string key(aname.get());
            key+="!!";
            if (rule->getNamespace())
            {
                auto_ptr_char ans(rule->getNamespace());
                key+=ans.get();
            }
            else
                key+="urn:mace:shibboleth:1.0:attributeNamespace:uri";
#endif
            m_attrMap[key]=rule;
            m_attrs.push_back(rule);
            if (rule->getAlias())
                m_aliasMap[rule->getAlias()]=rule;
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "Error while parsing AAP: " << e.what() << CategoryStream::ENDLINE;
        this->~XMLAAPImpl();
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log.error("Unexpected error while parsing AAP");
        this->~XMLAAPImpl();
        throw;
    }
#endif
}

XMLAAPImpl::~XMLAAPImpl()
{
    for (attrmap_t::iterator i=m_attrMap.begin(); i!=m_attrMap.end(); i++)
        delete i->second;
}

XMLAAPImpl::AttributeRule::AttributeRule(const DOMElement* e) :
    m_alias(e->hasAttributeNS(NULL,SHIB_L(Alias)) ? e->getAttributeNS(NULL,SHIB_L(Alias)) : NULL),
    m_header(e->hasAttributeNS(NULL,SHIB_L(Header)) ? e->getAttributeNS(NULL,SHIB_L(Header)) : NULL),
    m_scoped(false)
    
{
    m_name=e->getAttributeNS(NULL,SHIB_L(Name));
    m_namespace=e->getAttributeNS(NULL,SHIB_L(Namespace));
    if (!m_namespace || !*m_namespace)
        m_namespace=Constants::SHIB_ATTRIBUTE_NAMESPACE_URI;
    
    const XMLCh* caseSensitive=e->getAttributeNS(NULL,SHIB_L(CaseSensitive));
    m_caseSensitive=(!caseSensitive || !*caseSensitive || *caseSensitive==chDigit_1 || *caseSensitive==chLatin_t);
    
    const XMLCh* scoped=e->getAttributeNS(NULL,SHIB_L(Scoped));
    m_scoped=(scoped && (*scoped==chDigit_1 || *scoped==chLatin_t));
    
    // Check for an AnySite rule.
    DOMElement* anysite = saml::XML::getFirstChildElement(e);
    if (anysite && saml::XML::isElementNamed(static_cast<DOMElement*>(anysite),::XML::SHIB_NS,SHIB_L(AnySite)))
    {
        // Process Scope elements.
        DOMNodeList* vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(Scope));
        for (unsigned int i=0; vlist && i<vlist->getLength(); i++)
        {
            m_scoped=true;
            DOMElement* se=static_cast<DOMElement*>(vlist->item(i));
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
            {
                const XMLCh* accept=se->getAttributeNS(NULL,SHIB_L(Accept));
                if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                    m_anySiteRule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    m_anySiteRule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
        }

        // Check for an AnyValue rule.
        vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(AnyValue));
        if (vlist && vlist->getLength())
        {
            m_anySiteRule.anyValue=true;
        }
        else
        {
            // Process each Value element.
            vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(Value));
            for (unsigned int j=0; vlist && j<vlist->getLength(); j++)
            {
                DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                    const XMLCh* accept=ve->getAttributeNS(NULL,SHIB_L(Accept));
                    if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                        m_anySiteRule.valueAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                    else
                        m_anySiteRule.valueDenials.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                }
            }
        }
    }

    // Loop over the SiteRule elements.
    DOMNodeList* slist = e->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(SiteRule));
    for (unsigned int k=0; slist && k<slist->getLength(); k++)
    {
        const XMLCh* srulename=static_cast<DOMElement*>(slist->item(k))->getAttributeNS(NULL,SHIB_L(Name));
#ifdef HAVE_GOOD_STL
        m_siteMap[srulename]=SiteRule();
        SiteRule& srule=m_siteMap[srulename];
#else
        auto_ptr_char srulename2(srulename);
        m_siteMap[srulename2.get()]=SiteRule();
        SiteRule& srule=m_siteMap[srulename2.get()];
#endif

        // Process Scope elements.
        DOMNodeList* vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(Scope));
        for (unsigned int i=0; vlist && i<vlist->getLength(); i++)
        {
            m_scoped=true;
            DOMElement* se=static_cast<DOMElement*>(vlist->item(i));
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
            {
                const XMLCh* accept=se->getAttributeNS(NULL,SHIB_L(Accept));
                if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                    srule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    srule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
        }

        // Check for an AnyValue rule.
        vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(AnyValue));
        if (vlist && vlist->getLength())
        {
            srule.anyValue=true;
        }
        else
        {
            // Process each Value element.
            vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(::XML::SHIB_NS,SHIB_L(Value));
            for (unsigned int j=0; vlist && j<vlist->getLength(); j++)
            {
                DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                    const XMLCh* accept=ve->getAttributeNS(NULL,SHIB_L(Accept));
                    if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                        srule.valueAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                    else
                        srule.valueDenials.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                }
            }
        }
    }
}

XMLAAPImpl::AttributeRule::value_type XMLAAPImpl::AttributeRule::toValueType(const DOMElement* e)
{
    if (!XMLString::compareString(SHIB_L(literal),e->getAttributeNS(NULL,SHIB_L(Type))))
        return literal;
    else if (!XMLString::compareString(SHIB_L(regexp),e->getAttributeNS(NULL,SHIB_L(Type))))
        return regexp;
    else if (!XMLString::compareString(SHIB_L(xpath),e->getAttributeNS(NULL,SHIB_L(Type))))
        return xpath;
    throw MalformedException("Found an invalid value or scope rule type.");
}

const IAttributeRule* XMLAAP::lookup(const XMLCh* attrName, const XMLCh* attrNamespace) const
{
#ifdef HAVE_GOOD_STL
    xstring key=attrName;
    key=key + chBang + chBang + (attrNamespace ? attrNamespace : Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
#else
    auto_ptr_char aname(attrName);
    string key=aname.get();
    key+="!!";
    if (attrNamespace)
    {
        auto_ptr_char ans(attrNamespace);
        key+=ans.get();
    }
    else
        key+="urn:mace:shibboleth:1.0:attributeNamespace:uri";
#endif
    XMLAAPImpl* impl=dynamic_cast<XMLAAPImpl*>(getImplementation());
    XMLAAPImpl::attrmap_t::const_iterator i=impl->m_attrMap.find(key);
    return (i==impl->m_attrMap.end()) ? NULL : i->second;
}

const IAttributeRule* XMLAAP::lookup(const char* alias) const
{
    XMLAAPImpl* impl=dynamic_cast<XMLAAPImpl*>(getImplementation());
    map<string,const IAttributeRule*>::const_iterator i=impl->m_aliasMap.find(alias);
    return (i==impl->m_aliasMap.end()) ? NULL : i->second;
}

Iterator<const IAttributeRule*> XMLAAP::getAttributeRules() const
{
    return dynamic_cast<XMLAAPImpl*>(getImplementation())->m_attrs;
}

namespace {
    bool match(const XMLCh* exp, const XMLCh* test)
    {
        try
        {
            RegularExpression re(exp);
            if (re.matches(test))
                return true;
        }
        catch (XMLException& ex)
        {
            auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
            Category::getInstance(XMLPROVIDERS_LOGCAT".XMLAAPImpl").errorStream()
                << "caught exception while parsing regular expression: " << tmp.get() << CategoryStream::ENDLINE;
        }
        return false;
    }
}

bool XMLAAPImpl::AttributeRule::scopeCheck(
    const DOMElement* e,
    const IScopedRoleDescriptor* role,
    const vector<const SiteRule*>& ruleStack
    ) const
{
#ifdef _DEBUG
    saml::NDC ndc("scopeCheck");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");

    // Are we scoped?
    const XMLCh* scope=e->getAttributeNS(NULL,SHIB_L(Scope));
    if (!scope || !*scope) {
        // Are we allowed to be unscoped?
        if (m_scoped && log.isWarnEnabled()) {
                auto_ptr_char temp(m_name);
                log.warn("attribute (%s) is scoped, no scope supplied, rejecting it",temp.get());
        }
        return !m_scoped;
    }

    // With the new algorithm, we evaluate each matching rule in sequence, separately.
    for (vector<const SiteRule*>::const_iterator rule=ruleStack.begin(); rule!=ruleStack.end(); rule++) {

        // Now run any denials.
        vector<pair<value_type,const XMLCh*> >::const_iterator i;
        for (i=(*rule)->scopeDenials.begin(); i!=(*rule)->scopeDenials.end(); i++) {
            if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope))) {
                if (log.isWarnEnabled()) {
                    auto_ptr_char temp(m_name);
                    auto_ptr_char temp2(scope);
                    log.warn("attribute (%s) scope (%s) denied by site rule, rejecting it",temp.get(),temp2.get());
                }
                return false;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }

        // Now run any accepts.
        for (i=(*rule)->scopeAccepts.begin(); i!=(*rule)->scopeAccepts.end(); i++) {
            if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope))) {
                log.debug("matching site rule, scope match");
                return true;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }
    }

    // If we still can't decide, defer to metadata.
    if (role) {
        Iterator<pair<const XMLCh*,bool> > domains=role->getScopes();
        while (domains.hasNext()) {
            const pair<const XMLCh*,bool>& p=domains.next();
            if ((p.second && match(p.first,scope)) || !XMLString::compareString(p.first,scope)) {
                log.debug("scope match via site metadata");
                return true;
            }
        }
    }
    
    if (log.isWarnEnabled()) {
        auto_ptr_char temp(m_name);
        auto_ptr_char temp2(scope);
        log.warn("attribute (%s) scope (%s) not accepted",temp.get(),temp2.get());
    }
    return false;
}

bool XMLAAPImpl::AttributeRule::accept(const DOMElement* e, const IScopedRoleDescriptor* role) const
{
#ifdef _DEBUG
    saml::NDC ndc("accept");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");
    
    if (log.isDebugEnabled()) {
        auto_ptr_char temp(m_name);
        auto_ptr_char temp2(role ? role->getEntityDescriptor()->getId() : NULL);
        log.debug("evaluating value for attribute (%s) from site (%s)",temp.get(),temp2.get() ? temp2.get() : "<unspecified>");
    }
    
    // This is a complete revamp. The "any" cases become a degenerate case, the "least-specific" matching rule.
    // The first step is to build a list of matching rules, most-specific to least-specific.
    
    vector<const SiteRule*> ruleStack;
    if (role) {
        // Primary match is against entityID.
#ifdef HAVE_GOOD_STL
        const XMLCh* os=role->getEntityDescriptor()->getId();
#else
        auto_ptr_char pos(role->getEntityDescriptor()->getId());
        const char* os=pos.get();
#endif
        sitemap_t::const_iterator srule=m_siteMap.find(os);
        if (srule!=m_siteMap.end())
            ruleStack.push_back(&srule->second);
        
        // Secondary matches are on groups.
        const IEntitiesDescriptor* group=role->getEntityDescriptor()->getEntitiesDescriptor();
        while (group) {
            if (group->getName()) {
#ifdef HAVE_GOOD_STL
                os=group->getName();
#else
                auto_ptr_char gname(group->getName());
                const char* os=gname.get();
#endif
                srule=m_siteMap.find(os);
                if (srule!=m_siteMap.end())
                    ruleStack.push_back(&srule->second);
            }
            group = group->getEntitiesDescriptor();
        }
    }
    // Tertiary match is the AnySite rule.
    ruleStack.push_back(&m_anySiteRule);

    // Still don't support complex content models...
    DOMNode* n=e->getFirstChild();
    bool bSimple=(n && n->getNodeType()==DOMNode::TEXT_NODE);

    // With the new algorithm, we evaluate each matching rule in sequence, separately.
    for (vector<const SiteRule*>::const_iterator rule=ruleStack.begin(); rule!=ruleStack.end(); rule++) {

        // Check for shortcut AnyValue blanket rule.
        if ((*rule)->anyValue) {
            log.debug("matching site rule, any value match");
            return scopeCheck(e,role,ruleStack);
        }

        // Now run any denials.
        vector<pair<value_type,const XMLCh*> >::const_iterator i;
        for (i=(*rule)->valueDenials.begin(); bSimple && i!=(*rule)->valueDenials.end(); i++) {
            switch (i->first) {
                case literal:
                    if ((m_caseSensitive && !XMLString::compareString(i->second,n->getNodeValue())) ||
                        (!m_caseSensitive && !XMLString::compareIString(i->second,n->getNodeValue()))) {
                        if (log.isWarnEnabled()) {
                            auto_ptr_char temp(m_name);
                            log.warn("attribute (%s) value explicitly denied by site rule, rejecting it",temp.get());
                        }
                        return false;
                    }
                    break;
                
                case regexp:
                    if (match(i->second,n->getNodeValue())) {
                        if (log.isWarnEnabled()) {
                            auto_ptr_char temp(m_name);
                            log.warn("attribute (%s) value explicitly denied by site rule, rejecting it",temp.get());
                        }
                        return false;
                    }
                    break;
                
                case xpath:
                    log.warn("implementation does not support XPath value rules");
                    break;
            }
        }

        // Now run any accepts.
        for (i=(*rule)->valueAccepts.begin(); bSimple && i!=(*rule)->valueAccepts.end(); i++) {
            switch (i->first) {
                case literal:
                    if ((m_caseSensitive && !XMLString::compareString(i->second,n->getNodeValue())) ||
                        (!m_caseSensitive && !XMLString::compareIString(i->second,n->getNodeValue()))) {
                        log.debug("site rule, value match");
                        return scopeCheck(e,role,ruleStack);
                    }
                    break;
                
                case regexp:
                    if (match(i->second,n->getNodeValue())) {
                        log.debug("site rule, value match");
                        return scopeCheck(e,role,ruleStack);
                    }
                    break;
                
                case xpath:
                    log.warn("implementation does not support XPath value rules");
                    break;
            }
        }
    }

    if (log.isWarnEnabled()) {
        auto_ptr_char temp(m_name);
        auto_ptr_char temp2(n->getNodeValue());
        log.warn("%sattribute (%s) value (%s) could not be validated by policy, rejecting it",
                 (bSimple ? "" : "complex "),temp.get(),temp2.get());
    }
    return false;
}

void XMLAAPImpl::AttributeRule::apply(SAMLAttribute& attribute, const IRoleDescriptor* role) const
{
    // Check each value.
    DOMNodeList* vals=attribute.getValueElements();
    int i2=0;
    for (unsigned int i=0; vals && i < vals->getLength(); i++) {
        if (!accept(static_cast<DOMElement*>(vals->item(i)),role ? dynamic_cast<const IScopedRoleDescriptor*>(role) : NULL))
            attribute.removeValue(i2);
        else
            i2++;
    }
    
    // Now see if we trashed it irrevocably.
    attribute.checkValidity();
}
