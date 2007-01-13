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
#include <algorithm>
#include <log4cpp/Category.hh>
#include <shibsp/metadata/MetadataExt.h>
#include <shibsp/util/SPConstants.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace shibboleth;
using namespace saml;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

#include <xercesc/util/regx/RegularExpression.hpp>

namespace {

    class XMLAAPImpl
    {
    public:
        XMLAAPImpl(const DOMElement* e);
        ~XMLAAPImpl();

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }
    
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
            void apply(SAMLAttribute& attribute, const RoleDescriptor* role=NULL) const;
    
            enum value_type { literal, regexp, xpath };
        private:    
            const XMLCh* m_name;
            const XMLCh* m_namespace;
            xmltooling::auto_ptr_char m_alias;
            xmltooling::auto_ptr_char m_header;
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
                const RoleDescriptor* role,
                const vector<const SiteRule*>& ruleStack
                ) const;
            bool accept(const DOMElement* e, const RoleDescriptor* role=NULL) const;
            
            SiteRule m_anySiteRule;
    #ifdef HAVE_GOOD_STL
            typedef map<xmltooling::xstring,SiteRule> sitemap_t;
    #else
            typedef map<string,SiteRule> sitemap_t;
    #endif
            sitemap_t m_siteMap;
        };
    
        DOMDocument* m_document;
        bool anyAttribute;
        vector<const IAttributeRule*> m_attrs;
        map<string,const IAttributeRule*> m_aliasMap;
    #ifdef HAVE_GOOD_STL
        typedef map<xmltooling::xstring,AttributeRule*> attrmap_t;
    #else
        typedef map<string,AttributeRule*> attrmap_t;
    #endif
        attrmap_t m_attrMap;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLAAP : public IAAP, public ReloadableXMLFile
    {
    public:
        XMLAAP(const DOMElement* e) : ReloadableXMLFile(e), m_impl(NULL) {
            load();
        }
        ~XMLAAP() {
            delete m_impl;
        }
        
        bool anyAttribute() const {return m_impl->anyAttribute;}
        const IAttributeRule* lookup(const XMLCh* attrName, const XMLCh* attrNamespace=NULL) const;
        const IAttributeRule* lookup(const char* alias) const;
        Iterator<const IAttributeRule*> getAttributeRules() const;

    protected:
        pair<bool,DOMElement*> load();
        XMLAAPImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh Accept[]=        UNICODE_LITERAL_6(A,c,c,e,p,t);
    static const XMLCh Alias[]=         UNICODE_LITERAL_5(A,l,i,a,s);
    static const XMLCh AnyAttribute[]=  UNICODE_LITERAL_12(A,n,y,A,t,t,r,i,b,u,t,e);
    static const XMLCh AnySite[]=       UNICODE_LITERAL_7(A,n,y,S,i,t,e);
    static const XMLCh AnyValue[]=      UNICODE_LITERAL_8(A,n,y,V,a,l,u,e);
    static const XMLCh _AttributeRule[]=UNICODE_LITERAL_13(A,t,t,r,i,b,u,t,e,R,u,l,e);
    static const XMLCh CaseSensitive[]= UNICODE_LITERAL_13(C,a,s,e,S,e,n,s,i,t,i,v,e);
    static const XMLCh Header[]=        UNICODE_LITERAL_6(H,e,a,d,e,r);
    static const XMLCh Name[]=          UNICODE_LITERAL_4(N,a,m,e);
    static const XMLCh Namespace[]=     UNICODE_LITERAL_9(N,a,m,e,s,p,a,c,e);
    static const XMLCh Scoped[]=        UNICODE_LITERAL_6(S,c,o,p,e,d);
    static const XMLCh _SiteRule[]=     UNICODE_LITERAL_8(S,i,t,e,R,u,l,e);
    static const XMLCh Type[]=          UNICODE_LITERAL_4(T,y,p,e);
    static const XMLCh Value[]=         UNICODE_LITERAL_5(V,a,l,u,e);

    static const XMLCh _literal[]=      UNICODE_LITERAL_7(l,i,t,e,r,a,l);
    static const XMLCh _regexp[]=       UNICODE_LITERAL_6(r,e,g,e,x,p);
    static const XMLCh _xpath[]=        UNICODE_LITERAL_5(x,p,a,t,h);
}

IPlugIn* XMLAAPFactory(const DOMElement* e)
{
    return new XMLAAP(e);
}

pair<bool,DOMElement*> XMLAAP::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLAAPImpl* impl = new XMLAAPImpl(raw.second);
    
    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}

XMLAAPImpl::XMLAAPImpl(const DOMElement* e) : anyAttribute(false), m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLAAPImpl");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");

    try {
        // Check for AnyAttribute element.
        if (XMLHelper::getFirstChildElement(e,AnyAttribute)) {
            anyAttribute = true;
            log.warn("<AnyAttribute> found, will short-circuit all attribute value and scope filtering");
        }

        // Loop over the AttributeRule elements.
        e = XMLHelper::getFirstChildElement(e, _AttributeRule); 
        while (e) {
            AttributeRule* rule=new AttributeRule(e);
#ifdef HAVE_GOOD_STL
            xmltooling::xstring key=rule->getName();
            key=key + chBang + chBang + (rule->getNamespace() ? rule->getNamespace() : shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI);
#else
            xmltooling::auto_ptr_char aname(rule->getName());
            string key(aname.get());
            key+="!!";
            if (rule->getNamespace()) {
                xmltooling::auto_ptr_char ans(rule->getNamespace());
                key+=ans.get();
            }
            else {
                key+="urn:mace:shibboleth:1.0:attributeNamespace:uri";
            }
#endif
            m_attrMap[key]=rule;
            m_attrs.push_back(rule);
            if (rule->getAlias()) {
                // user can only apply to REMOTE_USER
                if (!strcmp(rule->getAlias(),"user")) {
                    if (strcmp(rule->getHeader(),"REMOTE_USER"))
                        log.error("<AttributeRule> cannot specify Alias of 'user', please use alternate value");
                    else {
                        m_aliasMap[rule->getAlias()]=rule;
                    }
                }
                else {
                    m_aliasMap[rule->getAlias()]=rule;
                }
            }
            
            e = XMLHelper::getNextSiblingElement(e, _AttributeRule);
        }
    }
    catch (exception&) {
#ifdef HAVE_GOOD_STL
        for_each(m_attrMap.begin(),m_attrMap.end(),xmltooling::cleanup_pair<xmltooling::xstring,AttributeRule>());
#else
        for_each(m_attrMap.begin(),m_attrMap.end(),xmltooling::cleanup_pair<string,AttributeRule>());
#endif
        throw;
    }
}

XMLAAPImpl::~XMLAAPImpl()
{
#ifdef HAVE_GOOD_STL
    for_each(m_attrMap.begin(),m_attrMap.end(),xmltooling::cleanup_pair<xmltooling::xstring,AttributeRule>());
#else
    for_each(m_attrMap.begin(),m_attrMap.end(),xmltooling::cleanup_pair<string,AttributeRule>());
#endif
    if (m_document)
        m_document->release();
}

XMLAAPImpl::AttributeRule::AttributeRule(const DOMElement* e) :
    m_alias(e->hasAttributeNS(NULL,Alias) ? e->getAttributeNS(NULL,Alias) : NULL),
    m_header(e->hasAttributeNS(NULL,Header) ? e->getAttributeNS(NULL,Header) : NULL),
    m_scoped(false)
    
{
    m_name=e->getAttributeNS(NULL,Name);
    m_namespace=e->getAttributeNS(NULL,Namespace);
    if (!m_namespace || !*m_namespace)
        m_namespace=shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI;
    
    const XMLCh* caseSensitive=e->getAttributeNS(NULL,CaseSensitive);
    m_caseSensitive=(!caseSensitive || !*caseSensitive || *caseSensitive==chDigit_1 || *caseSensitive==chLatin_t);
    
    const XMLCh* scoped=e->getAttributeNS(NULL,Scoped);
    m_scoped=(scoped && (*scoped==chDigit_1 || *scoped==chLatin_t));
    
    // Check for an AnySite rule.
    const DOMElement* anysite = XMLHelper::getFirstChildElement(e);
    if (anysite && XMLString::equals(anysite->getLocalName(),AnySite)) {
        // Process Scope elements.
        const DOMElement* se = XMLHelper::getFirstChildElement(anysite,Scope::LOCAL_NAME);
        while (se) {
            m_scoped=true;
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                const XMLCh* accept=se->getAttributeNS(NULL,Accept);
                if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                    m_anySiteRule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    m_anySiteRule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
            
            se = XMLHelper::getNextSiblingElement(se,Scope::LOCAL_NAME);
        }

        // Check for an AnyValue rule.
        if (XMLHelper::getFirstChildElement(anysite,AnyValue)) {
            m_anySiteRule.anyValue=true;
        }
        else {
            // Process each Value element.
            const DOMElement* ve = XMLHelper::getFirstChildElement(anysite,Value);
            while (ve) {
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                    const XMLCh* accept=ve->getAttributeNS(NULL,Accept);
                    if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                        m_anySiteRule.valueAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                    else
                        m_anySiteRule.valueDenials.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                }
                
                ve = XMLHelper::getNextSiblingElement(ve,Value);
            }
        }
    }

    // Loop over the SiteRule elements.
    const DOMElement* sr = XMLHelper::getFirstChildElement(e,_SiteRule);
    while (sr) {
        const XMLCh* srulename=sr->getAttributeNS(NULL,Name);
#ifdef HAVE_GOOD_STL
        m_siteMap[srulename]=SiteRule();
        SiteRule& srule=m_siteMap[srulename];
#else
        xmltooling::auto_ptr_char srulename2(srulename);
        m_siteMap[srulename2.get()]=SiteRule();
        SiteRule& srule=m_siteMap[srulename2.get()];
#endif

        // Process Scope elements.
        const DOMElement* se = XMLHelper::getFirstChildElement(sr,Scope::LOCAL_NAME);
        while (se) {
            m_scoped=true;
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                const XMLCh* accept=se->getAttributeNS(NULL,Accept);
                if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                    srule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    srule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
            
            se = XMLHelper::getNextSiblingElement(se,Scope::LOCAL_NAME);
        }

        // Check for an AnyValue rule.
        if (XMLHelper::getFirstChildElement(sr,AnyValue)) {
            srule.anyValue=true;
        }
        else
        {
            // Process each Value element.
            const DOMElement* ve = XMLHelper::getFirstChildElement(sr,Value);
            while (ve) {
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE) {
                    const XMLCh* accept=ve->getAttributeNS(NULL,Accept);
                    if (!accept || !*accept || *accept==chDigit_1 || *accept==chLatin_t)
                        srule.valueAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                    else
                        srule.valueDenials.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
                }
                
                ve = XMLHelper::getNextSiblingElement(ve,Value);
            }
        }
        
        sr = XMLHelper::getNextSiblingElement(sr,_SiteRule);
    }
}

XMLAAPImpl::AttributeRule::value_type XMLAAPImpl::AttributeRule::toValueType(const DOMElement* e)
{
    if (XMLString::equals(_literal,e->getAttributeNS(NULL,Type)))
        return literal;
    else if (XMLString::equals(_regexp,e->getAttributeNS(NULL,Type)))
        return regexp;
    else if (XMLString::equals(_xpath,e->getAttributeNS(NULL,Type)))
        return xpath;
    throw ConfigurationException("Found an invalid value or scope rule type.");
}

const IAttributeRule* XMLAAP::lookup(const XMLCh* attrName, const XMLCh* attrNamespace) const
{
#ifdef HAVE_GOOD_STL
    xmltooling::xstring key=attrName;
    key=key + chBang + chBang + (attrNamespace ? attrNamespace : shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI);
#else
    xmltooling::auto_ptr_char aname(attrName);
    string key=aname.get();
    key+="!!";
    if (attrNamespace) {
        xmltooling::auto_ptr_char ans(attrNamespace);
        key+=ans.get();
    }
    else {
        key+="urn:mace:shibboleth:1.0:attributeNamespace:uri";
    }
#endif
    XMLAAPImpl::attrmap_t::const_iterator i=m_impl->m_attrMap.find(key);
    return (i==m_impl->m_attrMap.end()) ? NULL : i->second;
}

const IAttributeRule* XMLAAP::lookup(const char* alias) const
{
    map<string,const IAttributeRule*>::const_iterator i=m_impl->m_aliasMap.find(alias);
    return (i==m_impl->m_aliasMap.end()) ? NULL : i->second;
}

Iterator<const IAttributeRule*> XMLAAP::getAttributeRules() const
{
    return m_impl->m_attrs;
}

namespace {
    bool match(const XMLCh* exp, const XMLCh* test)
    {
        try {
            RegularExpression re(exp);
            if (re.matches(test))
                return true;
        }
        catch (XMLException& ex) {
            xmltooling::auto_ptr_char tmp(ex.getMessage());
            Category::getInstance(XMLPROVIDERS_LOGCAT".AAP").errorStream()
                << "caught exception while parsing regular expression: " << tmp.get() << CategoryStream::ENDLINE;
        }
        return false;
    }
}

bool XMLAAPImpl::AttributeRule::scopeCheck(
    const DOMElement* e,
    const RoleDescriptor* role,
    const vector<const SiteRule*>& ruleStack
    ) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("scopeCheck");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");

    // Are we scoped?
    const XMLCh* scope=e->getAttributeNS(NULL,Scope::LOCAL_NAME);
    if (!scope || !*scope) {
        // Are we allowed to be unscoped?
        if (m_scoped && log.isWarnEnabled()) {
                xmltooling::auto_ptr_char temp(m_name);
                log.warn("attribute (%s) is scoped, no scope supplied, rejecting it",temp.get());
        }
        return !m_scoped;
    }

    // With the new algorithm, we evaluate each matching rule in sequence, separately.
    for (vector<const SiteRule*>::const_iterator rule=ruleStack.begin(); rule!=ruleStack.end(); rule++) {

        // Now run any denials.
        vector<pair<value_type,const XMLCh*> >::const_iterator i;
        for (i=(*rule)->scopeDenials.begin(); i!=(*rule)->scopeDenials.end(); i++) {
            if ((i->first==literal && XMLString::equals(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope))) {
                if (log.isWarnEnabled()) {
                    xmltooling::auto_ptr_char temp(m_name);
                    xmltooling::auto_ptr_char temp2(scope);
                    log.warn("attribute (%s) scope (%s) denied by site rule, rejecting it",temp.get(),temp2.get());
                }
                return false;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }

        // Now run any accepts.
        for (i=(*rule)->scopeAccepts.begin(); i!=(*rule)->scopeAccepts.end(); i++) {
            if ((i->first==literal && XMLString::equals(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope))) {
                log.debug("matching site rule, scope match");
                return true;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }
    }

    // If we still can't decide, defer to metadata.
    if (role && role->getExtensions()) {
        const vector<XMLObject*>& exts=const_cast<const Extensions*>(role->getExtensions())->getUnknownXMLObjects();
        for (vector<XMLObject*>::const_iterator it=exts.begin(); it!=exts.end(); ++it) {
            const Scope* s=dynamic_cast<const Scope*>(*it);
            if (!s)
                continue;
            if ((s->Regexp() && match(s->getValue(),scope)) || XMLString::equals(s->getValue(),scope)) {
                log.debug("scope match via site metadata");
                return true;
            }
        }
    }
    
    if (log.isWarnEnabled()) {
        xmltooling::auto_ptr_char temp(m_name);
        xmltooling::auto_ptr_char temp2(scope);
        log.warn("attribute (%s) scope (%s) not accepted",temp.get(),temp2.get());
    }
    return false;
}

bool XMLAAPImpl::AttributeRule::accept(const DOMElement* e, const RoleDescriptor* role) const
{
#ifdef _DEBUG
    xmltooling::NDC ndc("accept");
#endif
    Category& log=Category::getInstance(XMLPROVIDERS_LOGCAT".AAP");

    const EntityDescriptor* source = role ? dynamic_cast<const EntityDescriptor*>(role->getParent()) : NULL;

    if (log.isDebugEnabled()) {
        xmltooling::auto_ptr_char temp(m_name);
        xmltooling::auto_ptr_char temp2(source ? source->getEntityID() : NULL);
        log.debug("evaluating value for attribute (%s) from site (%s)",temp.get(),temp2.get() ? temp2.get() : "<unspecified>");
    }
    
    // This is a complete revamp. The "any" cases become a degenerate case, the "least-specific" matching rule.
    // The first step is to build a list of matching rules, most-specific to least-specific.
    
    vector<const SiteRule*> ruleStack;
    if (source) {
        // Primary match is against entityID.
#ifdef HAVE_GOOD_STL
        const XMLCh* os=source->getEntityID();
#else
        auto_ptr_char pos(source->getEntityID());
        const char* os=pos.get();
#endif
        sitemap_t::const_iterator srule=m_siteMap.find(os);
        if (srule!=m_siteMap.end())
            ruleStack.push_back(&srule->second);
        
        // Secondary matches are on groups.
        const EntitiesDescriptor* group=dynamic_cast<const EntitiesDescriptor*>(source->getParent());
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
            group=dynamic_cast<const EntitiesDescriptor*>(group->getParent());
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
                            xmltooling::auto_ptr_char temp(m_name);
                            log.warn("attribute (%s) value explicitly denied by site rule, rejecting it",temp.get());
                        }
                        return false;
                    }
                    break;
                
                case regexp:
                    if (match(i->second,n->getNodeValue())) {
                        if (log.isWarnEnabled()) {
                            xmltooling::auto_ptr_char temp(m_name);
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
        xmltooling::auto_ptr_char temp(m_name);
        xmltooling::auto_ptr_char temp2(n->getNodeValue());
        log.warn("%sattribute (%s) value (%s) could not be validated by policy, rejecting it",
                 (bSimple ? "" : "complex "),temp.get(),temp2.get());
    }
    return false;
}

void XMLAAPImpl::AttributeRule::apply(SAMLAttribute& attribute, const RoleDescriptor* role) const
{
    // Check each value.
    DOMNodeList* vals=attribute.getValueElements();
    int i2=0;
    for (XMLSize_t i=0; vals && i < vals->getLength(); i++) {
        if (!accept(static_cast<DOMElement*>(vals->item(i)),role))
            attribute.removeValue(i2);
        else
            i2++;
    }
    
    // Now see if we trashed it irrevocably.
    attribute.checkValidity();
}
