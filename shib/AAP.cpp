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


/* AAP.cpp - XML AAP implementation

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

#include <xercesc/framework/URLInputSource.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

class shibboleth::XMLAAPImpl
{
public:
    XMLAAPImpl(const char* pathname);
    ~XMLAAPImpl();
    
    void regAttributes() const;

    class AttributeRule : public IAttributeRule
    {
    public:
        AttributeRule(const DOMElement* e);
        ~AttributeRule() {}
        
        const XMLCh* getName() const { return m_name; }
        const XMLCh* getNamespace() const { return m_namespace; }
        const char* getFactory() const { return m_factory.get(); }
        const char* getAlias() const { return m_alias.get(); }
        const char* getHeader() const { return m_header.get(); }
        bool accept(const XMLCh* originSite, const DOMElement* e) const;

        enum value_type { literal, regexp, xpath };
    private:    
        const XMLCh* m_name;
        const XMLCh* m_namespace;
        auto_ptr<char> m_factory;
        auto_ptr<char> m_alias;
        auto_ptr<char> m_header;
        
        value_type toValueType(const DOMElement* e);
        bool scopeCheck(const XMLCh* originSite, const DOMElement* e) const;
        
        struct SiteRule
        {
            SiteRule() : anyValue(false) {}
            bool anyValue;
            vector<pair<value_type,const XMLCh*> > valueRules;
            vector<pair<value_type,const XMLCh*> > scopeDenials;
            vector<pair<value_type,const XMLCh*> > scopeAccepts;
        };

        SiteRule m_anySiteRule;
        map<xstring,SiteRule> m_siteMap;
    };

    vector<const IAttributeRule*> m_attrs;
    map<string,const IAttributeRule*> m_aliasMap;
    map<xstring,AttributeRule*> m_attrMap;
    DOMDocument* m_doc;
};

XMLAAPImpl::XMLAAPImpl(const char* pathname) : m_doc(NULL)
{
    NDC ndc("XMLAAPImpl");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLAAPImpl");

    saml::XML::Parser p;
    try
    {
        static XMLCh base[]={chLatin_f, chLatin_i, chLatin_l, chLatin_e, chColon, chForwardSlash, chForwardSlash, chForwardSlash, chNull};
        URLInputSource src(base,pathname);
        Wrapper4InputSource dsrc(&src,false);
        m_doc=p.parse(dsrc);

        log.infoStream() << "Loaded and parsed AAP file (" << pathname << ")" << CategoryStream::ENDLINE;

        DOMElement* e = m_doc->getDocumentElement();
        if (XMLString::compareString(XML::SHIB_NS,e->getNamespaceURI()) ||
            XMLString::compareString(SHIB_L(AttributeAcceptancePolicy),e->getLocalName()))
        {
            log.error("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
            throw MalformedException("Construction requires a valid AAP file: (shib:AttributeAcceptancePolicy as root element)");
        }

        // Loop over the AttributeRule elements.
        DOMNodeList* nlist = e->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(AttributeRule));
        for (int i=0; nlist && i<nlist->getLength(); i++)
        {
            AttributeRule* rule=new AttributeRule(static_cast<DOMElement*>(nlist->item(i)));
            m_attrMap[xstring(rule->getName()) + chBang + chBang + (rule->getNamespace() ? rule->getNamespace() : Constants::SHIB_ATTRIBUTE_NAMESPACE_URI)]=rule;
            m_attrs.push_back(rule);
            if (rule->getAlias())
                m_aliasMap[rule->getAlias()]=rule;
        }
    }
    catch (SAMLException& e)
    {
        log.errorStream() << "XML error while parsing AAP: " << e.what() << CategoryStream::ENDLINE;
        for (map<xstring,AttributeRule*>::iterator i=m_attrMap.begin(); i!=m_attrMap.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }
    catch (...)
    {
        log.error("Unexpected error while parsing AAP");
        for (map<xstring,AttributeRule*>::iterator i=m_attrMap.begin(); i!=m_attrMap.end(); i++)
            delete i->second;
        if (m_doc)
            m_doc->release();
        throw;
    }

}

XMLAAPImpl::~XMLAAPImpl()
{
    for (map<xstring,AttributeRule*>::iterator i=m_attrMap.begin(); i!=m_attrMap.end(); i++)
    {
        SAMLAttribute::unregFactory(i->second->getName(),i->second->getNamespace());
        delete i->second;
    }
    if (m_doc)
        m_doc->release();
}

void XMLAAPImpl::regAttributes() const
{
    for (map<xstring,AttributeRule*>::const_iterator i=m_attrMap.begin(); i!=m_attrMap.end(); i++)
    {
        SAMLAttributeFactory* f=ShibConfig::getConfig().getAttributeFactory(i->second->getFactory());
        if (f)
            SAMLAttribute::regFactory(i->second->getName(),i->second->getNamespace(),f);
    }
}

XMLAAPImpl::AttributeRule::AttributeRule(const DOMElement* e) :
    m_factory(e->hasAttributeNS(NULL,SHIB_L(Factory)) ? XMLString::transcode(e->getAttributeNS(NULL,SHIB_L(Factory))) : NULL),
    m_alias(e->hasAttributeNS(NULL,SHIB_L(Alias)) ? XMLString::transcode(e->getAttributeNS(NULL,SHIB_L(Alias))) : NULL),
    m_header(e->hasAttributeNS(NULL,SHIB_L(Header)) ? XMLString::transcode(e->getAttributeNS(NULL,SHIB_L(Header))) : NULL)
    
{
    static const XMLCh wTrue[] = {chLatin_t, chLatin_r, chLatin_u, chLatin_e, chNull};

    m_name=e->getAttributeNS(NULL,SHIB_L(Name));
    m_namespace=e->getAttributeNS(NULL,SHIB_L(Namespace));
    if (!m_namespace || !*m_namespace)
        m_namespace=Constants::SHIB_ATTRIBUTE_NAMESPACE_URI;
    
    // Check for an AnySite rule.
    DOMNode* anysite = e->getFirstChild();
    while (anysite && anysite->getNodeType()!=DOMNode::ELEMENT_NODE)
    {
        anysite = anysite->getNextSibling();
        continue;
    }

    if (anysite && !XMLString::compareString(XML::SHIB_NS,static_cast<DOMElement*>(anysite)->getNamespaceURI()) &&
        !XMLString::compareString(SHIB_L(AnySite),static_cast<DOMElement*>(anysite)->getLocalName()))
    {
        // Process Scope elements.
        DOMNodeList* vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(Scope));
        for (int i=0; vlist && i<vlist->getLength(); i++)
        {
            DOMElement* se=static_cast<DOMElement*>(vlist->item(i));
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
            {
                const XMLCh* accept=se->getAttributeNS(NULL,SHIB_L(Accept));
                if (!accept || !*accept || *accept==chDigit_1 || !XMLString::compareString(accept,wTrue))
                    m_anySiteRule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    m_anySiteRule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
        }

        // Check for an AnyValue rule.
        vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(AnyValue));
        if (vlist && vlist->getLength())
        {
            m_anySiteRule.anyValue=true;
        }
        else
        {
            // Process each Value element.
            vlist = static_cast<DOMElement*>(anysite)->getElementsByTagNameNS(XML::SHIB_NS,XML::Literals::Value);
            for (int j=0; vlist && j<vlist->getLength(); j++)
            {
                DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
                    m_anySiteRule.valueRules.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
            }
        }
    }

    // Loop over the SiteRule elements.
    DOMNodeList* slist = e->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(SiteRule));
    for (int k=0; slist && k<slist->getLength(); k++)
    {
        m_siteMap[static_cast<DOMElement*>(slist->item(k))->getAttributeNS(NULL,SHIB_L(Name))]=SiteRule();
        SiteRule& srule=m_siteMap[static_cast<DOMElement*>(slist->item(k))->getAttributeNS(NULL,SHIB_L(Name))];

        // Process Scope elements.
        DOMNodeList* vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(Scope));
        for (int i=0; vlist && i<vlist->getLength(); i++)
        {
            DOMElement* se=static_cast<DOMElement*>(vlist->item(i));
            DOMNode* valnode=se->getFirstChild();
            if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
            {
                const XMLCh* accept=se->getAttributeNS(NULL,SHIB_L(Accept));
                if (!accept || *accept==chDigit_1 || !XMLString::compareString(accept,wTrue))
                    srule.scopeAccepts.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
                else
                    srule.scopeDenials.push_back(pair<value_type,const XMLCh*>(toValueType(se),valnode->getNodeValue()));
            }
        }

        // Check for an AnyValue rule.
        vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(AnyValue));
        if (vlist && vlist->getLength())
        {
            srule.anyValue=true;
        }
        else
        {
            // Process each Value element.
            vlist = static_cast<DOMElement*>(slist->item(k))->getElementsByTagNameNS(XML::SHIB_NS,SHIB_L(Value));
            for (int j=0; vlist && j<vlist->getLength(); j++)
            {
                DOMElement* ve=static_cast<DOMElement*>(vlist->item(j));
                DOMNode* valnode=ve->getFirstChild();
                if (valnode && valnode->getNodeType()==DOMNode::TEXT_NODE)
                    srule.valueRules.push_back(pair<value_type,const XMLCh*>(toValueType(ve),valnode->getNodeValue()));
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

XMLAAP::XMLAAP(const char* pathname) : m_filestamp(0), m_source(pathname), m_impl(NULL)
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(pathname, &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(pathname, &stat_buf) == 0)
#endif
        m_filestamp=stat_buf.st_mtime;
    m_impl=new XMLAAPImpl(pathname);
    SAMLConfig::getConfig().saml_lock();
    m_impl->regAttributes();
    SAMLConfig::getConfig().saml_unlock();
    m_lock=RWLock::create();
}

XMLAAP::~XMLAAP()
{
    delete m_lock;
    delete m_impl;
}

void XMLAAP::lock()
{
    m_lock->rdlock();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0)
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0)
#endif
    {
        if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
        {
            // Elevate lock and recheck.
            m_lock->unlock();
            m_lock->wrlock();
            if (m_filestamp>0 && m_filestamp<stat_buf.st_mtime)
            {
                try
                {
                    XMLAAPImpl* new_mapper=new XMLAAPImpl(m_source.c_str());
                    SAMLConfig::getConfig().saml_lock();
                    delete m_impl;
                    m_impl=new_mapper;
                    m_impl->regAttributes();
                    SAMLConfig::getConfig().saml_unlock();
                    m_filestamp=stat_buf.st_mtime;
                    m_lock->unlock();
                }
                catch(SAMLException& e)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLAAP").error("failed to reload AAP, sticking with what we have: %s", e.what());
                }
                catch(...)
                {
                    m_lock->unlock();
                    saml::NDC ndc("lock");
                    Category::getInstance(SHIB_LOGCAT".XMLAAP").error("caught an unknown exception, sticking with what we have");
                }
            }
            else
            {
                m_lock->unlock();
            }
            m_lock->rdlock();
        }
    }
}

void XMLAAP::unlock()
{
    m_lock->unlock();
}

const IAttributeRule* XMLAAP::lookup(const XMLCh* attrName, const XMLCh* attrNamespace) const
{
    map<xstring,XMLAAPImpl::AttributeRule*>::const_iterator i=m_impl->m_attrMap.find(
        xstring(attrName) + chBang + chBang + (attrNamespace ? attrNamespace : Constants::SHIB_ATTRIBUTE_NAMESPACE_URI)
        );
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
        try
        {
            RegularExpression re(exp);
            if (re.matches(test))
                return true;
        }
        catch (XMLException& ex)
        {
            auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
            Category::getInstance(SHIB_LOGCAT".XMLAAPImpl").errorStream()
                << "caught exception while parsing regular expression: " << tmp.get() << CategoryStream::ENDLINE;
        }
        return false;
    }
}

bool XMLAAPImpl::AttributeRule::scopeCheck(const XMLCh* originSite, const DOMElement* e) const
{
    // Are we scoped?
    const XMLCh* scope=e->getAttributeNS(NULL,SHIB_L(Scope));
    if (!scope || !*scope)
        return true;

    NDC ndc("scopeCheck");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLAAPImpl");

    vector<pair<value_type,const XMLCh*> >::const_iterator i;

    // Denials take precedence, always.
    
    // Any site denials...
    for (i=m_anySiteRule.scopeDenials.begin(); i!=m_anySiteRule.scopeDenials.end(); i++)
    {
        if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
            (i->first==regexp && match(i->second,scope)))
        {
            if (log.isWarnEnabled())
            {
                auto_ptr<char> temp(XMLString::transcode(m_name));
                auto_ptr<char> temp2(XMLString::transcode(scope));
                log.warn("attribute %s scope {%s} denied by any-site AAP, rejecting it",temp.get(),temp2.get());
            }
            return false;
        }
        else if (i->first==xpath)
            log.warn("scope checking does not permit XPath rules");
    }

    map<xstring,SiteRule>::const_iterator srule=m_siteMap.find(originSite);
    if (srule!=m_siteMap.end())
    {
        // Site-specific denials...
        for (i=srule->second.scopeDenials.begin(); i!=srule->second.scopeDenials.end(); i++)
        {
            if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope)))
            {
                if (log.isWarnEnabled())
                {
                    auto_ptr<char> temp(XMLString::transcode(m_name));
                    auto_ptr<char> temp2(XMLString::transcode(scope));
                    log.warn("attribute %s scope {%s} denied by site AAP, rejecting it",temp.get(),temp2.get());
                }
                return false;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }
    }

    // Any site accepts...
    for (i=m_anySiteRule.scopeAccepts.begin(); i!=m_anySiteRule.scopeAccepts.end(); i++)
    {
        if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
            (i->first==regexp && match(i->second,scope)))
        {
            log.debug("any site, scope match");
            return true;
        }
        else if (i->first==xpath)
            log.warn("scope checking does not permit XPath rules");
    }

    if (srule!=m_siteMap.end())
    {
        // Site-specific accepts...
        for (i=srule->second.scopeAccepts.begin(); i!=srule->second.scopeAccepts.end(); i++)
        {
            if ((i->first==literal && !XMLString::compareString(i->second,scope)) ||
                (i->first==regexp && match(i->second,scope)))
            {
                log.debug("matching site, scope match");
                return true;
            }
            else if (i->first==xpath)
                log.warn("scope checking does not permit XPath rules");
        }
    }
    
    // If we still can't decide, defer to site metadata.
    OriginMetadata mapper(originSite);
    Iterator<pair<const XMLCh*,bool> > domains=
        (mapper.fail()) ? Iterator<pair<const XMLCh*,bool> >() : mapper->getSecurityDomains();
    while (domains.hasNext())
    {
        const pair<const XMLCh*,bool>& p=domains.next();
        if ((p.second && match(p.first,scope)) || !XMLString::compareString(p.first,scope))
        {
            log.debug("scope match via site metadata");
            return true;
        }
    }

    if (log.isWarnEnabled())
    {
        auto_ptr<char> temp(XMLString::transcode(m_name));
        auto_ptr<char> temp2(XMLString::transcode(scope));
        log.warn("attribute %s scope {%s} not accepted",temp.get(),temp2.get());
    }
    return false;
}

bool XMLAAPImpl::AttributeRule::accept(const XMLCh* originSite, const DOMElement* e) const
{
    NDC ndc("accept");
    Category& log=Category::getInstance(SHIB_LOGCAT".XMLAAPImpl");
    
    if (log.isDebugEnabled())
    {
        auto_ptr<char> temp(XMLString::transcode(m_name));
        auto_ptr<char> temp2(XMLString::transcode(originSite));
        log.debug("evaluating value for attribute %s from site %s",temp.get(),temp2.get());
    }
    
    if (m_anySiteRule.anyValue)
    {
        log.debug("any site, any value, match");
        return scopeCheck(originSite,e);
    }

    // Don't fully support complex content models...
    DOMNode* n=e->getFirstChild();
    bool bSimple=(n && n->getNodeType()==DOMNode::TEXT_NODE);

    vector<pair<value_type,const XMLCh*> >::const_iterator i;
    for (i=m_anySiteRule.valueRules.begin(); bSimple && i!=m_anySiteRule.valueRules.end(); i++)
    {
        if ((i->first==literal && !XMLString::compareString(i->second,n->getNodeValue())) ||
            (i->first==regexp && match(i->second,n->getNodeValue())))
        {
            log.debug("any site, value match");
            return scopeCheck(originSite,e);
        }
        else if (i->first==xpath)
            log.warn("implementation does not support XPath value rules");
    }

    map<xstring,SiteRule>::const_iterator srule=m_siteMap.find(originSite);
    if (srule==m_siteMap.end())
    {
        if (log.isWarnEnabled())
        {
            auto_ptr<char> temp(XMLString::transcode(m_name));
            auto_ptr<char> temp2(XMLString::transcode(originSite));
            log.warn("site %s not found in attribute %s ruleset, any value is rejected",temp2.get(),temp.get());
        }
        return false;
    }

    if (srule->second.anyValue)
    {
        log.debug("matching site, any value, match");
        return scopeCheck(originSite,e);
    }

    for (i=srule->second.valueRules.begin(); bSimple && i!=srule->second.valueRules.end(); i++)
    {
        if ((i->first==literal && !XMLString::compareString(i->second,n->getNodeValue())) ||
            (i->first==regexp && match(i->second,n->getNodeValue())))
        {
            log.debug("matching site, value match");
            return scopeCheck(originSite,e);
        }
        else if (i->first==xpath)
            log.warn("implementation does not support XPath value rules");
    }

    if (log.isWarnEnabled())
    {
        auto_ptr<char> temp(XMLString::transcode(m_name));
        auto_ptr<char> temp2(XMLString::transcode(n->getNodeValue()));
        log.warn("%sattribute %s value {%s} could not be validated by AAP, rejecting it",
                 (bSimple ? "" : "complex "),temp.get(),temp2.get());
    }
    return false;
}
