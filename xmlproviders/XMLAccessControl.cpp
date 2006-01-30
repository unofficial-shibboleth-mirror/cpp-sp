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

/* XMLAccessControl.cpp - an XML-based access control syntax

   Scott Cantor
   10/25/05
*/

#include "internal.h"

#include <algorithm>

#include <shib-target/shib-target.h>
#include <log4cpp/Category.hh>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace std;
using namespace log4cpp;

namespace {
    struct IAuthz {
        virtual ~IAuthz() {}
        virtual bool authorized(ShibTarget* st, ISessionCacheEntry* entry) const=0;
    };
    
    class Rule : public IAuthz
    {
    public:
        Rule(const DOMElement* e);
        ~Rule() {}
        bool authorized(ShibTarget* st, ISessionCacheEntry* entry) const;
    
    private:
        string m_alias;
        vector <string> m_vals;
    };
    
    class Operator : public IAuthz
    {
    public:
        Operator(const DOMElement* e);
        ~Operator();
        bool authorized(ShibTarget* st, ISessionCacheEntry* entry) const;
        
    private:
        enum operator_t { OP_NOT, OP_AND, OP_OR } m_op;
        vector<IAuthz*> m_operands;
    };

    class XMLAccessControlImpl : public ReloadableXMLFileImpl
    {
    public:
        XMLAccessControlImpl(const char* pathname) : ReloadableXMLFileImpl(pathname) { init(); }
        XMLAccessControlImpl(const DOMElement* e) : ReloadableXMLFileImpl(e) { init(); }
        void init();
        ~XMLAccessControlImpl() {delete m_rootAuthz;}
        
        IAuthz* m_rootAuthz;
    };

    class XMLAccessControl : public IAccessControl, public ReloadableXMLFile
    {
    public:
        XMLAccessControl(const DOMElement* e) : ReloadableXMLFile(e) {}
        ~XMLAccessControl() {}

        virtual bool authorized(ShibTarget* st, ISessionCacheEntry* entry) const;

    protected:
        virtual ReloadableXMLFileImpl* newImplementation(const char* pathname, bool first=true) const;
        virtual ReloadableXMLFileImpl* newImplementation(const DOMElement* e, bool first=true) const;
    };
}

IPlugIn* XMLAccessControlFactory(const DOMElement* e)
{
    auto_ptr<XMLAccessControl> a(new XMLAccessControl(e));
    a->getImplementation();
    return a.release();
}

Rule::Rule(const DOMElement* e)
{
    auto_ptr_char req(e->getAttributeNS(NULL,SHIB_L(require)));
    if (!req.get() || !*req.get())
        throw MalformedException("Access control rule missing require attribute");
    m_alias=req.get();
    
    auto_ptr_char vals(e->hasChildNodes() ? e->getFirstChild()->getNodeValue() : NULL);
#ifdef HAVE_STRTOK_R
    char* pos=NULL;
    const char* token=strtok_r(const_cast<char*>(vals.get()),"/",&pos);
#else
    const char* token=strtok(const_cast<char*>(vals.get()),"/");
#endif
    while (token) {
        m_vals.push_back(token);
#ifdef HAVE_STRTOK_R
        token=strtok_r(NULL,"/",&pos);
#else
        token=strtok(NULL,"/");
#endif
    }
}

bool Rule::authorized(ShibTarget* st, ISessionCacheEntry* entry) const
{
    // Map alias in rule to the attribute.
    Iterator<IAAP*> provs=st->getApplication()->getAAPProviders();
    AAP wrapper(provs,m_alias.c_str());
    if (wrapper.fail()) {
        st->log(ShibTarget::LogLevelWarn, string("AccessControl plugin didn't recognize rule (") + m_alias + "), check AAP for corresponding Alias");
        return false;
    }
    else if (!entry) {
        st->log(ShibTarget::LogLevelWarn, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return false;
    }
    
    // Find the corresponding attribute. This isn't very efficient...
    pair<const char*,const SAMLResponse*> filtered=entry->getFilteredTokens(false,true);
    Iterator<SAMLAssertion*> a_iter(filtered.second ? filtered.second->getAssertions() : EMPTY(SAMLAssertion*));
    while (a_iter.hasNext()) {
        SAMLAssertion* assert=a_iter.next();
        Iterator<SAMLStatement*> statements=assert->getStatements();
        while (statements.hasNext()) {
            SAMLAttributeStatement* astate=dynamic_cast<SAMLAttributeStatement*>(statements.next());
            if (!astate)
                continue;
            Iterator<SAMLAttribute*> attrs=astate->getAttributes();
            while (attrs.hasNext()) {
                SAMLAttribute* attr=attrs.next();
                if (!XMLString::compareString(attr->getName(),wrapper->getName()) &&
                    !XMLString::compareString(attr->getNamespace(),wrapper->getNamespace())) {
                    // Now we have to intersect the attribute's values against the rule's list.
                    Iterator<string> vals=attr->getSingleByteValues();
                    if (!vals.hasNext())
                        return false;
                    for (vector<string>::const_iterator ival=m_vals.begin(); ival!=m_vals.end(); ival++) {
                        vals.reset();
                        while (vals.hasNext()) {
                            const string& v=vals.next();
                            if ((wrapper->getCaseSensitive() && v == *ival) || (!wrapper->getCaseSensitive() && !strcasecmp(v.c_str(),ival->c_str()))) {
                                st->log(ShibTarget::LogLevelDebug, string("XMLAccessControl plugin expecting " + *ival + ", authz granted"));
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

Operator::Operator(const DOMElement* e)
{
    if (saml::XML::isElementNamed(e,shibtarget::XML::SHIBTARGET_NS,SHIB_L(NOT)))
        m_op=OP_NOT;
    else if (saml::XML::isElementNamed(e,shibtarget::XML::SHIBTARGET_NS,SHIB_L(AND)))
        m_op=OP_AND;
    else if (saml::XML::isElementNamed(e,shibtarget::XML::SHIBTARGET_NS,SHIB_L(OR)))
        m_op=OP_OR;
    else
        throw MalformedException("Unrecognized operator in access control rule");
    
    try {
        e=saml::XML::getFirstChildElement(e);
        if (saml::XML::isElementNamed(e,shibtarget::XML::SHIBTARGET_NS,SHIB_L(Rule)))
            m_operands.push_back(new Rule(e));
        else
            m_operands.push_back(new Operator(e));
        
        if (m_op==OP_NOT)
            return;
        
        e=saml::XML::getNextSiblingElement(e);
        while (e) {
            if (saml::XML::isElementNamed(e,shibtarget::XML::SHIBTARGET_NS,SHIB_L(Rule)))
                m_operands.push_back(new Rule(e));
            else
                m_operands.push_back(new Operator(e));
            e=saml::XML::getNextSiblingElement(e);
        }
    }
    catch (SAMLException&) {
        this->~Operator();
        throw;
    }
}

Operator::~Operator()
{
    for_each(m_operands.begin(),m_operands.end(),shibtarget::cleanup<IAuthz>());
}

bool Operator::authorized(ShibTarget* st, ISessionCacheEntry* entry) const
{
    switch (m_op) {
        case OP_NOT:
            return !m_operands[0]->authorized(st,entry);
        
        case OP_AND:
        {
            for (vector<IAuthz*>::const_iterator i=m_operands.begin(); i!=m_operands.end(); i++) {
                if (!(*i)->authorized(st,entry))
                    return false;
            }
            return true;
        }
        
        case OP_OR:
        {
            for (vector<IAuthz*>::const_iterator i=m_operands.begin(); i!=m_operands.end(); i++) {
                if ((*i)->authorized(st,entry))
                    return true;
            }
            return false;
        }
    }
    st->log(ShibTarget::LogLevelWarn,"Unknown operation in access control policy, denying access");
    return false;
}

void XMLAccessControlImpl::init()
{
#ifdef _DEBUG
    NDC ndc("init");
#endif
    Category* log=&Category::getInstance(XMLPROVIDERS_LOGCAT".AccessControl");

    try {
        // We need to move below the AccessControl root element if the policy is in a separate file.
        // Unlike most of the plugins, an inline policy will end up handing us the first inline
        // content element, and not the outer wrapper.
        const DOMElement* rootElement=ReloadableXMLFileImpl::m_root;
        if (saml::XML::isElementNamed(rootElement,shibtarget::XML::SHIBTARGET_NS,SHIB_L(AccessControl)))
            rootElement = saml::XML::getFirstChildElement(rootElement);
        
        if (saml::XML::isElementNamed(rootElement,shibtarget::XML::SHIBTARGET_NS,SHIB_L(Rule)))
            m_rootAuthz=new Rule(rootElement);
        else
            m_rootAuthz=new Operator(rootElement);
    }
    catch (SAMLException& e) {
        log->errorStream() << "Error while parsing access control configuration: " << e.what() << CategoryStream::ENDLINE;
        throw;
    }
#ifndef _DEBUG
    catch (...)
    {
        log->error("Unexpected error while parsing access control configuration");
        throw;
    }
#endif
}

ReloadableXMLFileImpl* XMLAccessControl::newImplementation(const char* pathname, bool first) const
{
    return new XMLAccessControlImpl(pathname);
}

ReloadableXMLFileImpl* XMLAccessControl::newImplementation(const DOMElement* e, bool first) const
{
    return new XMLAccessControlImpl(e);
}

bool XMLAccessControl::authorized(ShibTarget* st, ISessionCacheEntry* entry) const
{
    return static_cast<XMLAccessControlImpl*>(getImplementation())->m_rootAuthz->authorized(st,entry);
}
