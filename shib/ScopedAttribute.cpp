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


/* ScopedAttribute.cpp - eduPerson scoped attribute base class

   Scott Cantor
   6/4/02

   $History:$
*/

#include "internal.h"
#include <xercesc/util/regx/RegularExpression.hpp>
#include <log4cpp/Category.hh>

using namespace shibboleth;
using namespace saml;
using namespace log4cpp;
using namespace std;


ScopedAttribute::ScopedAttribute(const XMLCh* name, const XMLCh* ns, long lifetime,
                                 const saml::Iterator<const XMLCh*>& scopes,
                                 const saml::Iterator<const XMLCh*>& values)
    : SimpleAttribute(name,ns,lifetime,values)
{
    if (scopes.size()!=values.size())
        throw MalformedException(SAMLException::RESPONDER,"ScopedAttribute() requires the number of scopes to equal the number of values");

    while (scopes.hasNext())
        m_values.push_back(scopes.next());
}

ScopedAttribute::ScopedAttribute(DOMElement* e) : SimpleAttribute(e) {}

ScopedAttribute::~ScopedAttribute() {}

bool ScopedAttribute::addValue(DOMElement* e)
{
    static XMLCh empty[] = {chNull};
    if (SAMLAttribute::addValue(e))
    {
        DOMAttr* scope=e->getAttributeNodeNS(NULL,Scope);
        m_scopes.push_back(scope ? scope->getNodeValue() : empty);
        return true;
    }
    return false;
}

bool ScopedAttribute::accept(DOMElement* e) const
{
    if (!SimpleAttribute::accept(e))
        return false;

    OriginSiteMapper mapper(m_originSite.c_str());
    Iterator<pair<xstring,bool> > domains=
        (mapper.fail()) ? Iterator<pair<xstring,bool> >() : mapper->getSecurityDomains(m_originSite.c_str());
    const XMLCh* this_scope=NULL;
    DOMAttr* scope=e->getAttributeNodeNS(NULL,Scope);
    if (scope)
        this_scope=scope->getNodeValue();
    if (!this_scope || !*this_scope)
        this_scope=m_originSite.c_str();

    while (domains.hasNext())
    {
        const pair<xstring,bool>& p=domains.next();
        if (p.second)
        {
            try
            {
                RegularExpression re(p.first.c_str());
                if (re.matches(this_scope))
                    return true;
            }
            catch (XMLException& ex)
            {
                auto_ptr<char> tmp(XMLString::transcode(ex.getMessage()));
                NDC ndc("accept");
                Category& log=Category::getInstance(SHIB_LOGCAT".ScopedAttribute");
                log.errorStream() << "caught exception while parsing regular expression: " << tmp.get()
                    << CategoryStream::ENDLINE;
                return false;
            }
        }
        else if (p.first==this_scope)
            return true;
    }

    NDC ndc("accept");
    Category& log=Category::getInstance(SHIB_LOGCAT".ScopedAttribute");
    if (log.isWarnEnabled())
    {
        auto_ptr<char> tmp(toUTF8(this_scope));
        log.warn("rejecting value with scope of %s",tmp.get());
    }
    return false;
}

Iterator<xstring> ScopedAttribute::getValues() const
{
    if (m_scopedValues.empty())
    {
        vector<xstring>::const_iterator j=m_scopes.begin();
        for (vector<xstring>::const_iterator i=m_values.begin(); i!=m_values.end(); i++, j++)
            m_scopedValues.push_back((*i) + chAt + (!j->empty() ? (*j) : m_originSite));
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
            auto_ptr<char> temp(toUTF8(i->c_str()));
            if (temp.get())
                m_sbValues.push_back(temp.get());
        }
    }
    return Iterator<string>(m_sbValues);
}

SAMLObject* ScopedAttribute::clone() const
{
    ScopedAttribute* dest=new ScopedAttribute(m_name,m_namespace,m_lifetime);
    dest->m_values.assign(m_values.begin(),m_values.end());
    dest->m_scopes.assign(m_scopes.begin(),m_scopes.end());
    return dest;
}

DOMNode* ScopedAttribute::toDOM(DOMDocument* doc,bool xmlns) const
{
    SimpleAttribute::toDOM(doc,xmlns);

    int i=0;
    DOMNode* n=m_root->getFirstChild();
    while (n)
    {
        if (n->getNodeType()==DOMNode::ELEMENT_NODE)
        {
            static_cast<DOMElement*>(n)->setAttributeNS(NULL,Scope,
                (!m_scopes[i].empty() ? m_scopes[i].c_str() : m_originSite.c_str()));
            i++;
        }
        n=n->getNextSibling();
    }

    return m_root;
}

const XMLCh ScopedAttribute::Scope[] = { chLatin_S, chLatin_c, chLatin_o, chLatin_p, chLatin_e, chNull };
