/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * DOMPropertySet.cpp
 * 
 * DOM-based property set implementation.
 */

#include "internal.h"
#include "util/DOMPropertySet.h"

#include <algorithm>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

PropertySet::PropertySet()
{
}

PropertySet::~PropertySet()
{
}

DOMPropertySet::Remapper::Remapper()
{
}

DOMPropertySet::Remapper::~Remapper()
{
}

DOMPropertySet::STLRemapper::STLRemapper(const std::map<std::string, std::string>& rules) : m_rules(rules)
{
}

DOMPropertySet::STLRemapper::~STLRemapper()
{
}

const char* DOMPropertySet::STLRemapper::remap(const char* src, xmltooling::logging::Category& log) const
{
    map<string,string>::const_iterator i = src ? m_rules.find(src) : m_rules.end();
    if (i != m_rules.end()) {
        log.info("DEPRECATED: legacy configuration, remapping property/set (%s) to (%s)", src, i->second.c_str());
        return i->second.c_str();
    }
    else {
        return src;
    }
}

DOMPropertySet::DOMPropertySet() : m_parent(nullptr), m_root(nullptr)
{
}

DOMPropertySet::~DOMPropertySet()
{
    for (map<string,pair<char*,const XMLCh*> >::iterator i = m_map.begin(); i != m_map.end(); ++i)
        XMLString::release(&(i->second.first));
}

const PropertySet* DOMPropertySet::getParent() const
{
    return m_parent;
}

void DOMPropertySet::setParent(const PropertySet* parent)
{
    m_parent = parent;
}

const DOMElement* DOMPropertySet::getElement() const
{
    return m_root;
}

void DOMPropertySet::load(
    const DOMElement* e,
    Category* log,
    DOMNodeFilter* filter,
    const Remapper* remapper,
    const xmltooling::QName* unsetter
    )
{
#ifdef _DEBUG
    NDC ndc("load");
#endif
    if (!e)
        return;
    m_root=e;
    if (!log)
        log = &Category::getInstance(SHIBSP_LOGCAT ".PropertySet");

    // Process each attribute as a property.
    DOMNamedNodeMap* attrs=m_root->getAttributes();
    for (XMLSize_t i=0; i<attrs->getLength(); i++) {
        DOMNode* a=attrs->item(i);
        if (!XMLString::compareString(a->getNamespaceURI(), xmlconstants::XMLNS_NS)) {
            continue;
        }
        else if (unsetter && XMLHelper::isNodeNamed(a, unsetter->getNamespaceURI(), unsetter->getLocalPart())) {
            auto_ptr_char val(a->getNodeValue());
            string dup(val.get());
            split(m_unset, dup, is_space(), algorithm::token_compress_on);
            continue;
        }

        char* val=XMLString::transcode(a->getNodeValue());
        if (val && *val) {
            auto_ptr_char ns(a->getNamespaceURI());
            auto_ptr_char name(a->getLocalName());
            const char* realname=name.get();
            if (remapper) {
                realname = remapper->remap(realname, *log);
            }
            if (ns.get()) {
                const char* realns = ns.get();
                if (remapper) {
                    realns = remapper->remap(realns, *log);
                }
                else if (XMLString::equals(realns, shibspconstants::ASCII_SHIB2SPCONFIG_NS)) {
                    realns = shibspconstants::ASCII_SHIB3SPCONFIG_NS;
                }
                m_map[string("{") + realns + '}' + realname] = pair<char*, const XMLCh*>(val, a->getNodeValue());
                log->debug("added property {%s}%s (%s)", realns, realname, val);
            }
            else {
                m_map[realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log->debug("added property %s (%s)", realname, val);
            }
        }
    }
    
    // Process non-excluded elements as nested sets.
    DOMTreeWalker* walker =
        static_cast<DOMDocumentTraversal*>(
            m_root->getOwnerDocument())->createTreeWalker(const_cast<DOMElement*>(m_root),DOMNodeFilter::SHOW_ELEMENT,filter,false
            );
    e = static_cast<DOMElement*>(walker->firstChild());
    while (e) {
        auto_ptr_char ns(e->getNamespaceURI());
        auto_ptr_char name(e->getLocalName());
        const char* realname=name.get();
        if (remapper) {
            realname = remapper->remap(realname, *log);
        }
        string key;
        if (ns.get()) {
            const char* realns = ns.get();
            if (remapper) {
                realns = remapper->remap(realns, *log);
            }
            else if (XMLString::equals(realns, shibspconstants::ASCII_SHIB2SPCONFIG_NS)) {
                realns = shibspconstants::ASCII_SHIB3SPCONFIG_NS;
            }
            key = string("{") + realns + '}' + realname;
        }
        else {
            key = realname;
        }
        if (m_nested.find(key) != m_nested.end())
            log->warn("load() skipping duplicate property set: %s", key.c_str());
        else {
            boost::shared_ptr<DOMPropertySet> newset(new DOMPropertySet());
            newset->load(e,log,filter,remapper);
            m_nested[key] = newset;
            log->debug("added nested property set: %s", key.c_str());
        }
        e = static_cast<DOMElement*>(walker->nextSibling());
    }
    walker->release();
}

pair<bool,bool> DOMPropertySet::getBool(const char* name, const char* ns) const
{
    map< string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);


    if (i!=m_map.end())
        return make_pair(true,(!strcmp(i->second.first,"true") || !strcmp(i->second.first,"1")));
    else if (m_parent && m_unset.find(ns ? (string("{") + ns + '}' + name) : name) == m_unset.end()) {
        return m_parent->getBool(name, ns);
    }
    return make_pair(false,false);
}

pair<bool,const char*> DOMPropertySet::getString(const char* name, const char* ns) const
{
    map< string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return pair<bool,const char*>(true,i->second.first);
    else if (m_parent && m_unset.find(ns ? (string("{") + ns + '}' + name) : name) == m_unset.end())
        return m_parent->getString(name,ns);
    return pair<bool,const char*>(false,nullptr);
}

pair<bool,const XMLCh*> DOMPropertySet::getXMLString(const char* name, const char* ns) const
{
    map< string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return make_pair(true,i->second.second);
    else if (m_parent && m_unset.find(ns ? (string("{") + ns + '}' + name) : name) == m_unset.end())
        return m_parent->getXMLString(name,ns);
    return pair<bool,const XMLCh*>(false,nullptr);
}

pair<bool,unsigned int> DOMPropertySet::getUnsignedInt(const char* name, const char* ns) const
{
    map< string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        try {
            return pair<bool,unsigned int>(true,lexical_cast<unsigned int>(i->second.first));
        }
        catch (bad_lexical_cast&) {
            return pair<bool,unsigned int>(false,0);
        }
    }
    else if (m_parent && m_unset.find(ns ? (string("{") + ns + '}' + name) : name) == m_unset.end())
        return m_parent->getUnsignedInt(name,ns);
    return pair<bool,unsigned int>(false,0);
}

pair<bool,int> DOMPropertySet::getInt(const char* name, const char* ns) const
{
    map< string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end())
        return pair<bool,int>(true,atoi(i->second.first));
    else if (m_parent && m_unset.find(ns ? (string("{") + ns + '}' + name) : name) == m_unset.end())
        return m_parent->getInt(name,ns);
    return pair<bool,int>(false,0);
}

const PropertySet* DOMPropertySet::getPropertySet(const char* name, const char* ns) const
{
    map< string,boost::shared_ptr<DOMPropertySet> >::const_iterator i;

    if (ns)
        i = m_nested.find(string("{") + ns + '}' + name);
    else
        i = m_nested.find(name);

    return (i != m_nested.end()) ? i->second.get() : (m_parent ? m_parent->getPropertySet(name,ns) : nullptr);
}

bool DOMPropertySet::setProperty(const char* name, const char* val, const char* ns)
{
    string propname = ns ? (string("{") + ns + "}" + name) : name;

    // Erase existing property.
    if (m_map.count(propname) > 0) {
        XMLString::release(&m_map[propname].first);
        m_map.erase(propname);
    }

    char* dup = XMLString::replicate(val);
    auto_ptr_XMLCh widedup(val);
    m_injected.push_back(widedup.get());
    m_map[propname] = make_pair(dup, m_injected.back().c_str());

    return true;
}
