/*
 *  Copyright 2001-2007 Internet2
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

/**
 * DOMPropertySet.cpp
 * 
 * DOM-based property set implementation.
 */

#include "internal.h"
#include "util/DOMPropertySet.h"

#include <algorithm>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/XMLConstants.h>

using namespace shibsp;
using namespace xmltooling;
using namespace log4cpp;
using namespace xercesc;
using namespace std;

DOMPropertySet::~DOMPropertySet()
{
    for (map<string,pair<char*,const XMLCh*> >::iterator i=m_map.begin(); i!=m_map.end(); i++)
        XMLString::release(&(i->second.first));
    for_each(m_nested.begin(),m_nested.end(),cleanup_pair<string,DOMPropertySet>());
}

void DOMPropertySet::load(
    const DOMElement* e,
    Category& log,
    DOMNodeFilter* filter,
    const std::map<std::string,std::string>* remapper
    )
{
#ifdef _DEBUG
    NDC ndc("load");
#endif
    m_root=e;

    // Process each attribute as a property.
    DOMNamedNodeMap* attrs=m_root->getAttributes();
    for (XMLSize_t i=0; i<attrs->getLength(); i++) {
        DOMNode* a=attrs->item(i);
        if (!XMLString::compareString(a->getNamespaceURI(),xmlconstants::XMLNS_NS))
            continue;
        char* val=XMLString::transcode(a->getNodeValue());
        if (val && *val) {
            auto_ptr_char ns(a->getNamespaceURI());
            auto_ptr_char name(a->getLocalName());
            const char* realname=name.get();
            map<string,string>::const_iterator remap;
            if (remapper) {
                remap=remapper->find(realname);
                if (remap!=remapper->end()) {
                    log.warn("remapping property (%s) to (%s)",realname,remap->second.c_str());
                    realname=remap->second.c_str();
                }
            }
            if (ns.get()) {
                remap=remapper->find(ns.get());
                if (remap!=remapper->end())
                    m_map[string("{") + remap->second.c_str() + '}' + realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                else
                    m_map[string("{") + ns.get() + '}' + realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log.debug("added property {%s}%s (%s)",ns.get(),realname,val);
            }
            else {
                m_map[realname]=pair<char*,const XMLCh*>(val,a->getNodeValue());
                log.debug("added property %s (%s)",realname,val);
            }
        }
    }
    
    // Process non-excluded elements as nested sets.
    DOMTreeWalker* walker=
        static_cast<DOMDocumentTraversal*>(
            m_root->getOwnerDocument())->createTreeWalker(const_cast<DOMElement*>(m_root),DOMNodeFilter::SHOW_ELEMENT,filter,false
            );
    e=static_cast<DOMElement*>(walker->firstChild());
    while (e) {
        auto_ptr_char ns(e->getNamespaceURI());
        auto_ptr_char name(e->getLocalName());
        const char* realname=name.get();
        map<string,string>::const_iterator remap;
        if (remapper) {
            remap=remapper->find(realname);
            if (remap!=remapper->end()) {
                log.warn("remapping property set (%s) to (%s)",realname,remap->second.c_str());
                realname=remap->second.c_str();
            }
        }
        string key;
        if (ns.get()) {
            remap=remapper->find(ns.get());
            if (remap!=remapper->end())
                key=string("{") + remap->second.c_str() + '}' + realname;
            else
                key=string("{") + ns.get() + '}' + realname;
        }
        else
            key=realname;
        if (m_nested.find(key)!=m_nested.end())
            log.warn("load() skipping duplicate property set: %s",key.c_str());
        else {
            DOMPropertySet* set=new DOMPropertySet();
            set->load(e,log,filter,remapper);
            m_nested[key]=set;
            log.debug("added nested property set: %s",key.c_str());
        }
        e=static_cast<DOMElement*>(walker->nextSibling());
    }
    walker->release();
}

pair<bool,bool> DOMPropertySet::getBool(const char* name, const char* ns) const
{
    pair<bool,bool> ret(false,false);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=(!strcmp(i->second.first,"true") || !strcmp(i->second.first,"1"));
    }
    return ret;
}

pair<bool,const char*> DOMPropertySet::getString(const char* name, const char* ns) const
{
    pair<bool,const char*> ret(false,NULL);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=i->second.first;
    }
    return ret;
}

pair<bool,const XMLCh*> DOMPropertySet::getXMLString(const char* name, const char* ns) const
{
    pair<bool,const XMLCh*> ret(false,NULL);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=i->second.second;
    }
    return ret;
}

pair<bool,unsigned int> DOMPropertySet::getUnsignedInt(const char* name, const char* ns) const
{
    pair<bool,unsigned int> ret(false,0);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=strtol(i->second.first,NULL,10);
    }
    return ret;
}

pair<bool,int> DOMPropertySet::getInt(const char* name, const char* ns) const
{
    pair<bool,int> ret(false,0);
    map<string,pair<char*,const XMLCh*> >::const_iterator i;

    if (ns)
        i=m_map.find(string("{") + ns + '}' + name);
    else
        i=m_map.find(name);

    if (i!=m_map.end()) {
        ret.first=true;
        ret.second=atoi(i->second.first);
    }
    return ret;
}

const PropertySet* DOMPropertySet::getPropertySet(const char* name, const char* ns) const
{
    map<string,DOMPropertySet*>::const_iterator i;

    if (ns)
        i=m_nested.find(string("{") + ns + '}' + name);
    else
        i=m_nested.find(name);

    return (i!=m_nested.end()) ? i->second : NULL;
}
