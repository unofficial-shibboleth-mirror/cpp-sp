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
 * GSSAPIAttributeExtractor.cpp
 *
 * AttributeExtractor for a base64-encoded GSS-API context or name.
 */

#include "internal.h"

#ifdef HAVE_GSSAPI_NAMINGEXTS

#include <shibsp/exceptions.h>
#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/attribute/BinaryAttribute.h>
#include <shibsp/attribute/ScopedAttribute.h>
#include <shibsp/attribute/SimpleAttribute.h>
#include <shibsp/attribute/resolver/AttributeExtractor.h>
#include <shibsp/remoting/ddf.h>
#include <shibsp/util/SPConstants.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/unicode.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <boost/algorithm/string.hpp>

#ifdef SHIBSP_HAVE_GSSGNU
# include <gss.h>
#elif defined SHIBSP_HAVE_GSSMIT
# include <gssapi/gssapi_ext.h>
#else
# include <gssapi.h>
#endif


using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class GSSAPIExtractorImpl
    {
    public:
        GSSAPIExtractorImpl(const DOMElement* e, Category& log);
        ~GSSAPIExtractorImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void extractAttributes(gss_name_t initiatorName, vector<Attribute*>& attributes) const;
        void extractAttributes(gss_name_t initiatorName, gss_buffer_t namingAttribute, vector<Attribute*>& attributes) const;

        void getAttributeIds(vector<string>& attributes) const {
            attributes.insert(attributes.end(), m_attributeIds.begin(), m_attributeIds.end());
        }

    private:
        struct Rule {
            Rule() : authenticated(true), binary(false), scopeDelimiter(0) {}
            vector<string> ids;
            bool authenticated,binary;
            char scopeDelimiter;
        };

        Category& m_log;
        DOMDocument* m_document;
        map<string,Rule> m_attrMap;
        vector<string> m_attributeIds;
    };

    class GSSAPIExtractor : public AttributeExtractor, public ReloadableXMLFile
    {
    public:
        GSSAPIExtractor(const DOMElement* e)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor.GSSAPI")) {
            background_load();
        }
        ~GSSAPIExtractor() {
            shutdown();
        }

        void extractAttributes(
            const Application& application,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            if (m_impl)
                m_impl->getAttributeIds(attributes);
        }

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        scoped_ptr<GSSAPIExtractorImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* GSSAPIExtractorFactory(const DOMElement* const & e)
    {
        return new GSSAPIExtractor(e);
    }

    static const XMLCh _aliases[] =             UNICODE_LITERAL_7(a,l,i,a,s,e,s);
    static const XMLCh Attributes[] =           UNICODE_LITERAL_10(A,t,t,r,i,b,u,t,e,s);
    static const XMLCh _authenticated[] =       UNICODE_LITERAL_13(a,u,t,h,e,n,t,i,c,a,t,e,d);
    static const XMLCh _binary[] =              UNICODE_LITERAL_6(b,i,n,a,r,y);
    static const XMLCh GSSAPIAttribute[] =      UNICODE_LITERAL_15(G,S,S,A,P,I,A,t,t,r,i,b,u,t,e);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _name[] =                UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh _scopeDelimiter[] =      UNICODE_LITERAL_14(s,c,o,p,e,D,e,l,i,m,i,t,e,r);
};

GSSAPIExtractorImpl::GSSAPIExtractorImpl(const DOMElement* e, Category& log)
    : m_log(log), m_document(nullptr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("GSSAPIExtractorImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, Attributes))
        throw ConfigurationException("GSSAPI AttributeExtractor requires am:Attributes at root of configuration.");

    DOMElement* child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
    while (child) {
        // Check for missing name or id.
        const XMLCh* name = child->getAttributeNS(nullptr, _name);
        if (!name || !*name) {
            m_log.warn("skipping GSSAPIAttribute with no name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
            continue;
        }

        auto_ptr_char id(child->getAttributeNS(nullptr, _id));
        if (!id.get() || !*id.get()) {
            m_log.warn("skipping GSSAPIAttribute with no id");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
            continue;
        }
        else if (!strcmp(id.get(), "REMOTE_USER")) {
            m_log.warn("skipping GSSAPIAttribute, id of REMOTE_USER is a reserved name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
            continue;
        }

        // Fetch/create the map entry and see if it's a duplicate rule.
        auto_ptr_char attrname(name);
        Rule& decl = m_attrMap[attrname.get()];
        if (!decl.ids.empty()) {
            m_log.warn("skipping duplicate GSS-API Attribute mapping (same name)");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
            continue;
        }

        m_log.info("creating mapping for GSS-API Attribute %s", attrname.get());

        decl.ids.push_back(id.get());
        m_attributeIds.push_back(id.get());

        name = child->getAttributeNS(nullptr, _aliases);
        if (name && *name) {
            auto_ptr_char aliases(name);
            string dup(aliases.get());
            set<string> new_aliases;
            split(new_aliases, dup, is_space(), algorithm::token_compress_on);
            set<string>::iterator ru = new_aliases.find("REMOTE_USER");
            if (ru != new_aliases.end()) {
                m_log.warn("skipping alias, REMOTE_USER is a reserved name");
                new_aliases.erase(ru);
            }
            m_attributeIds.insert(m_attributeIds.end(), new_aliases.begin(), new_aliases.end());
        }

        decl.authenticated = XMLHelper::getAttrBool(child, true, _authenticated);
        decl.binary = XMLHelper::getAttrBool(child, false, _binary);
        string delim = XMLHelper::getAttrString(child, "", _scopeDelimiter);
        if (!delim.empty())
            decl.scopeDelimiter = delim[0];

        child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, GSSAPIAttribute);
    }
}

void GSSAPIExtractorImpl::extractAttributes(gss_name_t initiatorName, vector<Attribute*>& attributes) const
{
    OM_uint32 minor;
    gss_buffer_set_t attrnames = GSS_C_NO_BUFFER_SET;
    OM_uint32 major = gss_inquire_name(&minor, initiatorName, nullptr, nullptr, &attrnames);
    if (major == GSS_S_COMPLETE) {
        for (size_t i = 0; i < attrnames->count; ++i) {
            extractAttributes(initiatorName, &attrnames->elements[i], attributes);
        }
        gss_release_buffer_set(&minor, &attrnames);
    }
    else {
        m_log.warn("unable to extract attributes, GSS name attribute inquiry failed (%u:%u)", major, minor);
    }
}

void GSSAPIExtractorImpl::extractAttributes(
    gss_name_t initiatorName, gss_buffer_t namingAttribute, vector<Attribute*>& attributes
    ) const
{
    // First we have to determine if this GSS attribute is something we recognize.
    string attrname(reinterpret_cast<char*>(namingAttribute->value), namingAttribute->length);
    map<string,Rule>::const_iterator rule = m_attrMap.find(attrname);
    if (rule == m_attrMap.end()) {
        m_log.info("skipping unmapped GSS-API attribute: %s", attrname.c_str());
        return;
    }

    vector<string> values;

    OM_uint32 major,minor;
    int authenticated=-1,more=-1;
    do {
        gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
        major = gss_get_name_attribute(
            &minor, initiatorName, namingAttribute, &authenticated, nullptr, &buf, nullptr, &more
            );
        if (major == GSS_S_COMPLETE) {
            if (rule->second.authenticated && !authenticated) {
                m_log.warn("skipping unauthenticated GSS-API attribute: %s", attrname.c_str());
                gss_release_buffer(&minor, &buf);
                return;
            }
            if (buf.length) {
                values.push_back(string(reinterpret_cast<char*>(buf.value), buf.length));
            }
            gss_release_buffer(&minor, &buf);
        }
        else {
            m_log.warn("error obtaining values for GSS-API attribute (%s): %u:%u", attrname.c_str(), major, minor);
        }
    } while (major == GSS_S_COMPLETE && more);

    if (values.empty())
        return;

    if (rule->second.scopeDelimiter && !rule->second.binary) {
        auto_ptr<ScopedAttribute> scoped(new ScopedAttribute(rule->second.ids, rule->second.scopeDelimiter));
        vector< pair<string,string> >& dest = scoped->getValues();
        for (vector<string>::const_iterator v = values.begin(); v != values.end(); ++v) {
            const char* value = v->c_str();
            const char* scope = strchr(value, rule->second.scopeDelimiter);
            if (scope) {
                if (*(scope+1))
                    dest.push_back(pair<string,string>(v->substr(0, scope-value), scope + 1));
                else
                    m_log.warn("ignoring unscoped value");
            }
            else {
                m_log.warn("ignoring unscoped value");
            }
        }
        if (!scoped->getValues().empty()) {
            attributes.push_back(scoped.get());
            scoped.release();
        }
    }
    else if (rule->second.binary) {
        auto_ptr<BinaryAttribute> binary(new BinaryAttribute(rule->second.ids));
        binary->getValues() = values;
        attributes.push_back(binary.get());
        binary.release();
    }
    else {
        auto_ptr<SimpleAttribute> simple(new SimpleAttribute(rule->second.ids));
        simple->getValues() = values;
        attributes.push_back(simple.get());
        simple.release();
    }
}

void GSSAPIExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    if (!m_impl)
        return;

    static const XMLCh _GSSAPIContext[] = UNICODE_LITERAL_13(G,S,S,A,P,I,C,o,n,t,e,x,t);
    static const XMLCh _GSSAPIName[] = UNICODE_LITERAL_10(G,S,S,A,P,I,N,a,m,e);

    if (!XMLString::equals(xmlObject.getElementQName().getLocalPart(), _GSSAPIContext)
           && !XMLString::equals(xmlObject.getElementQName().getLocalPart(), _GSSAPIName)
        ) {
        m_log.debug("unable to extract attributes, unknown XML object type: %s", xmlObject.getElementQName().toString().c_str());
        return;
    }

    const XMLCh* encodedWide = xmlObject.getTextContent();
    if (!encodedWide || !*encodedWide) {
        m_log.warn("unable to extract attributes, GSSAPI element had no text content");
        return;
    }

    xsecsize_t x;
    OM_uint32 major,minor;
    auto_ptr_char encoded(encodedWide);

    gss_name_t srcname;
    gss_ctx_id_t gss = GSS_C_NO_CONTEXT;

    XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(encoded.get()), &x);
    if (decoded) {
        gss_buffer_desc importbuf;
        importbuf.length = x;
        importbuf.value = decoded;
        if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), _GSSAPIName)) {
#ifdef HAVE_GSSAPI_COMPOSITE_NAME
            major = gss_import_name(&minor, &importbuf, GSS_C_NT_EXPORT_NAME_COMPOSITE, &srcname);
#else
            major = gss_import_name(&minor, &importbuf, GSS_C_NT_EXPORT_NAME, &srcname);
#endif
            if (major == GSS_S_COMPLETE) {
                m_impl->extractAttributes(srcname, attributes);
                gss_release_name(&minor, &srcname);
            }
            else {
                m_log.warn("unable to extract attributes, GSS name import failed (%u:%u)", major, minor);
            }
            // We fall through here down to the GSS context check, which will exit us.
        }
        else {
            major = gss_import_sec_context(&minor, &importbuf, &gss);
            if (major != GSS_S_COMPLETE) {
                m_log.warn("unable to extract attributes, GSS context import failed (%u:%u)", major, minor);
                gss = GSS_C_NO_CONTEXT;
            }
        }
#ifdef SHIBSP_XERCESC_HAS_XMLBYTE_RELEASE
        XMLString::release(&decoded);
#else
        XMLString::release((char**)&decoded);
#endif
    }
    else {
        m_log.warn("unable to extract attributes, base64 decode of GSSAPI context or name failed");
    }

    if (gss == GSS_C_NO_CONTEXT) {
        return;
    }

    // Extract the initiator name from the context.
    major = gss_inquire_context(&minor, gss, &srcname, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (major == GSS_S_COMPLETE) {
        m_impl->extractAttributes(srcname, attributes);
        gss_release_name(&minor, &srcname);
    }
    else {
        m_log.warn("unable to extract attributes, GSS initiator name extraction failed (%u:%u)", major, minor);
    }

    gss_delete_sec_context(&minor, &gss, GSS_C_NO_BUFFER);
}

pair<bool,DOMElement*> GSSAPIExtractor::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<GSSAPIExtractorImpl> impl(new GSSAPIExtractorImpl(raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}

#endif
