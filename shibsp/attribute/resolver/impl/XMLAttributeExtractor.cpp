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
 * XMLAttributeExtractor.cpp
 *
 * AttributeExtractor based on an XML mapping file.
 */

#include "internal.h"
#include "exceptions.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/BasicFilteringContext.h"
#include "attribute/resolver/AttributeExtractor.h"
#include "remoting/ddf.h"
#include "security/SecurityPolicy.h"
#include "util/SPConstants.h"

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <boost/ptr_container/ptr_vector.hpp>
#include <boost/tuple/tuple.hpp>
#include <saml/SAMLConfig.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/ObservableMetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/TrustEngine.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;
using saml1::NameIdentifier;
using saml2::NameID;
using saml2::EncryptedAttribute;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLExtractorImpl : public ObservableMetadataProvider::Observer
    {
    public:
        XMLExtractorImpl(const DOMElement* e, Category& log);
        ~XMLExtractorImpl() {
            for (map<const ObservableMetadataProvider*,decoded_t>::iterator i=m_decodedMap.begin(); i!=m_decodedMap.end(); ++i) {
                i->first->removeObserver(this);
                for (decoded_t::iterator attrs = i->second.begin(); attrs!=i->second.end(); ++attrs)
                    for_each(attrs->second.begin(), attrs->second.end(), mem_fun_ref<DDF&,DDF>(&DDF::destroy));
            }
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void onEvent(const ObservableMetadataProvider& metadata) const {
            // Destroy attributes we cached from this provider.
            m_attrLock->wrlock();
            SharedLock wrapper(m_attrLock, false);
            decoded_t& d = m_decodedMap[&metadata];
            for (decoded_t::iterator a = d.begin(); a!=d.end(); ++a)
                for_each(a->second.begin(), a->second.end(), mem_fun_ref<DDF&,DDF>(&DDF::destroy));
            d.clear();
        }

        void extractAttributes(const Application&, const char*, const char*, const NameIdentifier&, ptr_vector<Attribute>&) const;
        void extractAttributes(const Application&, const char*, const char*, const NameID&, ptr_vector<Attribute>&) const;
        void extractAttributes(const Application&, const GenericRequest*, const char*, const char*, const saml1::Attribute&, ptr_vector<Attribute>&) const;
        void extractAttributes(const Application&, const GenericRequest*, const char*, const char*, const saml2::Attribute&, ptr_vector<Attribute>&) const;
        void extractAttributes(const Application&, const GenericRequest*, const char*, const char*, const saml1::AttributeStatement&, ptr_vector<Attribute>&) const;
        void extractAttributes(const Application&, const GenericRequest*, const char*, const char*, const saml2::AttributeStatement&, ptr_vector<Attribute>&) const;
        void extractAttributes(
            const Application&, const GenericRequest*, const ObservableMetadataProvider*, const XMLCh*, const char*, const Extensions&, ptr_vector<Attribute>&
            ) const;

        void getAttributeIds(vector<string>& attributes) const {
            attributes.insert(attributes.end(), m_attributeIds.begin(), m_attributeIds.end());
        }

        void generateMetadata(SPSSODescriptor& role) const;

    private:
        Category& m_log;
        DOMDocument* m_document;
        typedef map< pair<xstring,xstring>,pair< boost::shared_ptr<AttributeDecoder>,vector<string> > > attrmap_t;
        attrmap_t m_attrMap;
        vector<string> m_attributeIds;
        vector< tuple<xstring,xstring,bool> > m_requestedAttrs;

        // settings for embedded assertions in metadata
        string m_policyId;
        scoped_ptr<AttributeFilter> m_filter;
        scoped_ptr<MetadataProvider> m_metadata;
        scoped_ptr<TrustEngine> m_trust;
        bool m_entityAssertions,m_metaAttrCaching;

        // manages caching of decoded Attributes
        scoped_ptr<RWLock> m_attrLock;
        typedef map< const EntityAttributes*,vector<DDF> > decoded_t;
        mutable map<const ObservableMetadataProvider*,decoded_t> m_decodedMap;
    };

    class XMLExtractor : public AttributeExtractor, public ReloadableXMLFile
    {
    public:
        XMLExtractor(const DOMElement* e) : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor.XML")) {
            if (m_local && m_lock)
                m_log.warn("attribute mappings are reloadable; be sure to restart web server when adding new attribute IDs");
            background_load();
        }
        ~XMLExtractor() {
            shutdown();
        }

        // deprecated method
        void extractAttributes(
            const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
            ) const {
            extractAttributes(application, nullptr, issuer, xmlObject, attributes);
        }

        void extractAttributes(const Application&, const GenericRequest*, const RoleDescriptor*, const XMLObject&, vector<Attribute*>&) const;

        void getAttributeIds(std::vector<std::string>& attributes) const {
            if (m_impl)
                m_impl->getAttributeIds(attributes);
        }

        void generateMetadata(SPSSODescriptor& role) const {
            if (m_impl)
                m_impl->generateMetadata(role);
        }

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        scoped_ptr<XMLExtractorImpl> m_impl;

        void extractAttributes(const Application&, const GenericRequest*, const RoleDescriptor*, const XMLObject&, ptr_vector<Attribute>&) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL XMLAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new XMLExtractor(e);
    }

    static const XMLCh _aliases[] =                 UNICODE_LITERAL_7(a,l,i,a,s,e,s);
    static const XMLCh _AttributeDecoder[] =        UNICODE_LITERAL_16(A,t,t,r,i,b,u,t,e,D,e,c,o,d,e,r);
    static const XMLCh _AttributeFilter[] =         UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh Attributes[] =               UNICODE_LITERAL_10(A,t,t,r,i,b,u,t,e,s);
    static const XMLCh _id[] =                      UNICODE_LITERAL_2(i,d);
    static const XMLCh isRequested[] =              UNICODE_LITERAL_11(i,s,R,e,q,u,e,s,t,e,d);
    static const XMLCh _MetadataProvider[] =        UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh metadataAttributeCaching[] = UNICODE_LITERAL_24(m,e,t,a,d,a,t,a,A,t,t,r,i,b,u,t,e,C,a,c,h,i,n,g);
    static const XMLCh metadataPolicyId[] =         UNICODE_LITERAL_16(m,e,t,a,d,a,t,a,P,o,l,i,c,y,I,d);
    static const XMLCh _name[] =                    UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh nameFormat[] =               UNICODE_LITERAL_10(n,a,m,e,F,o,r,m,a,t);
    static const XMLCh _TrustEngine[] =             UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                    UNICODE_LITERAL_4(t,y,p,e);
};

XMLExtractorImpl::XMLExtractorImpl(const DOMElement* e, Category& log)
    : m_log(log),
        m_document(nullptr),
        m_policyId(XMLHelper::getAttrString(e, nullptr, metadataPolicyId)),
        m_entityAssertions(true),
        m_metaAttrCaching(XMLHelper::getAttrBool(e, true, metadataAttributeCaching))
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLExtractorImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, Attributes))
        throw ConfigurationException("XML AttributeExtractor requires am:Attributes at root of configuration.");

    DOMElement* child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _MetadataProvider);
    if (child) {
        try {
            string t(XMLHelper::getAttrString(child, nullptr, _type));
            if (t.empty())
                throw ConfigurationException("MetadataProvider element missing type attribute.");
            m_log.info("building MetadataProvider of type %s...", t.c_str());
            m_metadata.reset(SAMLConfig::getConfig().MetadataProviderManager.newPlugin(t.c_str(), child));
            m_metadata->init();
        }
        catch (std::exception& ex) {
            m_metadata.reset();
            m_entityAssertions = false;
            m_log.crit("error building/initializing dedicated MetadataProvider: %s", ex.what());
            m_log.crit("disabling support for Assertions in EntityAttributes extension");
        }
    }

    if (m_entityAssertions) {
        child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _TrustEngine);
        if (child) {
            try {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty())
                    throw ConfigurationException("TrustEngine element missing type attribute.");
                m_log.info("building TrustEngine of type %s...", t.c_str());
                m_trust.reset(XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(t.c_str(), child));
            }
            catch (std::exception& ex) {
                m_entityAssertions = false;
                m_log.crit("error building/initializing dedicated TrustEngine: %s", ex.what());
                m_log.crit("disabling support for Assertions in EntityAttributes extension");
            }
        }
    }

    if (m_entityAssertions) {
        child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _AttributeFilter);
        if (child) {
            try {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty())
                    throw ConfigurationException("AttributeFilter element missing type attribute.");
                m_log.info("building AttributeFilter of type %s...", t.c_str());
                m_filter.reset(SPConfig::getConfig().AttributeFilterManager.newPlugin(t.c_str(), child));
            }
            catch (std::exception& ex) {
                m_entityAssertions = false;
                m_log.crit("error building/initializing dedicated AttributeFilter: %s", ex.what());
                m_log.crit("disabling support for Assertions in EntityAttributes extension");
            }
        }
    }

    child = XMLHelper::getFirstChildElement(e, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
    while (child) {
        // Check for missing name or id.
        const XMLCh* name = child->getAttributeNS(nullptr, _name);
        if (!name || !*name) {
            m_log.warn("skipping Attribute with no name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        auto_ptr_char id(child->getAttributeNS(nullptr, _id));
        if (!id.get() || !*id.get()) {
            m_log.warn("skipping Attribute with no id");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }
        else if (!strcmp(id.get(), "REMOTE_USER")) {
            m_log.warn("skipping Attribute, id of REMOTE_USER is a reserved name");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        boost::shared_ptr<AttributeDecoder> decoder;
        try {
            DOMElement* dchild = XMLHelper::getFirstChildElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, _AttributeDecoder);
            if (dchild) {
                auto_ptr<xmltooling::QName> q(XMLHelper::getXSIType(dchild));
                if (q.get())
                    decoder.reset(SPConfig::getConfig().AttributeDecoderManager.newPlugin(*q.get(), dchild));
            }
            if (!decoder)
                decoder.reset(SPConfig::getConfig().AttributeDecoderManager.newPlugin(StringAttributeDecoderType, nullptr));
        }
        catch (std::exception& ex) {
            m_log.error("skipping Attribute (%s), error building AttributeDecoder: %s", id.get(), ex.what());
        }

        if (!decoder) {
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        // Empty NameFormat implies the usual Shib URI naming defaults.
        const XMLCh* format = child->getAttributeNS(nullptr, nameFormat);
        if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI) ||
                XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
            format = &chNull;  // ignore default Format/Namespace values

        // Fetch/create the map entry and see if it's a duplicate rule.
        pair< boost::shared_ptr<AttributeDecoder>,vector<string> >& decl = m_attrMap[pair<xstring,xstring>(name,format)];
        if (decl.first) {
            m_log.warn("skipping duplicate Attribute mapping (same name and nameFormat)");
            child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
            continue;
        }

        if (m_log.isInfoEnabled()) {
            auto_ptr_char n(name);
            auto_ptr_char f(format);
            m_log.info("creating mapping for Attribute %s%s%s", n.get(), *f.get() ? ", Format/Namespace:" : "", f.get());
        }

        decl.first = decoder;
        decl.second.push_back(id.get());
        m_attributeIds.push_back(id.get());

        // Check for isRequired/isRequested.
        bool requested = XMLHelper::getAttrBool(child, false, isRequested);
        bool required = XMLHelper::getAttrBool(child, false, RequestedAttribute::ISREQUIRED_ATTRIB_NAME);
        if (required || requested)
            m_requestedAttrs.push_back(tuple<xstring,xstring,bool>(name,format,required));

        name = child->getAttributeNS(nullptr, _aliases);
        if (name && *name) {
            m_log.warn("attribute mapping rule (%s) uses deprecated aliases feature, consider revising", id.get());
            auto_ptr_char aliases(name);
            string dup(aliases.get());
            set<string> new_aliases;
            split(new_aliases, dup, is_space(), algorithm::token_compress_on);
            set<string>::iterator ru = new_aliases.find("REMOTE_USER");
            if (ru != new_aliases.end()) {
                m_log.warn("skipping alias, REMOTE_USER is a reserved name");
                new_aliases.erase(ru);
            }
            decl.second.insert(decl.second.end(), new_aliases.begin(), new_aliases.end());
            m_attributeIds.insert(m_attributeIds.end(), new_aliases.begin(), new_aliases.end());
        }

        child = XMLHelper::getNextSiblingElement(child, shibspconstants::SHIB2ATTRIBUTEMAP_NS, saml1::Attribute::LOCAL_NAME);
    }

    if (m_metaAttrCaching)
        m_attrLock.reset(RWLock::create());
}

void XMLExtractorImpl::generateMetadata(SPSSODescriptor& role) const
{
    if (m_requestedAttrs.empty())
        return;
    int index = 1;
    const vector<AttributeConsumingService*>& svcs = const_cast<const SPSSODescriptor*>(&role)->getAttributeConsumingServices();
    for (vector<AttributeConsumingService*>::const_iterator s =svcs.begin(); s != svcs.end(); ++s) {
        pair<bool,int> i = (*s)->getIndex();
        if (i.first && index == i.second)
            index = i.second + 1;
    }
    AttributeConsumingService* svc = AttributeConsumingServiceBuilder::buildAttributeConsumingService();
    role.getAttributeConsumingServices().push_back(svc);
    svc->setIndex(index);
    ServiceName* sn = ServiceNameBuilder::buildServiceName();
    svc->getServiceNames().push_back(sn);
    sn->setName(dynamic_cast<EntityDescriptor*>(role.getParent())->getEntityID());
    static const XMLCh english[] = UNICODE_LITERAL_2(e,n);
    sn->setLang(english);

    for (vector< tuple<xstring,xstring,bool> >::const_iterator i = m_requestedAttrs.begin(); i != m_requestedAttrs.end(); ++i) {
        RequestedAttribute* req = RequestedAttributeBuilder::buildRequestedAttribute();
        svc->getRequestedAttributes().push_back(req);
        req->setName(i->get<0>().c_str());
        if (i->get<1>().empty())
            req->setNameFormat(saml2::Attribute::URI_REFERENCE);
        else
            req->setNameFormat(i->get<1>().c_str());
        if (i->get<2>())
            req->isRequired(true);
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const NameIdentifier& nameid,
    ptr_vector<Attribute>& attributes
    ) const
{
    const XMLCh* format = nameid.getFormat();
    if (!format || !*format)
        format = NameIdentifier::UNSPECIFIED;
    attrmap_t::const_iterator rule;
    if ((rule = m_attrMap.find(pair<xstring,xstring>(format,xstring()))) != m_attrMap.end()) {
        auto_ptr<Attribute> a(rule->second.first->decode(nullptr, rule->second.second, &nameid, assertingParty, relyingParty));
        if (a.get()) {
            attributes.push_back(a.get());
            a.release();
        }
    }
    else if (m_log.isDebugEnabled()) {
        auto_ptr_char temp(format);
        m_log.debug("skipping unmapped NameIdentifier with format (%s)", temp.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const char* assertingParty,
    const char* relyingParty,
    const NameID& nameid,
    ptr_vector<Attribute>& attributes
    ) const
{
    const XMLCh* format = nameid.getFormat();
    if (!format || !*format)
        format = NameID::UNSPECIFIED;
    attrmap_t::const_iterator rule;
    if ((rule = m_attrMap.find(pair<xstring,xstring>(format,xstring()))) != m_attrMap.end()) {
        auto_ptr<Attribute> a(rule->second.first->decode(nullptr, rule->second.second, &nameid, assertingParty, relyingParty));
        if (a.get()) {
            attributes.push_back(a.get());
            a.release();
        }
    }
    else if (m_log.isDebugEnabled()) {
        auto_ptr_char temp(format);
        m_log.debug("skipping unmapped NameID with format (%s)", temp.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const char* assertingParty,
    const char* relyingParty,
    const saml1::Attribute& attr,
    ptr_vector<Attribute>& attributes
    ) const
{
    const XMLCh* name = attr.getAttributeName();
    const XMLCh* format = attr.getAttributeNamespace();
    if (!name || !*name)
        return;
    if (!format || XMLString::equals(format, shibspconstants::SHIB1_ATTRIBUTE_NAMESPACE_URI))
        format = &chNull;
    attrmap_t::const_iterator rule;
    if ((rule = m_attrMap.find(pair<xstring,xstring>(name,format))) != m_attrMap.end()) {
        auto_ptr<Attribute> a(rule->second.first->decode(request, rule->second.second, &attr, assertingParty, relyingParty));
        if (a.get()) {
            attributes.push_back(a.get());
            a.release();
        }
    }
    else if (m_log.isInfoEnabled()) {
        auto_ptr_char temp1(name);
        auto_ptr_char temp2(format);
        m_log.info("skipping unmapped SAML 1.x Attribute with Name: %s%s%s", temp1.get(), *temp2.get() ? ", Namespace:" : "", temp2.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const char* assertingParty,
    const char* relyingParty,
    const saml2::Attribute& attr,
    ptr_vector<Attribute>& attributes
    ) const
{
    const XMLCh* name = attr.getName();
    const XMLCh* format = attr.getNameFormat();
    if (!name || !*name)
        return;
    if (!format || !*format)
        format = saml2::Attribute::UNSPECIFIED;
    else if (XMLString::equals(format, saml2::Attribute::URI_REFERENCE))
        format = &chNull;
    attrmap_t::const_iterator rule;
    if ((rule = m_attrMap.find(pair<xstring,xstring>(name,format))) != m_attrMap.end()) {
        auto_ptr<Attribute> a(rule->second.first->decode(request, rule->second.second, &attr, assertingParty, relyingParty));
        if (a.get()) {
            attributes.push_back(a.get());
            a.release();
            return;
        }
    }
    else if (XMLString::equals(format, saml2::Attribute::UNSPECIFIED)) {
        // As a fallback, if the format is "unspecified", null out the value and re-map.
        if ((rule = m_attrMap.find(pair<xstring,xstring>(name,xstring()))) != m_attrMap.end()) {
            auto_ptr<Attribute> a(rule->second.first->decode(request, rule->second.second, &attr, assertingParty, relyingParty));
            if (a.get()) {
                attributes.push_back(a.get());
                a.release();
                return;
            }
        }
    }

    if (m_log.isInfoEnabled()) {
        auto_ptr_char temp1(name);
        auto_ptr_char temp2(format);
        m_log.info("skipping unmapped SAML 2.0 Attribute with Name: %s%s%s", temp1.get(), *temp2.get() ? ", Format:" : "", temp2.get());
    }
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const char* assertingParty,
    const char* relyingParty,
    const saml1::AttributeStatement& statement,
    ptr_vector<Attribute>& attributes
    ) const
{
    static void (XMLExtractorImpl::* extract)(
        const Application&, const GenericRequest*, const char*, const char*, const saml1::Attribute&, ptr_vector<Attribute>&
        ) const = &XMLExtractorImpl::extractAttributes;
    for_each(
        make_indirect_iterator(statement.getAttributes().begin()), make_indirect_iterator(statement.getAttributes().end()),
        boost::bind(extract, this, boost::cref(application), request, assertingParty, relyingParty, _1, boost::ref(attributes))
        );
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const char* assertingParty,
    const char* relyingParty,
    const saml2::AttributeStatement& statement,
    ptr_vector<Attribute>& attributes
    ) const
{
    static void (XMLExtractorImpl::* extract)(
        const Application&, const GenericRequest*, const char*, const char*, const saml2::Attribute&, ptr_vector<Attribute>&
        ) const = &XMLExtractorImpl::extractAttributes;
    for_each(
        make_indirect_iterator(statement.getAttributes().begin()), make_indirect_iterator(statement.getAttributes().end()),
        boost::bind(extract, this, boost::cref(application), request, assertingParty, relyingParty, _1, boost::ref(attributes))
        );
}

void XMLExtractorImpl::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const ObservableMetadataProvider* observable,
    const XMLCh* entityID,
    const char* relyingParty,
    const Extensions& ext,
    ptr_vector<Attribute>& attributes
    ) const
{
    const vector<XMLObject*>& exts = ext.getUnknownXMLObjects();
    for (vector<XMLObject*>::const_iterator i = exts.begin(); i != exts.end(); ++i) {
        const EntityAttributes* container = dynamic_cast<const EntityAttributes*>(*i);
        if (!container)
            continue;

        bool useCache = false;
        map<const ObservableMetadataProvider*,decoded_t>::iterator cacheEntry;

        // Check for cached result.
        if (observable && m_metaAttrCaching) {
            m_attrLock->rdlock();
            cacheEntry = m_decodedMap.find(observable);
            if (cacheEntry == m_decodedMap.end()) {
                // We need to elevate the lock and retry.
                m_attrLock->unlock();
                m_attrLock->wrlock();
                cacheEntry = m_decodedMap.find(observable);
                if (cacheEntry == m_decodedMap.end()) {
                    SharedLock locker(m_attrLock, false);   // guard in case these throw

                    // It's still brand new, so hook it for cache activation.
                    observable->addObserver(this);

                    // Prime the map reference with an empty decoded map.
                    cacheEntry = m_decodedMap.insert(make_pair(observable,decoded_t())).first;

                    // Downgrade the lock.
                    // We don't have to recheck because we never erase the master map entry entirely, even on changes.
                    locker.release();   // unguard for lock downgrade
                    m_attrLock->unlock();
                    m_attrLock->rdlock();
                }
            }
            useCache = true;
        }

        if (useCache) {
            // We're holding the lock, so check the cache.
            decoded_t::iterator d = cacheEntry->second.find(container);
            if (d != cacheEntry->second.end()) {
                SharedLock locker(m_attrLock, false);   // pop the lock when we're done
                for (vector<DDF>::iterator obj = d->second.begin(); obj != d->second.end(); ++obj) {
                    auto_ptr<Attribute> wrapper(Attribute::unmarshall(*obj));
                    m_log.debug("recovered cached metadata attribute (%s)", wrapper->getId());
                    attributes.push_back(wrapper.get());
                    wrapper.release();
                }
                break;
            }
        }

        // Add a guard for the lock if we're caching.
        SharedLock locker(useCache ? m_attrLock.get() : nullptr, false);

        // Use a holding area to support caching.
        ptr_vector<Attribute> holding;

        // Extract attributes into holding area with no asserting party set.
        static void (XMLExtractorImpl::* extractV2Attr)(
            const Application&, const GenericRequest*, const char*, const char*, const saml2::Attribute&, ptr_vector<Attribute>&
            ) const = &XMLExtractorImpl::extractAttributes;
        for_each(
            make_indirect_iterator(container->getAttributes().begin()), make_indirect_iterator(container->getAttributes().end()),
            boost::bind(extractV2Attr, this, boost::ref(application), request, (const char*)nullptr, relyingParty, _1, boost::ref(holding))
            );

        if (entityID && m_entityAssertions) {
            const vector<saml2::Assertion*>& asserts = container->getAssertions();
            for (indirect_iterator<vector<saml2::Assertion*>::const_iterator> assert = make_indirect_iterator(asserts.begin());
                    assert != make_indirect_iterator(asserts.end()); ++assert) {
                if (!(assert->getSignature())) {
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char eid(entityID);
                        m_log.debug("skipping unsigned assertion in metadata extension for entity (%s)", eid.get());
                    }
                    continue;
                }
                else if (assert->getAttributeStatements().empty()) {
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char eid(entityID);
                        m_log.debug("skipping assertion with no AttributeStatement in metadata extension for entity (%s)", eid.get());
                    }
                    continue;
                }
                else {
                    // Check subject.
                    const NameID* subject = assert->getSubject() ? assert->getSubject()->getNameID() : nullptr;
                    if (!subject ||
                            !XMLString::equals(subject->getFormat(), NameID::ENTITY) ||
                            !XMLString::equals(subject->getName(), entityID)) {
                        if (m_log.isDebugEnabled()) {
                            auto_ptr_char eid(entityID);
                            m_log.debug("skipping assertion with improper Subject in metadata extension for entity (%s)", eid.get());
                        }
                        continue;
                    }
                }

                try {
                    // Set up and evaluate a policy for an AA asserting attributes to us.
                    shibsp::SecurityPolicy policy(application, &AttributeAuthorityDescriptor::ELEMENT_QNAME, false, m_policyId.c_str());
                    Locker locker(m_metadata.get());
                    if (m_metadata)
                        policy.setMetadataProvider(m_metadata.get());
                    if (m_trust)
                        policy.setTrustEngine(m_trust.get());
                    // Populate recipient as audience.
                    const XMLCh* issuer = assert->getIssuer() ? assert->getIssuer()->getName() : nullptr;
                    policy.getAudiences().push_back(application.getRelyingParty(issuer)->getXMLString("entityID").second);

                    // Extract assertion information for policy.
                    policy.setMessageID(assert->getID());
                    policy.setIssueInstant(assert->getIssueInstantEpoch());
                    policy.setIssuer(assert->getIssuer());

                    // Look up metadata for issuer.
                    if (policy.getIssuer() && policy.getMetadataProvider()) {
                        if (policy.getIssuer()->getFormat() && !XMLString::equals(policy.getIssuer()->getFormat(), saml2::NameIDType::ENTITY)) {
                            m_log.debug("non-system entity issuer, skipping metadata lookup");
                        }
                        else {
                            m_log.debug("searching metadata for entity assertion issuer...");
                            pair<const EntityDescriptor*,const RoleDescriptor*> lookup;
                            MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
                            mc.entityID_unicode = policy.getIssuer()->getName();
                            mc.role = &AttributeAuthorityDescriptor::ELEMENT_QNAME;
                            mc.protocol = samlconstants::SAML20P_NS;
                            lookup = policy.getMetadataProvider()->getEntityDescriptor(mc);
                            if (!lookup.first) {
                                auto_ptr_char iname(policy.getIssuer()->getName());
                                m_log.debug("no metadata found, can't establish identity of issuer (%s)", iname.get());
                            }
                            else if (!lookup.second) {
                                m_log.debug("unable to find compatible AA role in metadata");
                            }
                            else {
                                policy.setIssuerMetadata(lookup.second);
                            }
                        }
                    }

                    // Authenticate the assertion. We have to clone and marshall it to establish the signature for verification.
                    scoped_ptr<saml2::Assertion> tokencopy(assert->cloneAssertion());
                    tokencopy->marshall();
                    policy.evaluate(*tokencopy);
                    if (!policy.isAuthenticated()) {
                        if (m_log.isDebugEnabled()) {
                            auto_ptr_char tempid(tokencopy->getID());
                            auto_ptr_char eid(entityID);
                            m_log.debug(
                                "failed to authenticate assertion (%s) in metadata extension for entity (%s)", tempid.get(), eid.get()
                                );
                        }
                        continue;
                    }

                    // Override the asserting/relying party names based on this new issuer.
                    const EntityDescriptor* inlineEntity =
                        policy.getIssuerMetadata() ? dynamic_cast<const EntityDescriptor*>(policy.getIssuerMetadata()->getParent()) : nullptr;
                    auto_ptr_char inlineAssertingParty(inlineEntity ? inlineEntity->getEntityID() : nullptr);
                    relyingParty = application.getRelyingParty(inlineEntity)->getString("entityID").second;

                    // Use a private holding area for filtering purposes.
                    ptr_vector<Attribute> holding2;
                    const vector<saml2::Attribute*>& attrs2 =
                        const_cast<const saml2::AttributeStatement*>(tokencopy->getAttributeStatements().front())->getAttributes();
                    for_each(
                        make_indirect_iterator(attrs2.begin()), make_indirect_iterator(attrs2.end()),
                        boost::bind(extractV2Attr, this, boost::ref(application), request, inlineAssertingParty.get(), relyingParty, _1, boost::ref(holding2))
                        );

                    // Now we locally filter the attributes so that the actual issuer can be properly set.
                    // If we relied on outside filtering, the attributes couldn't be distinguished from the
                    // ones that come from the user's IdP.
                    if (m_filter && !holding2.empty()) {

                        // The filter API uses an unsafe container, so we have to transfer everything into one and back.
                        vector<Attribute*> unsafe_holding2;

                        // Use a local exception context since the container is unsafe.
                        try {
                            while (!holding2.empty()) {
                                ptr_vector<Attribute>::auto_type ptr = holding2.pop_back();
                                unsafe_holding2.push_back(ptr.get());
                                ptr.release();
                            }
                            BasicFilteringContext fc(application, unsafe_holding2, policy.getIssuerMetadata());
                            Locker filtlocker(m_filter.get());
                            m_filter->filterAttributes(fc, unsafe_holding2);

                            // Transfer back to safe container
                            while (!unsafe_holding2.empty()) {
                                auto_ptr<Attribute> ptr(unsafe_holding2.back());
                                unsafe_holding2.pop_back();
                                holding2.push_back(ptr.get());
                                ptr.release();
                            }
                        }
                        catch (std::exception& ex) {
                            m_log.error("caught exception filtering attributes: %s", ex.what());
                            m_log.error("dumping extracted attributes due to filtering exception");
                            for_each(unsafe_holding2.begin(), unsafe_holding2.end(), xmltooling::cleanup<Attribute>());
                            holding2.clear();   // in case the exception was during transfer between containers
                        }
                    }

                    if (!holding2.empty()) {
                        // Copy them over to the main holding tank, which transfers ownership.
                        holding.transfer(holding.end(), holding2);
                    }
                }
                catch (std::exception& ex) {
                    // Known exceptions are handled gracefully by skipping the assertion.
                    if (m_log.isDebugEnabled()) {
                        auto_ptr_char tempid(assert->getID());
                        auto_ptr_char eid(entityID);
                        m_log.debug(
                            "exception authenticating assertion (%s) in metadata extension for entity (%s): %s",
                            tempid.get(),
                            eid.get(),
                            ex.what()
                            );
                    }
                    continue;
                }
            }
        }

        if (!holding.empty()) {
            if (useCache) {
                locker.release();   // unguard to upgrade lock
                m_attrLock->unlock();
                m_attrLock->wrlock();
                SharedLock locker2(m_attrLock, false);   // pop the lock when we're done
                if (cacheEntry->second.count(container) == 0) {
                    static void (vector<DDF>::* push_back)(DDF const &) = &vector<DDF>::push_back;
                    vector<DDF>& marshalled = cacheEntry->second[container];
                    for_each(
                        holding.begin(), holding.end(),
                        boost::bind(push_back, boost::ref(marshalled), boost::bind(&Attribute::marshall, _1))
                        );
                }
            }

            // Copy them to the output parameter, which transfers ownership.
            attributes.transfer(attributes.end(), holding);
        }

        // If the lock is held, it's guarded.

        break;  // only process a single extension element
    }
}

void XMLExtractor::extractAttributes(
    const Application& application, const GenericRequest* request, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    if (!m_impl)
        return;

    ptr_vector<Attribute> holding;
    extractAttributes(application, request, issuer, xmlObject, holding);

    // Transfer ownership from the ptr_vector to the unsafe vector for API compatibility.
    // Any throws should leave each container in a consistent state. The holding container
    // is freed by us, and the result container by the caller.
    while (!holding.empty()) {
        ptr_vector<Attribute>::auto_type ptr = holding.pop_back();
        attributes.push_back(ptr.get());
        ptr.release();
    }
}

void XMLExtractor::extractAttributes(
    const Application& application, const GenericRequest* request, const RoleDescriptor* issuer, const XMLObject& xmlObject, ptr_vector<Attribute>& attributes
    ) const
{
    static void (XMLExtractor::* extractEncrypted)(
        const Application&, const GenericRequest*, const RoleDescriptor*, const XMLObject&, ptr_vector<Attribute>&
        ) const = &XMLExtractor::extractAttributes;
    static void (XMLExtractorImpl::* extractV1Statement)(
        const Application&, const GenericRequest*, const char*, const char*, const saml1::AttributeStatement&, ptr_vector<Attribute>&
        ) const = &XMLExtractorImpl::extractAttributes;

    const EntityDescriptor* entity = issuer ? dynamic_cast<const EntityDescriptor*>(issuer->getParent()) : nullptr;
    const char* relyingParty = application.getRelyingParty(entity)->getString("entityID").second;

    // Check for statements.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::AttributeStatement::LOCAL_NAME)) {
        const saml2::AttributeStatement* statement2 = dynamic_cast<const saml2::AttributeStatement*>(&xmlObject);
        if (statement2) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
            m_impl->extractAttributes(application, request, assertingParty.get(), relyingParty, *statement2, attributes);
            // Handle EncryptedAttributes inline so we have access to the role descriptor.
            const vector<saml2::EncryptedAttribute*>& encattrs = statement2->getEncryptedAttributes();
            for_each(
                make_indirect_iterator(encattrs.begin()), make_indirect_iterator(encattrs.end()),
                boost::bind(extractEncrypted, this, boost::ref(application), request, issuer, _1, boost::ref(attributes))
                );
            return;
        }

        const saml1::AttributeStatement* statement1 = dynamic_cast<const saml1::AttributeStatement*>(&xmlObject);
        if (statement1) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
            m_impl->extractAttributes(application, request, assertingParty.get(), relyingParty, *statement1, attributes);
            return;
        }

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    // Check for assertions.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Assertion::LOCAL_NAME)) {
        const saml2::Assertion* token2 = dynamic_cast<const saml2::Assertion*>(&xmlObject);
        if (token2) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
            const vector<saml2::AttributeStatement*>& statements = token2->getAttributeStatements();
            for (indirect_iterator<vector<saml2::AttributeStatement*>::const_iterator> s = make_indirect_iterator(statements.begin());
                    s != make_indirect_iterator(statements.end()); ++s) {
                m_impl->extractAttributes(application, request, assertingParty.get(), relyingParty, *s, attributes);
                // Handle EncryptedAttributes inline so we have access to the role descriptor.
                const vector<saml2::EncryptedAttribute*>& encattrs = const_cast<const saml2::AttributeStatement&>(*s).getEncryptedAttributes();
                for_each(
                    make_indirect_iterator(encattrs.begin()), make_indirect_iterator(encattrs.end()),
                    boost::bind(extractEncrypted, this, boost::ref(application), request, issuer, _1, boost::ref(attributes))
                    );
            }
            return;
        }

        const saml1::Assertion* token1 = dynamic_cast<const saml1::Assertion*>(&xmlObject);
        if (token1) {
            auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
            const vector<saml1::AttributeStatement*>& statements = token1->getAttributeStatements();
            for_each(make_indirect_iterator(statements.begin()), make_indirect_iterator(statements.end()),
                boost::bind(extractV1Statement, m_impl.get(), boost::ref(application), request, assertingParty.get(), relyingParty, _1, boost::ref(attributes))
                );
            return;
        }

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    // Check for metadata.
    if (XMLString::equals(xmlObject.getElementQName().getNamespaceURI(), samlconstants::SAML20MD_NS)) {
        const RoleDescriptor* roleToExtract = dynamic_cast<const RoleDescriptor*>(&xmlObject);
        const EntityDescriptor* entityToExtract = roleToExtract ? dynamic_cast<const EntityDescriptor*>(roleToExtract->getParent()) : nullptr;
        if (!entityToExtract)
            throw AttributeExtractionException("Unable to extract attributes, unknown metadata object type.");
        const Extensions* ext = entityToExtract->getExtensions();
        if (ext) {
            m_impl->extractAttributes(
                application,
                request,
                dynamic_cast<const ObservableMetadataProvider*>(application.getMetadataProvider(false)),
                entityToExtract->getEntityID(),
                relyingParty,
                *ext,
                attributes
                );
        }
        const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(entityToExtract->getParent());
        while (group) {
            ext = group->getExtensions();
            if (ext) {
                m_impl->extractAttributes(
                    application,
                    request,
                    dynamic_cast<const ObservableMetadataProvider*>(application.getMetadataProvider(false)),
                    nullptr,   // not an entity, so inline assertions won't be processed
                    relyingParty,
                    *ext,
                    attributes
                    );
            }
            group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
        }
        return;
    }

    // Check for attributes.
    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), saml1::Attribute::LOCAL_NAME)) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
        const saml2::Attribute* attr2 = dynamic_cast<const saml2::Attribute*>(&xmlObject);
        if (attr2)
            return m_impl->extractAttributes(application, request, assertingParty.get(), relyingParty, *attr2, attributes);

        const saml1::Attribute* attr1 = dynamic_cast<const saml1::Attribute*>(&xmlObject);
        if (attr1)
            return m_impl->extractAttributes(application, request, assertingParty.get(), relyingParty, *attr1, attributes);

        throw AttributeExtractionException("Unable to extract attributes, unknown object type.");
    }

    if (XMLString::equals(xmlObject.getElementQName().getLocalPart(), EncryptedAttribute::LOCAL_NAME)) {
        const EncryptedAttribute* encattr = dynamic_cast<const EncryptedAttribute*>(&xmlObject);
        if (encattr) {
            const XMLCh* recipient = application.getXMLString("entityID").second;
            CredentialResolver* cr = application.getCredentialResolver();
            if (!cr) {
                m_log.warn("found encrypted attribute, but no CredentialResolver was available");
                return;
            }

            try {
                Locker credlocker(cr);
                if (issuer) {
                    MetadataCredentialCriteria mcc(*issuer);
                    scoped_ptr<XMLObject> decrypted(encattr->decrypt(*cr, recipient, &mcc));
                    if (m_log.isDebugEnabled())
                        m_log.debugStream() << "decrypted Attribute: " << *decrypted << logging::eol;
                    return extractAttributes(application, request, issuer, *decrypted, attributes);
                }
                else {
                    scoped_ptr<XMLObject> decrypted(encattr->decrypt(*cr, recipient));
                    if (m_log.isDebugEnabled())
                        m_log.debugStream() << "decrypted Attribute: " << *decrypted << logging::eol;
                    return extractAttributes(application, request, issuer, *decrypted, attributes);
                }
            }
            catch (std::exception& ex) {
                m_log.error("failed to decrypt Attribute: %s", ex.what());
                return;
            }
        }
    }

    // Check for NameIDs.
    const NameID* name2 = dynamic_cast<const NameID*>(&xmlObject);
    if (name2) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
        return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *name2, attributes);
    }

    const NameIdentifier* name1 = dynamic_cast<const NameIdentifier*>(&xmlObject);
    if (name1) {
        auto_ptr_char assertingParty(entity ? entity->getEntityID() : nullptr);
        return m_impl->extractAttributes(application, assertingParty.get(), relyingParty, *name1, attributes);
    }

    m_log.debug("unable to extract attributes, unknown XML object type: %s", xmlObject.getElementQName().toString().c_str());
}

pair<bool,DOMElement*> XMLExtractor::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<XMLExtractorImpl> impl(new XMLExtractorImpl(raw.second, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}
