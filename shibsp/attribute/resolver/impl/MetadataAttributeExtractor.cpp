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
 * MetadataAttributeExtractor.cpp
 *
 * AttributeExtractor for SAML metadata content.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/SimpleAttribute.h"
#include "attribute/AttributeDecoder.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#include <boost/tuple/tuple.hpp>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class MetadataExtractor : public AttributeExtractor
    {
    public:
        MetadataExtractor(const DOMElement* e);
        ~MetadataExtractor() {}

        Lockable* lock() {
            return this;
        }

        void unlock() {
        }

        // deprecated
        void extractAttributes(
            const Application& application,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<shibsp::Attribute*>& attributes
            ) const {
            extractAttributes(application, nullptr, issuer, xmlObject, attributes);
        }

        void extractAttributes(
            const Application& application,
            const GenericRequest* request,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<shibsp::Attribute*>& attributes
            ) const;
        void getAttributeIds(vector<string>& attributes) const;

    private:
        string m_attributeProfiles,
            m_errorURL,
            m_displayName,
            m_description,
            m_informationURL,
            m_privacyURL,
            m_orgName,
            m_orgDisplayName,
            m_orgURL;
        typedef tuple< string,xstring,boost::shared_ptr<AttributeDecoder> > contact_tuple_t;
        typedef tuple< string,int,int,boost::shared_ptr<AttributeDecoder> > logo_tuple_t;
        vector<contact_tuple_t> m_contacts; // tuple is attributeID, contact type, decoder
        vector<logo_tuple_t> m_logos;       // tuple is attributeID, height, width, decoder

        template <class T> void doLangSensitive(const GenericRequest*, const vector<T*>&, const string&, vector<shibsp::Attribute*>&) const;
        void doContactPerson(const RoleDescriptor*, const contact_tuple_t&, vector<shibsp::Attribute*>&) const;
        void doLogo(const GenericRequest*, const vector<Logo*>&,const logo_tuple_t&, vector<shibsp::Attribute*>&) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeExtractor* SHIBSP_DLLLOCAL MetadataAttributeExtractorFactory(const DOMElement* const & e)
    {
        return new MetadataExtractor(e);
    }

    static const XMLCh _id[] = UNICODE_LITERAL_2(i,d);
    static const XMLCh _formatter[] = UNICODE_LITERAL_9(f,o,r,m,a,t,t,e,r);
};

MetadataExtractor::MetadataExtractor(const DOMElement* e)
    : m_attributeProfiles(XMLHelper::getAttrString(e, nullptr, AttributeProfile::LOCAL_NAME)),
        m_errorURL(XMLHelper::getAttrString(e, nullptr, RoleDescriptor::ERRORURL_ATTRIB_NAME)),
        m_displayName(XMLHelper::getAttrString(e, nullptr, DisplayName::LOCAL_NAME)),
        m_description(XMLHelper::getAttrString(e, nullptr, Description::LOCAL_NAME)),
        m_informationURL(XMLHelper::getAttrString(e, nullptr, InformationURL::LOCAL_NAME)),
        m_privacyURL(XMLHelper::getAttrString(e, nullptr, PrivacyStatementURL::LOCAL_NAME)),
        m_orgName(XMLHelper::getAttrString(e, nullptr, OrganizationName::LOCAL_NAME)),
        m_orgDisplayName(XMLHelper::getAttrString(e, nullptr, OrganizationDisplayName::LOCAL_NAME)),
        m_orgURL(XMLHelper::getAttrString(e, nullptr, OrganizationURL::LOCAL_NAME))
{
    e = e ? XMLHelper::getFirstChildElement(e) : nullptr;
    while (e) {
        if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2SPCONFIG_NS, ContactPerson::LOCAL_NAME)) {
            string id(XMLHelper::getAttrString(e, nullptr, _id));
            const XMLCh* type = e->getAttributeNS(nullptr, ContactPerson::CONTACTTYPE_ATTRIB_NAME);
            if (!id.empty() && type && *type) {
                boost::shared_ptr<AttributeDecoder> decoder(SPConfig::getConfig().AttributeDecoderManager.newPlugin(DOMAttributeDecoderType, e));
                m_contacts.push_back(contact_tuple_t(id, type, decoder));
            }
        }
        else if (XMLHelper::isNodeNamed(e, shibspconstants::SHIB2SPCONFIG_NS, Logo::LOCAL_NAME)) {
            string id(XMLHelper::getAttrString(e, nullptr, _id));
            int h(XMLHelper::getAttrInt(e, 0, Logo::HEIGHT_ATTRIB_NAME));
            int w(XMLHelper::getAttrInt(e, 0, Logo::WIDTH_ATTRIB_NAME));
            if (!id.empty()) {
                boost::shared_ptr<AttributeDecoder> decoder(SPConfig::getConfig().AttributeDecoderManager.newPlugin(DOMAttributeDecoderType, e));
                m_logos.push_back(logo_tuple_t(id, h, w, decoder));
            }
        }
        e = XMLHelper::getNextSiblingElement(e);
    }
}

void MetadataExtractor::getAttributeIds(vector<string>& attributes) const
{
    if (!m_attributeProfiles.empty())
        attributes.push_back(m_attributeProfiles);
    if (!m_errorURL.empty())
        attributes.push_back(m_errorURL);
    if (!m_displayName.empty())
        attributes.push_back(m_displayName);
    if (!m_description.empty())
        attributes.push_back(m_description);
    if (!m_informationURL.empty())
        attributes.push_back(m_informationURL);
    if (!m_privacyURL.empty())
        attributes.push_back(m_privacyURL);
    if (!m_orgName.empty())
        attributes.push_back(m_orgName);
    if (!m_orgDisplayName.empty())
        attributes.push_back(m_orgDisplayName);
    if (!m_orgURL.empty())
        attributes.push_back(m_orgURL);
    for (vector<contact_tuple_t>::const_iterator c = m_contacts.begin(); c != m_contacts.end(); ++c)
        attributes.push_back(c->get<0>());
    for (vector<logo_tuple_t>::const_iterator l = m_logos.begin(); l != m_logos.end(); ++l)
        attributes.push_back(l->get<0>());
}

void MetadataExtractor::extractAttributes(
    const Application& application,
    const GenericRequest* request,
    const RoleDescriptor* issuer,
    const XMLObject& xmlObject,
    vector<shibsp::Attribute*>& attributes
    ) const
{
    const RoleDescriptor* roleToExtract = dynamic_cast<const RoleDescriptor*>(&xmlObject);
    if (!roleToExtract)
        return;

    if (!m_attributeProfiles.empty()) {
        const vector<AttributeProfile*>* profiles = nullptr;
        const IDPSSODescriptor* idpRole = dynamic_cast<const IDPSSODescriptor*>(roleToExtract);
        if (idpRole) {
            profiles = &(idpRole->getAttributeProfiles());
        }
        else {
            const AttributeAuthorityDescriptor* aaRole = dynamic_cast<const AttributeAuthorityDescriptor*>(roleToExtract);
            if (aaRole) {
                profiles = &(aaRole->getAttributeProfiles());
            }
        }
        if (profiles && !profiles->empty()) {
            auto_ptr<SimpleAttribute> attr(new SimpleAttribute(vector<string>(1, m_attributeProfiles)));
            for (indirect_iterator<vector<AttributeProfile*>::const_iterator> i = make_indirect_iterator(profiles->begin());
                    i != make_indirect_iterator(profiles->end()); ++i) {
                auto_ptr_char temp(i->getProfileURI());
                if (temp.get())
                    attr->getValues().push_back(temp.get());
            }
            if (attr->valueCount() > 0) {
                attributes.push_back(attr.get());
                attr.release();
            }
        }
    }

    if (!m_errorURL.empty() && roleToExtract->getErrorURL()) {
        auto_ptr_char temp(roleToExtract->getErrorURL());
        if (temp.get() && *temp.get()) {
            auto_ptr<SimpleAttribute> attr(new SimpleAttribute(vector<string>(1, m_errorURL)));
            attr->getValues().push_back(temp.get());
            attributes.push_back(attr.get());
            attr.release();
        }
    }

    if (!m_displayName.empty() || !m_description.empty() || !m_informationURL.empty() || !m_privacyURL.empty()) {
        const Extensions* exts = roleToExtract->getExtensions();
        if (exts) {
            const UIInfo* ui;
            for (vector<XMLObject*>::const_iterator ext = exts->getUnknownXMLObjects().begin(); ext != exts->getUnknownXMLObjects().end(); ++ext) {
                ui = dynamic_cast<const UIInfo*>(*ext);
                if (ui) {
                    doLangSensitive(request, ui->getDisplayNames(), m_displayName, attributes);
                    doLangSensitive(request, ui->getDescriptions(), m_description, attributes);
                    doLangSensitive(request, ui->getInformationURLs(), m_informationURL, attributes);
                    doLangSensitive(request, ui->getPrivacyStatementURLs(), m_privacyURL, attributes);
                    const vector<Logo*>& logos = ui->getLogos();
                    if (!logos.empty()) {
                        for_each(
                            m_logos.begin(), m_logos.end(),
                            boost::bind(&MetadataExtractor::doLogo, this, request, boost::ref(logos), _1, boost::ref(attributes))
                            );
                    }
                    break;
                }
            }
        }
    }

    if (!m_orgName.empty() || !m_orgDisplayName.empty() || !m_orgURL.empty()) {
        const Organization* org = roleToExtract->getOrganization();
        if (!org)
            org = dynamic_cast<EntityDescriptor*>(roleToExtract->getParent())->getOrganization();
        if (org) {
            doLangSensitive(request, org->getOrganizationNames(), m_orgName, attributes);
            doLangSensitive(request, org->getOrganizationDisplayNames(), m_orgDisplayName, attributes);
            doLangSensitive(request, org->getOrganizationURLs(), m_orgURL, attributes);
        }
    }

    for_each(
        m_contacts.begin(), m_contacts.end(),
        boost::bind(&MetadataExtractor::doContactPerson, this, roleToExtract, _1, boost::ref(attributes))
        );
}

template <class T> void MetadataExtractor::doLangSensitive(
    const GenericRequest* request, const vector<T*>& objects, const string& id, vector<shibsp::Attribute*>& attributes
    ) const
{
    if (objects.empty() || id.empty())
        return;

    T* match = nullptr;
    if (request && request->startLangMatching()) {
        do {
            for (typename vector<T*>::const_iterator i = objects.begin(); !match && i != objects.end(); ++i) {
                if (request->matchLang((*i)->getLang()))
                    match = *i;
            }
        } while (!match && request->continueLangMatching());
    }
    if (!match)
        match = objects.front();

    auto_arrayptr<char> temp(toUTF8(match->getTextContent()));
    if (temp.get() && *temp.get()) {
        auto_ptr<SimpleAttribute> attr(new SimpleAttribute(vector<string>(1, id)));
        attr->getValues().push_back(temp.get());
        attributes.push_back(attr.get());
        attr.release();
    }
}

void MetadataExtractor::doLogo(
    const GenericRequest* request, const vector<Logo*>& logos, const logo_tuple_t& params, vector<shibsp::Attribute*>& attributes
    ) const
{
    if (logos.empty())
        return;

    pair<bool,int> dim;
    Logo* match = nullptr;
    int h = params.get<1>(), w = params.get<2>(), sizediff, bestdiff = INT_MAX;
    if (request && request->startLangMatching()) {
        do {
            for (vector<Logo*>::const_iterator i = logos.begin(); i != logos.end(); ++i) {
                if (!(*i)->getLang() || request->matchLang((*i)->getLang())) {
                    sizediff = 0;
                    if (h > 0) {
                        dim = (*i)->getHeight();
                        sizediff += abs(h - dim.second);
                    }
                    if (w > 0) {
                        dim = (*i)->getWidth();
                        sizediff += abs(w - dim.second);
                    }
                    if (sizediff < bestdiff) {
                        match = *i;
                        bestdiff = sizediff;
                    }
                }
                if (match && bestdiff == 0)
                    break;
            }
            if (match && bestdiff == 0)
                break;
        } while (request->continueLangMatching());
    }
    else if (h > 0 || w > 0) {
        for (vector<Logo*>::const_iterator i = logos.begin(); i != logos.end(); ++i) {
            sizediff = 0;
            if (h > 0) {
                dim = (*i)->getHeight();
                sizediff += abs(h - dim.second);
            }
            if (w > 0) {
                dim = (*i)->getWidth();
                sizediff += abs(w - dim.second);
            }
            if (sizediff < bestdiff) {
                match = *i;
                bestdiff = sizediff;
            }
            if (match && bestdiff == 0)
                break;
        }
    }

    if (!match)
        match = logos.front();

    if (!match->getDOM()) {
        match->marshall();
    }
    vector<string> ids(1, params.get<0>());
    auto_ptr<Attribute> attr(params.get<3>()->decode(ids, match));
    if (attr.get()) {
        attributes.push_back(attr.get());
        attr.release();
    }
}

void MetadataExtractor::doContactPerson(
    const RoleDescriptor* role, const contact_tuple_t& params, vector<shibsp::Attribute*>& attributes
    ) const
{
    const XMLCh* ctype = params.get<1>().c_str();
    static bool (*eq)(const XMLCh*, const XMLCh*) = &XMLString::equals;
    const ContactPerson* cp = find_if(role->getContactPersons(),boost::bind(eq, ctype, boost::bind(&ContactPerson::getContactType, _1)));
    if (!cp) {
        cp = find_if(dynamic_cast<EntityDescriptor*>(role->getParent())->getContactPersons(),
                boost::bind(eq, ctype, boost::bind(&ContactPerson::getContactType, _1)));
    }

    if (cp) {
        if (!cp->getDOM()) {
            cp->marshall();
        }
        vector<string> ids(1, params.get<0>());
        auto_ptr<Attribute> attr(params.get<2>()->decode(ids, cp));
        if (attr.get()) {
            attributes.push_back(attr.get());
            attr.release();
        }
    }
}
