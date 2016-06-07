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
 * AttributeResolverHandler.cpp
 *
 * Handler that runs the attribute resolver machinery and outputs the results directly.
 */

#include "internal.h"

#include <shibsp/Application.h>
#include <shibsp/exceptions.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/SPConfig.h>
#include <shibsp/SPRequest.h>
#include <shibsp/handler/SecuredHandler.h>
#include <shibsp/handler/RemotedHandler.h>

#include <boost/scoped_ptr.hpp>

#ifndef SHIBSP_LITE
#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/filtering/AttributeFilter.h>
#include <shibsp/attribute/filtering/BasicFilteringContext.h>
#include <shibsp/attribute/resolver/AttributeExtractor.h>
#include <shibsp/attribute/resolver/AttributeResolver.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>

#include <saml/exceptions.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <boost/iterator/indirect_iterator.hpp>
#endif

using namespace std;
using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;

#ifndef SHIBSP_LITE
using namespace opensaml::saml2md;
#endif

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL AttributeResolverHandler : public SecuredHandler, public RemotedHandler
    {
    public:
        AttributeResolverHandler(const DOMElement* e, const char* appId);
        virtual ~AttributeResolverHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;
        void receive(DDF& in, ostream& out);

    private:
        pair<bool,long> processMessage(
            const Application& application,
            const HTTPRequest& httpRequest,
            HTTPResponse& httpResponse
            ) const;

#ifndef SHIBSP_LITE
        ResolutionContext* resolveAttributes(
            const Application& application,
            const HTTPRequest& httpRequest,
            const RoleDescriptor* issuer,
            const XMLCh* protocol,
            const saml1::NameIdentifier* v1nameid,
            const saml2::NameID* nameid
            ) const;

        ostream& buildJSON(ostream& os, vector<shibsp::Attribute*>& attributes, const char* encoding) const;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AttributeResolverHandlerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new AttributeResolverHandler(p.first, p.second);
    }

};

#ifndef SHIBSP_LITE

namespace {
    class SHIBSP_DLLLOCAL DummyContext : public shibsp::ResolutionContext
    {
    public:
        DummyContext(const vector<Attribute*>& attributes) : m_attributes(attributes) {
        }

        virtual ~DummyContext() {
            for_each(m_attributes.begin(), m_attributes.end(), xmltooling::cleanup<Attribute>());
        }

        vector<Attribute*>& getResolvedAttributes() {
            return m_attributes;
        }
        vector<Assertion*>& getResolvedAssertions() {
            return m_tokens;
        }

    private:
        vector<Attribute*> m_attributes;
        static vector<Assertion*> m_tokens; // never any tokens, so just share an empty vector
    };

    static ostream& json_safe(ostream& os, const char* buf)
    {
        os << '"';
        for (; *buf; ++buf) {
            switch (*buf) {
                case '\\':
                case '"':
                    os << '\\';
                    os << *buf;
                    break;
                case '\b':
                    os << "\\b";
                    break;
                case '\t':
                    os << "\\t";
                    break;
                case '\n':
                    os << "\\n";
                    break;
                case '\f':
                    os << "\\f";
                    break;
                case '\r':
                    os << "\\r";
                    break;
                default:
                    os << *buf;
            }
        }
        os << '"';
        return os;
    }
};

vector<Assertion*> DummyContext::m_tokens;

#endif

AttributeResolverHandler::AttributeResolverHandler(const DOMElement* e, const char* appId)
        : SecuredHandler(e, Category::getInstance(SHIBSP_LOGCAT".AttributeResolverHandler"), "acl", "127.0.0.1 ::1")
{
    pair<bool,const char*> prop = getString("Location");
    if (!prop.first)
        throw ConfigurationException("AttributeQuery handler requires Location property.");
    string address(appId);
    address += prop.second;
    setAddress(address.c_str());
}

pair<bool,long> AttributeResolverHandler::run(SPRequest& request, bool isHandler) const
{
    // Check ACL in base class.
    pair<bool,long> ret = SecuredHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");
    request.setContentType("application/json; charset=utf-8");

    try {
        if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
            // When out of process, we run natively and directly process the message.
            return processMessage(request.getApplication(), request, request);
        }
        else {
            // When not out of process, we remote all the message processing.
            DDF out, in = wrap(request);
            DDFJanitor jin(in), jout(out);
            out=request.getServiceProvider().getListenerService()->send(in);
            return unwrap(request, out);
        }
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        istringstream msg("{}");
        return make_pair(true, request.sendError(msg));
    }
}

void AttributeResolverHandler::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid = in["application_id"].string();
    const Application* app = aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : nullptr;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) for AttributeResolver request", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for request, deleted?");
    }

    // Wrap a response shim.
    DDF ret(nullptr);
    DDFJanitor jout(ret);
    scoped_ptr<HTTPResponse> resp(getResponse(ret));
    scoped_ptr<HTTPRequest> req(getRequest(in));

    // Since we're remoted, the result should either be a throw, a false/0 return,
    // which we just return as an empty structure, or a response/redirect,
    // which we capture in the facade and send back.
    try {
        processMessage(*app, *req, *resp);
    }
    catch (std::exception& ex) {
        m_log.error("raising exception: %s", ex.what());
        throw;
    }
    out << ret;
}

pair<bool,long> AttributeResolverHandler::processMessage(
    const Application& application, const HTTPRequest& httpRequest, HTTPResponse& httpResponse
    ) const
{
#ifndef SHIBSP_LITE
    stringstream msg;

    pair<bool,const char*> param_protocol = getString("protocol", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_issuer = getString("entityID", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_format = getString("format", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_qual = getString("nameQualifier", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_spqual = getString("spNameQualifier", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_nameid = getString("nameId", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);
    pair<bool,const char*> param_encoding = getString("encoding", httpRequest, HANDLER_PROPERTY_REQUEST|HANDLER_PROPERTY_FIXED);

    if (!param_nameid.first) {
        // Something's horribly wrong.
        m_log.error("no nameId parameter supplied for request");
        throw FatalProfileException("Required nameId parameter not found");
    }

    auto_ptr_XMLCh entityID(param_issuer.second);
    auto_ptr_XMLCh nameID(param_nameid.second);
    auto_ptr_XMLCh format(param_format.second);

    if (param_protocol.first) {
        if (!strcmp(param_protocol.second, "SAML2.0"))
            param_protocol.second = "urn:oasis:names:tc:SAML:2.0:protocol"; // samlconstants::SAML20P_NS;
        else if (!strcmp(param_protocol.second, "SAML1.1"))
            param_protocol.second = "urn:oasis:names:tc:SAML:1.1:protocol"; // samlconstants::SAML11_PROTOCOL_ENUM;
        else if (!strcmp(param_protocol.second, "SAML1.0"))
            param_protocol.second = "urn:oasis:names:tc:SAML:1.0:protocol"; // samlconstants::SAML10_PROTOCOL_ENUM;
    }
    else {
        param_protocol.second = "urn:oasis:names:tc:SAML:2.0:protocol"; // samlconstants::SAML20P_NS;
    }
    auto_ptr_XMLCh protocol(param_protocol.second);

    try {
        MetadataProvider* m = application.getMetadataProvider();
        Locker mlock(m);

        pair<const EntityDescriptor*,const RoleDescriptor*> site = make_pair(nullptr, nullptr);
        if (entityID.get()) {
            MetadataProviderCriteria mc(application, entityID.get(), &IDPSSODescriptor::ELEMENT_QNAME, protocol.get());
            site = m->getEntityDescriptor(mc);
            if (!site.first)
                m_log.info("Unable to locate metadata for IdP (%s).", param_issuer.second);
        }

        auto_ptr_XMLCh nameQualifier(param_qual.first ? param_qual.second : param_issuer.second);
        auto_ptr_XMLCh spNameQualifier(param_spqual.first ? param_spqual.second
            : application.getRelyingParty(site.first)->getString("entityID").second);

        // Build NameID(s).
        scoped_ptr<saml1::NameIdentifier> v1name;
        scoped_ptr<saml2::NameID> v2name(saml2::NameIDBuilder::buildNameID());
        v2name->setName(nameID.get());
        v2name->setFormat(format.get());
        v2name->setNameQualifier(nameQualifier.get());
        v2name->setSPNameQualifier(spNameQualifier.get());
        if (!XMLString::equals(protocol.get(), samlconstants::SAML20P_NS)) {
            v1name.reset(saml1::NameIdentifierBuilder::buildNameIdentifier());
            v1name->setName(nameID.get());
            v1name->setFormat(format.get());
            v1name->setNameQualifier(nameQualifier.get());
        }

        scoped_ptr<ResolutionContext> ctx;
        ctx.reset(resolveAttributes(application, httpRequest, site.second, protocol.get(), v1name.get(), v2name.get()));

        buildJSON(msg, ctx->getResolvedAttributes(), param_encoding.second);
    }
    catch (std::exception& ex) {
        m_log.error("error while processing request: %s", ex.what());
        msg << "{}";
        return make_pair(true, httpResponse.sendError(msg));
    }
    return make_pair(true, httpResponse.sendResponse(msg));
#else
    return make_pair(false, 0L);
#endif
}

#ifndef SHIBSP_LITE
ResolutionContext* AttributeResolverHandler::resolveAttributes(
    const Application& application,
    const HTTPRequest& httpRequest,
    const RoleDescriptor* issuer,
    const XMLCh* protocol,
    const saml1::NameIdentifier* v1nameid,
    const saml2::NameID* nameid
    ) const
{
    // First we do the extraction of any pushed information, including from metadata.
    vector<Attribute*> resolvedAttributes;
    AttributeExtractor* extractor = application.getAttributeExtractor();
    if (extractor) {
        Locker extlocker(extractor);
        if (issuer) {
            pair<bool,const char*> mprefix = application.getString("metadataAttributePrefix");
            if (mprefix.first) {
                m_log.debug("extracting metadata-derived attributes...");
                try {
                    // We pass nullptr for "issuer" because the IdP isn't the one asserting metadata-based attributes.
                    extractor->extractAttributes(application, &httpRequest, nullptr, *issuer, resolvedAttributes);
                    for (indirect_iterator<vector<Attribute*>::iterator> a = make_indirect_iterator(resolvedAttributes.begin());
                            a != make_indirect_iterator(resolvedAttributes.end()); ++a) {
                        vector<string>& ids = a->getAliases();
                        for (vector<string>::iterator id = ids.begin(); id != ids.end(); ++id)
                            *id = mprefix.second + *id;
                    }
                }
                catch (std::exception& ex) {
                    m_log.error("caught exception extracting attributes: %s", ex.what());
                }
            }
        }

        m_log.debug("extracting attributes from NameID/NameIdentifier...");

        if (v1nameid || nameid) {
            try {
                if (v1nameid)
                    extractor->extractAttributes(application, &httpRequest, issuer, *v1nameid, resolvedAttributes);
                else
                    extractor->extractAttributes(application, &httpRequest, issuer, *nameid, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception extracting attributes: %s", ex.what());
            }
        }

        AttributeFilter* filter = application.getAttributeFilter();
        if (filter && !resolvedAttributes.empty()) {
            BasicFilteringContext fc(application, resolvedAttributes, issuer, nullptr, nullptr);
            Locker filtlocker(filter);
            try {
                filter->filterAttributes(fc, resolvedAttributes);
            }
            catch (std::exception& ex) {
                m_log.error("caught exception filtering attributes: %s", ex.what());
                m_log.error("dumping extracted attributes due to filtering exception");
                for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
                resolvedAttributes.clear();
            }
        }
    }

    try {
        AttributeResolver* resolver = application.getAttributeResolver();
        if (resolver) {
            m_log.debug("resolving attributes...");

            Locker locker(resolver);
            auto_ptr<ResolutionContext> ctx(
                resolver->createResolutionContext(
                    application,
                    &httpRequest,
                    issuer ? dynamic_cast<const saml2md::EntityDescriptor*>(issuer->getParent()) : nullptr,
                    protocol,
                    nameid,
                    nullptr,
                    nullptr,
                    nullptr,
                    &resolvedAttributes
                    )
                );
            resolver->resolveAttributes(*ctx);
            // Copy over any pushed attributes.
            while (!resolvedAttributes.empty()) {
                ctx->getResolvedAttributes().push_back(resolvedAttributes.back());
                resolvedAttributes.pop_back();
            }
            return ctx.release();
        }
    }
    catch (std::exception& ex) {
        m_log.error("attribute resolution failed: %s", ex.what());
    }

    if (!resolvedAttributes.empty()) {
        try {
            return new DummyContext(resolvedAttributes);
        }
        catch (bad_alloc&) {
            for_each(resolvedAttributes.begin(), resolvedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
        }
    }
    return nullptr;
}

ostream& AttributeResolverHandler::buildJSON(ostream& os, vector<shibsp::Attribute*>& attributes, const char* encoding) const
{
    m_log.debug("building JSON from attributes..");

    os << '{';

    indirect_iterator<vector<Attribute*>::const_iterator> ahead = make_indirect_iterator(attributes.begin());
    indirect_iterator<vector<Attribute*>::const_iterator> a = ahead;
    for (; a != make_indirect_iterator(attributes.end()); ++a) {

        if (a != ahead)
            os << ',';

        vector<string>::const_iterator shead = a->getAliases().begin();
        for (vector<string>::const_iterator s = shead; s != a->getAliases().end(); ++s) {
            if (s != shead)
                os << ',';
            os << endl << "    ";
            json_safe(os, s->c_str());
            os << " : ";

            if (!encoding || !strcmp(encoding,"JSON")) {
                os << '[' << endl;
                vector<string>::const_iterator vhead = a->getSerializedValues().begin();
                for (vector<string>::const_iterator v = vhead; v != a->getSerializedValues().end(); ++v) {
                    if (v != vhead)
                        os << ',';
                    os << endl << "        ";
                    json_safe(os, v->c_str());
                }
                os << endl << "    ]";
            }
            else if (!strcmp(encoding,"JSON/CGI")) {
                string attrValues;
                vector<string>::const_iterator vhead = a->getSerializedValues().begin();
                for (vector<string>::const_iterator v = vhead; v != a->getSerializedValues().end(); ++v) {
                    if (v != vhead)
                        attrValues += ';';
                    string::size_type pos = v->find_first_of(';', string::size_type(0));
                    if (pos != string::npos) {
                        string value(*v);
                        for (; pos != string::npos; pos = value.find_first_of(';', pos)) {
                            value.insert(pos, "\\");
                            pos += 2;
                        }
                        attrValues += value;
                    }
                    else {
                        attrValues += *v;
                    }
                }
                json_safe(os, attrValues.c_str());
            }

        }
    }
    if (a != ahead)
        os << endl;

    os << '}';

    return os;
}
#endif
