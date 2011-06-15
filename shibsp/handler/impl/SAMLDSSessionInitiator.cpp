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
 * SAMLDSSessionInitiator.cpp
 *
 * SAML Discovery Service support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
using namespace opensaml::saml2md;
#endif

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL SAMLDSSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        SAMLDSSessionInitiator(const DOMElement* e, const char* appId);
        virtual ~SAMLDSSessionInitiator() {}

        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        void generateMetadata(SPSSODescriptor& role, const char* handlerURL) const {
            // Initial guess at index to use.
            pair<bool,unsigned int> ix = getUnsignedInt("index");
            if (!ix.first)
                ix.second = 1;

            // Find maximum index in use and go one higher.
            if (role.getExtensions()) {
                const vector<XMLObject*>& exts = const_cast<const Extensions*>(role.getExtensions())->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_reverse_iterator i = exts.rbegin(); i != exts.rend(); ++i) {
                    const DiscoveryResponse* sub = dynamic_cast<DiscoveryResponse*>(*i);
                    if (sub) {
                        pair<bool,int> val = sub->getIndex();
                        if (val.first) {
                            if (ix.second <= val.second)
                                ix.second = val.second + 1;
                            break;
                        }
                    }
                }
            }

            const char* loc = getString("Location").second;
            string hurl(handlerURL);
            if (*loc != '/')
                hurl += '/';
            hurl += loc;
            auto_ptr_XMLCh widen(hurl.c_str());

            DiscoveryResponse* ep = DiscoveryResponseBuilder::buildDiscoveryResponse();
            ep->setLocation(widen.get());
            ep->setBinding(samlconstants::IDP_DISCOVERY_PROTOCOL_NS);
            ep->setIndex(ix.second);
            Extensions* ext = role.getExtensions();
            if (!ext) {
                ext = ExtensionsBuilder::buildExtensions();
                role.setExtensions(ext);
            }
            ext->getUnknownXMLObjects().push_back(ep);
        }
#endif

    private:
        const char* m_url;
        const char* m_returnParam;
        vector<string> m_preservedOptions;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL SAMLDSSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new SAMLDSSessionInitiator(p.first, p.second);
    }

};

SAMLDSSessionInitiator::SAMLDSSessionInitiator(const DOMElement* e, const char* appId)
        : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.SAMLDS")), m_url(nullptr), m_returnParam(nullptr)
{
    pair<bool,const char*> url = getString("URL");
    if (!url.first)
        throw ConfigurationException("SAMLDS SessionInitiator requires a URL property.");
    m_url = url.second;
    url = getString("entityIDParam");
    if (url.first)
        m_returnParam = url.second;

    pair<bool,const char*> options = getString("preservedOptions");
    if (options.first) {
        int j = 0;
        string opt = options.second;
        for (unsigned int i = 0;  i < opt.length();  i++) {
            if (opt.at(i) == ' ') {
                m_preservedOptions.push_back(opt.substr(j, i-j));
                j = i+1;
            }
        }
        m_preservedOptions.push_back(opt.substr(j, opt.length()-j));
    }
    else {
        m_preservedOptions.push_back("isPassive");
        m_preservedOptions.push_back("forceAuthn");
        m_preservedOptions.push_back("authnContextClassRef");
        m_preservedOptions.push_back("authnContextComparison");
        m_preservedOptions.push_back("NameIDFormat");
        m_preservedOptions.push_back("SPNameQualifier");
        m_preservedOptions.push_back("acsIndex");
    }

    m_supportedOptions.insert("isPassive");
}

pair<bool,long> SAMLDSSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // The IdP CANNOT be specified for us to run. Otherwise, we'd be redirecting to a DS
    // anytime the IdP's metadata was wrong.
    if (!entityID.empty() || !checkCompatibility(request, isHandler))
        return make_pair(false,0L);

    string target;
    pair<bool,const char*> prop;
    bool isPassive=false;
    const Application& app=request.getApplication();
    pair<bool,const char*> discoveryURL = pair<bool,const char*>(true, m_url);

    if (isHandler) {
        prop.second = request.getParameter("SAMLDS");
        if (prop.second && !strcmp(prop.second,"1")) {
            saml2md::MetadataException ex("No identity provider was selected by user.");
            ex.addProperty("statusCode", "urn:oasis:names:tc:SAML:2.0:status:Requester");
            ex.addProperty("statusCode2", "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP");
            ex.raise();
        }

        prop = getString("target", request);
        if (prop.first)
            target = prop.second;

        recoverRelayState(app, request, request, target, false);

        pair<bool,bool> passopt = getBool("isPassive", request);
        isPassive = passopt.first && passopt.second;

        prop.second = request.getParameter("discoveryURL");
        if (prop.second && *prop.second)
            discoveryURL.second = prop.second;
    }
    else {
        // Check for a hardwired target value in the map or handler.
        prop = getString("target", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        if (prop.first)
            target = prop.second;
        else
            target = request.getRequestURL();

        pair<bool,bool> passopt = getBool("isPassive", request, HANDLER_PROPERTY_MAP|HANDLER_PROPERTY_FIXED);
        isPassive = passopt.first && passopt.second;
        discoveryURL = request.getRequestSettings().first->getString("discoveryURL");
    }

    if (!discoveryURL.first)
        discoveryURL.second = m_url;
    m_log.debug("sending request to SAMLDS (%s)", discoveryURL.second);

    // Compute the return URL. We start with a self-referential link.
    string returnURL = request.getHandlerURL(target.c_str());
    prop = getString("Location");
    if (prop.first)
        returnURL += prop.second;
    returnURL += "?SAMLDS=1"; // signals us not to loop if we get no answer back

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but we've turned it back into a resource by this point, so if there's
        // a target on the URL, reset to that value.
        prop.second = request.getParameter("target");
        if (prop.second && *prop.second)
            target = prop.second;
    }
    preserveRelayState(app, request, target);
    if (!isHandler)
        preservePostData(app, request, request, target.c_str());

    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    if (isHandler) {
        // Now the hard part. The base assumption is to append the entire query string, if any,
        // to the self-link. But we want to replace target with the RelayState-preserved value
        // to hide it from the DS.
        const char* query = request.getQueryString();
        if (query) {
            // See if it starts with target.
            if (!strncmp(query, "target=", 7)) {
                // We skip this altogether and advance the query past it to the first separator.
                query = strchr(query, '&');
                // If we still have more, just append it.
                if (query && *(++query))
                    returnURL = returnURL + '&' + query;
            }
            else {
                // There's something in the query before target appears, so we have to find it.
                prop.second = strstr(query, "&target=");
                if (prop.second) {
                    // We found it, so first append everything up to it.
                    returnURL += '&';
                    returnURL.append(query, prop.second - query);
                    query = prop.second + 8; // move up just past the equals sign.
                    prop.second = strchr(query, '&');
                    if (prop.second)
                        returnURL += prop.second;
                }
                else {
                    // No target in the existing query, so just append it as is.
                    returnURL = returnURL + '&' + query;
                }
            }
        }

        // Now append the sanitized target as needed.
        if (!target.empty())
            returnURL = returnURL + "&target=" + urlenc->encode(target.c_str());
    }
    else {
        // For a virtual handler, we append target to the return link.
         if (!target.empty())
            returnURL = returnURL + "&target=" + urlenc->encode(target.c_str());
         // Preserve designated request settings on the URL.
         for (vector<string>::const_iterator opt = m_preservedOptions.begin(); opt != m_preservedOptions.end(); ++ opt) {
             prop = request.getRequestSettings().first->getString(opt->c_str());
             if (prop.first)
                 returnURL = returnURL + '&' + (*opt) + '=' + urlenc->encode(prop.second);
         }
    }

    string req=string(discoveryURL.second) + (strchr(discoveryURL.second,'?') ? '&' : '?') + "entityID=" + urlenc->encode(app.getString("entityID").second) +
        "&return=" + urlenc->encode(returnURL.c_str());
    if (m_returnParam)
        req = req + "&returnIDParam=" + m_returnParam;
    if (isPassive)
        req += "&isPassive=true";

    return make_pair(true, request.sendRedirect(req.c_str()));
}
