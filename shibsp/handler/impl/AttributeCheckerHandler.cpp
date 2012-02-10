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
 * AttributeCheckerHandler.cpp
 *
 * Handler for checking a session for required attributes.
 */

#include "internal.h"
#include "AccessControl.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"
#include "handler/AbstractHandler.h"
#include "util/TemplateParameters.h"

#include <fstream>
#include <sstream>
#include <boost/bind.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/algorithm/string.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/PathResolver.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL Blocker : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL Blocker g_Blocker;

    class SHIBSP_API AttributeCheckerHandler : public AbstractHandler
    {
    public:
        AttributeCheckerHandler(const DOMElement* e, const char* appId);
        virtual ~AttributeCheckerHandler() {}

        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        void flushSession(SPRequest& request) const {
            try {
                request.getApplication().getServiceProvider().getSessionCache()->remove(request.getApplication(), request, &request);
            }
            catch (std::exception&) {
            }
        }

        string m_template;
        bool m_flushSession;
        vector<string> m_attributes;
        scoped_ptr<AccessControl> m_acl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    Handler* SHIBSP_DLLLOCAL AttributeCheckerFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new AttributeCheckerHandler(p.first, p.second);
    }

    static const XMLCh attributes[] =   UNICODE_LITERAL_10(a,t,t,r,i,b,u,t,e,s);
    static const XMLCh _flushSession[] = UNICODE_LITERAL_12(f,l,u,s,h,S,e,s,s,i,o,n);
    static const XMLCh _template[] =    UNICODE_LITERAL_8(t,e,m,p,l,a,t,e);
};

AttributeCheckerHandler::AttributeCheckerHandler(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".AttributeCheckerHandler"), &g_Blocker)
{
    if (!SPConfig::getConfig().isEnabled(SPConfig::InProcess))
        return;
    m_template = XMLHelper::getAttrString(e, nullptr, _template);
    if (m_template.empty())
        throw ConfigurationException("AttributeChecker missing required template setting.");
    XMLToolingConfig::getConfig().getPathResolver()->resolve(m_template, PathResolver::XMLTOOLING_CFG_FILE);

    m_flushSession = XMLHelper::getAttrBool(e, false, _flushSession);

    string attrs(XMLHelper::getAttrString(e, nullptr, attributes));
    if (!attrs.empty()) {
        split(m_attributes, attrs, is_space(), algorithm::token_compress_on);
        if (m_attributes.empty())
            throw ConfigurationException("AttributeChecker unable to parse attributes setting.");
    }
    else {
        m_acl.reset(SPConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL, e));
    }
}

pair<bool,long> AttributeCheckerHandler::run(SPRequest& request, bool isHandler) const
{
    // If the checking passes, we route to the return URL, target URL, or homeURL in that order.
    const char* returnURL = request.getParameter("return");
    const char* target = request.getParameter("target");
    if (!returnURL)
        returnURL = target;
    if (returnURL)
        request.getApplication().limitRedirect(request, returnURL);
    else
        returnURL = request.getApplication().getString("homeURL").second;
    if (!returnURL)
        returnURL = "/";
       
    Session* session = nullptr;
    try {
        session = request.getSession(true, false, false);
        if (!session)
            request.log(SPRequest::SPWarn, "AttributeChecker found session unavailable immediately after creation");
    }
    catch (std::exception& ex) {
        request.log(SPRequest::SPWarn, string("AttributeChecker caught exception accessing session immediately after creation: ") + ex.what());
    }

    Locker sessionLocker(session, false);

    bool checked = false;
    if (session) {
        if (!m_attributes.empty()) {
            typedef multimap<string,const Attribute*> indexed_t;
            static indexed_t::const_iterator (indexed_t::* fn)(const string&) const = &indexed_t::find;
            const indexed_t& indexed = session->getIndexedAttributes();
            // Look for an attribute in the list that is not in the session multimap.
            // If that fails, the check succeeds.
            checked = (
                find_if(m_attributes.begin(), m_attributes.end(),
                    boost::bind(fn, boost::cref(indexed), _1) == indexed.end()) == m_attributes.end()
                );
        }
        else {
            checked = (m_acl && m_acl->authorized(request, session) == AccessControl::shib_acl_true);
        }
    }

    if (checked) {
        string loc(returnURL);
        request.absolutize(loc);
        return make_pair(true, request.sendRedirect(loc.c_str()));
    }

    request.setContentType("text/html; charset=UTF-8");
    request.setResponseHeader("Expires","Wed, 01 Jan 1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache,max-age=0");

    ifstream infile(m_template.c_str());
    if (infile) {
        TemplateParameters tp(nullptr, request.getApplication().getPropertySet("Errors"), session);
        tp.m_request = &request;
        stringstream str;
        XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, tp);
        if (m_flushSession) {
            sessionLocker.assign(); // unlock the session
            flushSession(request);
        }
        return make_pair(true, request.sendError(str));
    }

    if (m_flushSession) {
        sessionLocker.assign(); // unlock the session
        flushSession(request);
    }
    m_log.error("could not process error template (%s)", m_template.c_str());
    istringstream msg("Internal Server Error. Please contact the site administrator.");
    return make_pair(true, request.sendResponse(msg));
}
